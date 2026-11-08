//! Server lifecycle: startup, the public handle, and graceful shutdown.

mod accept;
mod bind;
mod budget;
mod connection;
mod idle;
mod prefixed;
mod proxy;
mod tls;

pub use proxy::resolve_client_ip;

use crate::AppState;
use crate::config::Config;
use crate::telemetry::{FLUSH_TIMEOUT, Telemetry};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

type BoxError = Box<dyn Error + Send + Sync>;

pub struct ServerHandle {
    addr: SocketAddr,
    state: Arc<AppState>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.state.telemetry.shutdown(FLUSH_TIMEOUT).await;
    }

    pub async fn wait(&mut self) {
        if let Some(task) = self.task.as_mut() {
            let _ = task.await;
        }
        self.task = None;
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            // Dropping the accept task drops its JoinSet, which aborts every connection task.
            task.abort();
        }
    }
}

/// Binding is complete when this returns, so callers may connect immediately.
pub async fn start(config: Config) -> Result<ServerHandle, BoxError> {
    config.validate()?;
    let telemetry = Telemetry::init(&config)?;
    start_with(config, telemetry).await
}

/// Like [`start`], with telemetry already built (embedders and tests).
pub async fn start_with(config: Config, telemetry: Telemetry) -> Result<ServerHandle, BoxError> {
    config.validate()?;
    // Load TLS before binding so a bad pair never leaves a listener behind.
    let acceptor = config
        .tls
        .as_ref()
        .map(|t| tls::load_tls(t, config.http2))
        .transpose()?;
    let addr = bind::resolve_bind_addr(&config.host, config.port).await?;
    let listener = bind::bind_listener(addr, &config)
        .map_err(|e| BoxError::from(format!("cannot bind {addr}: {e}")))?;
    let local = listener.local_addr()?;
    let state = AppState::with_telemetry(config, telemetry);
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(accept::accept_loop(listener, state.clone(), acceptor, rx));
    Ok(ServerHandle {
        addr: local,
        state,
        stop,
        task: Some(task),
    })
}

pub fn run(config: Config, on_bound: impl FnOnce(&ServerHandle)) -> Result<(), BoxError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut handle = start(config).await?;
        let callback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_bound(&handle)));
        if let Err(panic) = callback {
            handle.shutdown().await;
            std::panic::resume_unwind(panic);
        }
        tokio::select! {
            () = shutdown_signal() => {}
            () = handle.wait() => {}
        }
        handle.shutdown().await;
        Ok::<(), BoxError>(())
    });
    // Blocking-pool threads (file I/O) must not delay process exit.
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = async {
                match term.as_mut() {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Resolves once shutdown is requested; the watch guard must not live across awaits.
pub(super) async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}
