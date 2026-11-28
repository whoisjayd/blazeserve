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
use std::error::Error;
use std::future::Future;
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

/// Binds and immediately releases the address `start` would pick for `host` and `port`.
/// Returns the address that was actually tested. The result is a point-in-time answer.
pub fn probe_bind(host: &str, port: u16) -> Result<SocketAddr, BoxError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let addr = bind::resolve_bind_addr(host, port).await?;
        let listener = bind::bind_listener(addr, &Config::default())
            .map_err(|e| BoxError::from(format!("cannot bind {addr}: {e}")))?;
        Ok(listener.local_addr()?)
    })
}

/// Binding is complete when this returns, so callers may connect immediately.
pub async fn start(config: Config) -> Result<ServerHandle, BoxError> {
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
    let state = AppState::new(config);
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(accept::accept_loop(listener, state.clone(), acceptor, rx));
    Ok(ServerHandle {
        addr: local,
        state,
        stop,
        task: Some(task),
    })
}

/// Why a running server stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Ctrl+C or SIGTERM.
    Signal,
    /// The lifetime set with `expires_after` ran out.
    Expired,
    /// The accept loop ended on its own.
    Closed,
}

impl ServerHandle {
    /// Waits for `interrupt`, for `expiry`, or for the server to end on its own.
    pub async fn wait_until(
        &mut self,
        expiry: impl Future<Output = ()>,
        interrupt: impl Future<Output = ()>,
    ) -> StopReason {
        tokio::select! {
            () = interrupt => StopReason::Signal,
            () = expiry => StopReason::Expired,
            () = self.wait() => StopReason::Closed,
        }
    }
}

pub fn run(config: Config, on_bound: impl FnOnce(&ServerHandle)) -> Result<(), BoxError> {
    run_expiring(config, None, on_bound).map(|_| ())
}

/// Like [`run`], and stops serving after `expires_after` when given. The countdown starts
/// once the listener is bound.
pub fn run_expiring(
    config: Config,
    expires_after: Option<Duration>,
    on_bound: impl FnOnce(&ServerHandle),
) -> Result<StopReason, BoxError> {
    run_until(config, expires_after, std::future::pending(), on_bound)
}

/// Like [`run_expiring`], and also shuts down gracefully when `stop` resolves, as it does
/// for a request from `blaze stop`.
pub fn run_until(
    config: Config,
    expires_after: Option<Duration>,
    stop: impl Future<Output = ()>,
    on_bound: impl FnOnce(&ServerHandle),
) -> Result<StopReason, BoxError> {
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
        let expiry = async {
            match expires_after {
                Some(after) => tokio::time::sleep(after).await,
                None => std::future::pending().await,
            }
        };
        let interrupt = async {
            tokio::select! {
                () = crate::platform::shutdown_signal() => {}
                () = stop => {}
            }
        };
        let reason = handle.wait_until(expiry, interrupt).await;
        handle.shutdown().await;
        Ok::<StopReason, BoxError>(reason)
    });
    // Blocking-pool threads (file I/O) must not delay process exit.
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}

/// Resolves once shutdown is requested; the watch guard must not live across awaits.
pub(super) async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}
