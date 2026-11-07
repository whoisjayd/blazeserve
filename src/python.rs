//! Python bindings, built only with the `python` feature and exposed as `blazeserve._native`.

use crate::config::{Config, Credentials};
use crate::server::{self, ServerHandle};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;

pyo3::create_exception!(_native, BlazeError, PyException);

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("blaze-python")
            .enable_all()
            .build()
            .expect("the operating system refused to start worker threads")
    })
}

fn fail(message: impl ToString) -> PyErr {
    BlazeError::new_err(message.to_string())
}

/// A running file server. Closing it, leaving a `with` block or dropping it stops the listener.
#[pyclass(frozen, module = "blazeserve._native")]
struct Server {
    handle: Mutex<Option<ServerHandle>>,
    host: String,
    port: u16,
    tls: bool,
}

#[pymethods]
impl Server {
    #[new]
    #[pyo3(signature = (
        path = None,
        host = "127.0.0.1",
        port = 0,
        *,
        listing = true,
        auth = None,
        cors = false,
        no_cache = false,
        max_upload_mb = 0,
        rate_mbps = None,
        tls_cert = None,
        tls_key = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        path: Option<PathBuf>,
        host: &str,
        port: u16,
        listing: bool,
        auth: Option<&str>,
        cors: bool,
        no_cache: bool,
        max_upload_mb: u64,
        rate_mbps: Option<f64>,
        tls_cert: Option<PathBuf>,
        tls_key: Option<PathBuf>,
    ) -> PyResult<Self> {
        let target = path.unwrap_or_else(|| PathBuf::from("."));
        let target = std::fs::canonicalize(&target)
            .map_err(|e| fail(format!("cannot resolve {}: {e}", target.display())))?;
        let (base, single) = if target.is_file() {
            let parent = target.parent().map(PathBuf::from).unwrap_or_default();
            (parent, Some(target))
        } else {
            (target, None)
        };
        let config = Config {
            host: host.to_owned(),
            port,
            base,
            single,
            listing,
            cors,
            no_cache,
            rate_mbps,
            max_upload_bytes: max_upload_mb.saturating_mul(1024 * 1024),
            auth: auth
                .map(|a| Credentials::parse(a).map_err(|_| fail("auth must be USER:PASS")))
                .transpose()?,
            tls: Config::tls_pair(tls_cert, tls_key).map_err(fail)?,
            ..Config::default()
        };
        let tls = config.tls.is_some();
        let handle = py
            .detach(move || runtime().block_on(server::start(config)))
            .map_err(fail)?;
        let addr = handle.local_addr();
        Ok(Self {
            handle: Mutex::new(Some(handle)),
            host: display_host(addr.ip()),
            port: addr.port(),
            tls,
        })
    }

    /// Base URL of the server, for example `http://127.0.0.1:8000/`.
    #[getter]
    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}:{}/", self.host, self.port)
    }

    #[getter]
    fn port(&self) -> u16 {
        self.port
    }

    #[getter]
    fn running(&self) -> bool {
        self.handle.lock().is_ok_and(|h| h.is_some())
    }

    /// Stop accepting connections, give in-flight transfers a bounded grace period, and
    /// return. Calling it again does nothing.
    fn close(&self, py: Python<'_>) {
        let handle = self.handle.lock().ok().and_then(|mut h| h.take());
        if let Some(handle) = handle {
            py.detach(move || runtime().block_on(handle.shutdown()));
        }
    }

    /// Block until the server is closed. `KeyboardInterrupt` is raised on Ctrl+C.
    fn serve_forever(&self, py: Python<'_>) -> PyResult<()> {
        while self.running() {
            py.detach(|| std::thread::sleep(Duration::from_millis(100)));
            py.check_signals()?;
        }
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type = None, _exc_value = None, _traceback = None))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.close(py);
        false
    }

    fn __repr__(&self) -> String {
        format!("Server(url={:?}, running={})", self.url(), self.running())
    }
}

fn display_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_owned(),
        IpAddr::V6(v6) if v6.is_unspecified() => "[::1]".to_owned(),
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Streamed SHA-256 of a file as lowercase hex.
#[pyfunction]
fn sha256(py: Python<'_>, path: PathBuf) -> PyResult<String> {
    py.detach(|| crate::cli::sha256_file(&path))
        .map_err(PyErr::from)
}

/// Run the `blaze` command line with `argv` (without the program name) and return its exit status.
#[pyfunction]
#[pyo3(name = "main", signature = (argv = None))]
fn cli_main(py: Python<'_>, argv: Option<Vec<String>>) -> i32 {
    let args: Vec<String> = std::iter::once("blaze".to_owned())
        .chain(argv.unwrap_or_default())
        .collect();
    i32::from(py.detach(|| crate::cli::main_from(args)))
}

#[pymodule]
mod _native {
    use pyo3::prelude::*;

    #[pymodule_export]
    use super::{BlazeError, Server, cli_main, sha256};

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add("__version__", crate::VERSION)
    }
}
