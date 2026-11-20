//! Python bindings, built only with the `python` feature and exposed as `blazeserve._native`.
//!
//! Nothing here keeps its own list of options. A command line, and the settings of a
//! [`Server`], are built from the clap definition by [`crate::cli::argv`], so a new command or
//! option is available from Python as soon as it exists.

use crate::cli::argv::{self, OptValue};
use crate::server::{self, ServerHandle};
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;

pyo3::create_exception!(_native, BlazeError, PyException);

/// How often a waiting call looks for Ctrl+C.
const SIGNAL_POLL: Duration = Duration::from_millis(50);
/// How long a command gets to stop cleanly after Ctrl+C before the call gives up waiting.
const STOP_GRACE: Duration = Duration::from_secs(15);

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

fn misuse(message: impl ToString) -> PyErr {
    PyTypeError::new_err(message.to_string())
}

/// A value as command-line text: strings as they are, paths through `os.fspath`, numbers as
/// Python prints them.
fn text_of(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if value.is_instance_of::<PyString>() {
        return value.extract();
    }
    if value.hasattr("__fspath__")? {
        return value
            .py()
            .import("os")?
            .call_method1("fspath", (value,))?
            .extract();
    }
    if value.is_instance_of::<PyInt>() || value.is_instance_of::<PyFloat>() {
        return value.str()?.extract();
    }
    Err(misuse(format!(
        "expected a string, path or number, not {}",
        value.get_type().name()?
    )))
}

/// `None` leaves the option out; a bool is a switch; a list or tuple repeats the option.
fn option_value(value: &Bound<'_, PyAny>) -> PyResult<Option<OptValue>> {
    if value.is_none() {
        return Ok(None);
    }
    if value.is_instance_of::<PyBool>() {
        return Ok(Some(OptValue::Flag(value.extract()?)));
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        let items = value
            .try_iter()?
            .map(|item| text_of(&item?))
            .collect::<PyResult<Vec<_>>>()?;
        return Ok(Some(OptValue::Values(items)));
    }
    Ok(Some(OptValue::Values(vec![text_of(value)?])))
}

fn options_of(options: Option<&Bound<'_, PyDict>>) -> PyResult<Vec<(String, OptValue)>> {
    let mut out = Vec::new();
    if let Some(options) = options {
        for (key, value) in options.iter() {
            if let Some(value) = option_value(&value)? {
                out.push((key.extract::<String>()?, value));
            }
        }
    }
    Ok(out)
}

fn positional_of(values: &Bound<'_, PyTuple>) -> PyResult<Vec<String>> {
    values.iter().map(|v| text_of(&v)).collect()
}

/// Runs the CLI on its own thread and waits for it here, so Ctrl+C reaches Python as
/// `KeyboardInterrupt` and the command is asked to stop at its next safe point: transfers keep
/// their resume data and servers finish what they are sending. The GIL is released while
/// waiting, so other Python threads keep running.
fn run_cli(py: Python<'_>, args: Vec<String>) -> PyResult<i32> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("blaze-cli".into())
        .stack_size(8 << 20)
        .spawn(move || {
            let _ = tx.send(crate::cli::main_from(args));
        })
        .map_err(fail)?;
    // `Receiver` is not `Sync`, which releasing the GIL needs; only this function waits on it.
    let rx = Mutex::new(rx);
    let wait = |py: Python<'_>, limit: Duration| {
        py.detach(|| {
            rx.lock()
                .map_err(|_| RecvTimeoutError::Disconnected)
                .and_then(|r| r.recv_timeout(limit))
        })
    };
    loop {
        match wait(py, SIGNAL_POLL) {
            Ok(code) => return Ok(i32::from(code)),
            Err(RecvTimeoutError::Timeout) => {
                if let Err(interrupt) = py.check_signals() {
                    crate::cli::request_stop();
                    let _ = wait(py, STOP_GRACE);
                    return Err(interrupt);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(fail("the command stopped unexpectedly"));
            }
        }
    }
}

fn with_program(args: Vec<String>) -> Vec<String> {
    std::iter::once("blaze".to_owned()).chain(args).collect()
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
    /// Starts serving `path` (a folder, or a single file) on `host` and `port`; port 0 picks a
    /// free one. Any other keyword is an option of `blaze serve`, written with underscores,
    /// for example `max_upload_mb=100` or `hide=["*.env"]`, and is checked exactly as the
    /// command line checks it.
    #[new]
    #[pyo3(signature = (path = None, host = "127.0.0.1", port = 0, **options))]
    fn new(
        py: Python<'_>,
        path: Option<PathBuf>,
        host: &str,
        port: u16,
        options: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let mut opts = options_of(options)?;
        opts.push(("host".to_owned(), OptValue::Values(vec![host.to_owned()])));
        let mut positional = Vec::new();
        if let Some(path) = path {
            let target = std::fs::canonicalize(&path)
                .map_err(|e| fail(format!("cannot resolve {}: {e}", path.display())))?;
            let is_file = target.is_file();
            let target = target.to_string_lossy().into_owned();
            if is_file {
                opts.push(("single".to_owned(), OptValue::Values(vec![target])));
            } else {
                positional.push(target);
            }
        }
        let argv = argv::build("serve", &positional, &opts).map_err(misuse)?;
        let mut config = crate::cli::serve_config_from(&argv).map_err(fail)?;
        // The command line cannot ask for port 0, which is how a library picks a free port.
        config.port = port;
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
fn cli_main(py: Python<'_>, argv: Option<Vec<String>>) -> PyResult<i32> {
    run_cli(py, with_program(argv.unwrap_or_default()))
}

/// Run one command, taking its options as keywords: `run("get", url, connections=8)`.
/// Positional values follow the command; options use underscores. Returns the exit status.
#[pyfunction]
#[pyo3(signature = (command, *positional, **options))]
fn run(
    py: Python<'_>,
    command: &str,
    positional: &Bound<'_, PyTuple>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<i32> {
    let argv =
        argv::build(command, &positional_of(positional)?, &options_of(options)?).map_err(misuse)?;
    run_cli(py, with_program(argv))
}

/// The command line that `run` would use, without running it. Useful for checking a call.
#[pyfunction]
#[pyo3(signature = (command, *positional, **options))]
fn command_line(
    command: &str,
    positional: &Bound<'_, PyTuple>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<Vec<String>> {
    argv::build(command, &positional_of(positional)?, &options_of(options)?).map_err(misuse)
}

/// The commands `blaze` understands, as `(name, description)` pairs.
#[pyfunction]
fn commands() -> Vec<(String, String)> {
    argv::commands()
}

/// Check for, or install, a newer release. Returns the result as JSON text.
#[pyfunction]
#[pyo3(signature = (check = true, version = None, yes = false))]
fn upgrade(py: Python<'_>, check: bool, version: Option<String>, yes: bool) -> PyResult<String> {
    py.detach(|| crate::cli::upgrade_api(check, version, yes))
        .map_err(fail)
}

#[pymodule]
mod _native {
    use pyo3::prelude::*;

    #[pymodule_export]
    use super::{BlazeError, Server, cli_main, command_line, commands, run, sha256, upgrade};

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add("__version__", crate::VERSION)
    }
}
