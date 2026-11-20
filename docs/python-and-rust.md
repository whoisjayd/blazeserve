# Python and Rust

You can run BlazeServe from your own code. This is handy for tests that need a local file server, or for tools that want to share files without launching a separate process.

## Python

`pip install blazeserve` installs the `blaze` command and a Python module in one package. It works with Python 3.11 and newer.

```python
import blazeserve

with blazeserve.Server("./site", port=0, auth="ada:secret") as server:
    print(server.url)   # for example http://127.0.0.1:53124/
    # use any HTTP client against server.url
```

Using port `0` lets the system pick a free port, and `server.url` tells you which one. The server is already listening when the constructor returns, and it stops when you leave the `with` block.

### Options

`path`, `host` and `port` are the first arguments. Any other keyword is an option of `blaze serve`, written with underscores, and is checked exactly as the command line checks it:

```python
blazeserve.Server(
    "./site", port=0,
    auth="ada:secret", hide=["*.env", ".git"], cors=True, cors_origin="https://example.com",
    max_upload_mb=100, rate_mbps=50, tls_cert="cert.pem", tls_key="key.pem",
)
```

`True` and `False` switch an option on or off, a list repeats the option, and a path can be a string or a `pathlib.Path`. Settings that are wrong, such as a certificate without a key, raise `blazeserve.BlazeError`, and an option that does not exist raises `TypeError` naming the ones that do. The names come from the program itself, so an option added to `blaze serve` later works here without a new release of the Python code.

Unlike `blaze serve`, the Python server listens on the loopback address by default, so it is not visible to your network unless you ask for that with `host`. Everything else uses the same defaults as the command line.

### Every command

Each `blaze` command is a function with the same name. Positional values come first and options are keywords written with underscores. The return value is the exit status, which is `0` on success and uses the [exit codes](reference.md#exit-codes) otherwise.

```python
blazeserve.get("http://host:8000/big.iso", connections=8, extract=True)
blazeserve.put("backup.tar", "http://host:8000", limit_rate="2M", max_time="2h")
blazeserve.send("report.pdf", expires_after="20m")
blazeserve.get("http://host:8000/big.iso", background=True)   # prints the job ID
blazeserve.status(json=True)
blazeserve.run("get", "http://host:8000/big.iso", connections=8)   # the same, by name
blazeserve.commands()    # {"serve": "...", "get": "...", ...}
```

`blazeserve.command_line("get", url, connections=8)` shows the command line a call would run, without running it. Progress is drawn on the terminal exactly as on the command line, and a long call lets other Python threads keep running.

Press `Ctrl+C` during a call and it raises `KeyboardInterrupt` after asking the command to stop cleanly: a download keeps its resume data and a server finishes what it is sending. Background jobs, `status` and `stop` work from Python the same way, and the worker is started with the Python that is running your code.

### Other helpers

```python
blazeserve.sha256("big.iso")                      # checksum of a file
blazeserve.main(["get", "http://host:8000/big.iso"])   # run a command line as a list, returns the exit status
```

```python
blazeserve.upgrade()                          # check only; returns a dict
blazeserve.upgrade(check=False, yes=True)     # upgrade with pip
```

`upgrade()` returns the fields of `blaze upgrade --check --json` plus `status` and `message`, for example `{"current": "1.0.0", "latest": "1.1.0", "update_available": True, ...}`. It never asks a question, so an upgrade needs `yes=True`, and it raises `blazeserve.BlazeError` on failure. `python -m blazeserve upgrade` and the `blaze` command do the same as `blaze upgrade`, and run pip with the Python that started them. Upgrading a package that is in use can fail on Windows because the files are locked; close other programs that use it, or run `python -m pip install --upgrade blazeserve` from a fresh shell.

`serve_forever()` blocks until you press `Ctrl+C`, and `close()` stops a server without a `with` block.

## Rust

BlazeServe is also a Rust library. Use `blazeserve::config::Config` with `blazeserve::server::start` to run a server inside your own tokio runtime, and `blazeserve::cli::main_from` to run the command line from a list of arguments.

The repository's integration tests under `tests/` are good working examples.
