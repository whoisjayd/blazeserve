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

```python
blazeserve.Server(
    path=None, host="127.0.0.1", port=0, *,
    listing, hide, auth, cors, no_cache,
    max_upload_mb, rate_mbps, tls_cert, tls_key,
)
```

These match the command-line options of the same names. `hide` takes a list of patterns, for example `hide=["*.env", ".git"]`. Settings that are wrong, such as a certificate without a key, raise `blazeserve.BlazeError`.

Unlike `blaze serve`, the Python server listens on the loopback address by default, so it is not visible to your network unless you ask for that with `host`.

### Other helpers

```python
blazeserve.sha256("big.iso")                      # checksum of a file
blazeserve.main(["get", "http://host:8000/big.iso"])   # run any blaze command, returns the exit status
```

`serve_forever()` blocks until you press `Ctrl+C`, and `close()` stops a server without a `with` block. Resumable downloads and uploads are available through `blazeserve.main` and show progress as the command does.

## Rust

BlazeServe is also a Rust library. Use `blazeserve::config::Config` with `blazeserve::server::start` to run a server inside your own tokio runtime, and `blazeserve::cli::main_from` to run the command line from a list of arguments.

The repository's integration tests under `tests/` are good working examples.
