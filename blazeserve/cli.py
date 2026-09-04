import os
import socket
import sys
import webbrowser

try:
    import rich_click as click  # type: ignore[import-not-found]

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.TEXT_MARKUP = "markdown"
    click.rich_click.STYLE_HELPTEXT = "cyan"
    click.rich_click.STYLE_OPTION = "bold bright_white"
    click.rich_click.STYLE_SWITCH = "bold bright_white"
    click.rich_click.STYLE_HELPTEXT_FIRST_LINE = "bold cyan"
except ImportError:
    import click  # type: ignore

import contextlib

from rich import box
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .logging import get_console, setup_logging
from .server import run_server
from .utils import human_size, sha256_file

console = get_console()


def _resolve_auth(auth: str | None, auth_env: str | None) -> str | None:
    """Resolve and validate credentials without silently disabling requested auth."""
    if auth is None and auth_env:
        auth = os.environ.get(auth_env)
        if not auth:
            raise click.ClickException(
                f"Authentication environment variable {auth_env!r} is missing or empty."
            )
    if auth is not None and ":" not in auth:
        raise click.ClickException("Auth must be USER:PASS.")
    return auth


def _validate_tls_pair(tls_cert: str | None, tls_key: str | None) -> None:
    """Reject an incomplete TLS configuration instead of falling back to plaintext HTTP."""
    if bool(tls_cert) != bool(tls_key):
        raise click.ClickException("--tls-cert and --tls-key must be provided together.")


def _print_status(renderable, *, json_logs: bool) -> None:
    """Keep human-oriented status output out of a JSON log stream."""
    if json_logs:
        from rich.console import Console

        Console(stderr=True).print(renderable)
    else:
        console.print(renderable)


def _lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.05)
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=False,
)
@click.version_option(version=__version__, prog_name="blaze")
def cli() -> None:
    setup_logging("WARNING")


@cli.command("serve", short_help="Serve a directory or a single file.")
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=True, file_okay=True, path_type=str),
    default=".",
)
@click.option(
    "--host",
    default="0.0.0.0",
    show_default=True,
    help="Bind address (IPv4/IPv6 literal ok).",
)
@click.option(
    "-p",
    "--port",
    type=click.IntRange(1, 65535),
    default=8000,
    show_default=True,
    help="Port to listen on.",
)
@click.option(
    "--single",
    type=click.Path(exists=True, dir_okay=False, file_okay=True, path_type=str),
    help="Serve exactly this file.",
)
@click.option("--no-listing", is_flag=True, help="Disable directory listing.")
@click.option(
    "--chunk-mb",
    type=click.IntRange(4, 4096),
    default=256,
    show_default=True,
    help="mmap/read window size.",
)
@click.option(
    "--sock-sndbuf-mb",
    type=click.IntRange(1, 2048),
    default=128,
    show_default=True,
    help="SO_SNDBUF size.",
)
@click.option(
    "--timeout",
    type=click.IntRange(60, 86400),
    default=1800,
    show_default=True,
    help="Per-connection timeout (seconds).",
)
@click.option(
    "--rate-mbps",
    type=click.FloatRange(min=0.1),
    default=None,
    help="Throttle to MB/s (omit for unlimited).",
)
@click.option("--auth", metavar="USER:PASS", envvar=None, help="Enable HTTP Basic Auth.")
@click.option("--auth-env", metavar="ENVVAR", help="Load USER:PASS from environment variable.")
@click.option(
    "--tls-cert",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="TLS certificate (PEM).",
)
@click.option(
    "--tls-key",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="TLS private key (PEM).",
)
@click.option("--cors/--no-cors", default=False, show_default=True, help="Enable CORS.")
@click.option("--cors-origin", default="*", show_default=True, help="CORS allow origin.")
@click.option("--no-cache", is_flag=True, help="Disable HTTP caching.")
@click.option("--index", multiple=True, help="Additional index filenames to try (repeatable).")
@click.option(
    "--backlog",
    type=click.IntRange(1, 20000),
    default=8192,
    show_default=True,
    help="Listen backlog size.",
)
@click.option(
    "--precompress/--no-precompress",
    default=True,
    show_default=True,
    help="Serve .gz assets when safe.",
)
@click.option(
    "--max-upload-mb",
    type=click.IntRange(0, 1024 * 1024),
    default=0,
    show_default=True,
    help="Max upload size (0 = unlimited).",
)
@click.option("--open", "open_browser", is_flag=True, help="Open the URL in a browser on start.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose startup banner.")
@click.option(
    "--log-json/--no-log-json",
    default=False,
    envvar="BLAZE_LOG_JSON",
    help="Emit structured JSON log records.",
)
def serve_cmd(
    path: str,
    host: str,
    port: int,
    single: str | None,
    no_listing: bool,
    chunk_mb: int,
    sock_sndbuf_mb: int,
    timeout: int,
    rate_mbps: float | None,
    auth: str | None,
    auth_env: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    cors: bool,
    cors_origin: str,
    no_cache: bool,
    index: tuple[str, ...],
    backlog: int,
    precompress: bool,
    max_upload_mb: int,
    open_browser: bool,
    verbose: bool,
    log_json: bool = False,
) -> None:
    setup_logging("INFO" if verbose else "WARNING", json_logs=log_json)
    target = os.path.abspath(path)
    if single:
        single = os.path.abspath(single)
        if not os.path.isfile(single):
            raise click.ClickException(f"Single file not found: {single}")
        base = os.path.dirname(single)
    elif os.path.isfile(target):
        single = target
        base = os.path.dirname(target)
    else:
        if not os.path.isdir(target):
            raise click.ClickException(f"Path not found: {target}")
        base = target
    auth = _resolve_auth(auth, auth_env)
    _validate_tls_pair(tls_cert, tls_key)
    scheme = "https" if tls_cert else "http"
    lan = _lan_ip()
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold cyan")
    table.add_column(style="bold white")
    table.add_row("Serving", single or base)
    table.add_row("Local", f"[green]{scheme}://localhost:{port}/[/]")
    table.add_row("Network", f"[green]{scheme}://{lan}:{port}/[/]")

    # Add performance info if verbose
    if verbose:
        table.add_row("", "")  # Spacer
        table.add_row("Send Buffer", f"{sock_sndbuf_mb} MB")
        table.add_row("Chunk Size", f"{chunk_mb} MB")
        table.add_row("Backlog", str(backlog))
        if rate_mbps:
            table.add_row("Rate Limit", f"{rate_mbps} MB/s")
        table.add_row("Metrics", f"{scheme}://{lan}:{port}/__perf__")

    status_panel = Panel(
        table,
        title=f"[bold magenta]⚡ BlazeServe v{__version__}[/]",
        subtitle="Press Ctrl+C to stop",
        box=box.ROUNDED,
    )

    def report_started(_server: object) -> None:
        _print_status(status_panel, json_logs=log_json)
        if open_browser:
            with contextlib.suppress(OSError, webbrowser.Error):
                webbrowser.open(f"{scheme}://localhost:{port}/")

    try:
        run_server(
            host=host,
            port=port,
            base=base,
            single=single,
            listing=not no_listing,
            chunk_mb=chunk_mb,
            sndbuf_mb=sock_sndbuf_mb,
            timeout=timeout,
            rate_mbps=rate_mbps,
            auth=auth,
            tls_cert=tls_cert,
            tls_key=tls_key,
            cors=cors,
            cors_origin=cors_origin,
            no_cache=no_cache,
            log_json=log_json,
            index=list(index) if index else None,
            backlog=backlog,
            precompress=precompress,
            max_upload_mb=max_upload_mb,
            verbose=False,
            on_bound=report_started,
        )
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down...[/]")


@cli.command("send", short_help="Quick share a single file.")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, file_okay=True, path_type=str))
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("-p", "--port", type=click.IntRange(1, 65535), default=8000, show_default=True)
@click.option("--rate-mbps", type=click.FloatRange(min=0.1), default=None)
@click.option("--auth", metavar="USER:PASS")
@click.option("--auth-env", metavar="ENVVAR")
@click.option("--tls-cert", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--tls-key", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--cors/--no-cors", default=False, show_default=True)
@click.option("--cors-origin", default="*", show_default=True)
@click.option("--no-cache", is_flag=True)
@click.option("--backlog", type=click.IntRange(1, 20000), default=8192, show_default=True)
@click.option("--precompress/--no-precompress", default=True, show_default=True)
@click.option(
    "--max-upload-mb",
    type=click.IntRange(0, 1024 * 1024),
    default=0,
    show_default=True,
    help="Max upload size in MB (0 = disabled).",
)
@click.option(
    "--log-json/--no-log-json",
    default=False,
    envvar="BLAZE_LOG_JSON",
    help="Emit structured JSON log records.",
)
def send_cmd(
    file: str,
    host: str,
    port: int,
    rate_mbps: float | None,
    auth: str | None,
    auth_env: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    cors: bool,
    cors_origin: str,
    no_cache: bool,
    backlog: int,
    precompress: bool,
    max_upload_mb: int,
    log_json: bool = False,
) -> None:
    setup_logging("INFO", json_logs=log_json)
    ap = os.path.abspath(file)
    base = os.path.dirname(ap)
    auth = _resolve_auth(auth, auth_env)
    _validate_tls_pair(tls_cert, tls_key)
    scheme = "https" if tls_cert else "http"
    lan = _lan_ip()

    def report_started(_server: object) -> None:
        _print_status(f"[bold green]Share:[/] {ap}", json_logs=log_json)
        _print_status(f"[cyan]{scheme}://{lan}:{port}/[/]", json_logs=log_json)

    try:
        run_server(
            host=host,
            port=port,
            base=base,
            single=ap,
            listing=False,
            chunk_mb=256,
            sndbuf_mb=128,
            timeout=1800,
            rate_mbps=rate_mbps,
            auth=auth,
            tls_cert=tls_cert,
            tls_key=tls_key,
            cors=cors,
            cors_origin=cors_origin,
            no_cache=no_cache,
            index=None,
            log_json=log_json,
            backlog=backlog,
            precompress=precompress,
            max_upload_mb=max_upload_mb,
            verbose=False,
            on_bound=report_started,
        )
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down...[/]")


@cli.command("checksum", short_help="SHA256 for files.")
@click.argument("files", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=str))
def checksum_cmd(files):
    if not files:
        raise click.ClickException("Provide at least one file.")
    rows = []
    for p in files:
        ap = os.path.abspath(p)
        digest = sha256_file(ap)
        rows.append((digest, p, human_size(os.path.getsize(ap))))
    tbl = Table(title="SHA256", box=box.SIMPLE, show_lines=False)
    tbl.add_column("Digest", style="green")
    tbl.add_column("File", overflow="fold")
    tbl.add_column("Size", justify="right", style="cyan")
    for d, f, sz in rows:
        tbl.add_row(d, f, sz)
    console.print(tbl)


@cli.command("version", short_help="Show version and system info.")
@click.option("--json", "json_output", is_flag=True, help="Display machine-readable JSON.")
def version_cmd(json_output: bool = False) -> None:
    """Display version and system information."""
    import json
    import platform

    from rich.panel import Panel
    from rich.table import Table

    if json_output:
        data = {
            "name": "blazeserve",
            "version": __version__,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": platform.system(),
            "architecture": platform.machine(),
        }
        click.echo(json.dumps(data, indent=2))
        return

    # Create info table
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="bold cyan")
    info_table.add_column(style="white")

    info_table.add_row("Version", __version__)
    info_table.add_row(
        "Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    info_table.add_row("Platform", platform.system())
    info_table.add_row("Architecture", platform.machine())

    console.print(
        Panel(
            info_table,
            title="[bold magenta]⚡ BlazeServe[/]",
            subtitle="Ultra-fast HTTP file server",
            box=box.ROUNDED,
        )
    )


@cli.command("doctor", short_help="Validate system environment and server configuration.")
@click.argument("path", default=".", type=click.Path(path_type=str))
@click.option(
    "-p",
    "--port",
    type=click.IntRange(1, 65535),
    default=8000,
    help="Port to check availability.",
)
def doctor_cmd(path: str, port: int) -> None:
    """Run production readiness diagnostics on paths, ports, and OS capabilities."""
    import socket

    from rich.table import Table

    tbl = Table(title="⚡ BlazeServe Production Diagnostics", border_style="cyan")
    tbl.add_column("Component", style="bold")
    tbl.add_column("Status", style="bold")
    tbl.add_column("Details")

    all_ok = True
    abs_p = os.path.abspath(path)

    # Check 1: Base directory
    if os.path.isdir(abs_p) and os.access(abs_p, os.R_OK):
        tbl.add_row("Base Path", "[green]OK[/]", f"Readable directory: {abs_p}")
    else:
        tbl.add_row("Base Path", "[red]FAIL[/]", f"Cannot read: {abs_p}")
        all_ok = False

    # Check 2: Port availability
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            tbl.add_row("Port Binding", "[green]OK[/]", f"Port {port} is free to bind")
        except OSError as e:
            tbl.add_row("Port Binding", "[red]FAIL[/]", f"Port {port} in use: {e}")
            all_ok = False

    # Check 3: Zero-Copy Kernel Sendfile
    has_sendfile = hasattr(os, "sendfile") or hasattr(socket.socket, "sendfile")
    status_str = "[green]ENABLED[/]" if has_sendfile else "[yellow]FALLBACK[/]"
    details_str = (
        "Zero-copy kernel sendfile available"
        if has_sendfile
        else "Using mmap/buffered I/O fallback"
    )
    tbl.add_row("Zero-Copy I/O", status_str, details_str)

    # Check 4: Sequential Read Ahead
    has_fadvise = hasattr(os, "posix_fadvise")
    tbl.add_row(
        "Sequential Read Ahead",
        "[green]YES[/]" if has_fadvise else "[dim]N/A (Win32/Darwin)[/]",
        "POSIX_FADV_SEQUENTIAL optimization",
    )

    console.print(tbl)
    if not all_ok:
        raise click.Abort()


@cli.command("benchmark", short_help="Run performance benchmark.")
@click.option(
    "--url",
    default="http://localhost:8000",
    show_default=True,
    help="Server URL to benchmark.",
)
@click.option(
    "--size-mb",
    type=click.IntRange(1, 1000),
    default=100,
    show_default=True,
    help="Size of test download in MB.",
)
def benchmark_cmd(url: str, size_mb: int):
    """Run a speed benchmark against a BlazeServe server."""
    import time
    import urllib.request
    from urllib.parse import urlsplit

    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TransferSpeedColumn,
    )

    parsed_url = urlsplit(url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise click.ClickException(
            "Benchmark URL must be an HTTP(S) origin without credentials, query, or fragment."
        )
    benchmark_origin = url.rstrip("/")
    expected_bytes = size_mb * 1024 * 1024
    test_url = f"{benchmark_origin}/__speed__?bytes={expected_bytes}"

    console.print(f"[cyan]Benchmarking:[/] {benchmark_origin}")
    console.print(f"[cyan]Download size:[/] {size_mb} MB\n")

    # Warn for very large benchmarks
    if size_mb > 500:
        console.print(
            f"[yellow]⚠ Warning:[/] Large benchmark size ({size_mb} MB) "
            f"may impact server performance\n"
        )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Downloading...", total=expected_bytes)

            start_time = time.perf_counter()
            downloaded = 0

            with urllib.request.urlopen(test_url) as response:
                chunk_size = 1024 * 1024  # 1MB chunks
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    progress.update(task, advance=len(chunk))

            elapsed = time.perf_counter() - start_time
            if downloaded != expected_bytes:
                raise click.ClickException(
                    f"Benchmark download was incomplete: expected {expected_bytes} bytes, "
                    f"received {downloaded}."
                )

        # Display results
        speed_mbps = (downloaded / (1024 * 1024)) / elapsed

        result_table = Table(show_header=False, box=box.SIMPLE)
        result_table.add_column(style="bold cyan")
        result_table.add_column(style="bold green")

        result_table.add_row("Downloaded", f"{downloaded / (1024 * 1024):.2f} MB")
        result_table.add_row("Time", f"{elapsed:.2f} seconds")
        result_table.add_row("Speed", f"{speed_mbps:.2f} MB/s")

        console.print("\n[bold green]✓ Benchmark Complete[/]\n")
        console.print(result_table)

    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Benchmark failed: {e}") from e


def main() -> None:
    """Dispatch all invocations through Click's validated command boundary."""
    cli()


if __name__ == "__main__":
    main()
