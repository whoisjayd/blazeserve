import os
import sys
import socket
import webbrowser
from typing import Optional

try:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True
    click.rich_click.STYLE_HELPTEXT = "cyan"
    click.rich_click.STYLE_OPTION = "bold bright_white"
    click.rich_click.STYLE_SWITCH = "bold bright_white"
    click.rich_click.STYLE_HELPTEXT_FIRST_LINE = "bold cyan"
except Exception:
    import click  # type: ignore

from rich.table import Table
from rich.panel import Panel
from rich import box

from .logging import setup_logging, get_console
from .server import build_arg_parser, run_server
from .utils import sha256_file, human_size
from . import __version__

console = get_console()


def _lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.05)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
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
    "-p", "--port", type=int, default=8000, show_default=True, help="Port to listen on."
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
    default=128,
    show_default=True,
    help="mmap/read window size.",
)
@click.option(
    "--sock-sndbuf-mb",
    type=click.IntRange(1, 2048),
    default=64,
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
@click.option(
    "--auth", metavar="USER:PASS", envvar=None, help="Enable HTTP Basic Auth."
)
@click.option(
    "--auth-env", metavar="ENVVAR", help="Load USER:PASS from environment variable."
)
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
@click.option(
    "--cors-origin", default="*", show_default=True, help="CORS allow origin."
)
@click.option("--no-cache", is_flag=True, help="Disable HTTP caching.")
@click.option(
    "--index", multiple=True, help="Additional index filenames to try (repeatable)."
)
@click.option(
    "--backlog",
    type=click.IntRange(1, 20000),
    default=4096,
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
@click.option(
    "--open", "open_browser", is_flag=True, help="Open the URL in a browser on start."
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose startup banner.")
def serve_cmd(
    path: str,
    host: str,
    port: int,
    single: Optional[str],
    no_listing: bool,
    chunk_mb: int,
    sock_sndbuf_mb: int,
    timeout: int,
    rate_mbps: Optional[float],
    auth: Optional[str],
    auth_env: Optional[str],
    tls_cert: Optional[str],
    tls_key: Optional[str],
    cors: bool,
    cors_origin: str,
    no_cache: bool,
    index: tuple[str, ...],
    backlog: int,
    precompress: bool,
    max_upload_mb: int,
    open_browser: bool,
    verbose: bool,
) -> None:
    setup_logging("INFO" if verbose else "WARNING")
    target = os.path.abspath(path)
    if single:
        single = os.path.abspath(single)
        if not os.path.isfile(single):
            raise click.ClickException(f"Single file not found: {single}")
        base = os.path.dirname(single)
    else:
        if not os.path.exists(target):
            raise click.ClickException(f"Path not found: {target}")
        base = os.path.dirname(target) if os.path.isfile(target) else target
    os.chdir(base)
    if not auth and auth_env:
        val = os.environ.get(auth_env, "")
        if val:
            auth = val
    scheme = "https" if (tls_cert and tls_key) else "http"
    lan = _lan_ip()
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold cyan")
    table.add_column(style="bold white")
    table.add_row("Serving", single or base)
    table.add_row("Local", f"[green]{scheme}://localhost:{port}/[/]")
    table.add_row("Network", f"[green]{scheme}://{lan}:{port}/[/]")
    console.print(
        Panel(table, title="[bold magenta]BlazeServe", box=box.ROUNDED), soft_wrap=True
    )
    if open_browser:
        try:
            webbrowser.open(f"{scheme}://localhost:{port}/")
        except Exception:
            pass
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
            index=list(index) if index else None,
            backlog=backlog,
            precompress=precompress,
            max_upload_mb=max_upload_mb,
            verbose=False,
        )
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down...[/]")


@cli.command("send", short_help="Quick share a single file.")
@click.argument(
    "file", type=click.Path(exists=True, dir_okay=False, file_okay=True, path_type=str)
)
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("-p", "--port", type=int, default=8000, show_default=True)
@click.option("--rate-mbps", type=click.FloatRange(min=0.1), default=None)
@click.option("--auth", metavar="USER:PASS")
@click.option("--auth-env", metavar="ENVVAR")
@click.option("--tls-cert", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--tls-key", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option("--cors/--no-cors", default=False, show_default=True)
@click.option("--cors-origin", default="*", show_default=True)
@click.option("--no-cache", is_flag=True)
@click.option(
    "--backlog", type=click.IntRange(1, 20000), default=4096, show_default=True
)
@click.option("--precompress/--no-precompress", default=True, show_default=True)
@click.option(
    "--max-upload-mb", type=click.IntRange(0, 1024 * 1024), default=0, show_default=True
)
def send_cmd(
    file: str,
    host: str,
    port: int,
    rate_mbps: Optional[float],
    auth: Optional[str],
    auth_env: Optional[str],
    tls_cert: Optional[str],
    tls_key: Optional[str],
    cors: bool,
    cors_origin: str,
    no_cache: bool,
    backlog: int,
    precompress: bool,
    max_upload_mb: int,
) -> None:
    setup_logging("INFO")
    ap = os.path.abspath(file)
    base = os.path.dirname(ap)
    os.chdir(base)
    if not auth and auth_env:
        val = os.environ.get(auth_env, "")
        if val:
            auth = val
    scheme = "https" if (tls_cert and tls_key) else "http"
    lan = _lan_ip()
    console.print(f"[bold green]Share:[/] {ap}")
    console.print(f"[cyan]{scheme}://{lan}:{port}/[/]")
    try:
        run_server(
            host=host,
            port=port,
            base=base,
            single=ap,
            listing=False,
            chunk_mb=128,
            sndbuf_mb=64,
            timeout=1800,
            rate_mbps=rate_mbps,
            auth=auth,
            tls_cert=tls_cert,
            tls_key=tls_key,
            cors=cors,
            cors_origin=cors_origin,
            no_cache=no_cache,
            index=None,
            backlog=backlog,
            precompress=precompress,
            max_upload_mb=max_upload_mb,
            verbose=False,
        )
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down...[/]")


@cli.command("checksum", short_help="SHA256 for files.")
@click.argument(
    "files", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=str)
)
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


@cli.command("version", short_help="Show version.")
def version_cmd():
    console.print(f"[bold]BlazeServe[/] {__version__}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "serve",
        "send",
        "checksum",
        "version",
        "-h",
        "--help",
        "--version",
    ):
        try:
            parser = build_arg_parser()
            args = parser.parse_args()
            if getattr(args, "cmd", None) in (None, "serve"):
                target = os.path.abspath(getattr(args, "path", "."))
                if getattr(args, "single", None):
                    single = os.path.abspath(args.single)
                    base = os.path.dirname(single)
                else:
                    base = os.path.dirname(target) if os.path.isfile(target) else target
                os.chdir(base)
                run_server(
                    host=args.host,
                    port=args.port,
                    base=base,
                    single=getattr(args, "single", None),
                    listing=not getattr(args, "no_listing", False),
                    chunk_mb=getattr(args, "chunk_mb", 128),
                    sndbuf_mb=getattr(args, "sock_sndbuf_mb", 64),
                    timeout=getattr(args, "timeout", 1800),
                    rate_mbps=getattr(args, "rate_mbps", None),
                    auth=getattr(args, "auth", None),
                    tls_cert=getattr(args, "tls_cert", None),
                    tls_key=getattr(args, "tls_key", None),
                    cors=False,
                    cors_origin="*",
                    no_cache=False,
                    index=None,
                    backlog=4096,
                    precompress=True,
                    max_upload_mb=0,
                    verbose=False,
                )
                return
            if args.cmd == "send":
                ap = os.path.abspath(args.file)
                base = os.path.dirname(ap)
                os.chdir(base)
                run_server(
                    host=args.host,
                    port=args.port,
                    base=base,
                    single=ap,
                    listing=False,
                    chunk_mb=128,
                    sndbuf_mb=64,
                    timeout=1800,
                    rate_mbps=args.rate_mbps,
                    auth=args.auth,
                    tls_cert=args.tls_cert,
                    tls_key=args.tls_key,
                    cors=False,
                    cors_origin="*",
                    no_cache=False,
                    index=None,
                    backlog=4096,
                    precompress=True,
                    max_upload_mb=0,
                    verbose=False,
                )
                return
            if args.cmd == "checksum":
                rc = 0
                for p in args.files:
                    ap = os.path.abspath(p)
                    if not os.path.isfile(ap):
                        sys.stderr.write(f"Skip (not a file): {p}\n")
                        rc = 2
                        continue
                    print(f"{sha256_file(ap)}  {p}")
                sys.exit(rc)
        except SystemExit:
            raise
        except Exception as e:
            raise click.ClickException(str(e))
    cli()
