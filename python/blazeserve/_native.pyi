from os import PathLike
from types import TracebackType

__version__: str

class BlazeError(Exception): ...

class Server:
    def __init__(
        self,
        path: str | PathLike[str] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        listing: bool = True,
        hide: list[str] = ...,
        auth: str | None = None,
        cors: bool = False,
        no_cache: bool = False,
        max_upload_mb: int = 0,
        rate_mbps: float | None = None,
        tls_cert: str | PathLike[str] | None = None,
        tls_key: str | PathLike[str] | None = None,
    ) -> None: ...
    @property
    def url(self) -> str: ...
    @property
    def port(self) -> int: ...
    @property
    def running(self) -> bool: ...
    def close(self) -> None: ...
    def serve_forever(self) -> None: ...
    def __enter__(self) -> Server: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> bool: ...

def sha256(path: str | PathLike[str]) -> str: ...
def main(argv: list[str] | None = None) -> int: ...
