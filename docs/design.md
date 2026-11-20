# How BlazeServe works

This page is for people changing BlazeServe. It follows a request through the code and names the rules each stage keeps. [AGENTS.md](../AGENTS.md) has the full list of rules, and [CONTRIBUTING.md](../CONTRIBUTING.md) has the module map.

## From socket to response

1. `src/server/mod.rs` starts the server and owns shutdown. `bind` and `tls` open the listener. If TLS setup fails, nothing is left listening.
2. `accept` applies the connection limit. A connection over the limit is rejected with a `503`.
3. `connection` serves one connection with hyper. It sniffs the HTTP/2 preface (`prefixed`), closes idle connections (`idle`) and limits how fast one HTTP/2 connection opens streams (`budget`). `proxy` decides the client address and trusts forwarded headers only from a configured proxy.
4. `src/handler/mod.rs` routes the request. The order matters:
   1. `OPTIONS`, then unsupported methods.
   2. Authentication, for every `GET`, `HEAD`, `PUT`, `POST` and `DELETE`, before anything touches the filesystem or a status route.
   3. Paths under `/__upload__/` go to `src/upload/`. Other writes get `405`.
   4. The status routes (`/__health__`, `/__metrics__`, `/__zip__` and the rest).
   5. Everything else is a static file.

A rejected write closes the connection, so its unread body is never parsed as the next request.

## Serving a file

`resolve` turns the URL path into a file by decoding it once and checking it against the canonical root in `src/security.rs`, one path component at a time. `files` applies validators (`src/cache.rs`) and ranges (`src/range.rs`), and `pump` streams the file in bounded chunks. A precompressed `.br` or `.gz` sibling is never chosen for a range request.

## Uploads

The code is in `src/upload/`.

1. `target` resolves the destination under the root and names a staging file in the same directory, `.<name>.blaze-part-<id>`. Names carrying these markers are reserved: they are never served, listed or zipped, and cannot be uploaded to.
2. `stream` writes the body into the staging file in chunks. Any failure removes the staging file.
3. The digest headers are checked. A mismatch is `422` and nothing is published.
4. `publish` makes the file visible. With no `If-Match`, it hard-links the staging file to the target, so an existing file is never replaced (`409`). On a filesystem without hard links the upload is refused with `501`, because copying into the final name would let a reader see a partial file. With a current `If-Match` ETag it renames over the target. A stale one is `412`.
5. Resumable uploads (`resumable`) append chunks to a `.blaze-resume` file by offset, and publish when the last byte arrives.

The status table is at the top of `src/upload/mod.rs` and in [Uploads](uploads.md).

## ZIP streaming

`src/zip_stream/` builds the archive on a blocking thread and passes it to the response through a small bounded channel, so a slow client slows the producer and memory stays flat. Entries are stored, not compressed, with a data descriptor after each one, so the output never needs to seek back (`writer`). The length is unknown, so the response closes the connection. A failure part way through is sent as a body error, so the client never receives a truncated archive that looks complete.

## The transfer client

`blaze get` and `blaze put` are in `src/cli/transfer/`.

- `download` writes to `<name>.part` and keeps progress in `<name>.part.meta`. It resumes with `Range`, and renames the file into place only after it is complete.
- `segmented` handles larger files. It downloads 8 MiB segments in parallel and records which are done, so a restart repeats only unfinished segments.
- `upload` sends a file in chunks to the upload endpoint.
- `filename` takes the saved name from the server's `Content-Disposition`, keeping only a safe final path segment. `retry` decides how long to wait after a `429` or `503`. `extract` unpacks a finished archive in place with `hatchzip-core`.

## Shared state

`AppState` (in `src/lib.rs`) belongs to one server, so two servers in one process do not share settings. Metrics and rate limiters are shared across tasks. Keep their locks short and never hold one across `.await` or I/O.

## Where the tests are

Integration tests in `tests/` start a real server on a loopback port. See [Tests](../CONTRIBUTING.md#tests).
