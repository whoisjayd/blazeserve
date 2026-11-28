# Upload staging and publish internals

This note documents the invariants enforced by the upload subsystem in [`src/upload/`](../src/upload/mod.rs) and [`src/security.rs`](../src/security.rs). For user-facing instructions, see [Uploads](uploads.md) and the [Reference](reference.md#endpoints).

## 1. Request gating and early rejection

- **Authentication first:** `handler::route` authenticates `PUT`, `POST`, `GET`, `HEAD`, and `DELETE` before dispatching to `/__upload__/`. Unauthenticated write requests close the connection (`Connection: close`).
- **Disabled by default:** When `max_upload_bytes == 0`, every `/__upload__/` request—including `GET`, `HEAD`, and `DELETE` status/abort probes—returns `403` with `Connection: close`.
- **Pre-body header checks:** Before reading the body, `upload()` validates `If-Match` (rejecting `*` or empty tags with `400`), digest headers (`Content-Digest`, `Digest`, `X-Content-SHA256`, `Repr-Digest`; `400` if malformed), `Content-Range` (`400` if invalid), `precheck` (for non-range uploads), `Content-Length` (`411` if absent or if `Transfer-Encoding` is sent), and the declared size against `max_upload_bytes` (`413`).
- **Close on early rejection:** Every error returned before the request body is drained uses `reject()` or `reject_with()`, setting `Connection: close` so an unread body is never parsed as the next request on a keep-alive connection.

## 2. Target resolution, hidden entries, and reserved names

- **Canonical containment:** `parse_target` strips `/__upload__/`, percent-decodes the path once, trims `/` and `\`, and calls `security::resolve_under` against the canonicalized served root. Path traversal (`..`), backslashes, NUL bytes, symlinked parents escaping the root, and (on Windows) drive/stream colons, trailing dots/spaces, and reserved device names fail closed (`400` or `403`).
- **Reserved staging names (`security::is_reserved_name`):** Names containing `.blaze-part-`, ending with `.blaze-resume`, starting with `.blaze-part-`, or starting with `.blaze-resume-` are reserved:
  - `/__upload__/` rejects them with `400`.
  - Static `GET`/`HEAD` (including `?hash`), directory listings (`list_dir`), and streaming ZIPs (`collect_files`) skip them and answer `404 Not Found`, indistinguishable from missing files.
- **Hidden entries (`--hide`):** Under `/__upload__/`, hidden paths return `404 Not Found` (with `Connection: close`), matching static routes so a hidden file cannot be probed, created, or overwritten.

## 3. Staging files and exclusive creation

Staging files are placed in the destination's parent directory (`Target::dir`) so publication stays on the same filesystem:

| Mode | Staging file name (`name.len() <= 180`) | Long-name fallback (`name.len() > 180`) |
| :--- | :--- | :--- |
| Plain (`Staging::Part`) | `.<name>.blaze-part-<12-hex-id>` | `.blaze-part-<12-hex-id>` |
| Resumable (`Staging::Resume`) | `.<name>.blaze-resume` | `.blaze-resume-<16-hex-sha256>` |

- **Exclusive create (`security::create_upload_file`):** Canonicalizes the root, creates missing parent directories, verifies parent containment before and after `OpenOptions::new().write(true).create_new(true)`, and on Unix sets file mode `0600`. `create_new` fails with `AlreadyExists` even on a dangling final symlink. If parent containment fails after opening, the newly created file is deleted immediately and `403` is returned.
- **Resumable append (`security::open_existing_for_append`):** For an existing `Staging::Resume` file, verifies parent containment, checks `symlink_metadata` is a regular file (refusing symlinks), opens for write, checks `dev`/`ino` match on Unix, re-checks parent containment, and seeks to the end.

## 4. Streaming, cleanup, and resumable state

- **Plain uploads (`src/upload/plain.rs`):** Immediately after creating the `Staging::Part` file, `plain()` arms `StagingGuard { path, armed: true }`.
  - `StagingGuard::drop` deletes the `Staging::Part` file on every graceful failure path (idle timeout, short body, I/O error, `422` digest mismatch, or publish failure) as well as when a request future is dropped/cancelled.
  - `guard.armed` is cleared only after `publish` returns `Ok(())`.
- **Crash leftovers:** a killed process cannot run `StagingGuard`, so a `Staging::Part` file can stay behind. A later `PUT`, `POST` or `DELETE` in the same folder removes part files that have not been written to for 24 hours, scanning a folder at most once an hour. Younger files are kept because they may belong to a live upload in another server on the same root. `Staging::Resume` files are never swept.
- **Resumable uploads (`src/upload/resumable.rs`):**
  - `ActiveGuard` serializes concurrent writes or `DELETE`s targeting the same `Staging::Resume` path (`409` if already active).
  - `precheck` runs first; if the target appeared or `If-Match` became stale, the `Staging::Resume` file is removed so retries do not remain stuck on `409`.
  - If `staged != range.start`, the server returns `409` with `Upload-Offset` and `Connection: close`, keeping the staged prefix intact.
  - If a chunk fails its body digest (`Content-Digest`, `Digest`, or `X-Content-SHA256`), `set_len(range.start)` rolls the `Staging::Resume` file back to the prior offset and returns `422`.
  - **Kept across requests:** When `range.start + accepted < range.total`, `resumable()` flushes, calls `sync_data()`, and returns `202 Accepted` with `Upload-Offset` and `Upload-Length`, leaving the `Staging::Resume` file on disk for subsequent chunks.
  - **Final chunk cleanup:** When `range.start + accepted == range.total`, the assembled file is hashed (`hash_file`), verified against `Repr-Digest` (`422` on mismatch), and published. If reading/hashing, `Repr-Digest`, or `publish` fails, the `Staging::Resume` file is removed so a broken or colliding complete file does not trap retries in `409`.
- **Status and abort:** `GET`/`HEAD` on `/__upload__/<path>` reports `Upload-Offset` and `Upload-Complete: ?0` if a `Staging::Resume` file exists, or `Upload-Complete: ?1` if the published file exists (`404` otherwise). `DELETE` removes only a `Staging::Resume` file (`204`), never a published file (`404`).

## 5. Atomic publish and no-overwrite guarantee

All publish operations run on a blocking thread under `state.uploads.commit` (`Mutex<()>`), preventing concurrent in-process check-then-publish races.

- **Create without `If-Match` (`publish_create`):** Re-checks `security::is_safe_path` and calls `std::fs::hard_link(staging, target)`.
  - Hard-linking never overwrites an existing target (`AlreadyExists` -> `409 Conflict`) and makes the full, verified file visible atomically.
  - If the filesystem does not support hard links, `publish_create` refuses with `501 Not Implemented` (`PublishError::Unsupported`) rather than copying into the destination path, which would expose partial contents to readers.
  - Once `hard_link` succeeds, the staging link is removed.
- **Replace with `If-Match` (`publish_replace`):** Checks `symlink_metadata(target)` is a regular file (`412` if missing, `409` if non-regular), verifies `etag_for_metadata(&meta)` matches one of the caller's tags (`412` if stale), re-checks `security::is_safe_path`, and atomically `std::fs::rename`s the staging file over `target`.
- **Response:** Returns `201 Created` (create) or `200 OK` (replace) with `Content-Digest`, `Location`, and `ETag`.
