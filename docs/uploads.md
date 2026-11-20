# Uploads

BlazeServe can receive files as well as serve them, but this is switched off until you ask for it. Uploads write to your disk, so they deserve some care.

## Turn uploads on

```bash
export BLAZE_AUTH='alice:s3cret'
blaze serve ./incoming --max-upload-mb 500 --auth-env BLAZE_AUTH
```

`--max-upload-mb` is both the switch and the size limit. With the default of `0`, uploads are off. Always set a password when uploads are enabled on an address other people can reach. Without one, anyone who can connect can fill your disk up to the limit.

## Upload from the command line

```bash
blaze put ./big.iso http://host:8000/ --auth-env BLAZE_AUTH
```

The address `/__upload__/big.iso` puts the file at `big.iso` in the served folder, and `/__upload__/backups/big.iso` puts it at `backups/big.iso`. See [Sharing and downloading files](sharing-files.md#upload-a-file) for resuming and chunk sizes.

## How uploads behave

- **Nothing is overwritten.** If the file already exists, the server answers `409 Conflict`. To replace a file on purpose, send an `If-Match` header with the file's current `ETag`. If the tag is out of date, the server answers `412 Precondition Failed`, which means someone changed the file since you last looked. With the client, read the tag with `curl -I http://host:8000/big.iso` and pass it along:

  ```console
  blaze put ./big.iso http://host:8000/ --if-match '"3f2a9c1d5e7b8a0c4d6e"'
  ```

  The replacement starts from the first byte. If another upload has left a partial file at the destination, `blaze put` refuses to build on it. If the file changes between your check and the upload, the command fails instead of overwriting the newer version.
- **Files appear whole or not at all.** The upload is written to a temporary file next to its destination and moved into place only when everything checks out. If anything fails, the temporary file is deleted. A new file is published with a hard link, so the destination filesystem must support them. If it does not, the upload is refused with `501` and nothing appears at the final name.
- **Sizes and checksums are verified.** The server checks the length you declared. If you also send a checksum, the file is rejected when it does not match. `Content-Digest`, `Digest` and `X-Content-SHA256` are accepted, and `Repr-Digest` verifies a whole resumed file.
- **Partial uploads can be resumed.** `GET` or `HEAD` on an upload address reports how many bytes the server has, in an `Upload-Offset` header. `DELETE` discards a partial upload. It never deletes a finished file. A partial upload that can no longer finish, because the name has since been taken or a `If-Match` check failed, is discarded by the server and has to be started again.
- **Files are private to the server's user.** On Linux and macOS they are created with permissions `0600`.
- **Rejected uploads close the connection.** This prevents the unread body of a refused upload from being mistaken for the next request.

## Upload from the browser

When uploads are on, the folder page has a box where you can drop files or choose them. Files are sent one at a time, each as a single request.

- **Cancel** removes a queued file without sending anything, or stops the file being sent. The next file then starts.
- **Retry** appears after a failure and sends the file again when you press it. It is never automatic. A name that already exists is not retried, because uploads never overwrite.
- A file shows **Sending** and then **Waiting for server**. It only becomes **Uploaded** once the server confirms it. Reaching the end of the progress bar is not confirmation.
- If the connection drops, or you cancel just as the file finishes, the page asks the server what it has. If a file with that name is already there it says so as **not confirmed as yours**, instead of reporting success.
- The page reloads when everything uploaded cleanly. If anything failed, was cancelled or is uncertain, it stays put so you can read the results.

The browser does not resume a partial upload, and the page keeps selected files only until you reload it. Use `blaze put` to resume large files.

## Upload with plain HTTP

You can use any HTTP client. The paths and verbs are listed in the [reference](reference.md#endpoints). A simple upload looks like this:

```bash
curl -u alice:s3cret -T ./notes.txt http://host:8000/__upload__/notes.txt
```

Names matched by `--hide` are off limits to uploads too. `/__upload__/` answers `404` for them, exactly as for a file that does not exist, so a hidden file cannot be probed or created.

While a file is arriving it is staged under a reserved name beside its destination, such as `.notes.txt.blaze-part-<id>` or `.big.iso.blaze-resume`. Those names are never served, listed or added to a ZIP, and you cannot upload to them.

## Containers and Kubernetes

The example Compose and Kubernetes files mount your data read-only, so uploads cannot work out of the box. To enable them, mount a writable volume, set `--max-upload-mb` and require authentication. The Kubernetes example uses storage that disappears when the pod restarts, so change that first if you care about what is uploaded.
