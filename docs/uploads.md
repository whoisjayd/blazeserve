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

- **Nothing is overwritten.** If the file already exists, the server answers `409 Conflict`. To replace a file on purpose, send an `If-Match` header with the file's current `ETag`. If the tag is out of date, the server answers `412 Precondition Failed`, which means someone changed the file since you last looked.
- **Files appear whole or not at all.** The upload is written to a temporary file next to its destination and moved into place only when everything checks out. If anything fails, the temporary file is deleted.
- **Sizes and checksums are verified.** The server checks the length you declared. If you also send a checksum, the file is rejected when it does not match. `Content-Digest`, `Digest` and `X-Content-SHA256` are accepted, and `Repr-Digest` verifies a whole resumed file.
- **Partial uploads can be resumed.** `GET` or `HEAD` on an upload address reports how many bytes the server has, in an `Upload-Offset` header. `DELETE` discards a partial upload. It never deletes a finished file.
- **Files are private to the server's user.** On Linux and macOS they are created with permissions `0600`.
- **Rejected uploads close the connection.** This prevents the unread body of a refused upload from being mistaken for the next request.

## Upload with plain HTTP

You can use any HTTP client. The paths and verbs are listed in the [reference](reference.md#endpoints). A simple upload looks like this:

```bash
curl -u alice:s3cret -T ./notes.txt http://host:8000/__upload__/notes.txt
```

Uploads are not affected by `--hide`.

## Containers and Kubernetes

The example Compose and Kubernetes files mount your data read-only, so uploads cannot work out of the box. To enable them, mount a writable volume, set `--max-upload-mb` and require authentication. The Kubernetes example uses storage that disappears when the pod restarts, so change that first if you care about what is uploaded.
