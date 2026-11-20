# Sharing and downloading files

This guide covers the commands you use to move one file between two machines: `send`, `get` and `put`.

## Send a file

```bash
blaze send ./big.iso
```

`send` is `serve` for a single file, with the folder listing turned off. It accepts the same options for the network, passwords, HTTPS, speed limits and proxies, so these all work:

```bash
blaze send ./big.iso --qr                  # QR code for a phone
blaze send ./big.iso --rate-mbps 10        # give each downloader at most 10 MB/s
blaze send ./big.iso --auth-env BLAZE_AUTH # require a password
blaze send ./big.iso --expires-after 20m   # stop sharing after 20 minutes
```

### Stop sharing automatically

`--expires-after` takes a number with a unit (`s`, `m`, `h` or `d`) or several together, such as `90s`, `20m`, `2h`, `1d` or `1h30m`. The longest is `365d`. Zero, negative, unitless and unsupported values are refused before anything starts listening. Without the option, the share runs until you stop it.

The countdown starts once the port is bound, and the startup output shows the lifetime and the expected expiry time. When it runs out, BlazeServe stops accepting connections and ends keep-alive connections after their current response, then exits normally with `Stopped: share expired after 20m` on standard error. A download that is already in progress may keep going for up to 10 more seconds, so expiry is not an exact cutoff. Press Ctrl+C at any time to stop earlier.

The timer uses the monotonic clock, which on most systems does not advance while the computer sleeps. A suspended share is therefore not expired the moment the machine wakes; it stays available for the time that was left. Expiry only stops your server. It cannot recall copies that were already downloaded. `serve` does not have this option.

## Download a file

```bash
blaze get http://host:8000/big.iso
```

The file is saved under the name the server suggests in its `Content-Disposition` header. A folder downloaded as a ZIP, for example `blaze get 'http://host:8000/__zip__?path=docs'`, arrives as `docs.zip`. If the server suggests nothing usable, the last part of the URL is used, here `big.iso`. Only the final part of a suggested name is kept, and names that could write elsewhere or name a device are ignored. Use `-o` to choose another name, which always wins. While it downloads, BlazeServe writes to `big.iso.part`, then checks the size and renames it when the download is complete.

In a terminal, `get` and `put` draw a small live block with the file name, a progress bar with sizes, and the speed, time remaining and time elapsed. Nothing is drawn when the output is piped.

### Resuming

If the download is interrupted by a dropped connection, a closed laptop or a crash, run the same command again. BlazeServe asks the server for the rest of the file and appends it. It also confirms that the file on the server has not changed in the meantime. If it has, the download starts again from the beginning so you never end up with a mix of two versions.

Use `--no-resume` to always start from the beginning, and `--force` to replace a file that already exists.

### Extracting an archive

```bash
blaze get http://host:8000/game.zip --extract
```

When the download has been checked and renamed, the archive is unpacked into a folder named after it, next to it. The archive is consumed as its files come out, so you only need free space for about the extracted size instead of the archive and its contents together. BlazeServe checks that it fits before it changes anything, and keeps `--keep-free` untouched throughout. It also reads the whole archive and checks every file's checksum first, so a damaged download is refused while it is still intact. `--no-verify-first` skips that pass on very large archives. Add `--keep-archive` if you want the archive afterwards; that needs room for both.

If the extraction is interrupted, run the same command again and it resumes. Extraction is powered by [HatchZip](https://github.com/xevrion/hatchzip)'s engine. Encrypted archives are not supported here; use HatchZip itself for those.

### Making it faster

Large files are downloaded over several connections at once. The default is 4, and you can ask for anything from 1 to 128, or `max`:

```bash
blaze get http://host:8000/big.iso -c 8
blaze get http://host:8000/big.iso -c max
```

More connections only help when one stream cannot fill your link, which is typical on a very fast line to a distant server. Each connection costs a thread and a socket, and some servers throttle or block clients that open many, so BlazeServe prints a note above 16. The live display shows how many connections are in use.

If a server refuses or drops the extra connections and the retries run out, `get` does not give up. It halves the count, for example 32, 16, 8, 4, 2 and then 1, and carries on with the parts it already has. Permanent errors such as a wrong password or a missing file still stop the download straight away.

This applies to files of at least 8 MiB, from servers that support byte ranges and give the file a stable identity. If the server cannot do that, BlazeServe quietly falls back to a single stream. If a multi-connection download is interrupted, the next run skips the parts that already finished. Use `-c 1` to force a single stream.

To be polite to a shared network, cap the total speed:

```bash
blaze get http://host:8000/big.iso --limit-rate 2M
```

The rate is in bytes per second, with an optional `K`, `M` or `G` suffix (powers of 1024, decimals allowed, minimum `1K`). The cap covers all connections together.

### Checking the file

If the sender gives you a SHA-256 checksum, pass it in and BlazeServe will verify the finished file:

```bash
blaze get http://host:8000/big.iso --sha256 <checksum>
```

You can also compute a checksum yourself:

```bash
blaze checksum ./big.iso
```

A server can also tell you the checksum of a file it holds. Add `?hash` to the file's address, for example `http://host:8000/big.iso?hash`. The reply is a small piece of JSON with the size and SHA-256.

To have `blaze get` fetch that checksum and check the download for you, ask for it explicitly:

```bash
blaze get http://host:8000/big.iso --verify server-sha256
```

This only works against a BlazeServe server, and only when you ask for it. Before downloading, `blaze get` requests the file's address with `?hash` added (any query you already have, such as a signed link, is kept and never printed). After the download, and before the file is saved under its final name, it compares the size and SHA-256. If the server has no checksum to give, answers badly, refuses your password, or the result does not match, the command fails with a nonzero exit code and nothing is saved. A partial download is deleted on a mismatch, and a file that already existed (with `--force`) is left alone. This works the same for single-stream, parallel, resumed and empty downloads. `--verify` cannot be combined with `--sha256`.

Two things to know. The server hashes the whole file first, so a large file that has not been hashed before makes the download start later; the server remembers the result while the file is unchanged, so the next request is quick. And a checksum from the same server only shows that you received what that server holds. It does not prove who published the file, and a server that serves altered content can serve a matching checksum. When the checksum comes from somewhere you trust separately, use `--sha256` instead.

### Passwords and retries

For a server that asks for a password, prefer an environment variable so the password does not show up in your shell history or process list:

```bash
export BLAZE_AUTH='alice:s3cret'
blaze get http://host:8000/big.iso --auth-env BLAZE_AUTH
```

On Windows PowerShell, set it with `$env:BLAZE_AUTH = "alice:s3cret"`.

`--retries` sets how many failed attempts in a row are allowed before giving up. The default is 5, with a pause that grows between attempts.

### Time limits

`get` and `put` accept three separate limits. Each takes a number with `s`, `m`, `h` or `d` (for example `45s`, `30m`, `1h30m`) or `off`. A bare number such as `30` is rejected because it does not say whether it means seconds or minutes.

```bash
blaze get http://host:8000/big.iso --connect-timeout 20s --idle-timeout 45s --max-time 30m
blaze put ./big.iso http://host:8000/ --idle-timeout 60s --max-time 2h
```

- `--connect-timeout` (default `15s`) bounds setting up the connection.
- `--idle-timeout` (default `off`) stops a transfer when the other side stops moving data. A slow transfer that keeps making progress is never stopped by it, and neither is a wait you asked for with `--limit-rate`, or the pause between retries.
- `--max-time` (default `off`) is one budget for the whole command, counted from when it starts. It covers the upload checksum, every retry and pause, the transfer and the final check. It is not restarted by a retry, a chunk or a parallel connection. A pause that would not fit in what is left ends the command at once instead of waiting.

When a limit runs out the command stops with a non-zero exit code and says which limit it was. A partial download or upload is kept, so running the same command again continues where it stopped, and a file that was not fully received and verified is never put in place. `--max-time` does not cover unpacking with `--extract`.

If a server answers `429` or `503` with a `Retry-After` header, `get` and `put` wait at least that long before the next attempt, whether the header gives seconds or an HTTP date. A date that has already passed, or a value that is not valid, is ignored and the usual pause applies. The wait is never shorter than the usual pause, and a small random extra is added so parallel downloads do not return together. All connections of one download pause together. Other statuses ignore the header.

A server may ask for at most 5 minutes. If it asks for more, the transfer stops with an error saying so rather than retrying early. These pauses are not counted against a time limit, because `get` and `put` have none. `--retries 0` still never retries.

## Upload a file

Uploading needs a server that has uploads switched on. See [Uploads](uploads.md) for how to set that up.

```bash
blaze put ./big.iso http://host:8000/
```

Given just a server address, `put` uploads under `/__upload__/` using the file's name. You can also give a full destination such as `http://host:8000/__upload__/backups/big.iso`.

Uploads resume too. If the transfer breaks, run the same command and BlazeServe asks the server how much it already has, then sends the rest. Data goes up in chunks of 8 MB by default; change that with `--chunk-mb`. To leave bandwidth for other work, cap the upload speed with `--limit-rate`, for example `--limit-rate 2M`.
