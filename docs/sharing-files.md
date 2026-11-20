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

### Resuming

If the download is interrupted by a dropped connection, a closed laptop or a crash, run the same command again. BlazeServe asks the server for the rest of the file and appends it. It also confirms that the file on the server has not changed in the meantime. If it has, the download starts again from the beginning so you never end up with a mix of two versions.

Use `--no-resume` to always start from the beginning, and `--force` to replace a file that already exists.

### Making it faster

Large files are downloaded over several connections at once. The default is 4, and you can ask for up to 16:

```bash
blaze get http://host:8000/big.iso -c 8
```

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

### Passwords and retries

For a server that asks for a password, prefer an environment variable so the password does not show up in your shell history or process list:

```bash
export BLAZE_AUTH='alice:s3cret'
blaze get http://host:8000/big.iso --auth-env BLAZE_AUTH
```

On Windows PowerShell, set it with `$env:BLAZE_AUTH = "alice:s3cret"`.

`--retries` sets how many failed attempts in a row are allowed before giving up. The default is 5, with a pause that grows between attempts.

If a server answers `429` or `503` with a `Retry-After` header, `get` and `put` wait at least that long before the next attempt, whether the header gives seconds or an HTTP date. A date that has already passed, or a value that is not valid, is ignored and the usual pause applies. The wait is never shorter than the usual pause, and a small random extra is added so parallel downloads do not return together. All connections of one download pause together. Other statuses ignore the header.

A server may ask for at most 5 minutes. If it asks for more, the transfer stops with an error saying so rather than retrying early. These pauses are not counted against a time limit, because `get` and `put` have none. `--retries 0` still never retries.

## Upload a file

Uploading needs a server that has uploads switched on. See [Uploads](uploads.md) for how to set that up.

```bash
blaze put ./big.iso http://host:8000/
```

Given just a server address, `put` uploads under `/__upload__/` using the file's name. You can also give a full destination such as `http://host:8000/__upload__/backups/big.iso`.

Uploads resume too. If the transfer breaks, run the same command and BlazeServe asks the server how much it already has, then sends the rest. Data goes up in chunks of 8 MB by default; change that with `--chunk-mb`. To leave bandwidth for other work, cap the upload speed with `--limit-rate`, for example `--limit-rate 2M`.
