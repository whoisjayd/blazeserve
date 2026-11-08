# Getting started

BlazeServe is a single program called `blaze`. It serves files over HTTP, downloads and uploads them with resume, and checks them with a checksum. There is nothing else to install.

## Install it

Pick whichever method suits you.

| Method | Command |
| :--- | :--- |
| pip or uv | `pip install blazeserve` or `uv tool install blazeserve` |
| Cargo | `cargo install --git https://github.com/whoisjayd/blazeserve` |
| Download | Get an archive from the [Releases page](https://github.com/whoisjayd/blazeserve/releases) and check it against the `SHA256SUMS` file |
| Docker | `docker run --rm -p 8000:8000 -v "$PWD":/data:ro ghcr.io/whoisjayd/blazeserve:latest` |

Builds exist for Linux (x86_64 and aarch64, with glibc or musl), Windows x86_64, and macOS (Intel and Apple silicon). To build from source you need Rust 1.88 or newer.

Check that it works:

```bash
blaze version
```

## Serve a folder

```bash
blaze serve .
```

BlazeServe prints the addresses it is listening on. Open `http://localhost:8000` in a browser and you will see a listing of the current folder, with search and sorting. Anyone on your network can reach the same files at your machine's address, because `blaze serve` listens on all interfaces by default. Press `Ctrl+C` to stop it.

Some things to try next:

```bash
blaze serve ./site --port 9000          # use a different port
blaze serve ./site --host 127.0.0.1     # only this computer can connect
blaze serve ./site --no-listing         # hide the folder listing
blaze serve ./site --qr                 # print a QR code to open it on a phone
```

## Share one file

```bash
blaze send ./big.iso
```

This serves just that file and prints a link. Give the link to the other person, and stop the command when they are done.

## Download a file

```bash
blaze get http://host:8000/big.iso
```

If the connection drops, run the same command again. It carries on from where it stopped instead of starting over. See [Sharing and downloading files](sharing-files.md) for the details.

## Check it all works

```bash
blaze doctor ./site
```

`doctor` checks that the folder exists, that the port is free, and that your system supports what BlazeServe needs. It is the first thing to run if something seems wrong.

## Where to go next

- To protect a server with a password or HTTPS, read [Serving files](serving-files.md).
- To receive files, read [Uploads](uploads.md).
- To put BlazeServe on a real server, read [deploy/README.md](../deploy/README.md).
