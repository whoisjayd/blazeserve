# Getting started

BlazeServe is a single program called `blaze`. It serves files over HTTP, downloads and uploads them with resume, and checks them with a checksum. There is nothing else to install.

## Install it

Pick whichever method suits you.

| Method | Command |
| :--- | :--- |
| Linux / macOS script | `curl -fsSL https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.sh \| sh` |
| Windows PowerShell script | `irm https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.ps1 \| iex` |
| Cargo (prebuilt) | `cargo binstall blazeserve` |
| Cargo (from source) | `cargo install blazeserve` |
| pip or uv | `pip install blazeserve` or `uv tool install blazeserve` |
| Download | Get an archive from the [Releases page](https://github.com/whoisjayd/blazeserve/releases) and check it against `SHA256SUMS` |
| Docker | `docker run --rm -p 5949:5949 -v "$PWD":/data:ro ghcr.io/whoisjayd/blazeserve:latest` |

Release archives include the man page (`man/blaze.1`) and shell completions (`completions/`). Prebuilt builds exist for Linux (x86_64 and aarch64, with glibc or musl), Windows x86_64, and macOS (Intel and Apple silicon). None of the prebuilt options (`install.sh`, `install.ps1`, `cargo binstall`, pip/uv wheels, release archives, or Docker) need Rust or a C compiler.

### Using the install scripts

Both [`install.sh`](../install.sh) and [`install.ps1`](../install.ps1) download the release archive for your machine and verify its SHA-256 against the release `SHA256SUMS` file before placing `blaze`. Neither script asks for root or administrator privileges, and neither configures automatic updates.

- **Linux and macOS (`install.sh`):** installs to `~/.local/bin/blaze` (override with `BLAZE_INSTALL_DIR`, or pin a release with `BLAZE_VERSION=v1.1.0`). Remove it with:

  ```bash
  curl -fsSL https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.sh | sh -s -- --uninstall
  ```

- **Windows (`install.ps1`):** installs to `%LOCALAPPDATA%\Programs\BlazeServe\blaze.exe` and adds that folder to your user `PATH` (`BLAZE_VERSION=v1.1.0` pins a release). Remove it with:

  ```powershell
  $env:BLAZE_UNINSTALL = 1; irm https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.ps1 | iex
  ```

Checking `SHA256SUMS` guards against corrupted downloads and mismatched mirrors, not against a compromised release host. To verify who built an archive, download it from the release page and run `gh attestation verify` before running or extracting it:

```bash
gh attestation verify blazeserve-v1.1.0-x86_64-unknown-linux-musl.tar.gz --repo whoisjayd/blazeserve
```

### Building from source

To build from source with `cargo install blazeserve`, you need Rust 1.93 or newer and a C compiler. The default `extract` feature enables `hatchzip-core`, which compiles bundled zstd C source (via `zstd-sys`), and `ring` (used for TLS) also builds C and assembly sources.

To build without `hatchzip-core` (which turns off `blaze get --extract`), disable default features:

```bash
cargo install blazeserve --no-default-features
```

Note that `ring` may still require a C compiler depending on your platform.

### Check that it works

```bash
blaze version
blaze          # a guided menu: it asks, runs the command and shows what it ran
```

## Serve a folder

```bash
blaze serve .
```

BlazeServe prints the addresses it is listening on. Open `http://localhost:5949` in a browser and you will see a listing of the current folder, with search and sorting. Anyone on your network can reach the same files at your machine's address, because `blaze serve` listens on all interfaces by default. Press `Ctrl+C` to stop it.

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
blaze info http://host:5949/big.iso             # what you would get, without downloading
blaze get http://host:5949/big.iso
blaze get http://host:5949/game.zip --extract   # unpack in place; add --keep-archive to keep game.zip
```

If the connection drops, run the same command again. It carries on from where it stopped instead of starting over. See [Sharing and downloading files](sharing-files.md) for the details.

## Check it all works

```bash
blaze doctor ./site
```

`doctor` checks that the folder exists, that the port is free, and that your system supports what BlazeServe needs. It is the first thing to run if something seems wrong.

## Keep it up to date

```bash
blaze upgrade --check
blaze upgrade
```

`--check` only compares versions. `blaze upgrade` then updates BlazeServe the way you installed it: a downloaded program replaces itself, pip and Cargo installs run their own tool, and a container or a package manager such as Homebrew gets the command to run instead. It asks before it changes anything. In a script, add `--yes`. `blaze upgrade --version 1.0.0` installs an exact version, also an older one. See the [reference](reference.md#blaze-upgrade-options) for the details.

The download is checked against the `SHA256SUMS` file of the same release. That guards against a damaged or truncated download, but a checksum fetched from the same place cannot prove who built the file. To check that too, download the release archive and run `gh attestation verify <file> --repo whoisjayd/blazeserve` before you trust it.

## Where to go next

- To protect a server with a password or HTTPS, read [Serving files](serving-files.md).
- To receive files, read [Uploads](uploads.md).
- To put BlazeServe on a real server, read [deploy/README.md](../deploy/README.md).
