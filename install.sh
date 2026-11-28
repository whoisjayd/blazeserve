#!/bin/sh
# Installs BlazeServe (the `blaze` command) from the latest release, or updates it.
# Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.sh | sh
#
# It downloads the build for this machine, checks it against the published SHA256SUMS,
# and puts `blaze` in ~/.local/bin. No root required, and it does not auto-update.
# Remove it with: sh install.sh --uninstall
#
# To verify release provenance before trusting an archive, download the archive and run:
#   gh attestation verify <archive> --repo whoisjayd/blazeserve
#
# Environment:
#   BLAZE_INSTALL_DIR   where the program goes (default ~/.local/bin)
#   BLAZE_VERSION       a release tag like v2.0.0 (default: the latest)
#   BLAZE_BASE_URL      override download base URL (for mirrors or local testing)

set -eu

REPO="whoisjayd/blazeserve"
BIN_DIR="${BLAZE_INSTALL_DIR:-$HOME/.local/bin}"
TMP_DIR=""

fail() {
    printf 'blaze: %s\n' "$*" >&2
    exit 1
}

has() {
    command -v "$1" >/dev/null 2>&1
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

usage() {
    cat <<'EOF'
Usage: install.sh [--uninstall]

Environment variables:
  BLAZE_INSTALL_DIR   Destination directory (default: ~/.local/bin)
  BLAZE_VERSION       Release version or tag, e.g. v2.0.0 (default: latest)
  BLAZE_BASE_URL      Override release asset base URL
EOF
}

download() {
    url="$1"
    dest="$2"
    case "$url" in
        file://*)
            [ -n "${BLAZE_BASE_URL:-}" ] || fail "file:// URLs require BLAZE_BASE_URL"
            src_file="${url#file://}"
            [ -f "$src_file" ] || fail "download failed: $url"
            cp "$src_file" "$dest"
            ;;
        https://*)
            if has curl; then
                curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
            elif has wget; then
                wget -q --https-only -O "$dest" "$url"
            else
                fail "needs curl or wget"
            fi
            ;;
        *)
            fail "refusing non-HTTPS URL: $url"
            ;;
    esac
}

sha256_file() {
    if has sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif has shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        fail "needs sha256sum or shasum"
    fi
}

detect_target() {
    case "$(uname -s)" in
        Linux) os="unknown-linux-musl" ;;
        Darwin) os="apple-darwin" ;;
        *) fail "this installer is for Linux and macOS; on Windows use install.ps1" ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64) arch="x86_64" ;;
        aarch64 | arm64) arch="aarch64" ;;
        *) fail "no build for $(uname -m); build from source with cargo install blazeserve" ;;
    esac

    # An Intel shell under Rosetta still wants the native Apple Silicon build.
    if [ "$os" = "apple-darwin" ] && [ "$arch" = "x86_64" ] \
        && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = "1" ]; then
        arch="aarch64"
    fi

    printf '%s-%s\n' "$arch" "$os"
}

resolve_base_url() {
    if [ -n "${BLAZE_BASE_URL:-}" ]; then
        printf '%s\n' "${BLAZE_BASE_URL%/}"
        return
    fi
    if [ -n "${BLAZE_VERSION:-}" ]; then
        case "$BLAZE_VERSION" in
            v*) tag="$BLAZE_VERSION" ;;
            *) tag="v$BLAZE_VERSION" ;;
        esac
        printf 'https://github.com/%s/releases/download/%s\n' "$REPO" "$tag"
    else
        printf 'https://github.com/%s/releases/latest/download\n' "$REPO"
    fi
}

install_blaze() {
    target=$(detect_target)
    base=$(resolve_base_url)

    TMP_DIR=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # With "latest", the archive name carries the tag, so resolve it from SHA256SUMS first.
    download "$base/SHA256SUMS" "$TMP_DIR/SHA256SUMS"
    tr -d '\r' < "$TMP_DIR/SHA256SUMS" > "$TMP_DIR/SHA256SUMS.clean"

    expected=""
    name=""
    while IFS= read -r line; do
        case "$line" in
            "" | "#"*) continue ;;
        esac
        hash=$(printf '%s\n' "$line" | sed 's/[[:space:]].*//' | tr '[:upper:]' '[:lower:]')
        file=$(printf '%s\n' "$line" | sed 's/^[^[:space:]]*[[:space:]]*\*\{0,1\}//')
        case "$hash" in
            *[!0-9a-f]*) continue ;;
        esac
        [ "${#hash}" -eq 64 ] || continue
        if [ -n "${BLAZE_VERSION:-}" ]; then
            case "$BLAZE_VERSION" in
                v*) tag="$BLAZE_VERSION" ;;
                *) tag="v$BLAZE_VERSION" ;;
            esac
            if [ "$file" = "blazeserve-$tag-$target.tar.gz" ]; then
                expected="$hash"
                name="$file"
                break
            fi
        else
            case "$file" in
                */*) continue ;;
                blazeserve-v*-"$target".tar.gz)
                    expected="$hash"
                    name="$file"
                    break
                    ;;
            esac
        fi
    done < "$TMP_DIR/SHA256SUMS.clean"
    [ -n "$expected" ] || fail "no build for $target in this release"

    download "$base/$name" "$TMP_DIR/$name"
    actual=$(sha256_file "$TMP_DIR/$name" | tr '[:upper:]' '[:lower:]')
    [ "$actual" = "$expected" ] || fail "the download does not match its checksum; nothing was installed"

    tar -xzf "$TMP_DIR/$name" -C "$TMP_DIR"
    src_dir="$TMP_DIR/${name%.tar.gz}"
    [ -f "$src_dir/blaze" ] || fail "archive $name does not contain blaze"

    mkdir -p "$BIN_DIR"
    cp "$src_dir/blaze" "$BIN_DIR/.blaze.new"
    chmod 755 "$BIN_DIR/.blaze.new"
    if ! installed=$("$BIN_DIR/.blaze.new" --version); then
        rm -f "$BIN_DIR/.blaze.new"
        fail "the downloaded blaze does not run on this system; nothing was installed"
    fi
    mv -f "$BIN_DIR/.blaze.new" "$BIN_DIR/blaze"

    printf '%s installed in %s\n' "$installed" "$BIN_DIR"
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) printf 'Add to your PATH: export PATH="%s:$PATH"\n' "$BIN_DIR" ;;
    esac
}

uninstall_blaze() {
    rm -f "$BIN_DIR/blaze" "$BIN_DIR/.blaze.new"
    printf 'Removed %s/blaze\n' "$BIN_DIR"
}

main() {
    case "${1:-}" in
        "") install_blaze ;;
        --uninstall) uninstall_blaze ;;
        -h | --help) usage ;;
        *) fail "unknown option: $1" ;;
    esac
}

# Nothing above has executed yet. Piped from curl, the shell reads the script as it
# arrives, so a download cut off halfway stops before this line.
main "$@"
