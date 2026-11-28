#!/usr/bin/env python3
"""Writes the Homebrew, Scoop, winget and AUR manifests for one release.

    python3 packaging/update_manifests.py 1.2.0 path/to/SHA256SUMS out/

The hashes come only from SHA256SUMS; a missing asset stops the run, so a manifest can
never point at a file it has no hash for. Nothing is submitted anywhere.
"""

import json
import pathlib
import sys

REPO = "https://github.com/whoisjayd/blazeserve"
DESCRIPTION = "Fast file server and transfer tool for large files"
ASSETS = {
    "mac_arm": ("aarch64-apple-darwin", "tar.gz"),
    "mac_intel": ("x86_64-apple-darwin", "tar.gz"),
    "linux_arm": ("aarch64-unknown-linux-musl", "tar.gz"),
    "linux_intel": ("x86_64-unknown-linux-musl", "tar.gz"),
    "windows": ("x86_64-pc-windows-msvc", "zip"),
}


def read_sums(path):
    sums = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64:
            sums[parts[1].lstrip("*")] = parts[0].lower()
    return sums


def releases(version, sums):
    """`{key: (url, sha256, folder)}` for every asset the manifests name."""
    out = {}
    for key, (target, ext) in ASSETS.items():
        folder = f"blazeserve-v{version}-{target}"
        name = f"{folder}.{ext}"
        if name not in sums:
            raise SystemExit(f"SHA256SUMS has no entry for {name}")
        out[key] = (f"{REPO}/releases/download/v{version}/{name}", sums[name], folder)
    return out


def homebrew(version, r):
    def source(key):
        url, sha, _ = r[key]
        return f'      url "{url}"\n      sha256 "{sha}"\n'

    return f"""class Blazeserve < Formula
  desc "{DESCRIPTION}"
  homepage "{REPO}"
  version "{version}"
  license "MIT"

  on_macos do
    on_arm do
{source("mac_arm")}    end
    on_intel do
{source("mac_intel")}    end
  end

  on_linux do
    on_arm do
{source("linux_arm")}    end
    on_intel do
{source("linux_intel")}    end
  end

  def install
    bin.install "blaze"
    man1.install "man/blaze.1"
    bash_completion.install "completions/blaze.bash" => "blaze"
    zsh_completion.install "completions/_blaze"
    fish_completion.install "completions/blaze.fish"
  end

  test do
    (testpath/"hello.txt").write "blaze\\n"
    assert_match version.to_s, shell_output("#{{bin}}/blaze --version")
    assert_match "hello.txt", shell_output("#{{bin}}/blaze checksum hello.txt")
  end
end
"""


def scoop(version, r):
    url, sha, folder = r["windows"]
    return (
        json.dumps(
            {
                "version": version,
                "description": DESCRIPTION,
                "homepage": REPO,
                "license": "MIT",
                "architecture": {"64bit": {"url": url, "hash": sha, "extract_dir": folder}},
                "bin": "blaze.exe",
                "checkver": {"github": REPO},
                "autoupdate": {
                    "architecture": {
                        "64bit": {
                            "url": f"{REPO}/releases/download/v$version/"
                            "blazeserve-v$version-x86_64-pc-windows-msvc.zip",
                            "extract_dir": "blazeserve-v$version-x86_64-pc-windows-msvc",
                        }
                    },
                    "hash": {"url": "$baseurl/SHA256SUMS", "regex": "$sha256\\s+$basename"},
                },
            },
            indent=4,
        )
        + "\n"
    )


def winget(version, r):
    url, sha, folder = r["windows"]
    head = f"PackageIdentifier: whoisjayd.BlazeServe\nPackageVersion: {version}\n"
    tail = "ManifestVersion: 1.6.0\n"
    return {
        "whoisjayd.BlazeServe.yaml": head + "DefaultLocale: en-US\nManifestType: version\n" + tail,
        "whoisjayd.BlazeServe.installer.yaml": head
        + "InstallerType: zip\nNestedInstallerType: portable\nNestedInstallerFiles:\n"
        + f"- RelativeFilePath: {folder}\\blaze.exe\n  PortableCommandAlias: blaze\n"
        + f"Installers:\n- Architecture: x64\n  InstallerUrl: {url}\n"
        + f"  InstallerSha256: {sha.upper()}\nManifestType: installer\n"
        + tail,
        "whoisjayd.BlazeServe.locale.en-US.yaml": head
        + "PackageLocale: en-US\nPublisher: whoisjayd\nPackageName: BlazeServe\n"
        + f"License: MIT\nShortDescription: {DESCRIPTION}\nPackageUrl: {REPO}\n"
        + "ManifestType: defaultLocale\n"
        + tail,
    }


def pkgbuild(version, r):
    return f"""pkgname=blazeserve-bin
pkgver={version}
pkgrel=1
pkgdesc='{DESCRIPTION}'
arch=('x86_64' 'aarch64')
url='{REPO}'
license=('MIT')
provides=("blazeserve=$pkgver")
conflicts=('blazeserve')
options=('!strip' '!debug')
source_x86_64=("$pkgname-$pkgver-x86_64.tar.gz::{r["linux_intel"][0]}")
source_aarch64=("$pkgname-$pkgver-aarch64.tar.gz::{r["linux_arm"][0]}")
sha256sums_x86_64=('{r["linux_intel"][1]}')
sha256sums_aarch64=('{r["linux_arm"][1]}')

package() {{
  cd "blazeserve-v$pkgver-$CARCH-unknown-linux-musl"
  install -Dm755 blaze "$pkgdir/usr/bin/blaze"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 man/blaze.1 "$pkgdir/usr/share/man/man1/blaze.1"
  install -Dm644 completions/blaze.bash "$pkgdir/usr/share/bash-completion/completions/blaze"
  install -Dm644 completions/_blaze "$pkgdir/usr/share/zsh/site-functions/_blaze"
  install -Dm644 completions/blaze.fish "$pkgdir/usr/share/fish/vendor_completions.d/blaze.fish"
}}
"""


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    version, sums_path, out = argv
    version = version.removeprefix("v")
    r = releases(version, read_sums(sums_path))
    files = {
        "homebrew/Formula/blazeserve.rb": homebrew(version, r),
        "scoop/blazeserve.json": scoop(version, r),
        "aur/PKGBUILD": pkgbuild(version, r),
        **{f"winget/{name}": text for name, text in winget(version, r).items()},
    }
    for name, text in files.items():
        path = pathlib.Path(out) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(path)


if __name__ == "__main__":
    main(sys.argv[1:])
