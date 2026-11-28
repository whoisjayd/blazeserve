# Package manifests

`update_manifests.py` writes the Homebrew formula, Scoop manifest, winget manifests and AUR `PKGBUILD` for a release from its `SHA256SUMS`:

```console
python3 packaging/update_manifests.py 1.2.0 SHA256SUMS out/
```

The release workflow runs it and uploads the result as the `package-manifests` artifact. Nothing is submitted automatically: copy the files into the tap, bucket, `winget-pkgs` or AUR repository by hand. The manifests expect archives that carry `man/` and `completions/`, which releases after 1.1.0 do.
