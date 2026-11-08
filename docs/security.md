# Security

This page explains what BlazeServe is designed to withstand. To report a vulnerability, follow [SECURITY.md](../SECURITY.md).

## Who it defends against

BlazeServe assumes the person on the other end of the connection may be hostile. They can send any path, query string, header, upload name and body, and can behave badly on the connection. What they cannot do is run commands on your machine, so the protections are about how the server treats requests.

## Files stay inside the served folder

Every file that is read, uploaded or added to a ZIP is checked against the real location of the served folder, one path component at a time. These all fail closed, meaning the request is refused:

- `..` segments, including encoded and double-encoded ones
- sibling folders with a similar name, such as `/data-evil` next to `/data`
- symbolic links and Windows junctions that point outside the folder
- paths on a different Windows drive

A path is decoded exactly once, so `%252e%252e` is treated as an odd file name rather than as `..`.

## Passwords

Authentication runs before the server touches the filesystem or any status page. Both the user name and the password are compared in constant time, so response timing does not reveal how close a guess was. A missing or malformed login is rejected. If you point `--auth-env` at an empty or unset variable, the server refuses to start, so a typo cannot leave you unprotected.

## HTTPS

TLS 1.2 or newer is required. A certificate without its key, or the reverse, is rejected before the server opens a port. If TLS setup fails, nothing is left listening. Responses over HTTPS carry `Strict-Transport-Security`.

## Uploads

Uploads are off by default. When enabled, files are created exclusively, with owner-only permissions on Unix, and are never silently overwritten. A file is staged, verified and then moved into place, so nobody can download a half-written upload. See [Uploads](uploads.md) for the details.

## Browser safety

Every response sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`. File names shown in listings are escaped and encoded, so a file named with HTML or script in it cannot attack someone viewing the page.

## Staying up under load

The server limits connections, drops clients that are slow to send their request, closes idle connections, and reads files in small chunks so a large download never fills memory. Each HTTP/2 connection has a budget for opening new requests, which stops the rapid-reset style of flood. A range request cannot be used to multiply the response either: a request with more than 64 ranges, or ranges that add up to more than the file, simply gets the whole file.

## Logs and privacy

Passwords, `Authorization` headers, URLs containing credentials, TLS keys and file contents are never written to logs.

## What it does not protect against

Be aware of these limits.

- **Writers in the served folder.** The server checks a path and then opens it, and on some platforms those two steps are not a single atomic action. Someone who can already write inside the served folder could in theory swap a link at the wrong moment. Do not give untrusted people write access to a folder you serve.
- **A trusted proxy that lies.** Forwarded addresses are believed only from proxies you list with `--trust-proxy`. If one of those is compromised, it can claim any visitor identity. Also make sure visitors cannot reach BlazeServe directly, and that your proxy removes any `Forwarded` header sent by the client.
- **Floods from many machines.** Limits stop one client from hogging the server. A flood spread over many sources can still use up the connection slots.
- **Certificate renewal.** BlazeServe does not reload certificates. Restart it after renewing.

## Supply chain

Release files carry build provenance. To check a download:

```bash
gh attestation verify <file> --repo whoisjayd/blazeserve
```
