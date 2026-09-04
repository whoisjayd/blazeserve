# Systemd Production Deployment for BlazeServe

This directory provides a hardened systemd service for Linux hosts. BlazeServe binds its own listening socket; systemd socket activation is not supported.

## Hardening

The service uses `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `MemoryDenyWriteExecute=true`, restricted address families, and explicit process/file-descriptor limits. It binds to `127.0.0.1:8080` for use behind a local reverse proxy.

## Installation

```bash
# Create the dedicated user and content directory.
sudo useradd -r -u 10001 -s /sbin/nologin -d /srv/blazeserve blazeserve
sudo mkdir -p /srv/blazeserve
sudo chown -R blazeserve:blazeserve /srv/blazeserve

# Install and start the service.
sudo cp deploy/systemd/blazeserve.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blazeserve.service

# Inspect status and logs.
sudo systemctl status blazeserve.service
sudo journalctl -u blazeserve.service -f
```

Review the writable content path, bind address, upload policy, and reverse-proxy configuration before production use.
