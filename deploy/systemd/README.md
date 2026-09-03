# Systemd Production Deployment for BlazeServe

This directory provides production systemd service and socket units for Linux hosts with enterprise security hardening and socket activation.

## Hardening Features

- **Sandboxing**: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`.
- **Resource Limits**: `LimitNOFILE=1048576` (1M open file descriptors), `LimitNPROC=512`.
- **Memory Protection**: `MemoryDenyWriteExecute=true`, `RestrictRealtime=true`.
- **Restricted Address Families**: Only IPv4, IPv6, and UNIX domain sockets permitted.

## Installation

```bash
# 1. Create dedicated system user
sudo useradd -r -u 10001 -s /sbin/nologin -d /srv/blazeserve blazeserve
sudo mkdir -p /srv/blazeserve
sudo chown -R blazeserve:blazeserve /srv/blazeserve

# 2. Copy systemd unit files
sudo cp deploy/systemd/blazeserve.service /etc/systemd/system/
sudo cp deploy/systemd/blazeserve.socket /etc/systemd/system/

# 3. Reload daemon and start
sudo systemctl daemon-reload
sudo systemctl enable --now blazeserve.service

# 4. Inspect status and logs
sudo systemctl status blazeserve
sudo journalctl -u blazeserve -f
```
