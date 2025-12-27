# Production Deployment Guide

This guide covers deploying BlazeServe in production environments.

## Table of Contents

- [Installation](#installation)
- [Systemd Service](#systemd-service)
- [Docker Deployment](#docker-deployment)
- [Reverse Proxy Setup](#reverse-proxy-setup)
- [Performance Tuning](#performance-tuning)
- [Security Best Practices](#security-best-practices)
- [Monitoring](#monitoring)

## Installation

### From PyPI (Recommended)

```bash
pip install blazeserve
```

### From Source

```bash
git clone https://github.com/whoisjayd/blazeserve.git
cd blazeserve
pip install -e .
```

## Systemd Service

Create a systemd service file for automatic startup and process management.

### Basic Service

Create `/etc/systemd/system/blazeserve.service`:

```ini
[Unit]
Description=BlazeServe HTTP File Server
After=network.target
Documentation=https://github.com/whoisjayd/blazeserve

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/srv/downloads
ExecStart=/usr/local/bin/blaze serve /srv/downloads \
    --port 8080 \
    --rate-mbps 200 \
    --cors
Restart=on-failure
RestartSec=5s

# Security hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/downloads

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable blazeserve
sudo systemctl start blazeserve
sudo systemctl status blazeserve
```

### View Logs

```bash
sudo journalctl -u blazeserve -f
```

## Docker Deployment

### Basic Dockerfile

```dockerfile
FROM python:3.12-slim

# Install BlazeServe
RUN pip install --no-cache-dir blazeserve

# Create data directory
WORKDIR /data

# Expose port
EXPOSE 8000

# Run server
CMD ["blaze", "serve", ".",
     "--host", "0.0.0.0",
     "--port", "8000",
     "--chunk-mb", "256",
     "--sock-sndbuf-mb", "128"]
```

### Build and Run

```bash
docker build -t blazeserve .
docker run -d \
    -p 8000:8000 \
    -v /path/to/files:/data:ro \
    --name blazeserve \
    blazeserve
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  blazeserve:
    image: blazeserve:latest
    container_name: blazeserve
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - /path/to/files:/data:ro
    environment:
      - BLAZE_AUTH=user:password
    command: >
      blaze serve /data
        --host 0.0.0.0
        --port 8000
        --auth-env BLAZE_AUTH
        --cors
        --rate-mbps 100
```

## Reverse Proxy Setup

### Nginx

```nginx
upstream blazeserve {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name files.example.com;

    location / {
        proxy_pass http://blazeserve;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Support for large files
        proxy_request_buffering off;
        proxy_buffering off;
        
        # Timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
```

### Caddy

```caddyfile
files.example.com {
    reverse_proxy localhost:8000 {
        flush_interval -1
    }
}
```

## Performance Tuning

### For LAN/High-Speed Networks

```bash
blaze serve . \
    --chunk-mb 512 \
    --sock-sndbuf-mb 256 \
    --backlog 16384
```

### For Internet Serving

```bash
blaze serve . \
    --chunk-mb 256 \
    --sock-sndbuf-mb 128 \
    --rate-mbps 50 \
    --backlog 8192
```

### System Limits

Increase system limits for high-traffic scenarios:

```bash
# /etc/sysctl.conf
net.core.somaxconn = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fin_timeout = 30
```

Apply changes:

```bash
sudo sysctl -p
```

## Security Best Practices

### 1. Use Authentication

```bash
export BLAZE_AUTH="username:strong_password"
blaze serve . --auth-env BLAZE_AUTH
```

### 2. Enable TLS

```bash
blaze serve . \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

### 3. Limit Upload Size

```bash
blaze serve . --max-upload-mb 100
```

### 4. Run as Non-Root User

Never run as root. Use a dedicated user:

```bash
sudo useradd -r -s /bin/false blazeserve
sudo chown -R blazeserve:blazeserve /srv/files
```

### 5. Firewall Configuration

```bash
# Allow only specific IPs (example)
sudo ufw allow from 192.168.1.0/24 to any port 8000
sudo ufw enable
```

## Monitoring

### Health Check

```bash
curl http://localhost:8000/__health__
```

### Performance Metrics

```bash
curl http://localhost:8000/__perf__ | jq
```

### Prometheus Integration

Export metrics for Prometheus:

```bash
# Example script
while true; do
    curl -s http://localhost:8000/__perf__ | \
        jq -r '"blazeserve_bytes_sent \(.bytes_sent)
blazeserve_requests_total \(.requests_total)
blazeserve_requests_active \(.requests_active)
blazeserve_uptime_seconds \(.uptime_seconds)"' > /var/lib/node_exporter/blazeserve.prom
    sleep 10
done
```

### Log Aggregation

Configure systemd journal forwarding to your log aggregation system.

## Benchmarking

Test your deployment:

```bash
blaze benchmark --url http://localhost:8000 --size-mb 100
```

## Troubleshooting

### High CPU Usage

- Reduce `--chunk-mb` value
- Enable rate limiting with `--rate-mbps`

### Memory Issues

- Reduce `--chunk-mb` value
- Reduce `--sock-sndbuf-mb` value
- Lower `--backlog` value

### Connection Refused

- Check firewall settings
- Verify port is not already in use
- Check SELinux/AppArmor policies

## Support

- GitHub Issues: https://github.com/whoisjayd/blazeserve/issues
- Documentation: https://github.com/whoisjayd/blazeserve

## License

MIT License - see LICENSE file for details.
