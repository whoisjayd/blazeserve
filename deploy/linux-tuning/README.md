# Linux Kernel Tuning for High-Throughput HTTP

This directory contains kernel network parameters and automated tuning scripts designed to maximize socket accept rates, eliminate packet drops under burst traffic, and scale open file descriptors for BlazeServe.

## Key Tunables Explained

| Kernel Parameter | Value | Architectural Justification |
| :--- | :--- | :--- |
| `net.core.somaxconn` | `65535` | Expands socket listen backlog queue to prevent connection resets during high concurrency spikes. |
| `net.ipv4.tcp_max_syn_backlog` | `32768` | Increases SYN queue size to survive burst handshakes without dropping incoming connections. |
| `net.core.netdev_max_backlog` | `16384` | Increases packet processing queue size before network driver hands packets to IP stack. |
| `net.ipv4.tcp_fin_timeout` | `15` | Lowers FIN-WAIT-2 timeout from 60s to 15s to reclaim socket resources faster. |
| `net.ipv4.tcp_tw_reuse` | `1` | Allows safe recycling of TIME-WAIT sockets for outgoing connections without port exhaustion. |
| `net.core.rmem_max` / `wmem_max` | `16777216` | Sets 16MB maximum TCP window buffer size for 10Gbps+ link saturation. |
| `fs.file-max` | `2097152` | Expands system-wide open file limit to 2 million descriptors. |
| `vm.swappiness` | `10` | Minimizes kernel memory swapping to preserve physical RAM page cache for zero-copy file I/O. |

## Usage

```bash
# Check current system values against targets
./deploy/linux-tuning/tuning.sh --check

# Dry-run parameter changes
./deploy/linux-tuning/tuning.sh --dry-run

# Apply permanently to /etc/sysctl.d/99-blazeserve.conf (requires sudo)
sudo ./deploy/linux-tuning/tuning.sh --apply
```
