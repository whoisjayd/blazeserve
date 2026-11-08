#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---check}"
CONF_FILE="/etc/sysctl.d/99-blazeserve.conf"

SYSCTL_PARAMS=(
    "net.core.somaxconn=65535"
    "net.ipv4.tcp_max_syn_backlog=32768"
    "net.core.netdev_max_backlog=16384"
    "net.ipv4.tcp_fin_timeout=15"
    "net.ipv4.tcp_tw_reuse=1"
    "net.core.rmem_max=16777216"
    "net.core.wmem_max=16777216"
    "fs.file-max=2097152"
    "vm.swappiness=10"
)

case "${MODE}" in
    --check)
        for item in "${SYSCTL_PARAMS[@]}"; do
            key="${item%%=*}"
            target="${item##*=}"
            current=$(sysctl -n "${key}" 2>/dev/null || echo "N/A")
            printf "%-35s target=%-10s current=%s\n" "${key}" "${target}" "${current}"
        done
        ;;
    --dry-run)
        echo "Would write to ${CONF_FILE}:"
        for item in "${SYSCTL_PARAMS[@]}"; do
            echo "  ${item}"
        done
        ;;
    --apply)
        if [ "${EUID}" -ne 0 ]; then
            echo "--apply requires root; run with sudo." >&2
            exit 1
        fi
        cat > "${CONF_FILE}" <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 32768
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
fs.file-max = 2097152
vm.swappiness = 10
EOF
        sysctl -p "${CONF_FILE}"
        echo "Applied ${CONF_FILE}"
        ;;
    *)
        echo "Usage: $0 [--check | --dry-run | --apply]" >&2
        exit 1
        ;;
esac
