#!/usr/bin/env bash
set -uo pipefail

# =========================
# Shadowsocks auto-installer (Ubuntu)
# - shadowsocks-libev
# - UFW TCP+UDP rules (22 + SS port)
# - Auto cipher detection
# - No local_port/local_address in config
# - IP forwarding + TCP/UDP tuning
# - Progress + summary + ss:// link
# =========================

TOTAL_STEPS=9
STEP=0

log()  { printf "\033[1;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

progress() {
  STEP=$((STEP+1))
  printf "\n\033[1;34m[%d/%d]\033[0m %s\n" "$STEP" "$TOTAL_STEPS" "$1"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root: sudo bash install.sh"
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

random_password_10() {
  # 10 chars: letters + digits
  # Uses /dev/urandom (no external deps)
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10
}

detect_public_ip() {
  # Best effort:
  # 1) external (if available)
  # 2) local source IP
  local ip=""
  if need_cmd curl; then
    ip="$(curl -4 -fsS https://api.ipify.org || true)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)"
  fi
  echo "${ip:-YOUR_SERVER_IP}"
}

pick_best_cipher() {
  # Prefer modern AEAD ciphers; choose first supported by this ss-server build.
  local preferred=(
    "chacha20-ietf-poly1305"
    "xchacha20-ietf-poly1305"
    "aes-256-gcm"
    "aes-128-gcm"
    "chacha20-poly1305"
    "aes-256-cfb"
    "aes-128-cfb"
  )

  local help_out=""
  help_out="$(ss-server -h 2>&1 || true)"

  for c in "${preferred[@]}"; do
    if echo "$help_out" | tr ',' '\n' | grep -qiE "(^|[[:space:]])${c}([[:space:]]|$)"; then
      echo "$c"
      return 0
    fi
  done

  # Fallback: try to extract any cipher-looking tokens from help output
  local fallback=""
  fallback="$(echo "$help_out" | tr ',' '\n' | grep -E '^[a-z0-9-]+$' | head -n 1 || true)"
  echo "${fallback:-aes-256-gcm}"
}

configure_sysctl_optimizations() {
  # TCP/UDP speed/latency tuning; safe-ish defaults for VPS.
  # Note: Some values may be capped by kernel; that's fine.
  cat >/etc/sysctl.d/99-shadowsocks-tuning.conf <<'EOF'
# --- Shadowsocks performance tuning ---

# Enable IPv4 forwarding (required by user request)
net.ipv4.ip_forward=1

# BBR congestion control (good latency/throughput on modern kernels)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# TCP Fast Open
net.ipv4.tcp_fastopen=3

# Increase socket buffers (helps high BDP and UDP)
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384

# Backlogs
net.core.netdev_max_backlog=250000
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=8192

# Keepalive (pragmatic)
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10

# Misc
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fin_timeout=15
EOF

  # Apply immediately
  sysctl --system >/dev/null 2>&1 || true
}

configure_limits() {
  # Increase file limits for high concurrency
  cat >/etc/security/limits.d/99-shadowsocks.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
}

setup_ufw_rules() {
  local port="$1"

  # Ensure UFW installed and enabled
  apt-get install -y ufw >/dev/null

  # Allow SSH (22) and Shadowsocks TCP+UDP
  ufw allow 22/tcp >/dev/null
  ufw allow "${port}"/tcp >/dev/null
  ufw allow "${port}"/udp >/dev/null

  # Enable ufw non-interactively if not active
  if ! ufw status | grep -q "Status: active"; then
    yes | ufw enable >/dev/null || true
  fi
}

write_ss_config() {
  local port="$1"
  local password="$2"
  local method="$3"

  mkdir -p /etc/shadowsocks-libev

  # IMPORTANT: no local_port / local_address keys included
  cat >/etc/shadowsocks-libev/config.json <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${port},
  "password": "${password}",
  "timeout": 60,
  "method": "${method}",
  "mode": "tcp_and_udp",
  "fast_open": true,
}
EOF

  # Use /etc/default/shadowsocks-libev to point daemon to this config
  cat >/etc/default/shadowsocks-libev <<'EOF'
# Defaults for shadowsocks-libev
START=yes
CONFFILE=/etc/shadowsocks-libev/config.json
DAEMON_ARGS="-c ${CONFFILE}"
EOF
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y shadowsocks-libev curl ca-certificates >/dev/null
}

enable_and_restart_service() {
  systemctl daemon-reload
  systemctl enable shadowsocks-libev.service >/dev/null 2>&1 || true
  systemctl restart shadowsocks-libev.service
  sleep 0.5

  if ! systemctl is-active --quiet shadowsocks-libev.service; then
    err "Service is not running. Check logs:"
    echo "  journalctl -u shadowsocks-libev -e --no-pager"
    exit 1
  fi
}

ss_link() {
  # ss:// base64url(method:password@host:port)#name
  local method="$1" password="$2" host="$3" port="$4" name="$5"
  local raw="${method}:${password}@${host}:${port}"

  # base64 url-safe, no padding
  local b64
  b64="$(printf '%s' "$raw" | base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')"
  printf 'ss://%s#%s\n' "$b64" "$(printf '%s' "$name" | sed 's/ /%20/g')"
}

# -------- main --------
require_root

# Defaults
SS_PORT="${SS_PORT:-8388}"   # You can override: SS_PORT=443 bash install.sh
SS_NAME="${SS_NAME:-Shadowsocks}"

progress "Installing required packages (shadowsocks-libev, curl, certs)..."
install_packages

progress "Generating secure password (10 chars letters+digits)..."
SS_PASSWORD="$(random_password_10)"

progress "Auto-detecting best supported encryption method..."
SS_METHOD="$(pick_best_cipher)"
log "Selected method: ${SS_METHOD}"

progress "Applying sysctl TCP/UDP optimizations + enabling ip.forwarding=1..."
configure_sysctl_optimizations
configure_limits

progress "Writing Shadowsocks config (no local_port/local_address)..."
write_ss_config "$SS_PORT" "$SS_PASSWORD" "$SS_METHOD"

progress "Configuring UFW firewall (22/tcp + ${SS_PORT}/tcp + ${SS_PORT}/udp)..."
setup_ufw_rules "$SS_PORT"

progress "Restarting and enabling Shadowsocks service..."
enable_and_restart_service

progress "Generating Shadowsocks ss:// link..."
PUBLIC_IP="$(detect_public_ip)"
SS_URI="$(ss_link "$SS_METHOD" "$SS_PASSWORD" "$PUBLIC_IP" "$SS_PORT" "$SS_NAME")"

progress "Done. Printing summary..."
echo
echo "================== Shadowsocks Summary =================="
echo " Server IP   : ${PUBLIC_IP}"
echo " Server Port : ${SS_PORT}"
echo " Password    : ${SS_PASSWORD}"
echo " Method      : ${SS_METHOD}"
echo " Mode        : tcp_and_udp"
echo " UFW         : allowed 22/tcp, ${SS_PORT}/tcp, ${SS_PORT}/udp"
echo
echo " ss:// link  :"
echo " ${SS_URI}"
echo "========================================================="
echo
log "Useful commands:"
echo "  systemctl status shadowsocks-libev --no-pager"
echo "  journalctl -u shadowsocks-libev -e --no-pager"
echo "  ufw status verbose"


main "$@"

