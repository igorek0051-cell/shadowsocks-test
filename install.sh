#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Shadowsocks auto-install script (Ubuntu)
# - Installs shadowsocks-libev
# - Opens UFW for 22/tcp + SS port (tcp+udp)
# - Generates 10-char password (letters+digits)
# - Auto-detects best supported encryption method
# - Config: DOES NOT include local_port/local_address
# - Enables ip_forward=1
# - TCP/UDP tuning (BBR if available, buffers, fq, etc.)
# - Shows step-by-step progress
# - Prints summary + ss:// link
# ============================================================

TOTAL_STEPS=10
STEP=0

info()  { printf "\033[1;32m[INFO]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
error() { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

progress() {
  STEP=$((STEP+1))
  printf "\n\033[1;34m[%d/%d]\033[0m %s\n" "$STEP" "$TOTAL_STEPS" "$1"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    error "Run as root: sudo bash install.sh"
    exit 1
  fi
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

rand_password_10() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10
}

detect_public_ip() {
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
  # Preference order: modern AEAD first
  local preferred=(
    "chacha20-ietf-poly1305"
    "xchacha20-ietf-poly1305"
    "aes-256-gcm"
    "aes-128-gcm"
    "aes-256-cfb"
    "aes-128-cfb"
  )

  local h
  h="$(ss-server -h 2>&1 || true)"

  # Robust-ish: look for exact token boundaries in help text
  for c in "${preferred[@]}"; do
    if echo "$h" | grep -qiE "(^|[^a-z0-9_-])${c}([^a-z0-9_-]|$)"; then
      echo "$c"
      return 0
    fi
  done

  # Last-resort fallback
  echo "aes-256-gcm"
}

apply_sysctl_tuning() {
  # Try to enable BBR if kernel supports it; otherwise keep default congestion control.
  modprobe tcp_bbr >/dev/null 2>&1 || true

  local cc="cubic"
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    cc="bbr"
  else
    warn "BBR not available on this kernel; using default congestion control."
  fi

  cat >/etc/sysctl.d/99-shadowsocks-tuning.conf <<EOF
# --- Shadowsocks performance tuning ---

# Enable IPv4 forwarding (requested)
net.ipv4.ip_forward=1

# Queue discipline / congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=${cc}

# TCP Fast Open
net.ipv4.tcp_fastopen=3

# Bigger buffers (TCP/UDP)
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

# Keepalive
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10

# Misc
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fin_timeout=15
EOF

  sysctl --system >/dev/null 2>&1 || true
}

apply_limits() {
  cat >/etc/security/limits.d/99-shadowsocks.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y shadowsocks-libev ufw curl ca-certificates >/dev/null
}

write_config() {
  local port="$1" password="$2" method="$3"

  mkdir -p /etc/shadowsocks-libev

  # IMPORTANT: no local_port / local_address included
  cat >/etc/shadowsocks-libev/config.json <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${port},
  "password": "${password}",
  "timeout": 60,
  "method": "${method}",
  "mode": "tcp_and_udp",
  "fast_open": true,
  "reuse_port": true,
  "no_delay": true
}
EOF

  cat >/etc/default/shadowsocks-libev <<'EOF'
# Defaults for shadowsocks-libev
START=yes
CONFFILE=/etc/shadowsocks-libev/config.json
DAEMON_ARGS="-c ${CONFFILE}"
EOF
}

configure_ufw() {
  local port="$1"

  ufw allow 22/tcp >/dev/null
  ufw allow "${port}"/tcp >/dev/null
  ufw allow "${port}"/udp >/dev/null

  if ! ufw status | grep -q "Status: active"; then
    yes | ufw enable >/dev/null || true
  fi
}

restart_service() {
  systemctl daemon-reload
  systemctl enable shadowsocks-libev >/dev/null 2>&1 || true
  systemctl restart shadowsocks-libev
  sleep 0.5

  if ! systemctl is-active --quiet shadowsocks-libev; then
    error "Service is not running. Logs:"
    echo "  journalctl -u shadowsocks-libev -e --no-pager"
    exit 1
  fi
}

make_ss_link() {
  # ss:// base64url(method:password@host:port)#name
  local method="$1" password="$2" host="$3" port="$4" name="$5"
  local raw="${method}:${password}@${host}:${port}"

  local b64
  b64="$(printf '%s' "$raw" | base64 -w0 | tr -d '=' | tr '+/' '-_')"
  printf 'ss://%s#%s\n' "$b64" "$(printf '%s' "$name" | sed 's/ /%20/g')"
}

# -------------------- main --------------------
require_root

SS_PORT="${SS_PORT:-8388}"         # override: SS_PORT=443 bash install.sh
SS_NAME="${SS_NAME:-Shadowsocks}"

progress "Installing packages (shadowsocks-libev, ufw, curl, certs)..."
install_packages

progress "Generating password (10 chars: letters+digits)..."
SS_PASSWORD="$(rand_password_10)"

progress "Detecting best supported encryption method..."
SS_METHOD="$(pick_best_cipher)"
info "Selected method: ${SS_METHOD}"

progress "Applying TCP/UDP tuning + enabling ip_forward=1..."
apply_sysctl_tuning
apply_limits

progress "Writing Shadowsocks config (no local_port/local_address)..."
write_config "$SS_PORT" "$SS_PASSWORD" "$SS_METHOD"

progress "Configuring UFW (22/tcp + ${SS_PORT}/tcp + ${SS_PORT}/udp)..."
configure_ufw "$SS_PORT"

progress "Restarting & enabling Shadowsocks service..."
restart_service

progress "Detecting server public IP..."
PUBLIC_IP="$(detect_public_ip)"

progress "Generating ss:// link..."
SS_URI="$(make_ss_link "$SS_METHOD" "$SS_PASSWORD" "$PUBLIC_IP" "$SS_PORT" "$SS_NAME")"

progress "Printing summary..."
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
info "Useful commands:"
echo "  systemctl status shadowsocks-libev --no-pager"
echo "  journalctl -u shadowsocks-libev -e --no-pager"
echo "  ufw status verbose"
