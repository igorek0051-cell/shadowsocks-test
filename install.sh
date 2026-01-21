#!/usr/bin/env bash
set -uo pipefail

TOTAL_STEPS=12
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

rand_password_10() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10; }

detect_public_ip() {
  local ip=""
  if need_cmd curl; then ip="$(curl -4 -fsS https://api.ipify.org || true)"; fi
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)"
  fi
  echo "${ip:-YOUR_SERVER_IP}"
}

pick_best_cipher() {
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
  for c in "${preferred[@]}"; do
    if echo "$h" | grep -qiE "(^|[^a-z0-9_-])${c}([^a-z0-9_-]|$)"; then
      echo "$c"; return 0
    fi
  done
  echo "aes-256-gcm"
}

apply_sysctl_tuning() {
  modprobe tcp_bbr >/dev/null 2>&1 || true

  local cc="cubic"
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    cc="bbr"
  else
    warn "BBR not available on this kernel; using default congestion control."
  fi

  cat >/etc/sysctl.d/99-shadowsocks-tuning.conf <<EOF
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=${cc}
net.ipv4.tcp_fastopen=3

net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384

net.core.netdev_max_backlog=250000
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=8192

net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10

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
  cat >/etc/shadowsocks-libev/config.json <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${port},
  "password": "${password}",
  "timeout": 300,
  "method": "${method}",
  "mode": "tcp_and_udp",
  "fast_open": true,
  "reuse_port": true,
  "no_delay": true
}
EOF
}

add_edit_rights() {
  local grp="${SS_EDIT_GROUP:-sudo}"

  if ! getent group "$grp" >/dev/null 2>&1; then
    warn "Group '$grp' not found; skipping group edit rights."
    return 0
  fi

  chown -R root:"$grp" /etc/shadowsocks-libev
  chmod 2775 /etc/shadowsocks-libev
  chmod 0664 /etc/shadowsocks-libev/config.json

  info "Edit rights: /etc/shadowsocks-libev root:${grp}, dir=2775, config.json=664"
}

set_proc_tcp_fastopen() {
  # Explicit requirement
  echo 3 | tee /proc/sys/net/ipv4/tcp_fastopen >/dev/null || true
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

install_systemd_override() {
  # This avoids "Invalid config path" issues across Ubuntu package variants.
  mkdir -p /etc/systemd/system/shadowsocks-libev.service.d

  cat >/etc/systemd/system/shadowsocks-libev.service.d/override.conf <<'EOF'
[Service]
# Clear any previous ExecStart from the vendor unit
ExecStart=
# Start ss-server with an explicit config path
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json
EOF

  systemctl daemon-reload
}

restart_service() {
  systemctl enable shadowsocks-libev >/dev/null 2>&1 || true
  systemctl restart shadowsocks-libev
  sleep 0.7

  if ! systemctl is-active --quiet shadowsocks-libev; then
    error "Service is not running. Check:"
    echo "  journalctl -u shadowsocks-libev -e --no-pager"
    echo "  systemctl cat shadowsocks-libev --no-pager"
    exit 1
  fi
}

make_ss_link() {
  local method="$1" password="$2" host="$3" port="$4" name="$5"
  local raw="${method}:${password}@${host}:${port}"
  local b64
  b64="$(printf '%s' "$raw" | base64 -w0 | tr -d '=' | tr '+/' '-_')"
  printf 'ss://%s#%s\n' "$b64" "$(printf '%s' "$name" | sed 's/ /%20/g')"
}

# -------------------- main --------------------
require_root

SS_PORT="${SS_PORT:-8388}"
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

progress "Setting TCP Fast Open via /proc (echo 3 > /proc/sys/net/ipv4/tcp_fastopen)..."
set_proc_tcp_fastopen

progress "Writing Shadowsocks config (no local_port/local_address)..."
write_config "$SS_PORT" "$SS_PASSWORD" "$SS_METHOD"

progress "Adding edit rights on /etc/shadowsocks-libev and config.json..."
add_edit_rights

progress "Installing systemd override (explicit config path)..."
install_systemd_override

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
echo " Config      : /etc/shadowsocks-libev/config.json"
echo " ss:// link  :"
echo " ${SS_URI}"
echo "========================================================="
echo
info "Useful commands:"
echo "  systemctl status shadowsocks-libev --no-pager"
echo "  systemctl cat shadowsocks-libev --no-pager"
echo "  journalctl -u shadowsocks-libev -e --no-pager"
echo "  ufw status verbose"

echo "test 1"
