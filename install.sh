#!/usr/bin/env bash
set -euo pipefail

########################################
# Shadowsocks auto-install for Ubuntu
# - Installs shadowsocks-libev
# - Configures ss-server
# - Generates 10-char password (letters+digits)
# - Generates ss:// link
# - Opens UFW: 22/tcp + SS port tcp/udp
# - Enables ip_forward=1
# - Applies TCP/UDP optimizations (BBR/fq when available)
# - Prints summary
# - Generates OPTIONAL ss-local config with local_port=1080
#   and creates OPTIONAL ss-local systemd service (disabled by default)
#
# Usage:
#   sudo bash install_shadowsocks.sh
#
# Optional env overrides:
#   SS_PORT=8388 SS_METHOD=aes-256-gcm SS_PASSWORD=... SS_HOST=... SS_TAG="My Server"
########################################

LOG_PREFIX="[shadowsocks-installer]"
SS_CONFIG="/etc/shadowsocks-libev/config.json"
SS_LOCAL_CONFIG="/etc/shadowsocks-libev/local.json"
SYSCTL_FILE="/etc/sysctl.d/99-shadowsocks-optimizations.conf"

DEFAULT_PORT="443"
DEFAULT_METHOD="chacha20-ietf-poly1305"
DEFAULT_LOCAL_PORT="1080"

info()  { echo -e "${LOG_PREFIX} [INFO] $*"; }
warn()  { echo -e "${LOG_PREFIX} [WARN] $*" >&2; }
err()   { echo -e "${LOG_PREFIX} [ERROR] $*" >&2; }
die()   { err "$*"; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Please run as root: sudo bash $0"
  fi
}

# 3) Generate password consisting of 10 digits and letters
gen_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10
}

get_public_ip() {
  local ip=""
  if has_cmd curl; then
    ip="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [[ -z "${ip}" ]] && has_cmd wget; then
    ip="$(wget -qO- --timeout=4 https://api.ipify.org 2>/dev/null || true)"
  fi
  echo "${ip}"
}

install_dependencies() {
  info "Updating apt and installing dependencies..."
  apt-get update -y
  apt-get install -y --no-install-recommends \
    shadowsocks-libev \
    ufw \
    ca-certificates \
    curl \
    jq
}

# 1) Ufw port open for UDP and TCP of shadowsocks server including 22 port
configure_ufw() {
  local ss_port="$1"

  info "Configuring UFW (allow 22/tcp and ${ss_port}/tcp+udp)..."
  ufw --force enable >/dev/null

  ufw allow 22/tcp >/dev/null || true
  ufw allow "${ss_port}"/tcp >/dev/null || true
  ufw allow "${ss_port}"/udp >/dev/null || true

  info "UFW status:"
  ufw status verbose || true
}

# 5) Applications setting including restart of shadowsocks service
write_server_config() {
  local ss_port="$1"
  local ss_password="$2"
  local ss_method="$3"

  info "Writing ss-server config to ${SS_CONFIG} ..."
  mkdir -p "$(dirname "${SS_CONFIG}")"

  # NOTE: local_address removed as requested
  # 6) local_port is kept at 1080
  cat > "${SS_CONFIG}" <<EOF
{
  "server":"0.0.0.0",
  "server_port": ${ss_port},
  "local_port": ${DEFAULT_LOCAL_PORT},
  "password":"${ss_password}",
  "timeout": 300,
  "method":"${ss_method}",
  "mode":"tcp_and_udp",
  "fast_open": false,
  "reuse_port": true,
  "no_delay": true
}
EOF
}

# Optional client config (ss-local), also without local_address
write_local_client_config() {
  local server_host="$1"
  local ss_port="$2"
  local ss_password="$3"
  local ss_method="$4"

  info "Writing OPTIONAL ss-local (client) config to ${SS_LOCAL_CONFIG} (local_port=${DEFAULT_LOCAL_PORT}) ..."
  cat > "${SS_LOCAL_CONFIG}" <<EOF
{
  "server":"${server_host}",
  "server_port": ${ss_port},
  "local_port": ${DEFAULT_LOCAL_PORT},
  "password":"${ss_password}",
  "timeout": 300,
  "method":"${ss_method}",
  "mode":"tcp_and_udp"
}
EOF
}

enable_and_restart_service() {
  info "Enabling and restarting shadowsocks-libev service..."
  systemctl daemon-reload
  systemctl enable shadowsocks-libev >/dev/null || true
  systemctl restart shadowsocks-libev

  sleep 1
  if ! systemctl is-active --quiet shadowsocks-libev; then
    err "Service is NOT running."
    err "Recent logs:"
    journalctl -u shadowsocks-libev -n 120 --no-pager || true
    die "Fix the error above and re-run."
  fi

  info "Service is running."
}

# 7) Add ip.forwarding = 1
# 8) Optimization of TCP and UDP connection to improve speed and latency
apply_network_optimizations() {
  info "Applying sysctl optimizations + enabling IP forwarding..."

  cat > "${SYSCTL_FILE}" <<'EOF'
# Shadowsocks performance tuning (safe-ish defaults)

# Enable routing/forwarding
net.ipv4.ip_forward = 1

# Basic security/sanity
net.ipv4.tcp_syncookies = 1

# Queue / congestion control (best on modern kernels)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP improvements
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_mtu_probing = 1

# Buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Backlog
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# Wider ephemeral ports
net.ipv4.ip_local_port_range = 10240 65535
EOF

  if ! sysctl --system >/dev/null 2>&1; then
    warn "Some sysctl values may not be supported by your kernel. Details:"
    sysctl --system || true
  fi

  local cc qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  info "Applied: ip_forward=$(sysctl -n net.ipv4.ip_forward), congestion_control=${cc}, qdisc=${qdisc}"
}

# 2) Shadowsocks link generator
# ss://BASE64(method:password@host:port)#TAG
ss_link() {
  local method="$1"
  local password="$2"
  local host="$3"
  local port="$4"
  local tag="$5"

  local userinfo="${method}:${password}@${host}:${port}"
  local b64=""

  if has_cmd openssl; then
    b64="$(printf '%s' "${userinfo}" | openssl base64 -A)"
  else
    b64="$(printf '%s' "${userinfo}" | base64 | tr -d '\n')"
  fi

  tag="${tag// /%20}"
  printf "ss://%s#%s\n" "${b64}" "${tag}"
}

create_optional_ss_local_service() {
  info "Creating OPTIONAL ss-local systemd service (disabled by default)..."
  cat > /etc/systemd/system/ss-local.service <<EOF
[Unit]
Description=Shadowsocks Local Client (ss-local)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-local -c ${SS_LOCAL_CONFIG} -u
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  info "ss-local service created. To enable it: systemctl enable --now ss-local"
}

# 4) Printing summary
print_summary() {
  local host="$1"
  local ss_port="$2"
  local ss_method="$3"
  local ss_password="$4"
  local link="$5"

  echo
  echo "================== SUMMARY =================="
  echo "Server Host/IP : ${host}"
  echo "Server Port    : ${ss_port} (TCP+UDP)"
  echo "Method         : ${ss_method}"
  echo "Password       : ${ss_password}"
  echo "Local Port     : ${DEFAULT_LOCAL_PORT} (client/local config)"
  echo
  echo "Shadowsocks URI:"
  echo "${link}"
  echo
  echo "Config files:"
  echo " - Server: ${SS_CONFIG}"
  echo " - Local : ${SS_LOCAL_CONFIG} (optional client config)"
  echo
  echo "Commands:"
  echo " - Status : systemctl status shadowsocks-libev --no-pager"
  echo " - Logs   : journalctl -u shadowsocks-libev -n 200 --no-pager"
  echo " - Restart: systemctl restart shadowsocks-libev"
  echo "============================================="
  echo
}

main() {
  need_root

  local ss_port ss_method ss_password server_host tag link

  ss_port="${SS_PORT:-${DEFAULT_PORT}}"
  ss_method="${SS_METHOD:-${DEFAULT_METHOD}}"
  ss_password="${SS_PASSWORD:-$(gen_password)}"

  server_host="${SS_HOST:-}"
  if [[ -z "${server_host}" ]]; then
    server_host="$(get_public_ip)"
  fi
  if [[ -z "${server_host}" ]]; then
    server_host="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "${server_host}" ]]; then
    server_host="$(hostname)"
  fi

  tag="${SS_TAG:-Shadowsocks}"

  info "Starting installation with: port=${ss_port}, method=${ss_method}, host=${server_host}, local_port=${DEFAULT_LOCAL_PORT}"

  install_dependencies
  configure_ufw "${ss_port}"

  write_server_config "${ss_port}" "${ss_password}" "${ss_method}"
  write_local_client_config "${server_host}" "${ss_port}" "${ss_password}" "${ss_method}"

  apply_network_optimizations

  enable_and_restart_service
  create_optional_ss_local_service

  link="$(ss_link "${ss_method}" "${ss_password}" "${server_host}" "${ss_port}" "${tag}")"
  print_summary "${server_host}" "${ss_port}" "${ss_method}" "${ss_password}" "${link}"

  info "Done."
}

main "$@"
