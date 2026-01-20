#!/usr/bin/env bash
set -euo pipefail

# ===================== DEFAULTS =====================
SS_PORT="${SS_PORT:-8388}"
SS_LOCAL_PORT=1080
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n')}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_USER="${SS_USER:-shadowsocks}"
SS_CONFIG_DIR="/etc/shadowsocks-libev"
SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"
SS_SERVICE_NAME="shadowsocks-libev"
SYSCTL_FILE="/etc/sysctl.d/99-shadowsocks.conf"
# ====================================================

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "Run as root (use sudo)."; }

detect_ubuntu() {
  [[ -r /etc/os-release ]] || die "Cannot detect OS (missing /etc/os-release)."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "This script supports Ubuntu only (detected: ${ID:-unknown})."
}

install_deps() {
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl ufw openssl software-properties-common
}

install_shadowsocks() {
  # Try official repo first; fallback to PPA if package metadata not present.
  if ! apt-cache show shadowsocks-libev >/dev/null 2>&1; then
    add-apt-repository -y ppa:max-c-lv/shadowsocks-libev
    apt-get update -y
  fi
  apt-get install -y shadowsocks-libev
}

create_user() {
  if ! id -u "$SS_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SS_USER"
  fi
}

write_config() {
  mkdir -p "$SS_CONFIG_DIR"
  cat > "$SS_CONFIG_FILE" <<EOF
{
  "server": ["0.0.0.0", "::0"],
  "server_port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}",
  "timeout": 300,
  "mode": "tcp_and_udp",
  "fast_open": true
}
EOF
  chmod 600 "$SS_CONFIG_FILE"
  chown -R root:root "$SS_CONFIG_DIR"
}

write_systemd() {
  cat > /etc/systemd/system/${SS_SERVICE_NAME}.service <<EOF
[Unit]
Description=Shadowsocks Server (shadowsocks-libev)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SS_USER}
Group=${SS_USER}
ExecStart=/usr/bin/ss-server -c ${SS_CONFIG_FILE} -u
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SS_CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SS_SERVICE_NAME}.service"
}

apply_sysctl() {
  cat > "$SYSCTL_FILE" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
}

configure_firewall() {
  ufw --force enable >/dev/null || true
  ufw allow "${SS_PORT}/tcp" >/dev/null
  ufw allow "${SS_PORT}/udp" >/dev/null
}

get_public_ip() {
  curl -fsS https://api.ipify.org || echo YOUR_SERVER_IP
}

generate_ss_human() {
  echo "${SS_METHOD}:${SS_PASSWORD}@$(get_public_ip):${SS_PORT}"
}

generate_ss_link() {
  # Standard ss:// link: base64(method:password@server:port)
  printf '%s' "$(generate_ss_human)" | base64 | tr -d '\n=' | sed 's/^/ss:\/\//'
}

print_summary() {
  local ip human link
  ip="$(get_public_ip)"
  human="$(generate_ss_human)"
  link="$(generate_ss_link)"

  echo
  echo "==================== INSTALL COMPLETE ===================="
  echo "Server IP:    ${ip}"
  echo "Server Port:  ${SS_PORT}"
  echo "Password:     ${SS_PASSWORD}"
  echo "Method:       ${SS_METHOD}"
  echo "Service:      ${SS_SERVICE_NAME}.service"
  echo "Config file:  ${SS_CONFIG_FILE}"
  echo "Sysctl file:  ${SYSCTL_FILE}"
  echo
  echo "🔓 Human-readable (server):"
  echo "  ${human}"
  echo
  echo "📌 Client local port (set in your Shadowsocks client):"
  echo "  ${SS_LOCAL_PORT}"
  echo
  echo "🔗 Import link (ss://):"
  echo "  ${link}"
  echo
  echo "📄 Client JSON example:"
  cat <<EOF
{
  "server": "${ip}",
  "server_port": ${SS_PORT},
  "local_address": "127.0.0.1",
  "local_port": ${SS_LOCAL_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}"
}
EOF
  echo
  echo "Useful checks:"
  echo "  systemctl status ${SS_SERVICE_NAME} --no-pager"
  echo "  journalctl -u ${SS_SERVICE_NAME} -e --no-pager"
  echo "  ss -lntup | grep ${SS_PORT}"
  echo "  sysctl net.ipv4.ip_forward"
  echo "=========================================================="
}

main() {
  need_root
  detect_ubuntu

  install_deps
  install_shadowsocks
  create_user
  write_config
  write_systemd
  apply_sysctl
  configure_firewall
  print_summary
}

main "$@"
