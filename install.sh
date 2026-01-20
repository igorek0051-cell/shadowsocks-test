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
# ====================================================

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "Run as root"; }

install_deps() {
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl ufw openssl software-properties-common
}

install_shadowsocks() {
  if ! apt-cache show shadowsocks-libev >/dev/null 2>&1; then
    add-apt-repository -y ppa:max-c-lv/shadowsocks-libev
    apt-get update -y
  fi
  apt-get install -y shadowsocks-libev
}

create_user() {
  id -u "$SS_USER" >/dev/null 2>&1 || \
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SS_USER"
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
}

write_systemd() {
  cat > /etc/systemd/system/${SS_SERVICE_NAME}.service <<EOF
[Unit]
Description=Shadowsocks Server
After=network-online.target

[Service]
User=${SS_USER}
ExecStart=/usr/bin/ss-server -c ${SS_CONFIG_FILE} -u
Restart=on-failure
LimitNOFILE=1048576

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SS_SERVICE_NAME}"
}

enable_bbr() {
  cat > /etc/sysctl.d/99-shadowsocks.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null || true
}

configure_firewall() {
  ufw --force enable >/dev/null || true
  ufw allow "${SS_PORT}/tcp"
  ufw allow "${SS_PORT}/udp"
}

get_public_ip() {
  curl -fsS https://api.ipify.org || echo YOUR_SERVER_IP
}

generate_ss_human() {
  echo "${SS_METHOD}:${SS_PASSWORD}@$(get_public_ip):${SS_PORT}"
}

generate_ss_link() {
  printf '%s' "$(generate_ss_human)" | base64 | tr -d '\n=' | sed 's/^/ss:\/\//'
}

print_summary() {
  echo
  echo "==================== INSTALL COMPLETE ===================="
  echo
  echo "🔓 Human-readable (server side):"
  echo "  $(generate_ss_human)"
  echo
  echo "📌 Client local port (SOCKS5):"
  echo "  ${SS_LOCAL_PORT}"
  echo
  echo "🔗 Import link:"
  echo "  $(generate_ss_link)"
  echo
  echo "📄 Client JSON example:"
  cat <<EOF
{
  "server": "$(get_public_ip)",
  "server_port": ${SS_PORT},
  "local_address": "127.0.0.1",
  "local_port": ${SS_LOCAL_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}"
}
EOF
  echo
  echo "=========================================================="
}

main() {
  need_root
  install_deps
  install_shadowsocks
  create_user
  write_config
  write_systemd
  enable_bbr
  configure_firewall
  print_summary
}

main "$@"
