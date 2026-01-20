#!/usr/bin/env bash
set -euo pipefail

# ===================== DEFAULTS =====================
SS_PORT="${SS_PORT:-8388}"
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n')}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_USER="${SS_USER:-shadowsocks}"
SS_CONFIG_DIR="/etc/shadowsocks-libev"
SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"
SS_SERVICE_NAME="shadowsocks-libev"
# ====================================================

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  [[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"
}

detect_ubuntu() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || die "This script supports Ubuntu only (detected: ${ID:-unknown})."
  else
    die "Cannot detect OS (missing /etc/os-release)."
  fi
}

install_deps() {
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl wget ufw jq openssl software-properties-common
}

install_shadowsocks() {
  # Try official repo first
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
  "timeout": 300,
  "method": "${SS_METHOD}",
  "fast_open": true,
  "mode": "tcp_and_udp"
}
EOF
  chmod 600 "$SS_CONFIG_FILE"
  chown -R root:root "$SS_CONFIG_DIR"
}

write_systemd() {
  cat > /etc/systemd/system/${SS_SERVICE_NAME}.service <<EOF
[Unit]
Description=Shadowsocks-libev Server
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

enable_bbr() {
  cat > /etc/sysctl.d/99-shadowsocks-tuning.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null || true
}

configure_firewall() {
  # Enable UFW if present (we install it earlier)
  ufw --force enable >/dev/null || true
  ufw allow "${SS_PORT}/tcp" >/dev/null
  ufw allow "${SS_PORT}/udp" >/dev/null
}

print_summary() {
  local public_ip
  public_ip="$(curl -fsS https://api.ipify.org || true)"

  echo
  echo "==================== INSTALL COMPLETE ===================="
  echo "Server IP:    ${public_ip:-<your_server_ip>}"
  echo "Server Port:  ${SS_PORT}"
  echo "Password:     ${SS_PASSWORD}"
  echo "Method:       ${SS_METHOD}"
  echo "Service:      ${SS_SERVICE_NAME}.service"
  echo "Config file:  ${SS_CONFIG_FILE}"
  echo
  echo "Client JSON:"
  cat <<EOF
{
  "server": "${public_ip:-YOUR_SERVER_IP}",
  "server_port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}"
}
EOF
  echo "=========================================================="
  echo
  echo "Useful checks:"
  echo "  systemctl status ${SS_SERVICE_NAME} --no-pager"
  echo "  journalctl -u ${SS_SERVICE_NAME} -e --no-pager"
  echo "  ss -lntup | grep ${SS_PORT}"
}

main() {
  need_root
  detect_ubuntu

  echo "[1/8] Installing dependencies..."
  install_deps

  echo "[2/8] Installing shadowsocks-libev..."
  install_shadowsocks

  echo "[3/8] Creating system user..."
  create_user

  echo "[4/8] Writing config..."
  write_config

  echo "[5/8] Setting up systemd..."
  write_systemd

  echo "[6/8] Enabling BBR..."
  enable_bbr

  echo "[7/8] Configuring firewall (UFW)..."
  configure_firewall

  echo "[8/8] Done."
  print_summary
}

main "$@"