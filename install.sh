```bash
#!/usr/bin/env bash
set -euo pipefail

# ===================== SETTINGS (override via env) =====================
SS_PORT="${SS_PORT:-443}"
SS_LOCAL_PORT=1080                    # client-side only (some clients require it)
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_USER="${SS_USER:-shadowsocks}"

SS_CONFIG_DIR="/etc/shadowsocks-libev"
SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"

# Use a UNIQUE service name to avoid conflicts with distro scripts
SS_SERVICE_NAME="ss-server-custom"

SYSCTL_FILE="/etc/sysctl.d/99-shadowsocks.conf"
ENABLE_NAT="${ENABLE_NAT:-0}"         # set to 1 to enable iptables MASQUERADE
# ======================================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
log()  { echo "[install] $*"; }

# 10-char password (letters+digits only)
generate_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10
}

# Generate password if not provided
SS_PASSWORD="${SS_PASSWORD:-$(generate_password)}"

need_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

detect_ubuntu() {
  [[ -r /etc/os-release ]] || die "Cannot detect OS."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Ubuntu only."
}

validate_settings() {
  [[ "$SS_PORT" =~ ^[0-9]+$ ]] || die "SS_PORT must be numeric."
  (( SS_PORT >= 1 && SS_PORT <= 65535 )) || die "SS_PORT must be 1..65535."
  [[ -n "$SS_PASSWORD" ]] || die "SS_PASSWORD empty."
  [[ -n "$SS_METHOD" ]] || die "SS_METHOD empty."
}

install_deps() {
  log "Installing dependencies..."
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl ufw openssl software-properties-common jq iproute2
}

install_shadowsocks() {
  log "Installing shadowsocks-libev..."
  if ! apt-cache show shadowsocks-libev >/dev/null 2>&1; then
    add-apt-repository -y ppa:max-c-lv/shadowsocks-libev
    apt-get update -y
  fi
  apt-get install -y shadowsocks-libev
}

create_user() {
  if ! id -u "$SS_USER" >/dev/null 2>&1; then
    log "Creating system user: ${SS_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SS_USER"
  fi
}

read_existing_port_if_any() {
  [[ -f "$SS_CONFIG_FILE" ]] && jq -r '.server_port // empty' "$SS_CONFIG_FILE" 2>/dev/null || true
}

write_config() {
  log "Writing server config to ${SS_CONFIG_FILE}"
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

  # Allow the service user to read the config
  chown -R "${SS_USER}:${SS_USER}" "$SS_CONFIG_DIR"
  chmod 750 "$SS_CONFIG_DIR"
  chmod 640 "$SS_CONFIG_FILE"
}

write_systemd() {
  log "Installing systemd service: ${SS_SERVICE_NAME}.service"
  cat > "/etc/systemd/system/${SS_SERVICE_NAME}.service" <<EOF
[Unit]
Description=Shadowsocks Server (custom)
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
  log "Applying sysctl tuning (BBR + ip_forward)..."
  cat > "$SYSCTL_FILE" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
}

configure_firewall() {
  local old_port="$1"

  log "Configuring UFW (allow SSH 22 + SS port)..."
  ufw allow 22/tcp >/dev/null
  ufw allow "${SS_PORT}/tcp" >/dev/null
  ufw allow "${SS_PORT}/udp" >/dev/null

  if [[ -n "$old_port" && "$old_port" != "$SS_PORT" ]]; then
    ufw delete allow "${old_port}/tcp" >/dev/null 2>&1 || true
    ufw delete allow "${old_port}/udp" >/dev/null 2>&1 || true
  fi

  ufw --force enable >/dev/null || true
}

setup_iptables_masquerade() {
  [[ "$ENABLE_NAT" == "1" ]] || return 0
  log "Enabling NAT (iptables MASQUERADE)..."

  local wan_if
  wan_if="$(ip route | awk '/^default/ {print $5; exit}')"
  [[ -n "$wan_if" ]] || die "Cannot detect outbound interface."

  apt-get install -y iptables-persistent >/dev/null
  iptables -t nat -C POSTROUTING -o "$wan_if" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$wan_if" -j MASQUERADE
  iptables-save > /etc/iptables/rules.v4
}

get_public_ip() {
  curl -fsS https://api.ipify.org || echo YOUR_SERVER_IP
}

generate_ss_human() {
  echo "${SS_METHOD}:${SS_PASSWORD}@$(get_public_ip):${SS_PORT}"
}

# Keep base64 padding for compatibility
generate_ss_link() {
  echo "ss://$(printf '%s' "$(generate_ss_human)" | base64 | tr -d '\n')"
}

health_checks() {
  log "Health checks..."
  systemctl is-active --quiet "${SS_SERVICE_NAME}.service" || die "Service not running. Check: journalctl -u ${SS_SERVICE_NAME} -e --no-pager"

  if ss -lntup | grep -q ":${SS_PORT}"; then
    log "Listening OK on :${SS_PORT}"
  else
    die "Service active but port :${SS_PORT} not listening. Check conflicts: ss -lntup | grep ':${SS_PORT}'"
  fi
}

print_summary() {
  local ip
  ip="$(get_public_ip)"
  echo
  echo "==================== DONE ===================="
  echo "Server IP:    ${ip}"
  echo "Server Port:  ${SS_PORT}"
  echo "Method:       ${SS_METHOD}"
  echo "Password:     ${SS_PASSWORD}"
  echo "Service:      ${SS_SERVICE_NAME}.service"
  echo
  echo "Human-readable:"
  echo "  $(generate_ss_human)"
  echo
  echo "ss:// link:"
  echo "  $(generate_ss_link)"
  echo
  echo "Client JSON (includes local_port=1080 for strict clients):"
  cat <<EOF
{
  "server": "${ip}",
  "server_port": ${SS_PORT},
  "local_port": ${SS_LOCAL_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}"
}
EOF
  echo
  echo "If next you want:"
  echo "  NAT rules (iptables / nftables)"
  echo "================================================"
}

main() {
  need_root
  detect_ubuntu
  validate_settings

  install_deps
  install_shadowsocks
  create_user

  local old_port
  old_port="$(read_existing_port_if_any)"

  write_config
  write_systemd
  apply_sysctl
  setup_iptables_masquerade
  configure_firewall "$old_port"

  systemctl restart "${SS_SERVICE_NAME}.service"
  health_checks
  print_summary
}

main "$@"
```
