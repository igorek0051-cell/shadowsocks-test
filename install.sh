```bash
#!/usr/bin/env bash
set -euo pipefail

# ===================== SETTINGS (override via env) =====================
SS_PORT="${SS_PORT:-443}"
SS_LOCAL_PORT=1080                    # client-side only (some clients require it)
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n')}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_USER="${SS_USER:-shadowsocks}"

SS_CONFIG_DIR="/etc/shadowsocks-libev"
SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"
SS_SERVICE_NAME="shadowsocks-libev"

SYSCTL_FILE="/etc/sysctl.d/99-shadowsocks.conf"
LIMITS_FILE="/etc/security/limits.d/99-shadowsocks.conf"

ENABLE_NAT="${ENABLE_NAT:-0}"         # set to 1 to enable iptables MASQUERADE
# ======================================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }

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
  info "Installing dependencies..."
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl ufw openssl software-properties-common jq iproute2
}

install_shadowsocks() {
  info "Installing shadowsocks-libev..."
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

read_existing_port_if_any() {
  [[ -f "$SS_CONFIG_FILE" ]] && jq -r '.server_port // empty' "$SS_CONFIG_FILE" 2>/dev/null || true
}

write_config() {
  info "Writing server config..."
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
  info "Installing systemd service..."
  cat > /etc/systemd/system/${SS_SERVICE_NAME}.service <<EOF
[Unit]
Description=Shadowsocks Server
After=network-online.target
Wants=network-online.target

[Service]
User=${SS_USER}
Group=${SS_USER}
ExecStart=/usr/bin/ss-server -c ${SS_CONFIG_FILE} -u
Restart=on-failure
RestartSec=2

# High-load friendly limits
LimitNOFILE=1048576

# Some hardening
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

apply_sysctl_base() {
  info "Applying base sysctl (BBR + ip_forward)..."
  cat > "$SYSCTL_FILE" <<EOF
# Queue + congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Forwarding (needed for routing/NAT use-cases)
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
}

# ---- NEW: TCP/UDP performance tuning (safe defaults) ----
apply_sysctl_tcp_udp_tuning() {
  info "Applying TCP/UDP tuning sysctl..."

  cat >> "$SYSCTL_FILE" <<'EOF'

# --- TCP tuning ---
# Allow bigger socket buffers for high-BDP links
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=262144
net.core.wmem_default=262144

# TCP autotuning ranges: min default max
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864

# Larger backlog queues
net.core.netdev_max_backlog=250000
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=16384

# Faster recycle of TIME-WAIT sockets (safe setting)
net.ipv4.tcp_fin_timeout=15

# Enable MTU probing (helps with PMTU blackholes)
net.ipv4.tcp_mtu_probing=1

# --- UDP tuning ---
# Increase UDP memory pressure thresholds (kernel pages)
net.ipv4.udp_mem=65536 131072 262144

# Minimum per-socket UDP buffer sizes
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
EOF

  sysctl --system >/dev/null || true
}

# ---- NEW: Increase per-user file descriptor limits (helps high conn counts) ----
apply_limits_nofile() {
  info "Applying nofile limits..."
  cat > "$LIMITS_FILE" <<EOF
${SS_USER} soft nofile 1048576
${SS_USER} hard nofile 1048576
EOF
}
# --------------------------------------------------------

configure_firewall() {
  local old_port="$1"

  info "Configuring UFW (open SSH 22 + SS port)..."
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

  info "Enabling NAT (iptables MASQUERADE)..."
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
  info "Health checks..."
  systemctl is-active --quiet "${SS_SERVICE_NAME}.service" || warn "Service not active"
  ss -lntup | grep -q ":${SS_PORT}" || warn "Port ${SS_PORT} not listening"
  ufw status | grep -qE "\\b${SS_PORT}/tcp\\b" || warn "UFW tcp rule missing for ${SS_PORT}"
  ufw status | grep -qE "\\b${SS_PORT}/udp\\b" || warn "UFW udp rule missing for ${SS_PORT}"
}

print_summary() {
  local ip
  ip="$(get_public_ip)"
  echo
  echo "==================== INSTALL COMPLETE ===================="
  echo "Server IP:    ${ip}"
  echo "Server Port:  ${SS_PORT}"
  echo "Method:       ${SS_METHOD}"
  echo "Password:     ${SS_PASSWORD}"
  echo "Service:      ${SS_SERVICE_NAME}.service"
  echo
  echo "🔓 Human-readable:"
  echo "  $(generate_ss_human)"
  echo
  echo "🔗 ss:// link:"
  echo "  $(generate_ss_link)"
  echo
  echo "📌 Client settings (some clients require local_port):"
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
  echo "=========================================================="
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

  apply_sysctl_base
  apply_sysctl_tcp_udp_tuning
  apply_limits_nofile

  setup_iptables_masquerade
  configure_firewall "$old_port"

  systemctl restart "${SS_SERVICE_NAME}.service"
  health_checks
  print_summary
}

main "$@"
```
