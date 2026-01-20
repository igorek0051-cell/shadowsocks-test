#!/usr/bin/env bash
set -euo pipefail

# ===================== SETTINGS (override via env) =====================
SS_PORT="${SS_PORT:-443}"
SS_LOCAL_PORT=1080                    # REQUIRED by many clients (client-side only)
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n')}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
SS_USER="${SS_USER:-shadowsocks}"

SS_CONFIG_DIR="/etc/shadowsocks-libev"
SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"
SS_SERVICE_NAME="shadowsocks-libev"
SYSCTL_FILE="/etc/sysctl.d/99-shadowsocks.conf"

ENABLE_NAT="${ENABLE_NAT:-0}"         # set to 1 to enable iptables MASQUERADE
# ======================================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }

need_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

detect_ubuntu() {
  [[ -r /etc/os-release ]] || die "Cannot detect OS."
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
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SS
