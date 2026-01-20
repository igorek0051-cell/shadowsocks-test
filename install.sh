#!/usr/bin/env bash
set -euo pipefail

#############################################
# Shadowsocks-libev Auto Installer (Ubuntu)
#############################################

# -------- REQUIRED USER INPUT --------
: "${SS_PASSWORD:?ERROR: You must set SS_PASSWORD}"

# -------- User config (env override allowed) --------
SS_PORT="${SS_PORT:-}"                   # empty = auto (443 -> fallback)
SS_METHOD="${SS_METHOD:-aes-256-gcm}"
SS_MODE="${SS_MODE:-tcp_and_udp}"
SS_TIMEOUT="${SS_TIMEOUT:-300}"
SS_FAST_OPEN="${SS_FAST_OPEN:-true}"
SS_LOCAL_PORT="${SS_LOCAL_PORT:-1080}"   # client only

# -------- Paths --------
SS_CONF_DIR="/etc/shadowsocks-libev"
SS_CONF_FILE="${SS_CONF_DIR}/config.json"
SYSCTL_TUNE_FILE="/etc/sysctl.d/99-shadowsocks-tuning.conf"

# -------- Colors --------
C_RESET="\033[0m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_CYAN="\033[36m"

# -------- Spinner --------
_spinner_pid=""

start_spinner() {
  printf "%b%s%b " "${C_CYAN}" "$1" "${C_RESET}"
  (
    local spin='-\|/' i=0
    while true; do
      i=$(( (i + 1) % 4 ))
      printf "\b%s" "${spin:$i:1}"
      sleep 0.1
    done
  ) &
  _spinner_pid=$!
}

stop_spinner() {
  kill "${_spinner_pid}" 2>/dev/null || true
  wait "${_spinner_pid}" 2>/dev/null || true
  printf "\b%bDONE%b\n" "${C_GREEN}" "${C_RESET}"
}

run_step() {
  start_spinner "$1"
  shift
  ( "$@" ) >/tmp/ss_install.log 2>&1 || {
    stop_spinner
    echo -e "${C_RED}FAILED${C_RESET}"
    tail -n 100 /tmp/ss_install.log
    exit 1
  }
  stop_spinner
}

# -------- Helpers --------
require_root() {
  [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
}

get_public_ip() {
  curl -4fsS https://api.ipify.org || echo "YOUR_SERVER_IP"
}

base64_urlsafe() {
  base64 -w0 | tr '+/' '-_' | tr -d '='
}

gen_ss_link() {
  printf 'ss://%s' "$(printf '%s' "$1:$2@$3:$4" | base64_urlsafe)"
}

port_is_listening() {
  ss -lntu | sed 's/\[//g;s/\]//g' | grep -qE "[:.]$1$"
}

pick_free_port() {
  for p in 443 8388 8443 8090; do
    port_is_listening "$p" || { echo "$p"; return; }
  done
  while :; do
    p=$((20000 + RANDOM % 40000))
    port_is_listening "$p" || { echo "$p"; return; }
  done
}

# -------- Install steps --------
install_base() {
  apt update -y
  apt install -y curl ca-certificates ufw iproute2
}

install_shadowsocks() {
  apt install -y shadowsocks-libev
}

apply_sysctl() {
  cat > "$SYSCTL_TUNE_FILE" <<EOF
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_fastopen=3
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
EOF
  sysctl --system >/dev/null
}

configure_shadowsocks() {
  mkdir -p "$SS_CONF_DIR"
  cat > "$SS_CONF_FILE" <<EOF
{
  "server":["0.0.0.0","::0"],
  "server_port": $SS_PORT,
  "password": "$SS_PASSWORD",
  "timeout": $SS_TIMEOUT,
  "method": "$SS_METHOD",
  "mode": "$SS_MODE",
  "fast_open": $SS_FAST_OPEN
}
EOF
  systemctl enable shadowsocks-libev >/dev/null
  systemctl restart shadowsocks-libev
}

configure_ufw() {
  ufw allow 22/tcp
  ufw allow "$SS_PORT"/tcp
  ufw allow "$SS_PORT"/udp
  ufw --force enable
}

verify() {
  systemctl is-active --quiet shadowsocks-libev
  port_is_listening "$SS_PORT"
}

# -------- Main --------
main() {
  require_root

  run_step "0/7 Installing base packages..." install_base

  run_step "1/7 Selecting server port..." bash -c 'true'
  SS_PORT="${SS_PORT:-$(pick_free_port)}"

  run_step "2/7 Installing shadowsocks-libev..." install_shadowsocks

  run_step "3/7 Applying TCP/UDP tuning..." apply_sysctl
  run_step "4/7 Configuring Shadowsocks..." configure_shadowsocks
  run_step "5/7 Configuring firewall..." configure_ufw
  run_step "6/7 Verifying service..." verify

  IP="$(get_public_ip)"
  LINK="$(gen_ss_link "$SS_METHOD" "$SS_PASSWORD" "$IP" "$SS_PORT")"

  echo
  echo "=========== SUMMARY ==========="
  echo "Server IP:    $IP"
  echo "Server Port:  $SS_PORT"
  echo "Method:       $SS_METHOD"
  echo "Password:     (user-provided)"
  echo
  echo "Shadowsocks link:"
  echo "$LINK"
  echo
  echo "Client local port: $SS_LOCAL_PORT"
  echo "==============================="
}

main "$@"

