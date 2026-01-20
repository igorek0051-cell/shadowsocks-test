#!/usr/bin/env bash
set -euo pipefail

#############################################
# Shadowsocks-libev Auto Installer (Ubuntu)
# Features:
# 1) UFW open TCP+UDP for SS port + 22/tcp
# 2) ss:// link generator
# 3) Random 10-char password (letters+digits)
# 4) Applies settings + restarts SS service
# 5) Client local port 1080 (shown in summary; NOT in server config)
# 6) net.ipv4.ip_forward=1
# 7) TCP/UDP optimizations (BBR, fq, buffers, etc.)
# 8) Does NOT include local_port in server config
# 9) Progress spinner
# 10) Prints a summary at end
# + Auto-detect best cipher
# + Try port 443, fallback automatically if busy
#############################################

# -------- User-tunable (env overrides) --------
SS_PORT="${SS_PORT:-}"                 # empty => auto choose (443 then fallback)
SS_METHOD="${SS_METHOD:-auto}"         # auto => detect best supported
SS_MODE="${SS_MODE:-tcp_and_udp}"      # tcp_only | udp_only | tcp_and_udp
SS_TIMEOUT="${SS_TIMEOUT:-300}"
SS_FAST_OPEN="${SS_FAST_OPEN:-true}"   # true/false
SS_LOCAL_PORT="${SS_LOCAL_PORT:-1080}" # client local port (not stored on server)

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
  local msg="${1:-Working...}"
  printf "%b%s%b " "${C_CYAN}" "${msg}" "${C_RESET}"
  (
    local spin='-\|/'
    local i=0
    while true; do
      i=$(( (i + 1) % 4 ))
      printf "\b%s" "${spin:$i:1}"
      sleep 0.1
    done
  ) &
  _spinner_pid=$!
}

stop_spinner() {
  if [[ -n "${_spinner_pid}" ]] && kill -0 "${_spinner_pid}" 2>/dev/null; then
    kill "${_spinner_pid}" 2>/dev/null || true
    wait "${_spinner_pid}" 2>/dev/null || true
    _spinner_pid=""
    printf "\b%bDONE%b\n" "${C_GREEN}" "${C_RESET}"
  else
    echo
  fi
}

run_step() {
  local title="$1"
  shift
  start_spinner "${title}"
  ( "$@" ) >/tmp/ss_install.log 2>&1 || {
    stop_spinner
    echo -e "${C_RED}FAILED${C_RESET}: ${title}"
    echo "---- Last 200 lines of log ----"
    tail -n 200 /tmp/ss_install.log || true
    exit 1
  }
  stop_spinner
}

# -------- Logging --------
log()  { echo -e "[INFO] $*"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
die()  { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; exit 1; }

# -------- Helpers --------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root: sudo bash $0"
  fi
}

is_ubuntu() {
  [[ -r /etc/os-release ]] && grep -qi "ubuntu" /etc/os-release
}

rand_password_10() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10
}

get_public_ip() {
  local ip=""
  ip="$(curl -4fsS https://api.ipify.org 2>/dev/null || true)"
  [[ -z "${ip}" ]] && ip="$(curl -4fsS https://ifconfig.co/ip 2>/dev/null || true)"
  [[ -z "${ip}" ]] && ip="$(curl -4fsS https://icanhazip.com 2>/dev/null | tr -d '\n' || true)"
  echo "${ip}"
}

base64_urlsafe_nopad() {
  base64 -w0 | tr '+/' '-_' | tr -d '='
}

gen_ss_link() {
  # SIP002 basic: ss://BASE64(method:password@host:port)
  local method="$1" password="$2" host="$3" port="$4"
  local userinfo="${method}:${password}@${host}:${port}"
  local b64
  b64="$(printf '%s' "${userinfo}" | base64_urlsafe_nopad)"
  printf 'ss://%s' "${b64}"
}

have_aesni() {
  [[ -r /proc/cpuinfo ]] && grep -qiE '(^flags|Features).*\\baes\\b' /proc/cpuinfo
}

supported_methods() {
  command -v ss-server >/dev/null 2>&1 || return 1
  local out=""
  out="$(ss-server -h 2>/dev/null || true)"
  [[ -z "$out" ]] && out="$(ss-server --help 2>/dev/null || true)"
  echo "$out" | tr ' ' '\n' | tr ',' '\n' | tr -d '\r' \
    | grep -E '^(aes-(128|192|256)-(gcm|cfb|ctr)|chacha20-ietf-poly1305|chacha20-poly1305|xchacha20-ietf-poly1305|2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305)$' \
    | sort -u
}

pick_best_cipher() {
  # Keep explicit method if user set it (not auto)
  if [[ "${SS_METHOD:-auto}" != "auto" && -n "${SS_METHOD:-}" ]]; then
    echo "${SS_METHOD}"
    return 0
  fi

  local methods=""
  methods="$(supported_methods || true)"

  if have_aesni; then
    local pref=( "aes-256-gcm" "aes-128-gcm" "chacha20-ietf-poly1305" "chacha20-poly1305" )
    for m in "${pref[@]}"; do
      if [[ -n "$methods" ]] && echo "$methods" | grep -qx "$m"; then
        echo "$m"; return 0
      fi
    done
    echo "aes-256-gcm"; return 0
  else
    local pref=( "chacha20-ietf-poly1305" "chacha20-poly1305" "aes-128-gcm" "aes-256-gcm" )
    for m in "${pref[@]}"; do
      if [[ -n "$methods" ]] && echo "$methods" | grep -qx "$m"; then
        echo "$m"; return 0
      fi
    done
    echo "chacha20-ietf-poly1305"; return 0
  fi
}

ensure_tools() {
  # Install needed base tools (git not required; ss checks require iproute2)
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates ufw iproute2
}

install_shadowsocks() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y shadowsocks-libev
}

port_is_listening() {
  local port="$1"
  # Normalize [::]:443 -> :: :443 by stripping brackets
  ss -lntu 2>/dev/null | awk '{print $5}' | sed 's/\[//g; s/\]//g' | grep -E "[:.]${port}$" -q
}

pick_free_port() {
  local candidates=(443 8388 8443 8090)
  local p
  for p in "${candidates[@]}"; do
    if ! port_is_listening "${p}"; then
      echo "${p}"
      return 0
    fi
  done

  for _ in $(seq 1 80); do
    p=$(( 20000 + RANDOM % 40001 ))
    if ! port_is_listening "${p}"; then
      echo "${p}"
      return 0
    fi
  done

  die "Could not find a free port."
}

select_port() {
  # If SS_PORT empty -> try 443 else fallback
  if [[ -z "${SS_PORT}" ]]; then
    if port_is_listening 443; then
      SS_PORT="$(pick_free_port)"
      warn "Port 443 is busy. Selected free port: ${SS_PORT}"
    else
      SS_PORT="443"
      log "Port 443 is free. Using: ${SS_PORT}"
    fi
  else
    # User provided port; if busy, fallback
    if port_is_listening "${SS_PORT}"; then
      warn "Port ${SS_PORT} appears busy. Selecting a free port..."
      SS_PORT="$(pick_free_port)"
      warn "Selected free port: ${SS_PORT}"
    fi
  fi
}

apply_sysctl_tuning() {
  cat > "${SYSCTL_TUNE_FILE}" <<'EOF'
# Shadowsocks tuning

# Enable IPv4 forwarding
net.ipv4.ip_forward=1

# Congestion control (BBR) + fair queueing
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Queue / backlog
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384

# TCP performance
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=10
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1

# Buffers (TCP/UDP)
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
EOF

  sysctl --system >/dev/null
}

configure_shadowsocks_server() {
  local password="$1"

  mkdir -p "${SS_CONF_DIR}"

  # IMPORTANT: do NOT put local_port here (server config only)
  cat > "${SS_CONF_FILE}" <<EOF
{
  "server":["0.0.0.0","::0"],
  "server_port": ${SS_PORT},
  "password": "${password}",
  "timeout": ${SS_TIMEOUT},
  "method": "${SS_METHOD}",
  "mode": "${SS_MODE}",
  "fast_open": ${SS_FAST_OPEN}
}
EOF

  systemctl daemon-reload
  systemctl enable shadowsocks-libev >/dev/null 2>&1 || true
  systemctl restart shadowsocks-libev
}

configure_ufw() {
  ufw allow 22/tcp
  ufw allow "${SS_PORT}"/tcp
  ufw allow "${SS_PORT}"/udp
  ufw --force enable
}

verify_service_and_port() {
  systemctl --no-pager --full status shadowsocks-libev >/dev/null
  ss -lntup | sed 's/\[//g; s/\]//g' | grep -E ":(\b${SS_PORT}\b)" >/dev/null
}

# -------- Main --------
main() {
  require_root
  if ! is_ubuntu; then
    warn "This script is intended for Ubuntu. Continuing anyway..."
  fi

  echo -e "${C_CYAN}Shadowsocks-libev Auto Installer${C_RESET}"
  echo "----------------------------------------"

  run_step "0/7 Installing base tools (curl, ufw, iproute2)..." ensure_tools
  run_step "1/7 Checking port 443 availability + selecting port..." bash -c 'true'
  select_port

  run_step "2/7 Installing shadowsocks-libev..." install_shadowsocks

  log "Auto-detecting best supported encryption method..."
  SS_METHOD="$(pick_best_cipher)"
  log "Selected method: ${SS_METHOD}"

  local password
  password="$(rand_password_10)"

  run_step "3/7 Applying TCP/UDP optimizations + enabling IP forwarding..." apply_sysctl_tuning
  run_step "4/7 Configuring Shadowsocks server + restarting service..." configure_shadowsocks_server "${password}"
  run_step "5/7 Configuring UFW rules (22 + SS TCP/UDP)..." configure_ufw
  run_step "6/7 Verifying service and listening port..." verify_service_and_port

  local public_ip
  public_ip="$(get_public_ip)"
  [[ -z "${public_ip}" ]] && public_ip="YOUR_SERVER_IP"

  local ss_link
  ss_link="$(gen_ss_link "${SS_METHOD}" "${password}" "${public_ip}" "${SS_PORT}")"

  echo
  echo -e "${C_GREEN}================ SUMMARY ================${C_RESET}"
  echo -e "Server IP:        ${C_CYAN}${public_ip}${C_RESET}"
  echo -e "Server Port:      ${C_CYAN}${SS_PORT}${C_RESET}"
  echo -e "Method:           ${C_CYAN}${SS_METHOD}${C_RESET}"
  echo -e "Password:         ${C_CYAN}${password}${C_RESET}"
  echo -e "Mode:             ${C_CYAN}${SS_MODE}${C_RESET}"
  echo -e "Server config:    ${C_CYAN}${SS_CONF_FILE}${C_RESET}"
  echo
  echo -e "Shadowsocks link: ${C_CYAN}${ss_link}${C_RESET}"
  echo
  echo -e "${C_YELLOW}Client note:${C_RESET} Set your client local port to ${C_CYAN}${SS_LOCAL_PORT}${C_RESET} (NOT stored on server)."
  echo -e "Example client config (for your device):"
  cat <<EOF
{
  "server": "${public_ip}",
  "server_port": ${SS_PORT},
  "local_address": "127.0.0.1",
  "local_port": ${SS_LOCAL_PORT},
  "password": "${password}",
  "timeout": ${SS_TIMEOUT},
  "method": "${SS_METHOD}",
  "mode": "${SS_MODE}"
}
EOF
  echo
  echo -e "${C_GREEN}Check service:${C_RESET}  systemctl status shadowsocks-libev"
  echo -e "${C_GREEN}Restart service:${C_RESET} systemctl restart shadowsocks-libev"
  echo -e "${C_GREEN}UFW status:${C_RESET}     ufw status verbose"
  echo -e "${C_GREEN}=========================================${C_RESET}"
}

main "$@"

