#!/usr/bin/env bash
set -euo pipefail

########################################
# Shadowsocks auto-install (Ubuntu)
# Additions:
# - Auto-detect best method (AES-NI -> aes-256-gcm; else chacha20-ietf-poly1305)
# - Optional port 443 check + automatic fallback
########################################

# --------- User-tunable defaults ----------
# If SS_PORT is NOT provided, script tries 443 then falls back automatically
SS_PORT="${SS_PORT:-}"                      # empty -> auto choose
SS_METHOD="${SS_METHOD:-auto}"              # auto -> detect
SS_TIMEOUT="${SS_TIMEOUT:-300}"
SS_FAST_OPEN="${SS_FAST_OPEN:-true}"        # TCP Fast Open (server side)
SS_MODE="${SS_MODE:-tcp_and_udp}"           # tcp_only | udp_only | tcp_and_udp

# Client-side local port (NOT written into server config)
SS_LOCAL_PORT="${SS_LOCAL_PORT:-1080}"

# Config paths
SS_CONF_DIR="/etc/shadowsocks-libev"
SS_CONF_FILE="${SS_CONF_DIR}/config.json"
SYSCTL_TUNE_FILE="/etc/sysctl.d/99-shadowsocks-tuning.conf"

# --------- Colors ----------
C_RESET="\033[0m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_CYAN="\033[36m"

# --------- Spinner / progress ----------
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
    echo "---- Last 160 lines of log ----"
    tail -n 160 /tmp/ss_install.log || true
    exit 1
  }
  stop_spinner
}

# --------- Helpers ----------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${C_RED}ERROR:${C_RESET} Please run as root (use sudo)."
    exit 1
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
  local method="$1"
  local password="$2"
  local host="$3"
  local port="$4"
  local userinfo="${method}:${password}@${host}:${port}"
  local b64
  b64="$(printf '%s' "${userinfo}" | base64_urlsafe_nopad)"
  printf 'ss://%s' "${b64}"
}

have_aesni() {
  # Detect AES-NI on x86/x86_64
  if [[ -r /proc/cpuinfo ]] && grep -qiE '(^flags|Features).*\\baes\\b' /proc/cpuinfo; then
    return 0
  fi
  return 1
}

detect_best_method() {
  # Only decides if SS_METHOD=auto
  # Rule:
  # - AES-NI present -> aes-256-gcm
  # - else -> chacha20-ietf-poly1305 (usually better on non-AES CPUs)
  if have_aesni; then
    echo "aes-256-gcm"
  else
    echo "chacha20-ietf-poly1305"
  fi
}

port_is_listening() {
  local port="$1"
  # If any process already listening on TCP or UDP port
  ss -lntu 2>/dev/null | awk '{print $5}' | grep -E "[:.]${port}$" -q
}

pick_free_port() {
  # Preference order: 443 -> 8388 -> 8443 -> 8090 -> random free (20000-60000)
  local candidates=(443 8388 8443 8090)
  local p
  for p in "${candidates[@]}"; do
    if ! port_is_listening "${p}"; then
      echo "${p}"
      return 0
    fi
  done

  # Random search
  for _ in $(seq 1 80); do
    p=$(( 20000 + RANDOM % 40001 ))
    if ! port_is_listening "${p}"; then
      echo "${p}"
      return 0
    fi
  done

  echo -e "${C_RED}ERROR:${C_RESET} Could not find a free port."
  exit 1
}

select_server_port() {
  # If SS_PORT empty -> prefer 443, else fallback to free port
  if [[ -z "${SS_PORT}" ]]; then
    if port_is_listening 443; then
      SS_PORT="$(pick_free_port)"
    else
      SS_PORT="443"
    fi
    return 0
  fi

  # If user explicitly sets SS_PORT, keep it but warn if busy
  if port_is_listening "${SS_PORT}"; then
    echo -e "${C_YELLOW}Warning:${C_RESET} Port ${SS_PORT} appears busy. Trying to pick a free port..."
    SS_PORT="$(pick_free_port)"
  fi
}

# --------- Steps ----------
install_packages() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y shadowsocks-libev ufw curl ca-certificates
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

configure_shadowsocks() {
  local password="$1"

  mkdir -p "${SS_CONF_DIR}"

  # IMPORTANT: server config does NOT contain local_port
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
  systemctl --no-pager --full status shadowsocks-libev >/dev/null
}

configure_ufw() {
  ufw allow 22/tcp
  ufw allow "${SS_PORT}"/tcp
  ufw allow "${SS_PORT}"/udp
  ufw --force enable
}

verify_port_listening() {
  ss -lntup | grep -E ":(\b${SS_PORT}\b)" >/dev/null
}

# --------- Main ----------
main() {
  require_root
  if ! is_ubuntu; then
    echo -e "${C_YELLOW}Warning:${C_RESET} Script is intended for Ubuntu. Continuing anyway..."
  fi

  echo -e "${C_CYAN}Shadowsocks auto-install for Ubuntu${C_RESET}"
  echo "------------------------------------"

  run_step "0/7 Checking port 443 availability + selecting port..." select_server_port

  # Detect method if auto
  if [[ "${SS_METHOD}" == "auto" ]]; then
    SS_METHOD="$(detect_best_method)"
  fi

  local password
  password="$(rand_password_10)"
  ${SS_PORT} = '430'
  run_step "1/7 Installing packages (shadowsocks-libev, ufw, curl)..." install_packages
  run_step "2/7 Applying TCP/UDP optimizations + enabling IP forwarding..." apply_sysctl_tuning
  run_step "3/7 Configuring Shadowsocks server + restarting service..." configure_shadowsocks "${password}"
  run_step "4/7 Configuring UFW rules (22 + SS TCP/UDP)..." configure_ufw
  run_step "5/7 Verifying port is listening..." verify_port_listening

  local public_ip
  public_ip="$(get_public_ip)"
  if [[ -z "${public_ip}" ]]; then
    public_ip="YOUR_SERVER_IP"
  fi

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
  echo -e "${C_YELLOW}Client note:${C_RESET} Set your client local port to ${C_CYAN}${SS_LOCAL_PORT}${C_RESET} (not stored on server)."
  echo -e "Example client config snippet:"
  cat <<EOF
{
  "server": "${public_ip}",
  "server_port": ${SS_PORT},
  "password": "${password}",
  "timeout": ${SS_TIMEOUT},
  "method": "${SS_METHOD}",
  "mode": "${SS_MODE}"
}
EOF
  echo
  echo -e "${C_GREEN}Service:${C_RESET} systemctl status shadowsocks-libev"
  echo -e "${C_GREEN}Restart:${C_RESET} systemctl restart shadowsocks-libev"
  echo -e "${C_GREEN}UFW status:${C_RESET} ufw status verbose"
  echo -e "${C_GREEN}=========================================${C_RESET}"
}

main "$@"
