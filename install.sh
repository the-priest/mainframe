#!/usr/bin/env bash
# mainframe installer — detects OS and installs deps + desktop entry
set -e

G='\033[92m'; R='\033[91m'; Y='\033[93m'; C='\033[96m'; D='\033[2m'; X='\033[0m'

banner() {
  cat <<EOF
${G}
  __  __  ___ ___ _  _ ___ ___    _   __  __ ___
 |  \/  |/ _ \_ _| \| | __| _ \  /_\ |  \/  | __|
 | |\/| | (_) | || .\` | _||   / / _ \| |\/| | _|
 |_|  |_|\___/___|_|\_|_| |_|_\\_/_/ \_\_|  |_|___|
${X}${D} installer${X}

EOF
}

detect_env() {
  if [ -n "$PREFIX" ] && [ -d "$PREFIX/etc" ] && echo "$PREFIX" | grep -q "com.termux"; then
    echo "termux"; return
  fi
  if [ -d "/data/data/com.offsec.nethunter" ] || [ -f /etc/nethunter-version ]; then
    echo "nethunter"; return
  fi
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      kali|debian|ubuntu|parrot|raspbian|linuxmint) echo "debian"; return ;;
      arch|blackarch|manjaro|endeavouros)            echo "arch"; return ;;
      fedora|rhel|centos|rocky|almalinux)            echo "fedora"; return ;;
    esac
    case "$ID_LIKE" in
      *debian*) echo "debian"; return ;;
      *arch*)   echo "arch";   return ;;
      *fedora*|*rhel*) echo "fedora"; return ;;
    esac
  fi
  echo "unknown"
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${R}needs root. re-run with sudo.${X}"
    exit 1
  fi
}

install_debian() {
  echo -e "${C}>> apt: installing deps${X}"
  apt update -qq
  apt install -y python3 aircrack-ng wireless-tools iw iproute2 \
                 network-manager ieee-data policykit-1 procps
}

install_arch() {
  echo -e "${C}>> pacman: installing deps${X}"
  pacman -Sy --noconfirm --needed python aircrack-ng wireless_tools iw iproute2 \
                                   networkmanager polkit
  # ieee-data may not be in default repos
  echo -e "${D}note: install ieee-data manually for MAC vendor lookup${X}"
}

install_fedora() {
  echo -e "${C}>> dnf: installing deps${X}"
  dnf install -y python3 aircrack-ng wireless-tools iw iproute \
                 NetworkManager polkit
}

install_termux() {
  echo -e "${Y}termux detected.${X}"
  echo -e "${D}termux cannot run monitor mode without root.${X}"
  echo -e "${D}for phone use, install kali nethunter chroot and run this from there.${X}"
  pkg install -y python aircrack-ng iw 2>/dev/null || true
}

install_files() {
  local prefix="${1:-/usr/local}"
  echo -e "${C}>> installing to ${prefix}${X}"

  install -m 755 mainframe.py     "${prefix}/bin/mainframe"
  install -m 755 mainframe-launch "${prefix}/bin/mainframe-launch"

  if [ -d /usr/share/applications ]; then
    install -m 644 mainframe.desktop /usr/share/applications/mainframe.desktop
  fi
  if [ -d /usr/share/icons/hicolor ]; then
    install -D -m 644 icon.svg /usr/share/icons/hicolor/scalable/apps/mainframe.svg
    gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
  fi
  update-desktop-database 2>/dev/null || true
}

banner

ENV="$(detect_env)"
echo -e "${C}detected:${X} ${G}${ENV}${X}\n"

case "$ENV" in
  termux)
    install_termux
    install -m 755 mainframe.py     "$PREFIX/bin/mainframe"
    install -m 755 mainframe-launch "$PREFIX/bin/mainframe-launch"
    echo -e "\n${G}done.${X} run: ${C}mainframe${X}"
    echo -e "${Y}note:${X} termux cannot deauth without root. use nethunter chroot."
    exit 0
    ;;
  debian|nethunter)
    need_root
    install_debian
    install_files /usr/local
    ;;
  arch)
    need_root
    install_arch
    install_files /usr/local
    ;;
  fedora)
    need_root
    install_fedora
    install_files /usr/local
    ;;
  *)
    echo -e "${R}unknown OS.${X} install manually:"
    echo "  - python3, aircrack-ng, wireless-tools, iw, network-manager, ieee-data"
    echo "  - copy mainframe.py to /usr/local/bin/mainframe"
    exit 1
    ;;
esac

echo
echo -e "${G}${ENV} install complete.${X}"
echo -e "${D}run from terminal:${X}  sudo mainframe"
echo -e "${D}or launch from app menu (Mainframe).${X}"
