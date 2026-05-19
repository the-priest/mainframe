#!/usr/bin/env bash
# mainframe uninstaller
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "needs root."
  exit 1
fi

echo "removing mainframe..."
rm -f /usr/local/bin/mainframe
rm -f /usr/local/bin/mainframe-launch
rm -f /usr/share/applications/mainframe.desktop
rm -f /usr/share/icons/hicolor/scalable/apps/mainframe.svg

gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database 2>/dev/null || true

echo "done."
