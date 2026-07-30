#!/usr/bin/env bash
# Set up the touchscreen kiosk on a Raspberry Pi (Debian + labwc/Wayland).
#
#   sudo ./setup-kiosk.sh
#
# Installs a system service for the kiosk web app (root, so scans can use
# arp-scan/nmap/tcpdump) and a labwc autostart entry that opens Chromium
# full-screen against it. Safe to re-run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${KIOSK_PORT:-8770}"
KIOSK_USER="${SUDO_USER:-$(id -un)}"
USER_HOME="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo: sudo $0" >&2
  exit 1
fi

echo "==> kiosk for user '$KIOSK_USER' (home $USER_HOME), port $PORT"

if ! command -v chromium >/dev/null && ! command -v chromium-browser >/dev/null; then
  echo "==> installing chromium"
  apt-get update -qq && apt-get install -y chromium
fi
BROWSER="$(command -v chromium || command -v chromium-browser)"

echo "==> installing systemd service"
cat > /etc/systemd/system/netsnapshot-kiosk.service <<EOF
[Unit]
Description=Network Snapshot kiosk UI
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $HERE/kiosk.py --host 127.0.0.1 --port $PORT
WorkingDirectory=$HERE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now netsnapshot-kiosk.service

echo "==> writing labwc autostart"
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$USER_HOME/.config/labwc"
AUTOSTART="$USER_HOME/.config/labwc/autostart"
MARK="# --- netsnapshot kiosk ---"
# Drop any previous block so re-runs don't stack duplicate launches.
if [[ -f "$AUTOSTART" ]] && grep -qF "$MARK" "$AUTOSTART"; then
  sed -i "/$(printf '%s' "$MARK" | sed 's/[][\/.*^$]/\\&/g')/,/# --- end netsnapshot kiosk ---/d" "$AUTOSTART"
fi
cat >> "$AUTOSTART" <<EOF
$MARK
# Wait for the kiosk server to answer before opening the browser.
( for i in \$(seq 1 30); do
    curl -sf -o /dev/null http://127.0.0.1:$PORT/ && break
    sleep 1
  done
  $BROWSER \\
    --kiosk --app=http://127.0.0.1:$PORT/ \\
    --noerrdialogs --disable-infobars --disable-session-crashed-bubble \\
    --disable-features=TranslateUI --overscroll-history-navigation=0 \\
    --check-for-update-interval=31536000 \\
    --user-data-dir=$USER_HOME/.config/netsnapshot-kiosk-chrome ) &
# --- end netsnapshot kiosk ---
EOF
chown "$KIOSK_USER:$KIOSK_USER" "$AUTOSTART"
chmod +x "$AUTOSTART" 2>/dev/null || true

echo
echo "==> done"
systemctl --no-pager --lines=3 status netsnapshot-kiosk.service || true
echo
echo "UI:      http://127.0.0.1:$PORT/"
echo "Browser: reboot, or run the autostart block manually to open it now."
