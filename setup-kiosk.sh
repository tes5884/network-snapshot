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

echo "==> installing browser user service"
# A user service rather than a bare autostart line: it restarts the browser if
# it crashes, and `systemctl --user restart kiosk-browser` reloads the UI
# without touching the session.
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$USER_HOME/.config/systemd/user"
cat > "$USER_HOME/.config/systemd/user/kiosk-browser.service" <<EOF
[Unit]
Description=Network Snapshot kiosk browser
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
Environment=WAYLAND_DISPLAY=wayland-0
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:$PORT/ && exit 0; sleep 1; done; exit 0'
ExecStart=$BROWSER \\
  --ozone-platform=wayland \\
  --kiosk --app=http://127.0.0.1:$PORT/ \\
  --noerrdialogs --disable-infobars --disable-session-crashed-bubble \\
  --disable-features=TranslateUI --overscroll-history-navigation=0 \\
  --check-for-update-interval=31536000 \\
  --user-data-dir=$USER_HOME/.config/netsnapshot-kiosk-chrome
Restart=always
RestartSec=3

[Install]
WantedBy=graphical-session.target
EOF
chown -R "$KIOSK_USER:$KIOSK_USER" "$USER_HOME/.config/systemd"

# The user manager needs to be running to enable this; loginctl enable-linger
# makes it come up at boot even before the graphical session settles.
loginctl enable-linger "$KIOSK_USER" || true
sudo -u "$KIOSK_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$KIOSK_USER")" \
  systemctl --user daemon-reload || true
sudo -u "$KIOSK_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$KIOSK_USER")" \
  systemctl --user enable kiosk-browser.service || true

# Older installs put the launch in labwc's autostart — remove it so the browser
# doesn't open twice.
AUTOSTART="$USER_HOME/.config/labwc/autostart"
if [[ -f "$AUTOSTART" ]] && grep -qF "# --- netsnapshot kiosk ---" "$AUTOSTART"; then
  sed -i '/# --- netsnapshot kiosk ---/,/# --- end netsnapshot kiosk ---/d' "$AUTOSTART"
fi

echo
echo "==> done"
systemctl --no-pager --lines=3 status netsnapshot-kiosk.service || true
echo
echo "UI:      http://127.0.0.1:$PORT/"
echo "Browser: systemctl --user start kiosk-browser   (or just reboot)"
