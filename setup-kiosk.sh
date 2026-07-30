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
systemctl enable netsnapshot-kiosk.service
# restart, not `enable --now`: on a re-run the service is already up and would
# otherwise keep serving the old code.
systemctl restart netsnapshot-kiosk.service

echo "==> installing labwc autostart launch"
# The browser launches from the compositor's own autostart rather than a systemd
# user service. Under linger the user manager starts long before the session,
# and Chromium launched from there never mapped a window; autostart runs inside
# the graphical session with its environment already correct.
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$USER_HOME/.config/labwc"
AUTOSTART="$USER_HOME/.config/labwc/autostart"
MARK="# --- netsnapshot kiosk ---"
touch "$AUTOSTART"
# Drop any previous block so re-runs don't stack duplicate launches.
sed -i '/# --- netsnapshot kiosk ---/,/# --- end netsnapshot kiosk ---/d' "$AUTOSTART"
cat >> "$AUTOSTART" <<EOF
$MARK
KIOSK_PORT=$PORT /bin/bash $HERE/kiosk-browser.sh >/tmp/kiosk-browser.log 2>&1 &
# --- end netsnapshot kiosk ---
EOF
chown "$KIOSK_USER:$KIOSK_USER" "$AUTOSTART"

# Launcher so the kiosk can be reopened after "Close kiosk" without a reboot —
# in the app menu, and as an icon on the desktop where it's actually findable
# on a touchscreen.
DESKTOP_ENTRY="[Desktop Entry]
Type=Application
Name=Network Snapshot Kiosk
Comment=Open the touchscreen scanning UI
Exec=env KIOSK_PORT=$PORT /bin/bash $HERE/kiosk-browser.sh
Icon=utilities-system-monitor
Terminal=false
Categories=System;"

APPS="$USER_HOME/.local/share/applications"
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$APPS"
printf '%s\n' "$DESKTOP_ENTRY" > "$APPS/netsnapshot-kiosk.desktop"
chown -R "$KIOSK_USER:$KIOSK_USER" "$APPS"

# The desktop dir is localised on some installs; XDG_DESKTOP_DIR is the truth.
DESKTOP_DIR="$(sudo -u "$KIOSK_USER" xdg-user-dir DESKTOP 2>/dev/null || true)"
[[ -z "$DESKTOP_DIR" || "$DESKTOP_DIR" == "$USER_HOME" ]] && DESKTOP_DIR="$USER_HOME/Desktop"
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$DESKTOP_DIR"
printf '%s\n' "$DESKTOP_ENTRY" > "$DESKTOP_DIR/netsnapshot-kiosk.desktop"
# The file manager only launches a desktop .desktop file that is executable;
# without this it opens it in a text editor instead.
chmod +x "$DESKTOP_DIR/netsnapshot-kiosk.desktop"
chown "$KIOSK_USER:$KIOSK_USER" "$DESKTOP_DIR/netsnapshot-kiosk.desktop"
# pcmanfm keeps its own trust flag; set it where the attr is supported.
sudo -u "$KIOSK_USER" gio set "$DESKTOP_DIR/netsnapshot-kiosk.desktop" \
  metadata::trusted true >/dev/null 2>&1 || true

# Remove the user service from earlier installs — it never worked under linger
# and would fight the autostart launch.
if [[ -f "$USER_HOME/.config/systemd/user/kiosk-browser.service" ]]; then
  KUID="$(id -u "$KIOSK_USER")"
  sudo -u "$KIOSK_USER" XDG_RUNTIME_DIR="/run/user/$KUID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$KUID/bus" \
    systemctl --user disable --now kiosk-browser.service >/dev/null 2>&1 || true
  rm -f "$USER_HOME/.config/systemd/user/kiosk-browser.service"
fi

echo
echo "==> done"
systemctl --no-pager --lines=3 status netsnapshot-kiosk.service || true
echo
echo "UI:      http://127.0.0.1:$PORT/"
echo "Browser: reboot (autostart), log at /tmp/kiosk-browser.log"
