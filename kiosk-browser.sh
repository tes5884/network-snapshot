#!/usr/bin/env bash
# Launch the kiosk browser once the session and the kiosk server are ready.
#
# This is the ExecStart of the kiosk-browser user service. The waiting lives
# here rather than in ExecStartPre so the unit is a single exec — the same shape
# that works when launched by hand.
#
#   KIOSK_PORT   port the kiosk server listens on (default 8770)
#   KIOSK_PROFILE  chromium profile dir (wiped on every start)
set -u

PORT="${KIOSK_PORT:-8770}"
PROFILE="${KIOSK_PROFILE:-$HOME/.config/netsnapshot-kiosk-chrome}"
BROWSER="$(command -v chromium || command -v chromium-browser)"
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}"

log() { echo "[kiosk-browser] $*" >&2; }

# The compositor and the kiosk server both come up after this service can
# start, so wait for each rather than racing them.
for _ in $(seq 1 120); do
  [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ] || { sleep 1; continue; }
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/" || { sleep 1; continue; }
  break
done

if [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; then
  log "no compositor at $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"; exit 1
fi
if ! curl -sf -o /dev/null "http://127.0.0.1:$PORT/"; then
  log "kiosk server not answering on $PORT"; exit 1
fi

# On the Pi desktop the panel and file manager map at the same moment; let the
# session settle so the kiosk window isn't opened underneath them.
if [ -x /usr/bin/wf-panel-pi ]; then
  for _ in $(seq 1 60); do
    pgrep -x wf-panel-pi >/dev/null && break
    sleep 1
  done
fi
sleep 5

# Always start clean: a wedged profile renders a permanently blank window and
# there is no state here worth keeping.
rm -rf "$PROFILE"

log "starting $BROWSER on $WAYLAND_DISPLAY"
# Relaunch if it exits, so a crash doesn't leave a dead screen in the field.
while true; do
  "$BROWSER" \
    --ozone-platform=wayland \
    --kiosk --app="http://127.0.0.1:$PORT/" \
    --noerrdialogs --disable-infobars --disable-session-crashed-bubble \
    --overscroll-history-navigation=0 \
    --check-for-update-interval=31536000 \
    --password-store=basic \
    --user-data-dir="$PROFILE"
  log "browser exited ($?) — restarting"
  rm -rf "$PROFILE"
  sleep 3
done
