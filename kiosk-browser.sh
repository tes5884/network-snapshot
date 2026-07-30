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

# Only ever one launcher. Every instance wipes the shared Chromium profile on
# start, so a second one (a double-tap on the desktop launcher, or autostart
# racing a manual start) pulls the profile out from under the running browser
# and leaves a blank window with no way back.
LOCK="${XDG_RUNTIME_DIR:-/tmp}/netsnapshot-kiosk.lock"
exec 9>"$LOCK" || true
if command -v flock >/dev/null && ! flock -n 9; then
  log "kiosk already running — nothing to do"
  exit 0
fi

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

# At boot the panel and file manager map at the same moment, and a kiosk window
# opened right then can land underneath them — so wait for the session and let
# it settle. Started by hand from the desktop the session is already up, and
# waiting 5s there just makes the launcher feel broken.
SETTLE=1
if [ -x /usr/bin/wf-panel-pi ] && ! pgrep -x wf-panel-pi >/dev/null; then
  SETTLE=5
  for _ in $(seq 1 60); do
    pgrep -x wf-panel-pi >/dev/null && break
    sleep 1
  done
fi
sleep "$SETTLE"

# Always start clean: a wedged profile renders a permanently blank window and
# there is no state here worth keeping.
rm -rf "$PROFILE"

log "starting $BROWSER on $WAYLAND_DISPLAY"
# "Close kiosk" in the UI drops this flag before killing the browser; without it
# the restart loop below would immediately bring the kiosk back.
STOP_FLAG="$(dirname "$0")/.kiosk-stop"
rm -f "$STOP_FLAG"

# Has the page actually rendered? A live UI polls the server constantly, so the
# server's idea of when it last heard from a page is the only honest signal —
# Chromium can sit there alive with an unmapped window or a blank page, and
# process checks all look fine.
ui_stale_seconds() {
  curl -sf --max-time 3 "http://127.0.0.1:$PORT/api/ui-alive" 2>/dev/null || echo 9999
}

stop_requested() {
  [ -e "$STOP_FLAG" ] && { rm -f "$STOP_FLAG"; return 0; }
  return 1
}

# Relaunch if it exits, so a crash doesn't leave a dead screen in the field.
while true; do
  rm -rf "$PROFILE"
  "$BROWSER" \
    --ozone-platform=wayland \
    --kiosk --app="http://127.0.0.1:$PORT/" \
    --noerrdialogs --disable-infobars --disable-session-crashed-bubble \
    --no-first-run --overscroll-history-navigation=0 \
    --check-for-update-interval=31536000 \
    --password-store=basic \
    --user-data-dir="$PROFILE" &
  BPID=$!

  # Give it up to ~75s to show a page, then treat it as failed to render.
  rendered=0
  for _ in $(seq 1 15); do
    sleep 5
    stop_requested && { kill "$BPID" 2>/dev/null; log "closed from the UI"; exit 0; }
    kill -0 "$BPID" 2>/dev/null || break          # died on its own
    [ "$(ui_stale_seconds)" -lt 20 ] && { rendered=1; break; }
  done

  if [ "$rendered" = 1 ]; then
    log "UI is live"
    # Healthy: sit on it, and keep checking that it stays live.
    while kill -0 "$BPID" 2>/dev/null; do
      sleep 10
      stop_requested && { kill "$BPID" 2>/dev/null; log "closed from the UI"; exit 0; }
      if [ "$(ui_stale_seconds)" -gt 60 ]; then
        log "UI went silent — restarting browser"
        kill "$BPID" 2>/dev/null; sleep 2; break
      fi
    done
  else
    log "browser never rendered — restarting"
    kill "$BPID" 2>/dev/null
  fi

  sleep 2
  pkill -x chromium 2>/dev/null   # reap any stragglers holding the profile
  stop_requested && { log "closed from the UI"; exit 0; }
  sleep 2
done
