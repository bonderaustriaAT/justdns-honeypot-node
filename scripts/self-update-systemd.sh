#!/usr/bin/env bash
# Self-update for a bare-metal (systemd) node, the counterpart to self-update.sh
# for Docker nodes. Pulls this repo and reinstalls the shipper (and nodeui if it
# is installed). Cowrie and OpenCanary are upstream software and are left
# untouched, so an update never risks breaking the honeypots themselves.
#
# Run it from the repo clone, as root (it writes into /opt):
#
#   sudo ./scripts/self-update-systemd.sh
#
# Or let the timer call it (scripts/systemd/justdns-update-native.timer).
#
# Paths can be overridden with SHIPPER_DIR / NODEUI_DIR if you installed
# elsewhere. On a failed git pull it changes nothing and the timer retries.
set -eu

cd "$(dirname "$0")/.."
SHIPPER_DIR="${SHIPPER_DIR:-/opt/justdns-shipper}"
NODEUI_DIR="${NODEUI_DIR:-/opt/justdns-nodeui}"
WEBDECOY_DIR="${WEBDECOY_DIR:-/opt/justdns-webdecoy}"
LOCK="/tmp/justdns-selfupdate-native.lock"

log() { echo "[self-update] $*"; }

if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK"
  flock -n 9 || { log "laeuft bereits, breche ab"; exit 0; }
fi

before="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

log "git pull"
if ! git pull --rebase --autostash --no-edit; then
  log "git pull fehlgeschlagen, nichts geaendert. Naechster Lauf versucht es erneut."
  git rebase --abort 2>/dev/null || true
  exit 1
fi
after="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

# Shipper: erst validieren, dann einspielen (nur bei gueltigem Python).
python3 -m py_compile shipper/shipper.py
install -D -m 0644 shipper/shipper.py "$SHIPPER_DIR/shipper.py"
log "shipper aktualisiert -> $SHIPPER_DIR/shipper.py"

# nodeui nur, wenn ueberhaupt installiert.
if [ -d "$NODEUI_DIR" ]; then
  python3 -m py_compile nodeui/nodeui.py
  install -m 0644 nodeui/nodeui.py "$NODEUI_DIR/nodeui.py"
  systemctl restart justdns-nodeui 2>/dev/null || true
  log "nodeui aktualisiert"
fi

# web-decoy nur, wenn installiert.
if [ -d "$WEBDECOY_DIR" ]; then
  python3 -m py_compile webdecoy/webdecoy.py
  install -m 0644 webdecoy/webdecoy.py "$WEBDECOY_DIR/webdecoy.py"
  systemctl restart justdns-webdecoy 2>/dev/null || true
  log "web-decoy aktualisiert"
fi

# Der Shipper laeuft als oneshot ueber seinen Timer, der naechste Lauf nutzt die
# neue Datei automatisch. Timer nur anstupsen, damit er sicher scharf ist.
systemctl restart justdns-shipper.timer 2>/dev/null || true

if [ "$before" = "$after" ]; then
  log "schon aktuell ($after)"
else
  log "fertig: $before -> $after"
fi
