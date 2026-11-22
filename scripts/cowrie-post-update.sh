#!/usr/bin/env bash
# Wendet nach einem cowrie-Self-Update alle JustDNS-cowrie-Anpassungen in einem
# Lauf wieder an und startet cowrie einmal neu. Jede Teil-Komponente ist fuer
# sich idempotent, dieser Wrapper fasst sie nur zusammen.
#
# Hintergrund: self-update-systemd.sh laesst cowrie BEWUSST unangetastet (damit
# ein Node-Update die Honeypots nie bricht). cowrie aktualisiert sich separat und
# ueberschreibt dabei commands/__init__.py, core/auth.py, den honeyfs und
# fs.pickle. Danach dieses Skript laufen lassen, um Persona + Realismus
# wiederherzustellen:
#
#   sudo ./scripts/cowrie-post-update.sh
#   sudo ./scripts/cowrie-post-update.sh --off   # alle Anpassungen zurueck
#
# Reihenfolge beim --off ist umgekehrt. Fehlt eine Komponente, wird sie
# uebersprungen (Warnung), der Rest laeuft weiter.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
COWRIE_USER="${COWRIE_USER:-cowrie}"
COWRIE_SERVICE="${COWRIE_SERVICE:-cowrie}"
OFF=""
[ "${1:-}" = "--off" ] && OFF="--off"

log() { echo "[cowrie-post-update] $*"; }

run_sh() {  # $1 = Skriptname in scripts/
  local s="$HERE/$1"
  if [ ! -f "$s" ]; then log "uebersprungen (fehlt): $1"; return 0; fi
  log "-> $1 ${OFF}"
  bash "$s" $OFF
}

run_persona() {
  local s="$HERE/persona_ubuntu_patch.py"
  if [ ! -f "$s" ]; then log "uebersprungen (fehlt): persona_ubuntu_patch.py"; return 0; fi
  log "-> persona_ubuntu_patch.py ${OFF} (als $COWRIE_USER)"
  runuser -u "$COWRIE_USER" -- python3 "$s" $OFF
}

if [ -n "$OFF" ]; then
  run_persona
  run_sh install-auth-failfirst.sh
  run_sh install-proc-fingerprint.sh
  run_sh install-fake-cli.sh
else
  run_sh install-fake-cli.sh
  run_sh install-proc-fingerprint.sh
  run_sh install-auth-failfirst.sh
  run_persona
fi

log "cowrie ($COWRIE_SERVICE) neu starten"
systemctl restart "$COWRIE_SERVICE"
log "fertig."
