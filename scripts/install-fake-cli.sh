#!/usr/bin/env bash
# Haengt die JustDNS-Fake-CLI-Kommandos (enable/system/shell/linuxshell/
# enablelinuxshell) in cowrie ein: kopiert das Command-Modul nach
# src/cowrie/commands/ und traegt es in command_modules (__init__.py) ein.
# Idempotent. --off entfernt es wieder.
#
# Hintergrund: IoT-Botnets springen mit dieser CLI-Sequenz aus der Router-/DVR-
# Hersteller-CLI in die Linux-Shell. Ohne die Kommandos bricht der Bot bei
# "command not found" ab. Als stiller Erfolg (exit 0) bleibt er in der Fake-
# Shell und tippt seine Nachlade-Kommandos.
#
# WICHTIG: cowrie-Self-Update kann die Dateien ueberschreiben -> danach erneut
# laufen lassen (wie install-auth-failfirst.sh).
#
#   sudo ./scripts/install-fake-cli.sh
#   sudo ./scripts/install-fake-cli.sh --off
set -eu

COWRIE_SRC="${COWRIE_SRC:-/home/cowrie/cowrie/src/cowrie}"
CMDDIR="$COWRIE_SRC/commands"
INIT="$CMDDIR/__init__.py"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_MOD="${HERE}/../cowrie/fake_cli.py"
DST_MOD="$CMDDIR/fake_cli.py"
MARK="# >>> justdns fake-cli >>>"

if [ ! -f "$INIT" ]; then
  echo "cowrie commands/__init__.py nicht gefunden: $INIT" >&2
  exit 1
fi

if [ "${1:-}" = "--off" ]; then
  rm -f "$DST_MOD" "${DST_MOD}c" 2>/dev/null || true
  sed -i "/$MARK/d" "$INIT"
  echo "Fake-CLI entfernt."
  exit 0
fi

if [ ! -f "$SRC_MOD" ]; then
  echo "Modul nicht gefunden: $SRC_MOD" >&2
  exit 1
fi

cp -f "$SRC_MOD" "$DST_MOD"
chown --reference="$INIT" "$DST_MOD" 2>/dev/null || true

if grep -qF "$MARK" "$INIT"; then
  echo "Fake-CLI bereits in command_modules."
else
  sed -i "s/^command_modules = \[/command_modules = [\n    \"fake_cli\",  $MARK/" "$INIT"
  echo "Fake-CLI in command_modules eingetragen."
fi
echo "Fake-CLI installiert ($DST_MOD). cowrie neu starten."
