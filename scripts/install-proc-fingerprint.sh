#!/usr/bin/env bash
# Legt eine realistische /proc/cpuinfo in den cowrie-honeyfs. IoT-Loader lesen
# cpuinfo, um die Architektur des Ziels zu bestimmen und das passende Binary zu
# waehlen. Das mitgelieferte cowrie liefert /proc/cpuinfo LEER (size 0) -> dieses
# Fingerprint-Signal fehlt. honeyfs fuellt nur leere Dateien; init_honeyfs setzt
# beim Start A_REALFILE auf den passenden T_FILE-Eintrag im Pickle-FS -> cat
# liefert dann den Inhalt. (/proc/version + /proc/meminfo bringt cowrie bereits
# mit eigenem Fake-Inhalt mit, honeyfs ueberschreibt die nicht - daher hier nur
# cpuinfo.) Rein additiv, idempotent. --off entfernt die Datei wieder.
#
#   sudo ./scripts/install-proc-fingerprint.sh
#   sudo ./scripts/install-proc-fingerprint.sh --off
set -eu

COWRIE_HOME="${COWRIE_HOME:-/home/cowrie/cowrie}"
HONEYFS="$COWRIE_HOME/honeyfs"
DST="$HONEYFS/proc"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${HERE}/../cowrie/honeyfs/proc"
FILES="cpuinfo"

if [ ! -d "$HONEYFS" ]; then
  echo "honeyfs nicht gefunden: $HONEYFS" >&2
  exit 1
fi

if [ "${1:-}" = "--off" ]; then
  for f in $FILES; do rm -f "$DST/$f"; done
  rmdir "$DST" 2>/dev/null || true
  echo "proc-Fingerprint entfernt."
  exit 0
fi

if [ ! -d "$SRC" ]; then
  echo "Quelle nicht gefunden: $SRC" >&2
  exit 1
fi

mkdir -p "$DST"
for f in $FILES; do
  cp -f "$SRC/$f" "$DST/$f"
  chown --reference="$HONEYFS" "$DST/$f" 2>/dev/null || true
  chmod 0644 "$DST/$f"
done
chown --reference="$HONEYFS" "$DST" 2>/dev/null || true
echo "proc-Fingerprint installiert ($DST). cowrie neu starten."
