#!/usr/bin/env bash
# Haengt die JustDNS-Auth-Klasse AuthFailFirst in cowrie.core.auth ein.
#
# cowrie laedt die auth_class per getattr() aus dem Modul cowrie.core.auth und
# faellt sonst auf UserDB zurueck. Eine eigene Klasse muss daher in genau diese
# Datei. Dieses Skript haengt cowrie/auth_failfirst.py an auth.py an, idempotent
# (nur wenn noch nicht vorhanden).
#
# WICHTIG: Ein cowrie-Self-Update kann auth.py ueberschreiben. Danach dieses
# Skript erneut laufen lassen (z.B. als ExecStartPost der cowrie-Unit oder nach
# dem Update-Timer). Ohne die Klasse faellt cowrie auf UserDB zurueck.
#
#   sudo ./scripts/install-auth-failfirst.sh
#   sudo ./scripts/install-auth-failfirst.sh --off   # Klasse wieder entfernen
set -eu

AUTH="${COWRIE_AUTH_PY:-/home/cowrie/cowrie/src/cowrie/core/auth.py}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SNIPPET="${HERE}/../cowrie/auth_failfirst.py"
MARK_BEGIN="# >>> justdns AuthFailFirst >>>"
MARK_END="# <<< justdns AuthFailFirst <<<"

if [ ! -f "$AUTH" ]; then
  echo "cowrie auth.py nicht gefunden: $AUTH" >&2
  exit 1
fi

if [ "${1:-}" = "--off" ]; then
  if grep -qF "$MARK_BEGIN" "$AUTH"; then
    sed -i "/$(printf '%s' "$MARK_BEGIN" | sed 's/[.[\*^$/]/\\&/g')/,/$(printf '%s' "$MARK_END" | sed 's/[.[\*^$/]/\\&/g')/d" "$AUTH"
    echo "AuthFailFirst aus $AUTH entfernt."
  else
    echo "AuthFailFirst war nicht eingehaengt."
  fi
  exit 0
fi

if grep -qF "class AuthFailFirst" "$AUTH"; then
  echo "AuthFailFirst bereits vorhanden in $AUTH."
  exit 0
fi

{
  printf '\n\n%s\n' "$MARK_BEGIN"
  cat "$SNIPPET"
  printf '%s\n' "$MARK_END"
} >> "$AUTH"
echo "AuthFailFirst an $AUTH angehaengt."
