#!/usr/bin/env bash
# Telnet-WAN-Port auf cowrie-Telnet umleiten.
#
# Cowrie-Telnet lauscht non-root auf 2223. Wo der WAN-Port 23 auf der Node
# ankommt (oder ein anderer Dienst auf Port 23 lauscht), leitet diese nft-Regel
# 23 -> 2223 um. So landen die Telnet-Logins in der cowrie-Fake-Shell und ihre
# Nachlade-Kommandos (busybox/wget/tftp) werden mitgeschnitten. Telnet ist der
# Haupt-Vektor fuer IoT-Botnets.
#
# Auf einer frischen Node kann man den WAN-Port 23 auch direkt auf 2223
# forwarden (wie SSH 22->2222) und dieses Skript weglassen. Auf CT131 ersetzt
# die Umleitung den OpenCanary-Telnet (dort "telnet.enabled": false setzen),
# weil der WAN-Forward dort auf Port 23 zeigt.
#
# Es wird nur PREROUTING/nat umgeschrieben. Eingehende Angriffe bleiben
# unberuehrt, nur das Ziel-Port wird getauscht.
#
#   sudo ./scripts/telnet-redirect.sh            # anwenden
#   sudo ./scripts/telnet-redirect.sh --dry-run  # nur die Regeln zeigen
#   sudo ./scripts/telnet-redirect.sh --off      # wieder entfernen
#
# Env:
#   TELNET_WAN_PORT     "23"     eingehender Port
#   COWRIE_TELNET_PORT  "2223"   cowrie-Telnet-Port
set -eu

MODE="apply"
case "${1:-}" in
  --dry-run) MODE="dry" ;;
  --off) MODE="off" ;;
  "" ) MODE="apply" ;;
  *) echo "Unbekannt: $1" >&2; exit 2 ;;
esac

TABLE_FAMILY="ip"
TABLE_NAME="justdns_telnet"
WAN_PORT="${TELNET_WAN_PORT:-23}"
DST_PORT="${COWRIE_TELNET_PORT:-2223}"

if [ "$MODE" = "off" ]; then
  nft delete table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null && echo "Telnet-Redirect entfernt." || echo "War nicht aktiv."
  exit 0
fi

read -r -d '' RULESET <<EOF || true
table ${TABLE_FAMILY} ${TABLE_NAME} {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport ${WAN_PORT} redirect to :${DST_PORT}
    }
}
EOF

if [ "$MODE" = "dry" ]; then
  echo "$RULESET"
  exit 0
fi

# Tabelle frisch setzen (idempotent).
nft delete table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null || true
printf '%s\n' "$RULESET" | nft -f -
echo "Telnet-Redirect aktiv: ${WAN_PORT} -> ${DST_PORT}."
