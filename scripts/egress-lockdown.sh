#!/usr/bin/env bash
# Egress-Lockdown fuer eine Honeypot-Node.
#
# Die Decoys (Cowrie deny-all, OpenCanary, web-/raw-decoy) sind reine SERVER und
# bauen nie selbst eine Verbindung nach aussen auf. Diese Firewall erlaubt der
# Node ausgehend deshalb nur das Noetige (Intake, DNS, NTP und - fuer das
# Self-Update - HTTPS) und verwirft/loggt alles andere NEUE ausgehende. Baut die
# Node doch etwas Unerwartetes auf, ist das ein Kompromittierungs-Signal, das
# der Compromise-Canary (scripts/compromise-canary.sh) meldet.
#
# WICHTIG: Es wird nur der OUTPUT gefiltert. Eingehende Angriffe (INPUT) bleiben
# voellig unberuehrt - sonst waere es kein Honeypot. established/related bleibt
# offen, Antworten auf Admin-SSH (eingehend) also auch. Man sperrt sich damit
# nicht aus.
#
#   sudo ./scripts/egress-lockdown.sh            # anwenden
#   sudo ./scripts/egress-lockdown.sh --dry-run  # nur die Regeln zeigen
#   sudo ./scripts/egress-lockdown.sh --off      # wieder entfernen
#
# Env (Defaults passen zur JustDNS-Infra, fuer Fremd-Nodes anpassen):
#   EGRESS_INTAKE      "192.168.20.52:8787"            Intake host:port (tcp)
#   EGRESS_RESOLVERS   "192.168.20.5,192.168.20.25"    DNS-Resolver
#   EGRESS_ALLOW_HTTPS "1"   443 ausgehend erlauben (fuer Self-Update ueber GitHub)
#   EGRESS_ALLOW_NTP   "1"   123/udp ausgehend erlauben (Zeitsync)
set -eu

MODE="apply"
case "${1:-}" in
  --dry-run) MODE="dry" ;;
  --off) MODE="off" ;;
  "" ) MODE="apply" ;;
  *) echo "Unbekannt: $1" >&2; exit 2 ;;
esac

TABLE_FAMILY="inet"
TABLE_NAME="justdns_egress"

if [ "$MODE" = "off" ]; then
  nft delete table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null && echo "Egress-Lockdown entfernt." || echo "War nicht aktiv."
  exit 0
fi

INTAKE="${EGRESS_INTAKE:-192.168.20.52:8787}"
RESOLVERS="${EGRESS_RESOLVERS:-192.168.20.5,192.168.20.25}"
ALLOW_HTTPS="${EGRESS_ALLOW_HTTPS:-1}"
ALLOW_NTP="${EGRESS_ALLOW_NTP:-1}"

INTAKE_IP="${INTAKE%:*}"
INTAKE_PORT="${INTAKE##*:}"
RES_SET="$(echo "$RESOLVERS" | tr ',' ' ' | xargs | tr ' ' ',')"

HTTPS_RULE=""
[ "$ALLOW_HTTPS" = "1" ] && HTTPS_RULE='    tcp dport 443 ct state new accept'
NTP_RULE=""
[ "$ALLOW_NTP" = "1" ] && NTP_RULE='    udp dport 123 ct state new accept'

RULES="table ${TABLE_FAMILY} ${TABLE_NAME} {
  chain output {
    type filter hook output priority 0; policy accept;

    oifname \"lo\" accept
    ct state established,related accept
    ct state invalid drop

    # Diagnose erlauben (Ping etc.).
    meta l4proto { icmp, ipv6-icmp } accept

    # DNS zu den eigenen Resolvern.
    ip daddr { ${RES_SET} } udp dport 53 accept
    ip daddr { ${RES_SET} } tcp dport 53 accept

    # Intake (Shipper meldet dorthin).
    ip daddr ${INTAKE_IP} tcp dport ${INTAKE_PORT} accept
${NTP_RULE}
${HTTPS_RULE}

    # Alles andere NEUE ausgehende: loggen (Canary liest das) und verwerfen.
    ct state new log prefix \"jd-egress-drop \" drop
    meta nfproto ipv4 ip daddr != 127.0.0.0/8 drop
    meta nfproto ipv6 drop
  }
}"

if [ "$MODE" = "dry" ]; then
  echo "$RULES"
  exit 0
fi

# Atomar ersetzen: alte Tabelle weg, neue laden.
nft delete table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null || true
printf '%s\n' "$RULES" | nft -f -
echo "Egress-Lockdown aktiv:"
echo "  Intake    ${INTAKE_IP}:${INTAKE_PORT}"
echo "  Resolver  ${RES_SET}"
echo "  HTTPS     $([ "$ALLOW_HTTPS" = 1 ] && echo erlaubt || echo gesperrt)"
echo "  NTP       $([ "$ALLOW_NTP" = 1 ] && echo erlaubt || echo gesperrt)"
