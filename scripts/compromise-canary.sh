#!/usr/bin/env bash
# Compromise-Canary fuer eine Honeypot-Node.
#
# Die Decoys sind reine Server und rufen nie nach aussen. Baut die Node doch
# eine ausgehende Verbindung zu etwas Nicht-Erlaubtem auf, ist das ein starkes
# Kompromittierungs-Signal (z.B. ein ausgebrochener Angreifer, der nachladen
# will). Dieses Skript findet solche Verbindungen ueber ss und schlaegt Alarm.
# Im Enforce-Modus stoppt es zusaetzlich die Honeypot-Dienste, um die Node
# einzudaemmen.
#
# Ergaenzt die Egress-Firewall (scripts/egress-lockdown.sh): die Firewall
# BLOCKT, der Canary ERKENNT und MELDET (die Firewall allein waere stumm).
#
#   ./scripts/compromise-canary.sh            # nur pruefen + alarmieren
#   CANARY_ENFORCE=1 ./scripts/compromise-canary.sh   # zusaetzlich Dienste stoppen
#
# Env:
#   CANARY_ALLOW_IPS    "192.168.20.52 192.168.20.5 192.168.20.25" (Intake + DNS)
#   CANARY_ALLOW_PORTS  "53 123 443 8787" (erlaubte Zielports, u.a. HTTPS/Intake)
#   CANARY_ENFORCE      "1" -> bei Fund die Decoys stoppen
#   CANARY_SERVICES     zu stoppende Dienste
#   CANARY_WEBHOOK      optionale URL, bekommt bei Fund ein POST (curl noetig)
#   CANARY_ALERT_FILE   Default /var/tmp/justdns-canary-alert.log
set -eu

ALLOW_IPS="${CANARY_ALLOW_IPS:-192.168.20.52 192.168.20.5 192.168.20.25}"
ALLOW_PORTS="${CANARY_ALLOW_PORTS:-53 123 443 8787}"
ENFORCE="${CANARY_ENFORCE:-0}"
SERVICES="${CANARY_SERVICES:-justdns-rawdecoy justdns-webdecoy cowrie opencanary}"
ALERT_FILE="${CANARY_ALERT_FILE:-/var/tmp/justdns-canary-alert.log}"
WEBHOOK="${CANARY_WEBHOOK:-}"

in_list() { local n="$1"; shift; for x in "$@"; do [ "$x" = "$n" ] && return 0; done; return 1; }

# Unsere eigenen Listen-Ports = eingehende Serverdienste. Verbindungen, deren
# LOKALER Port einer davon ist, sind eingehend (Angreifer -> Node) und ok.
LPORTS=$(ss -tlnH 2>/dev/null | sed -E 's/.*:([0-9]+)[[:space:]].*/\1/' | sort -u)

anomalies=""
# Etablierte TCP-Verbindungen durchgehen. Robust: pro Zeile die beiden
# "adresse:port"-Tokens einsammeln (local zuerst, peer als zweites). Das ist
# unabhaengig davon, ob ss eine State-Spalte ausgibt oder nicht.
while read -r line; do
  [ -z "$line" ] && continue
  addrs=$(printf '%s\n' "$line" | tr ' \t' '\n\n' | grep -E ':[0-9]+$' || true)
  laddr=$(printf '%s\n' "$addrs" | sed -n 1p)
  raddr=$(printf '%s\n' "$addrs" | sed -n 2p)
  [ -z "$laddr" ] || [ -z "$raddr" ] && continue
  lport="${laddr##*:}"
  rip="${raddr%:*}";  rip="${rip##*\[}"; rip="${rip%\]}"
  rport="${raddr##*:}"
  # eingehend (wir sind Server auf lport)?
  if echo "$LPORTS" | grep -qx "$lport"; then continue; fi
  # Loopback ignorieren.
  case "$rip" in 127.*|::1|"") continue;; esac
  # erlaubtes Ziel?
  if in_list "$rip" $ALLOW_IPS; then continue; fi
  if in_list "$rport" $ALLOW_PORTS; then continue; fi
  anomalies="${anomalies}${laddr} -> ${raddr}\n"
done < <(ss -tnH state established 2>/dev/null)

if [ -z "$anomalies" ]; then
  exit 0
fi

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host="$(hostname)"
msg="[${ts}] CANARY ${host}: unerwartete ausgehende Verbindung(en):
$(printf '%b' "$anomalies")"
printf '%s\n' "$msg" | tee -a "$ALERT_FILE" >&2

if [ -n "$WEBHOOK" ] && command -v curl >/dev/null 2>&1; then
  curl -s -m 10 -X POST --form-string "text=${msg}" "$WEBHOOK" >/dev/null 2>&1 || true
fi

if [ "$ENFORCE" = "1" ]; then
  for s in $SERVICES; do systemctl stop "$s" 2>/dev/null || true; done
  printf '%s\n' "[${ts}] CANARY ${host}: Dienste gestoppt (Enforce): ${SERVICES}" | tee -a "$ALERT_FILE" >&2
fi
exit 1
