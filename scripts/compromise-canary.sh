#!/usr/bin/env bash
# Compromise-Canary fuer eine Honeypot-Node.
#
# Die Decoys sind reine Server und rufen nie nach aussen. Baut die Node doch
# eine ausgehende Verbindung zu etwas Nicht-Erlaubtem auf, ist das ein starkes
# Kompromittierungs-Signal (z.B. ein ausgebrochener Angreifer, der nachladen
# will). Dieses Skript findet solche Verbindungen ueber ss und MELDET sie an die
# Intake. Im Dashboard erscheint der Alarm; der Mensch bestaetigt oder ignoriert
# ihn. Es passiert NICHTS automatisch - ausser im optionalen Enforce-Modus, der
# zusaetzlich die Honeypot-Dienste stoppt (Default aus).
#
# Ergaenzt die Egress-Firewall (scripts/egress-lockdown.sh): die Firewall
# BLOCKT, der Canary ERKENNT und MELDET (die Firewall allein waere stumm).
#
#   ./scripts/compromise-canary.sh            # pruefen + an Dashboard melden
#   CANARY_ENFORCE=1 ./scripts/compromise-canary.sh   # zusaetzlich Dienste stoppen
#
# Intake-Ziel (URL + Token) wird aus der Shipper-Config gelesen, kein Extra-Setup.
#
# Env:
#   CANARY_ALLOW_IPS    "192.168.20.52 192.168.20.5 192.168.20.25" (Intake + DNS)
#   CANARY_ALLOW_PORTS  "53 123 443 8787" (erlaubte Zielports, u.a. HTTPS/Intake)
#   CANARY_ENFORCE      "1" -> bei Fund die Decoys stoppen (Default 0 = nur melden)
#   CANARY_SERVICES     zu stoppende Dienste (nur im Enforce-Modus)
#   CANARY_INTAKE_CONF  Shipper-Config mit INTAKE_URL + TOKEN (Default /etc/justdns-shipper.conf)
#   CANARY_INTAKE_URL   ueberschreibt INTAKE_URL aus der Config
#   CANARY_TOKEN        ueberschreibt TOKEN aus der Config
#   CANARY_WEBHOOK      optionale Zusatz-URL, bekommt bei Fund ein POST
#   CANARY_ALERT_FILE   lokales Log, Default /var/tmp/justdns-canary-alert.log
set -eu

ALLOW_IPS="${CANARY_ALLOW_IPS:-192.168.20.52 192.168.20.5 192.168.20.25}"
ALLOW_PORTS="${CANARY_ALLOW_PORTS:-53 123 443 8787}"
ENFORCE="${CANARY_ENFORCE:-0}"
SERVICES="${CANARY_SERVICES:-justdns-rawdecoy justdns-webdecoy cowrie opencanary}"
ALERT_FILE="${CANARY_ALERT_FILE:-/var/tmp/justdns-canary-alert.log}"
WEBHOOK="${CANARY_WEBHOOK:-}"
INTAKE_CONF="${CANARY_INTAKE_CONF:-/etc/justdns-shipper.conf}"

conf_val() { sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*(.*)$/\1/p" "$INTAKE_CONF" 2>/dev/null | head -1; }
INTAKE_URL="${CANARY_INTAKE_URL:-$(conf_val INTAKE_URL)}"
INTAKE_TOKEN="${CANARY_TOKEN:-$(conf_val TOKEN)}"

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
detail="$(printf '%b' "$anomalies" | sed '/^$/d' | tr '\n' ';' | sed 's/;$//')"
msg="[${ts}] CANARY ${host}: unerwartete ausgehende Verbindung(en):
$(printf '%b' "$anomalies")"
printf '%s\n' "$msg" | tee -a "$ALERT_FILE" >&2

# An die Intake melden -> Alarm im Dashboard (Mensch bestaetigt/ignoriert).
if [ -n "$INTAKE_URL" ] && [ -n "$INTAKE_TOKEN" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$INTAKE_URL" "$INTAKE_TOKEN" "$detail" <<'PY' || true
import sys, json, urllib.request
url = sys.argv[1].rstrip('/') + "/canary-alert"
req = urllib.request.Request(url, data=json.dumps({"detail": sys.argv[3]}).encode(),
                             method="POST")
req.add_header("Authorization", "Bearer " + sys.argv[2])
req.add_header("Content-Type", "application/json")
try:
    urllib.request.urlopen(req, timeout=8).read()
except Exception as e:
    print("[canary] Intake-Meldung fehlgeschlagen:", e, file=sys.stderr)
PY
fi

if [ -n "$WEBHOOK" ] && command -v curl >/dev/null 2>&1; then
  curl -s -m 10 -X POST --form-string "text=${msg}" "$WEBHOOK" >/dev/null 2>&1 || true
fi

if [ "$ENFORCE" = "1" ]; then
  for s in $SERVICES; do systemctl stop "$s" 2>/dev/null || true; done
  printf '%s\n' "[${ts}] CANARY ${host}: Dienste gestoppt (Enforce): ${SERVICES}" | tee -a "$ALERT_FILE" >&2
fi
exit 1
