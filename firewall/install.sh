#!/bin/sh
# JustDNS Firewall-Reader (Unifi, nur lesen) - Installer.
#
# Wird vom in der Node-UI generierten Befehl aufgerufen:
#   curl -fsSL https://intake.example/firewall/install | sudo bash -s -- \
#       --unifi-url https://192.168.1.1 --site default [--insecure] [--intake-url <url>]
#
# Laedt den Reader von der Intake, fragt den read-only API-Key sicher ab (nicht
# im Befehl), schreibt Config + systemd-Timer (jede Minute), startet einmal.
# Idempotent: erneuter Lauf aktualisiert nur.
set -eu

INTAKE_URL="https://intake.justdns.justfuture.at"
UNIFI_URL=""
SITE="default"
VERIFY_TLS="1"
NAME="UDM-Pro"

DEST="/opt/justdns-firewall"
STATE_DIR="/var/lib/justdns-firewall"
CONF="/etc/justdns-unifi.conf"

die() { echo "FEHLER: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --unifi-url)  UNIFI_URL="${2:-}"; shift 2 ;;
        --site)       SITE="${2:-}"; shift 2 ;;
        --insecure)   VERIFY_TLS="0"; shift ;;
        --intake-url) INTAKE_URL="${2:-}"; shift 2 ;;
        --name)       NAME="${2:-}"; shift 2 ;;
        *) die "unbekannte Option: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "bitte als root ausfuehren (sudo)."
[ -n "$UNIFI_URL" ] || die "--unifi-url fehlt."
command -v python3 >/dev/null 2>&1 || die "python3 nicht gefunden."
command -v systemctl >/dev/null 2>&1 || die "systemd nicht gefunden."
[ -r /dev/tty ] || die "kein Terminal fuer die Key-Abfrage. Config spaeter in $CONF eintragen."

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
    else die "weder curl noch wget vorhanden."; fi
}

printf "UniFi read-only API-Key (Eingabe bleibt verborgen): " > /dev/tty
stty -echo < /dev/tty 2>/dev/null || true
IFS= read -r API_KEY < /dev/tty
stty echo < /dev/tty 2>/dev/null || true
printf "\n" > /dev/tty
[ -n "$API_KEY" ] || die "kein API-Key eingegeben."

echo "[install] Reader nach $DEST ..."
mkdir -p "$DEST" "$STATE_DIR"
fetch "${INTAKE_URL%/}/firewall/reader.py" "$DEST/unifi_reader.py"
python3 -c "compile(open('$DEST/unifi_reader.py').read(),'reader','exec')" \
    || die "heruntergeladener Reader ist kein gueltiges Python."

echo "[install] Config $CONF ..."
umask 027
cat > "$CONF" <<EOF
INTAKE_URL=$INTAKE_URL
TOKEN=
UNIFI_URL=$UNIFI_URL
UNIFI_API_KEY=$API_KEY
UNIFI_USER=
UNIFI_PASS=
UNIFI_SITE=$SITE
VERIFY_TLS=$VERIFY_TLS
NAME=$NAME
STATE_FILE=$STATE_DIR/unifi-state.json
LOOKBACK_MIN=60
EOF
chmod 0640 "$CONF"

echo "[install] systemd-Unit + Timer ..."
cat > /etc/systemd/system/justdns-unifi.service <<'EOF'
[Unit]
Description=JustDNS Firewall-Reader (Unifi, nur lesen -> Intake-API)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=UNIFI_CONFIG=/etc/justdns-unifi.conf
ExecStart=/usr/bin/python3 /opt/justdns-firewall/unifi_reader.py
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/justdns-firewall
EOF

cat > /etc/systemd/system/justdns-unifi.timer <<'EOF'
[Unit]
Description=JustDNS Firewall-Reader jede Minute

[Timer]
OnBootSec=50s
OnUnitActiveSec=1min
AccuracySec=15s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now justdns-unifi.timer

echo "[install] Testlauf ..."
if systemctl start justdns-unifi.service; then
    echo "[install] OK - Reader laeuft (Controller=$UNIFI_URL, Site=$SITE)."
    echo "[install] Status: journalctl -u justdns-unifi.service -n 20 --no-pager"
else
    die "Testlauf fehlgeschlagen - siehe: journalctl -u justdns-unifi.service -n 30"
fi
