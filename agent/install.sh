#!/bin/sh
# JustDNS Fleet-Agent - Installer.
#
# Wird vom in der Node-UI generierten Befehl aufgerufen:
#   curl -fsSL http://<node>:8090/agent/install | sudo bash -s -- \
#       --name <lxc> --app <nginx|caddy|node64|npm|apache|haproxy|sshd|fail2ban> \
#       [--intake-url <url>] [--log-glob <glob>]
#
# Laedt den Agent von der Node, registriert sich selbst (kein Token noetig),
# schreibt Config + systemd-Timer (jede Minute), startet einmal zur Kontrolle.
# Idempotent: erneuter Lauf aktualisiert nur.
set -eu

INTAKE_URL="https://intake.justdns.justfuture.at"
NAME=""
APP=""
TOKEN=""
LOG_GLOB=""

DEST="/opt/justdns-agent"
STATE_DIR="/var/lib/justdns-agent"
CONF="/etc/justdns-agent.conf"

die() { echo "FEHLER: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --name)       NAME="${2:-}"; shift 2 ;;
        --app)        APP="${2:-}"; shift 2 ;;
        --token)      TOKEN="${2:-}"; shift 2 ;;
        --intake-url) INTAKE_URL="${2:-}"; shift 2 ;;
        --log-glob)   LOG_GLOB="${2:-}"; shift 2 ;;
        *) die "unbekannte Option: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || die "bitte als root ausfuehren (sudo)."
[ -n "$APP" ] || die "--app fehlt."
command -v python3 >/dev/null 2>&1 || die "python3 nicht gefunden."
command -v systemctl >/dev/null 2>&1 || die "systemd nicht gefunden."
case "$APP" in
    nginx|caddy|node64|npm|apache|haproxy|sshd|fail2ban) : ;;
    *) die "--app '$APP' nicht unterstuetzt." ;;
esac

fetch() {
    # $1 url, $2 ziel
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "weder curl noch wget vorhanden."
    fi
}

if [ -z "$TOKEN" ]; then
    echo "[install] Registriere Agent an der Node ..."
    TOKEN=$(python3 - "${INTAKE_URL%/}/agent/register" "$NAME" "$APP" <<'PY'
import json, sys, urllib.request
url, host, app = sys.argv[1], sys.argv[2], sys.argv[3]
body = json.dumps({"host": host, "app": app, "kind": "agent"}).encode()
req = urllib.request.Request(url, data=body, method="POST",
                            headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        sys.stdout.write(json.load(r).get("token", ""))
except Exception as exc:
    sys.stderr.write(str(exc) + "\n")
PY
)
    [ -n "$TOKEN" ] || die "Selbst-Registrierung an $INTAKE_URL fehlgeschlagen."
fi

echo "[install] Agent nach $DEST ..."
mkdir -p "$DEST" "$STATE_DIR"
fetch "${INTAKE_URL%/}/agent/agent.py" "$DEST/justdns-agent.py"
python3 -c "compile(open('$DEST/justdns-agent.py').read(),'agent','exec')" \
    || die "heruntergeladener Agent ist kein gueltiges Python."

echo "[install] Config $CONF ..."
umask 027
cat > "$CONF" <<EOF
INTAKE_URL=$INTAKE_URL
TOKEN=$TOKEN
APP=$APP
HOST=$NAME
LOG_GLOB=$LOG_GLOB
REJECT_STATUS=401,403,404,405,429,444
STATE_FILE=$STATE_DIR/state.json
BATCH=500
EOF
chmod 0640 "$CONF"

echo "[install] systemd-Unit + Timer ..."
cat > /etc/systemd/system/justdns-agent.service <<'EOF'
[Unit]
Description=JustDNS Fleet-Agent (App-Ablehnungen -> Intake-API)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=AGENT_CONFIG=/etc/justdns-agent.conf
ExecStart=/usr/bin/python3 /opt/justdns-agent/justdns-agent.py
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/justdns-agent
EOF

cat > /etc/systemd/system/justdns-agent.timer <<'EOF'
[Unit]
Description=JustDNS Fleet-Agent jede Minute

[Timer]
OnBootSec=45s
OnUnitActiveSec=1min
AccuracySec=15s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now justdns-agent.timer

echo "[install] Testlauf ..."
if systemctl start justdns-agent.service; then
    echo "[install] OK - Agent laeuft (App=$APP, Host=${NAME:-<leer>})."
    echo "[install] Status: journalctl -u justdns-agent.service -n 20 --no-pager"
else
    die "Testlauf fehlgeschlagen - siehe: journalctl -u justdns-agent.service -n 30"
fi
