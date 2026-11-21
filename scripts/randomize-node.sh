#!/usr/bin/env bash
# Rolls this node's fingerprint to random, realistic values so several nodes do
# not look like the same fleet. Edits the config files in place:
#
#   cowrie/cowrie.cfg           hostname + SSH version banner (coherent profile)
#   opencanary/opencanary.conf  node_id + FTP/HTTP/MySQL banners
#   .env                        WEBDECOY_PERSONA
#
# It also makes the SSH host key unique per node and (best effort) writes a
# matching /etc/os-release, /etc/issue and /etc/motd into the Cowrie honeyfs so
# the persona is consistent instead of randomly mixed.
#
# Cowrie here is deny-all: pre-auth an attacker only sees the SSH banner, the
# host key and the KEX algorithms. hostname/uname/MOTD/packages are only shown
# once a shell opens, which deny-all never grants. The host key and a coherent
# banner are therefore the values that matter most against fingerprinting; the
# honeyfs files are prepared for the case you later enable interactive logins.
#
# Run it ONCE before the first start, from the repo root:
#
#   ./scripts/randomize-node.sh
#   docker compose up -d
#
# Re-running rolls new values. After a change restart the stack
# (docker compose up -d) so the honeypots pick them up.
set -eu

cd "$(dirname "$0")/.."

COWRIE_CFG="cowrie/cowrie.cfg"
OC_CONF="opencanary/opencanary.conf"

# Coherent OS profiles: hostname, SSH version and the os-release/issue/motd
# values always come from the SAME profile, so nothing contradicts (no Debian
# banner next to an Ubuntu MOTD). Format per line:
#   ssh_version|pretty_name|version_id|os_id|hostname hostname ...
OS_PROFILES=(
  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6|Ubuntu 22.04.4 LTS|22.04|ubuntu|web-prod-01 app-node-3 vps-fra-1 cloud-07 srv01"
  "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9|Ubuntu 20.04.6 LTS|20.04|ubuntu|host-de-2 node-a4 backup-01 db02 intranet-sv"
  "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3|Debian GNU/Linux 12 (bookworm)|12|debian|mail01 ns1 gw-edge-02 fileserver kvm-12"
  "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2|Debian GNU/Linux 10 (buster)|10|debian|srv-web-01 vps-01 edge02 relay1 store-03"
  "SSH-2.0-OpenSSH_7.4|CentOS Linux 7 (Core)|7|centos|cpanel01 whm-node app-rhel-2 www3 mysql-01"
)

HTTP_BANNERS=(
  "Apache/2.4.52 (Ubuntu)"
  "Apache/2.2.22 (Ubuntu)"
  "nginx/1.18.0 (Ubuntu)"
  "Apache/2.4.41 (Ubuntu)"
  "nginx/1.14.2"
  "Apache/2.4.29 (Ubuntu)"
)

MYSQL_BANNERS=(
  "5.5.43-0ubuntu0.14.04.1"
  "5.7.33-0ubuntu0.16.04.1"
  "8.0.28-0ubuntu0.20.04.3"
  "5.6.51"
  "10.3.39-MariaDB-0ubuntu0.20.04.1"
)

FTP_BANNERS=(
  "vsFTPd 3.0.3"
  "ProFTPD 1.3.5 Server"
  "Pure-FTPd"
  "FTP server ready"
  "FileZilla Server"
)

# Web-Decoy personas (must match webdecoy/webdecoy.py).
WEB_PERSONAS=(apache_old wordpress phpmyadmin springboot router)

pick() { local a=("$@"); echo "${a[$((RANDOM % ${#a[@]}))]}"; }

# --- pick a coherent OS profile ---
PROFILE=$(pick "${OS_PROFILES[@]}")
IFS='|' read -r SSH_V OS_PRETTY OS_VERID OS_ID HOSTPOOL <<<"$PROFILE"
# shellcheck disable=SC2206
HOSTS=($HOSTPOOL)
HOSTNAME_V=$(pick "${HOSTS[@]}")

MYSQL_V=$(pick "${MYSQL_BANNERS[@]}")
FTP_V=$(pick "${FTP_BANNERS[@]}")
PERSONA_V=$(pick "${WEB_PERSONAS[@]}")
NODE_ID="node-$(tr -dc 'a-f0-9' </dev/urandom | head -c 8)"

# sed with | as delimiter (banners contain / but never |).
sed -i -E "s|^hostname = .*|hostname = ${HOSTNAME_V}|" "$COWRIE_CFG"
sed -i -E "s|^version = .*|version = ${SSH_V}|" "$COWRIE_CFG"

sed -i -E "s|(\"device.node_id\": )\"[^\"]*\"|\1\"${NODE_ID}\"|" "$OC_CONF"
sed -i -E "s|(\"mysql.banner\": )\"[^\"]*\"|\1\"${MYSQL_V}\"|" "$OC_CONF"
sed -i -E "s|(\"ftp.banner\": )\"[^\"]*\"|\1\"${FTP_V}\"|" "$OC_CONF"

# Web-Persona in die .env schreiben (die docker compose liest). Nur wenn .env da
# ist; sonst Hinweis. Bestehende Zeile ersetzen, sonst anhaengen.
ENV_FILE=".env"
if [ -f "$ENV_FILE" ]; then
  if grep -q "^WEBDECOY_PERSONA=" "$ENV_FILE"; then
    sed -i -E "s|^WEBDECOY_PERSONA=.*|WEBDECOY_PERSONA=${PERSONA_V}|" "$ENV_FILE"
  else
    printf '\nWEBDECOY_PERSONA=%s\n' "$PERSONA_V" >> "$ENV_FILE"
  fi
  PERSONA_NOTE="(in .env gesetzt)"
else
  PERSONA_NOTE="(keine .env gefunden, setze WEBDECOY_PERSONA=${PERSONA_V} selbst)"
fi

# --- honeyfs persona (best effort): os-release/issue/motd passend zum Profil ---
# Honeyfs-Pfad je nach Layout. Nur schreiben, wenn das Verzeichnis existiert;
# in deny-all wird es ohnehin nie gezeigt, es ist Vorbereitung fuer spaeter.
HONEYFS=""
for cand in "cowrie/honeyfs" "honeyfs" "cowrie/src/cowrie/data/honeyfs"; do
  if [ -d "$cand/etc" ] || [ -d "$cand" ]; then HONEYFS="$cand"; break; fi
done
HONEYFS_NOTE="(kein honeyfs gefunden, uebersprungen)"
if [ -n "$HONEYFS" ]; then
  mkdir -p "$HONEYFS/etc"
  if [ "$OS_ID" = "centos" ]; then
    printf 'NAME="CentOS Linux"\nVERSION="7 (Core)"\nID="centos"\nVERSION_ID="7"\nPRETTY_NAME="%s"\n' \
      "$OS_PRETTY" > "$HONEYFS/etc/os-release"
    printf '\\S\nKernel \\r on an \\m\n\n' > "$HONEYFS/etc/issue"
  else
    printf 'PRETTY_NAME="%s"\nNAME="%s"\nVERSION_ID="%s"\nID=%s\nID_LIKE=debian\n' \
      "$OS_PRETTY" "${OS_PRETTY%% *}" "$OS_VERID" "$OS_ID" > "$HONEYFS/etc/os-release"
    printf '%s \\n \\l\n\n' "$OS_PRETTY" > "$HONEYFS/etc/issue"
  fi
  printf 'Welcome to %s (GNU/Linux)\n\n * Documentation:  https://help.%s.com\n\n' \
    "$OS_PRETTY" "$OS_ID" > "$HONEYFS/etc/motd"
  HONEYFS_NOTE="(os-release/issue/motd in $HONEYFS/etc geschrieben)"
fi

# --- SSH-Hostkey pro Node eindeutig machen ---
# Geklonte/aus einem Image gestartete Nodes teilen sich sonst denselben
# Cowrie-Hostkey und sind damit trivial als eine Flotte zu korrelieren. Die
# vorhandenen Hostkeys entfernen, Cowrie erzeugt beim naechsten Start frische,
# eindeutige. Beide ueblichen Pfade abdecken (bare-metal und Volume-Mount).
KEY_NOTE="(kein Hostkey-Verzeichnis gefunden)"
for kd in "cowrie/var/lib/cowrie" "var/lib/cowrie" "/home/cowrie/cowrie/var/lib/cowrie"; do
  if [ -d "$kd" ] && ls "$kd"/ssh_host_*_key >/dev/null 2>&1; then
    rm -f "$kd"/ssh_host_*_key "$kd"/ssh_host_*_key.pub 2>/dev/null || true
    KEY_NOTE="(Hostkeys in $kd entfernt, Cowrie erzeugt beim Start frische)"
    break
  fi
done

echo "Node-Fingerprint neu gewuerfelt (kohaerentes Profil):"
echo "  os profil     ${OS_PRETTY} (${OS_ID} ${OS_VERID})"
echo "  hostname      ${HOSTNAME_V}"
echo "  ssh version   ${SSH_V}"
echo "  node_id       ${NODE_ID}"
echo "  mysql         ${MYSQL_V}"
echo "  ftp           ${FTP_V}"
echo "  web persona   ${PERSONA_V} ${PERSONA_NOTE}"
echo "  honeyfs       ${HONEYFS_NOTE}"
echo "  ssh hostkey   ${KEY_NOTE}"
echo
echo "Jetzt neu starten: docker compose up -d"
