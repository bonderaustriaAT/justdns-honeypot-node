#!/usr/bin/env bash
# Rolls this node's fingerprint to random, realistic values so several nodes do
# not look like the same fleet. Edits the config files in place:
#
#   cowrie/cowrie.cfg        hostname + SSH version banner
#   opencanary/opencanary.conf  node_id + FTP/HTTP/MySQL banners
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

# Realistic, boring pools. Nothing here points back to JustDNS.
HOSTNAMES=(srv01 web-prod-01 db02 mail01 vps-fra-1 app-node-3 gw-edge-02 \
  fileserver backup-01 ns1 cloud-07 kvm-12 host-de-2 node-a4 intranet-sv)

SSH_VERSIONS=(
  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  "SSH-2.0-OpenSSH_7.4"
  "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9"
  "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
  "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
  "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
  "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
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

pick() { local a=("$@"); echo "${a[$((RANDOM % ${#a[@]}))]}"; }

HOSTNAME_V=$(pick "${HOSTNAMES[@]}")
SSH_V=$(pick "${SSH_VERSIONS[@]}")
HTTP_V=$(pick "${HTTP_BANNERS[@]}")
MYSQL_V=$(pick "${MYSQL_BANNERS[@]}")
FTP_V=$(pick "${FTP_BANNERS[@]}")
NODE_ID="node-$(tr -dc 'a-f0-9' </dev/urandom | head -c 8)"

# sed with | as delimiter (banners contain / but never |).
sed -i -E "s|^hostname = .*|hostname = ${HOSTNAME_V}|" "$COWRIE_CFG"
sed -i -E "s|^version = .*|version = ${SSH_V}|" "$COWRIE_CFG"

sed -i -E "s|(\"device.node_id\": )\"[^\"]*\"|\1\"${NODE_ID}\"|" "$OC_CONF"
sed -i -E "s|(\"http.banner\": )\"[^\"]*\"|\1\"${HTTP_V}\"|" "$OC_CONF"
sed -i -E "s|(\"mysql.banner\": )\"[^\"]*\"|\1\"${MYSQL_V}\"|" "$OC_CONF"
sed -i -E "s|(\"ftp.banner\": )\"[^\"]*\"|\1\"${FTP_V}\"|" "$OC_CONF"

echo "Node-Fingerprint neu gewuerfelt:"
echo "  hostname    ${HOSTNAME_V}"
echo "  ssh version ${SSH_V}"
echo "  node_id     ${NODE_ID}"
echo "  http        ${HTTP_V}"
echo "  mysql       ${MYSQL_V}"
echo "  ftp         ${FTP_V}"
echo
echo "Jetzt neu starten: docker compose up -d"
