# JustDNS Firewall-Reader (Unifi, nur lesen)

Liest IPS/IDS-Alarme und Firewall-Drops vom Unifi-Controller und meldet die
Quell-IPs an die Fleet-Intake. Nur lesen, keine Aenderung am Controller.

Reads IPS/IDS alerts and firewall drops from the Unifi controller and reports the
source IPs to the Fleet-Intake. Read-only, no change to the controller.

---

## Deutsch

### Einrichten

Auf dem Host (z. B. neben der Intake) `justdns-unifi.conf.example` nach
`/etc/justdns-unifi.conf` kopieren und ausfuellen: Auth per **API-Key** (UniFi OS,
empfohlen) **oder** lokalem Konto (nur lesen). Dann:

```
install -m 644 systemd/justdns-unifi.service /etc/systemd/system/
install -m 644 systemd/justdns-unifi.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now justdns-unifi.timer
```

Der Reader registriert sich beim ersten Lauf selbst als Firewall-Sensor
(`kind=firewall`) und muss danach im Dashboard freigegeben werden. Selbstsigniertes
Controller-Zertifikat im LAN: `VERIFY_TLS=0`.

### API-Key erzeugen (UniFi OS)

Bevorzugte Auth ist ein UniFi-OS-API-Key (Header `X-API-KEY`). Im Controller:

1. Controller-Oberflaeche oeffnen (UniFi OS, die Gateway-/Cloud-Key-IP).
2. **Einstellungen -> Control Plane -> Integrations** (je nach Version auch oben
   rechts ueber das Konto-/Admin-Menue), **API-Key erstellen**.
3. Der Key wird **nur einmal** angezeigt - sofort kopieren und in
   `UNIFI_API_KEY` eintragen.

Nur-lesen: den Key unter einem **Viewer**-Admin (read-only Rolle) erzeugen, dann
kann er nichts aendern. Der Reader liest ohnehin nur (`/stat/alarm`). Alternativ
ein lokales Viewer-Konto als `UNIFI_USER` + `UNIFI_PASS`.

### Datenschutz

Es werden nur Quell-IP, Grund (`ips_alert`/`fw_drop`) und Signaturname gemeldet.
Private IPs werden von der Intake markiert und nie veroeffentlicht.

### Dateien

- `unifi_reader.py` - Reader (stdlib, nur lesen).
- `justdns-unifi.conf.example` - Konfigurationsvorlage.
- `systemd/justdns-unifi.{service,timer}` - Timer-Units.

---

## English

### Setup

On the host (e.g. next to the Intake), copy `justdns-unifi.conf.example` to
`/etc/justdns-unifi.conf` and fill it in: auth via **API key** (UniFi OS,
recommended) **or** a local account (read-only). Then:

```
install -m 644 systemd/justdns-unifi.service /etc/systemd/system/
install -m 644 systemd/justdns-unifi.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now justdns-unifi.timer
```

The reader self-registers as a firewall sensor (`kind=firewall`) on first run and
must then be approved in the dashboard. Self-signed controller certificate on the
LAN: `VERIFY_TLS=0`.

### Create an API key (UniFi OS)

Preferred auth is a UniFi OS API key (header `X-API-KEY`). In the controller:

1. Open the controller UI (UniFi OS, the gateway/Cloud Key IP).
2. **Settings -> Control Plane -> Integrations** (depending on version also via the
   account/admin menu top right), **Create API Key**.
3. The key is shown **only once** - copy it immediately and set it in
   `UNIFI_API_KEY`.

Read-only: create the key under a **Viewer** admin (read-only role) so it cannot
change anything. The reader only reads anyway (`/stat/alarm`). Alternatively use a
local Viewer account as `UNIFI_USER` + `UNIFI_PASS`.

### Privacy

Only source IP, reason (`ips_alert`/`fw_drop`) and signature name are reported.
Private IPs are flagged by the Intake and never published.

### Files

- `unifi_reader.py` - reader (stdlib, read-only).
- `justdns-unifi.conf.example` - configuration template.
- `systemd/justdns-unifi.{service,timer}` - timer units.
