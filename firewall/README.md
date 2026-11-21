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

### Privacy

Only source IP, reason (`ips_alert`/`fw_drop`) and signature name are reported.
Private IPs are flagged by the Intake and never published.

### Files

- `unifi_reader.py` - reader (stdlib, read-only).
- `justdns-unifi.conf.example` - configuration template.
- `systemd/justdns-unifi.{service,timer}` - timer units.
