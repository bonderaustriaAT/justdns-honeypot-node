# JustDNS Firewall-Reader (Unifi, nur lesen)

Die Honeypot-Node fragt den Unifi-Controller direkt ab und holt **alle** geblockten
externen Zugriffe (ext->intern und ext->Gateway) aus dem UniFi-OS-System-Log
(Kategorie SECURITY: IPS/IDS und Firewall-Drops), nicht nur IPS. Nur lesend, keine
Aenderung am Controller. Die Quell-IPs gehen an die Node; sie leitet an die Intake weiter.

The honeypot node queries the Unifi controller directly and pulls **all** blocked
external accesses (ext->internal and ext->gateway) from the UniFi OS system log
(category SECURITY: IPS/IDS and firewall drops), not just IPS. Read-only, no change to
the controller. Source IPs go to the node, which forwards them to the Intake.

---

## Deutsch

### Einrichten (aus der Node-UI)

In der Node-UI auf **+ Sensor anbinden** gehen, unter *Firewall anbinden* Controller-URL,
Site und den read-only API-Key eintragen und **Firewall verbinden** klicken. Die Node
testet den Controller, meldet die Firewall als Sensor an und holt die Block-Logs danach
jede Minute. Der API-Key bleibt auf der Node und geht nicht an die Intake.

Selbstsigniertes Controller-Zertifikat im LAN: Haekchen *TLS-Pruefung aus* gesetzt lassen.

### API-Key erzeugen (UniFi OS)

Auth ist ein UniFi-OS-API-Key (Header `X-API-KEY`). Im Controller:

1. Controller-Oberflaeche oeffnen (UniFi OS, die Gateway-/Cloud-Key-IP).
2. **Einstellungen -> Control Plane -> Integrations**, **API-Key erstellen**.
3. Der Key wird **nur einmal** angezeigt, sofort kopieren.

Nur-lesen: den Key unter einem **Viewer**-Admin (read-only Rolle) erzeugen. Der Reader
liest ohnehin nur das System-Log.

### Manuell / auf einem anderen Host (optional)

Statt der Direktanbindung kann `unifi_reader.py` auch eigenstaendig laufen:
`justdns-unifi.conf.example` nach `/etc/justdns-unifi.conf` kopieren, ausfuellen
(`UNIFI_URL`, `UNIFI_API_KEY`, `UNIFI_SITE`, `INTAKE_URL` auf die Node zeigen) und die
Units aktivieren:

```
install -m 644 systemd/justdns-unifi.service /etc/systemd/system/
install -m 644 systemd/justdns-unifi.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now justdns-unifi.timer
```

### Datenschutz

Gemeldet werden nur Quell-IP, Grund (`ips_alert`/`fw_drop`) und Signaturname. Private IPs
werden von der Intake markiert und nie veroeffentlicht.

### Dateien

- `unifi_reader.py` - Reader (stdlib, nur lesen, System-Log + klassische Alarme).
- `justdns-unifi.conf.example` - Konfigurationsvorlage fuer den manuellen Betrieb.
- `systemd/justdns-unifi.{service,timer}` - Timer-Units fuer den manuellen Betrieb.

---

## English

### Setup (from the node UI)

In the node UI open **+ Sensor anbinden**, under *Firewall anbinden* enter the controller
URL, site and the read-only API key, then click **Firewall verbinden**. The node tests the
controller, registers the firewall as a sensor and pulls the block logs every minute
afterwards. The API key stays on the node and is not sent to the Intake.

Self-signed controller certificate on the LAN: leave *TLS-Pruefung aus* checked.

### Create an API key (UniFi OS)

Auth is a UniFi OS API key (header `X-API-KEY`). In the controller:

1. Open the controller UI (UniFi OS, the gateway/Cloud Key IP).
2. **Settings -> Control Plane -> Integrations**, **Create API Key**.
3. The key is shown **only once**, copy it immediately.

Read-only: create the key under a **Viewer** admin (read-only role). The reader only reads
the system log anyway.

### Manual / on another host (optional)

Instead of the direct connection, `unifi_reader.py` can run standalone: copy
`justdns-unifi.conf.example` to `/etc/justdns-unifi.conf`, fill it in (`UNIFI_URL`,
`UNIFI_API_KEY`, `UNIFI_SITE`, `INTAKE_URL` pointing at the node) and enable the units:

```
install -m 644 systemd/justdns-unifi.service /etc/systemd/system/
install -m 644 systemd/justdns-unifi.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now justdns-unifi.timer
```

### Privacy

Only source IP, reason (`ips_alert`/`fw_drop`) and signature name are reported. Private IPs
are flagged by the Intake and never published.

### Files

- `unifi_reader.py` - reader (stdlib, read-only, system log + classic alarms).
- `justdns-unifi.conf.example` - configuration template for standalone operation.
- `systemd/justdns-unifi.{service,timer}` - timer units for standalone operation.
