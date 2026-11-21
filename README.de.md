# JustDNS Honeypot Node

*English: [README.md](README.md)*

Betreibe einen kleinen Honeypot und hilf dabei, genau die Leute zu blocken, die
ihn angreifen. Dieses Repo liefert dir einen fertigen Multi-Service-Honeypot
(Cowrie fuer SSH, dazu OpenCanary fuer FTP, Telnet, HTTP, MySQL, RDP und VNC)
und einen Shipper, der jeden Versuch an JustDNS meldet. Daraus entsteht die
oeffentliche Blockliste
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
die jeder zum Filtern bekannter Angreifer nutzen kann.

Dein Node registriert sich beim ersten Start selbst, du musst dich also nirgends
anmelden. Er laeuft einfach und meldet, was er sieht.

## So funktioniert es

```
  Angreifer
     |
     v
  Cowrie      SSH-Login-Versuche            -> cowrie.json
  OpenCanary  FTP/Telnet/HTTP/MySQL/RDP/VNC -> opencanary.log
     |
     v
  Shipper  ------->  JustDNS  ------->  oeffentliche Blockliste: justdns-threat-ips
```

Hinter dem Honeypot steckt kein echter Dienst. Jeder Login scheitert mit
Absicht, dadurch wird jeder Versuch erfasst und der Angreifer kommt nirgendwo
hin. Der Shipper liest die Logs, buendelt das Neue und schickt es an JustDNS.
Ist JustDNS mal nicht erreichbar, geht nichts verloren: der Shipper macht beim
naechsten Lauf da weiter, wo er aufgehoert hat.

## Was dein Node an uns sendet

Das ist der wichtige Teil, deshalb hier vollstaendig. Pro Angriffsversuch
schickt der Shipper genau diese Felder:

| Feld        | Beispiel                | Wozu |
|-------------|-------------------------|------|
| `sensor_id` | `own-berlin-01`         | welcher Node gemeldet hat |
| `ts`        | `2026-11-21T10:00:00Z`  | wann es passiert ist (UTC) |
| `src_ip`    | `203.0.113.7`           | die IP des Angreifers |
| `service`   | `SSH`                   | welcher Dienst getroffen wurde |
| `dst_port`  | `2222`                  | der Port auf deinem Node |
| `username`  | `root`                  | der probierte Benutzername |
| `password`  | `123456`                | das probierte Passwort |

Ja, die probierten Benutzernamen und Passwoerter sind dabei. Wir behalten sie,
damit die Zugangsdaten in Abuse-Meldungen an die Netze fliessen koennen, aus
denen die Angriffe kommen. Es sind die Rateversuche des Angreifers gegen einen
Fake-Dienst, nicht die echten Zugangsdaten von irgendwem.

Was wir **nicht** bekommen: nichts ueber dich oder deine Maschine. Keine
Hostnamen, keine Systemdaten, keine Dateiinhalte, keinen Traffic ausser den
oben genannten Login-Versuchen am Honeypot.

Was damit passiert: die Angreifer-IPs landen in der oeffentlichen Blockliste,
damit andere sie filtern koennen, und die Zugangsdaten gehen in Abuse-Meldungen
an die betroffenen Netze.

## Voraussetzungen

- Ein Linux-Host, den du bedenkenlos ins Internet stellst, am besten ein
  kleiner VPS oder eine isolierte VM. Behandle ihn als wegwerfbar.
- Docker samt Docker-Compose-Plugin, oder ein nackter Host, wenn du lieber den
  systemd-Weg weiter unten gehst.
- Keine Anmeldung noetig. Dein Node registriert sich beim ersten Start selbst.

## Node registrieren

Du musst dich nirgends anmelden. Beim ersten Lauf registriert sich der Shipper
selbst bei JustDNS und sendet sofort. Wenn du moechtest, dass wir wissen, dass
ein Node von dir ist, mach ein Issue in diesem Repo auf oder melde dich ueber
den Kontakt auf der JustDNS-Seite.

## Schnellstart (Docker)

```bash
git clone https://github.com/bonderaustriaAT/justdns-honeypot-node.git
cd justdns-honeypot-node
cp .env.example .env
# optional: in .env einen Node-Namen (SENSOR_ID) setzen. Kein Token noetig.
docker compose up -d
```

Der erste Lauf baut einmalig das OpenCanary-Image und startet dann Cowrie (SSH
auf 2222), OpenCanary (die anderen Dienste), den Shipper und die Live-Ansicht.
Pruefen, ob alles laeuft:

```bash
docker compose ps
docker compose logs -f shipper
```

Der Shipper schreibt bei jedem Lauf, wie viele Events er gesendet hat. Auf
einem frischen Node steht das auf null, bis der erste Angreifer auftaucht, was
auf einer oeffentlichen IP meist nicht lange dauert.

## Angriffe auf den Node leiten: Port-Forwarding

Dein Node faengt nur, was ihn auch erreicht. Leite darum die Dienst-Ports vom
WAN (Heim-Router oder Cloud-Firewall) auf diesen Host weiter. Nur SSH wechselt
den Port, weil Cowrie auf 2222 lauscht; alles andere geht 1:1 durch.

| Dienst  | Angreifer treffen (WAN) | Auf diesen Host weiterleiten | Faengt |
|---------|-------------------------|------------------------------|--------|
| SSH     | tcp/22                  | tcp/2222                     | Cowrie |
| FTP     | tcp/21                  | tcp/21                       | OpenCanary |
| Telnet  | tcp/23                  | tcp/23                       | OpenCanary |
| HTTP    | tcp/80                  | tcp/80                       | OpenCanary |
| MySQL   | tcp/3306                | tcp/3306                     | OpenCanary |
| RDP     | tcp/3389                | tcp/3389                     | OpenCanary |
| VNC     | tcp/5900                | tcp/5900                     | OpenCanary |

- **Heim-Router:** fuer jeden WAN-Port oben eine Portweiterleitung auf die
  LAN-IP dieses Hosts anlegen, Ziel ist der "weiterleiten"-Port. SSH 22 geht auf
  2222, der Rest auf dieselbe Nummer.
- **Cloud-VPS:** diese Ports in der Firewall bzw. Security-Group oeffnen. Sie
  liegen schon auf dem passenden Port, ausser SSH, das du auf 2222 schickst
  (oder `COWRIE_SSH_PORT=22` setzen, siehe unten).

Du musst nicht alle weiterleiten. SSH allein zieht schon staendig Traffic; die
anderen holst du dir fuer mehr dazu.

SSH direkt auf Port 22: ist Port 22 am Host frei (dein Admin-SSH laeuft woanders),
setze `COWRIE_SSH_PORT=22` in `.env`, starte `docker compose up -d` neu und
leite WAN tcp/22 direkt auf 22.

Halte deine eigenen echten Dienste und dein echtes SSH auf anderen Ports und
leite nie eine Weiterleitung auf etwas Echtes.

## Pruefen, ob es laeuft

```bash
# hat der Honeypot schon etwas protokolliert?
docker compose exec cowrie tail -f var/log/cowrie/cowrie.json

# was hat der Shipper gesendet?
docker compose logs --tail=20 shipper
```

Echte Versuche gehen sofort an JustDNS. Die Angreifer-IPs tauchen kurz darauf in
der oeffentlichen Blockliste auf.

## Live-Ansicht auf deinem Node

Zum Setup gehoert ein kleines lokales Dashboard, das die Angriffe auf deinen
eigenen Node in Echtzeit zeigt: Quell-IPs, welcher Dienst getroffen wurde, und
die Benutzernamen und Passwoerter, die die Angreifer probiert haben, mit den
aktivsten Quellen daneben. Es liest dieselben Logs wie der Shipper und
aktualisiert sich alle paar Sekunden.

Mit Docker laeuft es bereits und ist aus deinem internen Netz erreichbar unter
`http://<node-ip>:8080` (die LAN-Adresse des Nodes).

Es zeigt Angreifer-Zugangsdaten, also halte es im internen Netz und leite es
nicht aus dem WAN weiter. Brauchst du doch Zugriff von aussen, setze
`NODEUI_TOKEN` in `.env` und haeng einen TLS-Reverse-Proxy davor.

Auf einem nackten Host (systemd) laeuft es wie der Shipper: `nodeui/nodeui.py`
nach `/opt/justdns-nodeui/` installieren und
`nodeui/systemd/justdns-nodeui.service` aktivieren.

## Dienste auf diesem Node

Ab Werk laufen beide Honeypots, `docker compose up -d` deckt also schon ab:

- **SSH** auf 2222, via Cowrie.
- **FTP, Telnet, HTTP, MySQL, RDP, VNC**, via OpenCanary, auf ihren
  Standard-Ports.

Jeder Versuch auf einem davon wird gleich protokolliert und gesendet und taucht
in der Live-Ansicht auf. Die OpenCanary-Config liegt in
[`opencanary/opencanary.conf`](opencanary/opencanary.conf); setz
`device.node_id` auf deinen eigenen Namen, wenn du magst. Einen Dienst
abschalten: dort sein `*.enabled` auf `false` setzen und seinen Port aus der
`docker-compose.yml` nehmen. Hinweise zum Betrieb von OpenCanary ohne Docker
stehen in [opencanary/README.md](opencanary/README.md).

## Ohne Docker (systemd)

Wenn du Cowrie (und evtl. OpenCanary) schon auf dem Host betreibst, kannst du
nur den Shipper laufen lassen:

```bash
sudo install -D shipper/shipper.py /opt/justdns-shipper/shipper.py
sudo cp shipper/shipper.conf.example /etc/justdns-shipper.conf
# /etc/justdns-shipper.conf bearbeiten: INTAKE_URL und deine Logpfade (kein Token noetig)
sudo install -d -o cowrie -g cowrie /var/lib/justdns-shipper
sudo cp shipper/systemd/justdns-shipper.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-shipper.timer
```

Der Shipper braucht nur die Python-Standardbibliothek, also keine extra Pakete.

## Aktualisieren

```bash
git pull
docker compose pull
docker compose up -d
```

## Sicherheitshinweise

- Betreibe das auf einem Host, den du wegwerfen kannst. Es ist ein Koeder, kein
  Dienst, auf den du dich verlaesst.
- Lass nichts Echtes auf dem weitergeleiteten Port laufen.
- Der Honeypot laesst niemanden rein, es gibt also keine Shell zum Ausbrechen,
  trotzdem ist eine isolierte Box gute Praxis.

## Stoppen oder aufhoeren

```bash
docker compose down
```

Sag uns Bescheid, wenn du endgueltig aufhoerst. Schon beigetragene Daten bleiben
in der oeffentlichen Blockliste, es sind nur Angreifer-IPs, nichts
Persoenliches.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
