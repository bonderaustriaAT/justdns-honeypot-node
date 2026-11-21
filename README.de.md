# JustDNS Honeypot Node

*English: [README.md](README.md)*

Betreibe einen kleinen Honeypot und hilf dabei, genau die Leute zu blocken, die
ihn angreifen. Dieses Repo liefert dir einen fertigen Multi-Service-Honeypot
(Cowrie fuer SSH; OpenCanary fuer FTP, Telnet, MySQL, RDP, VNC und Redis; ein
Web-Decoy fuer HTTP, die Docker-API und Elasticsearch) und einen Shipper, der
jeden Versuch an JustDNS meldet. Daraus entsteht die oeffentliche Blockliste
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
die jeder zum Filtern bekannter Angreifer nutzen kann.

Jeder Dienst ist ein reiner Koeder. Er zeigt bewusst alte, "verwundbar"
aussehende Versionen, um Angreifer anzulocken, laeuft aber nichts Echtes, es gibt
also keine echte Luecke zum Ausnutzen. Siehe [Sicherheit](#sicherheit).

Dein Node registriert sich beim ersten Start selbst, du musst dich also nirgends
anmelden. Er laeuft einfach und meldet, was er sieht.

## So funktioniert es

```
  Angreifer
     |
     v
  Cowrie      SSH                            -> cowrie.json
  OpenCanary  FTP/Telnet/MySQL/RDP/VNC/Redis -> opencanary.log
  Web-Decoy   HTTP / Docker-API / Elastic    -> webdecoy.log
     |
     v
  Shipper  ------->  JustDNS  ------->  oeffentliche Blockliste: justdns-threat-ips
```

Hinter dem Honeypot steckt kein echter Dienst. Jeder Login scheitert mit Absicht
und jede "verwundbare" Seite ist eine feste Attrappe, dadurch wird jeder Versuch
erfasst und der Angreifer kommt nirgendwo Echtes hin. Der Shipper liest die Logs,
buendelt das Neue und schickt es an JustDNS. Ist JustDNS mal nicht erreichbar,
geht nichts verloren: der Shipper macht beim naechsten Lauf da weiter, wo er
aufgehoert hat.

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
./scripts/randomize-node.sh   # einmalig: Fingerprint (Hostname, Banner) wuerfeln
docker compose up -d
```

`randomize-node.sh` setzt Hostname, SSH-Version, die FTP/MySQL-Banner und die
Web-Decoy-Persona auf zufaellige, plausible Werte. So sehen mehrere Nodes nicht
wie dieselbe Flotte aus und sind schwerer als Honeypot zu erkennen. Der Schritt
ist optional, aber empfohlen, vor allem wenn du mehr als einen Node betreibst.

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

| Dienst        | Angreifer treffen (WAN) | Auf diesen Host weiterleiten | Faengt |
|---------------|-------------------------|------------------------------|--------|
| SSH           | tcp/22                  | tcp/2222                     | Cowrie |
| FTP           | tcp/21                  | tcp/21                       | OpenCanary |
| Telnet        | tcp/23                  | tcp/23                       | OpenCanary |
| MySQL         | tcp/3306                | tcp/3306                     | OpenCanary |
| RDP           | tcp/3389                | tcp/3389                     | OpenCanary |
| VNC           | tcp/5900                | tcp/5900                     | OpenCanary |
| Redis         | tcp/6379                | tcp/6379                     | OpenCanary |
| HTTP          | tcp/80                  | tcp/80                       | Web-Decoy |
| HTTP (alt)    | tcp/8080                | tcp/8080                     | Web-Decoy |
| Docker-API    | tcp/2375                | tcp/2375                     | Web-Decoy |
| Elasticsearch | tcp/9200                | tcp/9200                     | Web-Decoy |

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
`http://<node-ip>:8090` (die LAN-Adresse des Nodes; 8080 ist ein
Angreifer-Port).

Es zeigt Angreifer-Zugangsdaten, also halte es im internen Netz und leite es
nicht aus dem WAN weiter. Brauchst du doch Zugriff von aussen, setze
`NODEUI_TOKEN` in `.env` und haeng einen TLS-Reverse-Proxy davor.

Auf einem nackten Host (systemd) laeuft es wie der Shipper: `nodeui/nodeui.py`
nach `/opt/justdns-nodeui/` installieren und
`nodeui/systemd/justdns-nodeui.service` aktivieren.

## Dienste auf diesem Node

Ab Werk startet `docker compose up -d` alle drei Decoys:

- **SSH** auf 2222, via Cowrie.
- **FTP, Telnet, MySQL, RDP, VNC, Redis**, via OpenCanary, auf ihren
  Standard-Ports.
- **HTTP (80, 8080), Docker-API (2375), Elasticsearch (9200)**, via Web-Decoy.
  Es zeigt pro Node eine "verwundbare" Persona und antwortet auf die Pfade, die
  Scanner abklopfen, alles als feste Attrappen.

Jeder Versuch wird protokolliert und gesendet. Die OpenCanary-Config liegt in
[`opencanary/opencanary.conf`](opencanary/opencanary.conf) (setz `device.node_id`
auf deinen eigenen Namen, wenn du magst); ein Protokoll abschalten: sein
`*.enabled` auf `false` setzen und seinen Port aus der `docker-compose.yml`
nehmen. Die Web-Personas stehen in
[`webdecoy/webdecoy.py`](webdecoy/webdecoy.py); die aktive ist `WEBDECOY_PERSONA`
in `.env`, gewuerfelt von `randomize-node.sh`. Hinweise zum Betrieb von
OpenCanary ohne Docker stehen in [opencanary/README.md](opencanary/README.md).

## Sicherheit

Alles hier ist ein Koeder. Es gibt keine echte Luecke zum Oeffnen, weil hinter
keinem Port ein echter Dienst steckt:

- Die "verwundbaren" Versionen (altes Apache, altes Elasticsearch, eine offene
  Docker-API und so weiter) sind nur Banner und feste Fake-Seiten. Fuer einen
  Scanner sehen sie ausnutzbar aus, dahinter laeuft aber nichts.
- Das Web-Decoy fasst nie die Festplatte an. Jede Antwort kommt aus einer festen
  Map im Code, Path-Traversal wie `/../../etc/passwd` trifft also nichts Echtes.
  Es fuehrt keinen hochgeladenen Code aus und speichert keine Uploads.
- Cowrie und OpenCanary sind isolierte Fake-Implementierungen; ein Login kommt
  nie in etwas Echtes hinein.
- Trotzdem: auf einem wegwerfbaren Host betreiben und deine eigenen echten
  Dienste auf anderen Ports halten. Ein Koeder ist nur sicher, solange nichts
  Echtes daneben liegt.

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

Das Web-Decoy laeuft genauso (nur Standardbibliothek). Ist Port 80 am Host belegt,
in der Unit aus `WEBDECOY_WEB_PORTS` nehmen und nur 8080 lassen:

```bash
sudo install -D webdecoy/webdecoy.py /opt/justdns-webdecoy/webdecoy.py
sudo cp webdecoy/systemd/justdns-webdecoy.service /etc/systemd/system/
# optional: in der Unit WEBDECOY_WEB_PORTS=8080 setzen, wenn 80 belegt ist
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-webdecoy.service
```

Damit sich eine bare-metal-Node selbst aktualisiert, den nativen Self-Update-Timer
installieren. Er holt dieses Repo einmal am Tag und spielt den Shipper neu ein
(Cowrie und OpenCanary sind Upstream und bleiben unangetastet):

```bash
sudo cp scripts/systemd/justdns-update-native.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-update-native.timer
```

## Aktualisieren

Von Hand, aus dem Repo-Verzeichnis:

```bash
./scripts/self-update.sh
```

Holt neue Commits und Images und baut nur das neu, was sich geaendert hat. Deine
lokalen Fingerprint-Aenderungen aus `randomize-node.sh` bleiben erhalten. Der
alte manuelle Weg geht weiter (`git pull && docker compose pull && docker compose
up -d`).

### Automatische Updates

Die Node aktualisiert sich selbst, ohne Extra-Container. Den systemd-Timer einmal
installieren (Pfad in der Unit anpassen, falls du woanders als nach
`/opt/justdns-honeypot-node` geklont hast):

```bash
sudo cp scripts/systemd/justdns-update.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-update.timer
```

Laeuft einmal am Tag mit zufaelliger Verzoegerung. Pruefen mit
`systemctl list-timers justdns-update.timer` und
`journalctl -u justdns-update.service`. Die Image-Versionen bleiben gepinnt, ein
Update bringt also nur, was in einem neuen Commit steht; nichts springt von
selbst auf eine neue Version.

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
