# JustDNS Honeypot Node

*English: [README.md](README.md)*

Betreibe einen kleinen Honeypot und hilf dabei, genau die Leute zu blocken, die
ihn angreifen. Dieses Repo liefert dir einen fertigen SSH-Honeypot (Cowrie) und
einen Shipper, der jeden Login-Versuch an JustDNS meldet. Von dort fliessen die
Quell-IPs in die oeffentliche Blockliste
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
die jeder zum Filtern bekannter Angreifer nutzen kann.

Dein Node bekommt nie Schreibrechte an der Liste. Er meldet nur, was er sieht.
Die Liste selbst wird zentral und erst nach Filterung von JustDNS gepflegt.

## So funktioniert es

```
  Angreifer
     |
     v
  Cowrie (SSH-Honeypot)         jeder Login-Versuch -> cowrie.json
  OpenCanary (optional)         FTP/Telnet/HTTP/... -> opencanary.log
     |
     v
  Shipper  --HTTPS POST /events (dein Token)-->  JustDNS Intake
                                                     |
                                                     v
                                     zentraler Processor + Filter
                                                     |
                                                     v
                          oeffentliche Liste: justdns-threat-ips
```

Hinter dem Honeypot steckt kein echter Dienst. Jeder Login scheitert mit
Absicht, dadurch wird jeder Versuch erfasst und der Angreifer kommt nirgendwo
hin. Der Shipper liest die Logs, buendelt das Neue und schickt es mit deinem
Token. Ist der Intake mal nicht erreichbar, geht nichts verloren: der Shipper
macht beim naechsten Lauf da weiter, wo er aufgehoert hat.

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
oben genannten Login-Versuchen am Honeypot. Das Token identifiziert deinen Node
und sonst nichts.

Noch ein paar Dinge, die du wissen solltest:

- Von einem externen Node wird eine IP erst dann fuer die Liste in Betracht
  gezogen, wenn sie mindestens **zwei** Versuche auf deinem Node gemacht hat.
  Ein einzelner Streifschuss wird ignoriert.
- Bevor etwas veroeffentlicht wird, werfen zentrale Filter bekannte Scanner und
  Research-Crawler raus (per Reverse-DNS), grosse geteilte Infrastruktur wie
  Cloudflare- und Google-Bereiche, Carrier-Grade-NAT und alles auf der
  Allowlist.
- Die oeffentliche Liste ist kumulativ. Einmal gelistet, bleibt eine IP
  gelistet.
- Dein Submission-Token ist write-only. Es kann Events melden und sonst nichts,
  und wir koennen es allein fuer deinen Node jederzeit widerrufen.

## Voraussetzungen

- Ein Linux-Host, den du bedenkenlos ins Internet stellst, am besten ein
  kleiner VPS oder eine isolierte VM. Behandle ihn als wegwerfbar.
- Docker samt Docker-Compose-Plugin, oder ein nackter Host, wenn du lieber den
  systemd-Weg weiter unten gehst.
- Eine `SENSOR_ID` und ein `TOKEN` von JustDNS (siehe unten).

## Token bekommen

Mach ein Issue in diesem Repo auf mit einer kurzen Notiz, dass du einen Node
betreiben willst, oder melde dich ueber den Kontakt auf der JustDNS-Seite. Du
bekommst eine `SENSOR_ID` und ein `TOKEN` zurueck. Das Token uebergeben wir
direkt, nicht in einem oeffentlichen Thread.

## Schnellstart (Docker)

```bash
git clone https://github.com/bonderaustriaAT/justdns-honeypot-node.git
cd justdns-honeypot-node
cp .env.example .env
# .env bearbeiten, SENSOR_ID und TOKEN eintragen
docker compose up -d
```

Das startet den Cowrie-Honeypot auf Port 2222 und daneben den Shipper. Pruefen,
ob beide laufen:

```bash
docker compose ps
docker compose logs -f shipper
```

Der Shipper schreibt bei jedem Lauf, wie viele Events er gesendet hat. Auf
einem frischen Node steht das auf null, bis der erste Angreifer auftaucht, was
auf einer oeffentlichen IP meist nicht lange dauert.

## Angreifer auf den Node leiten

Angreifer klopfen an Port 22. Der Honeypot lauscht auf 2222, also leitest du
den Traffic dorthin. Zwei gaengige Wege:

- Am Router oder in der Cloud-Firewall WAN `tcp/22` auf Port `2222` dieses
  Hosts weiterleiten.
- Oder, auf einem Host, wo Port 22 frei ist, in der `.env`
  `COWRIE_SSH_PORT=22` setzen und `docker compose up -d` erneut laufen lassen.
  Dann lauscht der Honeypot direkt auf 22.

Dein eigenes echtes SSH laeuft auf einem anderen Port und zeigt nicht auf den
Honeypot.

## Pruefen, ob es laeuft

```bash
# hat der Honeypot schon etwas protokolliert?
docker compose exec cowrie tail -f var/log/cowrie/cowrie.json

# was hat der Shipper gesendet?
docker compose logs --tail=20 shipper
```

Sobald echte Versuche auftauchen, erscheinen die Quell-IPs wenige Minuten nach
dem naechsten Lauf des zentralen Processors in der oeffentlichen Liste.

## Mehr Dienste (optional)

Cowrie deckt SSH ab, wo der meiste Laerm herkommt. Wenn du zusaetzlich FTP,
Telnet, HTTP, MySQL, RDP und VNC willst, stell OpenCanary daneben. Siehe
[opencanary/README.md](opencanary/README.md). Der Shipper liest dessen Log
automatisch mit.

## Ohne Docker (systemd)

Wenn du Cowrie (und evtl. OpenCanary) schon auf dem Host betreibst, kannst du
nur den Shipper laufen lassen:

```bash
sudo install -D shipper/shipper.py /opt/justdns-shipper/shipper.py
sudo cp shipper/shipper.conf.example /etc/justdns-shipper.conf
# /etc/justdns-shipper.conf bearbeiten: SENSOR_ID, TOKEN, INTAKE_URL, Logpfade
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
- Halte dein Token geheim. Wenn es durchsickert, sag Bescheid, dann widerrufen
  wir es.
- Lass nichts Echtes auf dem weitergeleiteten Port laufen.
- Der Honeypot laesst niemanden rein, es gibt also keine Shell zum Ausbrechen,
  trotzdem ist eine isolierte Box gute Praxis.

## Stoppen oder aufhoeren

```bash
docker compose down
```

Sag uns Bescheid, wenn du endgueltig aufhoerst, dann entfernen wir deinen Node
und widerrufen sein Token. Schon beigetragene Daten bleiben in der
oeffentlichen Liste, da die Liste kumulativ ist und keine persoenlichen Daten
enthaelt, nur Angreifer-IPs.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
