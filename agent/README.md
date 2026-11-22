# JustDNS Fleet-Agent

Schlanker Log-Agent fuer eigene LXCs/VMs: liest die Ablehnungen einer
unterstuetzten Anwendung und meldet die Quell-IP an die Fleet-Intake. Optional,
auf dem eigenen Host installiert. Nur Python-Standardbibliothek.

Lean log agent for your own LXCs/VMs: reads a supported application's rejections
and reports the source IP to the Fleet-Intake. Optional, installed on your own
host. Python standard library only.

---

## Deutsch

### Was er tut

Der Agent tailt die Logs einer App, filtert **Ablehnungen** (abgelehnte oder
blockierte Zugriffe) und schickt die Quell-IP an die Intake. Versand at-least-once
ueber Byte-Offsets: Offsets ruecken erst nach erfolgreichem POST vor, bei
Intake-Ausfall bleibt alles liegen und geht beim naechsten Lauf raus.

Unterstuetzte Profile: `nginx`, `apache`, `caddy`, `npm`, `haproxy`, `sshd`,
`fail2ban`. node64 wird nicht getailt (kein Datei-Log) - es hat die eigene
Direktanbindung im nodeui (*node64 anbinden*).

### Installieren

In der Node-UI unter **+ Sensor anbinden -> Agent ausrollen** Name und App waehlen;
der fertige Befehl erscheint. Auf dem Host als root:

```
curl -fsSL http://<node>:8090/agent/install | sudo bash -s -- \
  --name web-02 --app nginx
```

Kein Token noetig: der Installer registriert den Agent selbst an der Node, laedt ihn,
schreibt `/etc/justdns-agent.conf` (0640) und installiert einen systemd-Timer (jede
Minute). Abweichender Logpfad: `--log-glob` anhaengen oder `LOG_GLOB` in der Config
setzen. Der Agent meldet an die Node; sie leitet an die zentrale Intake weiter.

Der Agent erscheint in der Intake-Review-Queue. Erst nach Freigabe fliessen seine
oeffentlichen IPs weiter.

### Datenschutz

Der Agent sendet nur Quell-IP, App, Grund und Pfad/Status - keine Payloads, keine
Request-Bodies. Private IPs (RFC1918, CGNAT, loopback, link-local, ULA) werden von
der Intake markiert und **nie** veroeffentlicht.

### Was veroeffentlicht wird

Gemeldete IPs werden **nie automatisch** publiziert. Die Intake stuft
"not wanted"-Traffic als Kandidat ein; der Betreiber gibt ihn manuell frei. Erst
dann kann eine oeffentliche IP in die Blockliste wandern, durch dieselben
Guardrails wie Honeypot-IPs.

### Dateien

- `justdns-agent.py` - Log-Agent (stdlib, at-least-once Offsets).
- `install.sh` - Installer, von der Intake unter `/agent/install` ausgeliefert.
- `justdns-agent.conf.example` - Konfigurationsvorlage.
- `systemd/justdns-agent.{service,timer}` - Timer-Units.

---

## English

### What it does

The agent tails an app's logs, filters out **rejections** (denied or blocked
requests) and sends the source IP to the Intake. At-least-once over byte offsets:
offsets advance only after a successful POST, so nothing is lost if the Intake is
down - it goes out on the next run.

Supported profiles: `nginx`, `apache`, `caddy`, `npm`, `haproxy`, `sshd`,
`fail2ban`. node64 is not tailed (no file log) - it has its own direct
connection in the nodeui (*node64 anbinden*).

### Install

In the node UI under **+ Sensor anbinden -> Agent ausrollen**, choose a name and
the app; the ready-made command appears. On the host as root:

```
curl -fsSL http://<node>:8090/agent/install | sudo bash -s -- \
  --name web-02 --app nginx
```

No token needed: the installer self-registers the agent at the node, fetches it,
writes `/etc/justdns-agent.conf` (0640) and installs a systemd timer (every minute).
Non-default log path: append `--log-glob` or set `LOG_GLOB` in the config. The agent
reports to the node, which forwards to the central Intake.

The agent shows up in the Intake review queue. Only after approval do its public IPs
flow on.

### Privacy

The agent sends only source IP, app, reason and path/status - no payloads, no
request bodies. Private IPs (RFC1918, CGNAT, loopback, link-local, ULA) are flagged
by the Intake and **never** published.

### What gets published

Reported IPs are **never** published automatically. The Intake flags "not wanted"
traffic as a candidate; the operator approves it manually. Only then can a public
IP enter the blocklist, through the same guardrails as honeypot IPs.

### Files

- `justdns-agent.py` - log agent (stdlib, at-least-once offsets).
- `install.sh` - installer, served by the Intake at `/agent/install`.
- `justdns-agent.conf.example` - configuration template.
- `systemd/justdns-agent.{service,timer}` - timer units.
