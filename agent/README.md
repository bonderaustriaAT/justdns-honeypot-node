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

Unterstuetzte Profile: `nginx`, `apache`, `caddy`, `node64`, `npm`, `haproxy`,
`sshd`, `fail2ban`.

### Installieren

Im Dashboard der Intake unter **Agent-Modul -> Agents** Name und App waehlen,
**Agent anlegen** - der fertige Befehl erscheint. Auf dem Host als root:

```
curl -fsSL https://intake.justdns.justfuture.at/agent/install | sudo bash -s -- \
  --name web-02 --app nginx --token <token>
```

Der Installer laedt den Agent, schreibt `/etc/justdns-agent.conf` (0640) und
installiert einen systemd-Timer (jede Minute). Abweichender Logpfad: `--log-glob`
anhaengen oder `LOG_GLOB` in der Config setzen.

Der Agent erscheint im Dashboard als **ausstehend**. Erst nach Freigabe fliessen
seine oeffentlichen IPs weiter.

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

Supported profiles: `nginx`, `apache`, `caddy`, `node64`, `npm`, `haproxy`,
`sshd`, `fail2ban`.

### Install

In the Intake dashboard under **Agent-Modul -> Agents**, choose a name and the
app, then **Agent anlegen** - the ready-made command appears. On the host as root:

```
curl -fsSL https://intake.justdns.justfuture.at/agent/install | sudo bash -s -- \
  --name web-02 --app nginx --token <token>
```

The installer fetches the agent, writes `/etc/justdns-agent.conf` (0640) and
installs a systemd timer (every minute). Non-default log path: append `--log-glob`
or set `LOG_GLOB` in the config.

The agent shows up as **pending** in the dashboard. Only after approval do its
public IPs flow on.

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
