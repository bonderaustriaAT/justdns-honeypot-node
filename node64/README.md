# JustDNS node64-Reader (PROXY64, nur lesen)

Die Honeypot-Node liest das node64-Zugriffslog und holt die **eigenen**
Policy-Blocks von node64: Exploit-/WAF-Treffer, Access-List-Denies,
Rate-Limit-Bans und honeypot_instant_block. Blocklist-Treffer werden bewusst
ausgelassen, sie stehen schon auf der Liste (keine Zirkularitaet). Nur lesend,
keine Aenderung an node64. Die Quell-IPs gehen an die Node, die unter ihrer
Identitaet an die Intake weiterleitet.

The honeypot node reads the node64 access log and pulls node64's **own** policy
blocks: exploit/WAF hits, access-list denies, rate-limit bans and
honeypot_instant_block. Blocklist hits are deliberately skipped, they are already
on the list (no circularity). Read-only. Source IPs go to the node, which
forwards them to the Intake under its own identity.

---

## Deutsch

### Einrichten (aus der Node-UI)

In der Node-UI auf **+ Sensor anbinden**, unter *node64 anbinden* die node64-URL
und den API-Key eintragen und **node64 verbinden** klicken. Die Node testet den
Zugang, meldet node64 als Sensor an und holt die Policy-Blocks danach jede Minute.
Der API-Key bleibt auf der Node und geht nicht an die Intake.

Selbstsigniertes Zertifikat im LAN: Haekchen *TLS-Pruefung aus* gesetzt lassen.

### API-Key erzeugen (node64)

In node64 unter **Einstellungen &rarr; API-Keys** einen Key mit Prefix `node64_`
erzeugen (nur lesen reicht). Der MCP-Key (`mcp64_`) wird von der REST-API nicht
akzeptiert.

### Was gemeldet wird

Nur Quell-IP, Grund und angefragter Pfad. Die node64-Gruende werden gemappt:

| node64        | gemeldet als | Review     |
|---------------|--------------|------------|
| `exploit`     | `waf_block`  | hoch       |
| `honeypot`    | `waf_block`  | hoch       |
| `acl`         | `http_403`   | Pfad/Volumen entscheidet |
| `rate_limit`  | `http_429`   | Volumen entscheidet |
| `blocklist`   | -            | ausgelassen |

Private Quell-IPs markiert die Intake und veroeffentlicht sie nie. Nichts wird
automatisch gelistet - gemeldete IPs landen als Kandidaten in der Review-Queue.

### Manuell / auf einem anderen Host (optional)

Statt der Direktanbindung kann `node64_reader.py` auch eigenstaendig laufen:
`justdns-node64.conf.example` nach `/etc/justdns-node64.conf` kopieren, ausfuellen
(`NODE64_URL`, `NODE64_API_KEY`, `INTAKE_URL` auf die Node zeigen) und die Units
aktivieren:

```
install -m 644 systemd/justdns-node64.service /etc/systemd/system/
install -m 644 systemd/justdns-node64.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now justdns-node64.timer
```

Wenn der Reader den Log-Endpunkt nicht findet, `NODE64_LOG_PATH` in der Config auf
den REST-Pfad des Zugriffslogs setzen.

### Dateien

- `node64_reader.py` - Reader (stdlib, nur lesen, blocklist ausgenommen).
- `justdns-node64.conf.example` - Konfigurationsvorlage fuer den manuellen Betrieb.
- `systemd/justdns-node64.{service,timer}` - Timer-Units fuer den manuellen Betrieb.

---

## English

### Setup (from the node UI)

In the node UI open **+ Sensor anbinden**, under *node64 anbinden* enter the
node64 URL and API key, then click **node64 verbinden**. The node tests access,
registers node64 as a sensor and pulls the policy blocks every minute. The API key
stays on the node and is not sent to the Intake.

Self-signed certificate on the LAN: leave *TLS-Pruefung aus* checked.

### Create an API key (node64)

In node64 under **Settings &rarr; API keys** create a key with prefix `node64_`
(read-only is enough). The MCP key (`mcp64_`) is not accepted by the REST API.

### What is reported

Only source IP, reason and requested path. node64 reasons are mapped: `exploit`
and `honeypot` to `waf_block` (high), `acl` to `http_403`, `rate_limit` to
`http_429`; `blocklist` is skipped. Private source IPs are flagged by the Intake
and never published. Nothing is listed automatically - reported IPs land as
candidates in the review queue.

### Manual / on another host (optional)

Instead of the direct connection, `node64_reader.py` can run standalone: copy
`justdns-node64.conf.example` to `/etc/justdns-node64.conf`, fill it in and enable
the units (see the German section). Set `NODE64_LOG_PATH` if the reader cannot find
the access-log endpoint.

### Files

- `node64_reader.py` - reader (stdlib, read-only, blocklist excluded).
- `justdns-node64.conf.example` - configuration template for standalone operation.
- `systemd/justdns-node64.{service,timer}` - timer units for standalone operation.
