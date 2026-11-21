# JustDNS Honeypot Node

*Deutsch: [README.de.md](README.de.md)*

Run a small honeypot, help block the people who attack it. This repo gives you
a ready to run multi-service honeypot (Cowrie for SSH; OpenCanary for FTP,
Telnet, MySQL, RDP, VNC and Redis; a web-decoy for HTTP, the Docker API and
Elasticsearch) and a shipper that forwards every attempt to JustDNS. Those
attacker IPs become the public blocklist
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
which anyone can use to filter known attackers.

Every service is a pure decoy. It shows deliberately old, "vulnerable" looking
versions to draw attackers in, but it runs nothing real, so there is no actual
vulnerability to exploit. See [Safety](#safety).

Your node registers itself on first run, so there is nothing to sign up for. It
just runs and reports what it sees.

## How it works

```
  attacker
     |
     v
  Cowrie      SSH                            -> cowrie.json
  OpenCanary  FTP/Telnet/MySQL/RDP/VNC/Redis -> opencanary.log
  web-decoy   HTTP / Docker-API / Elastic    -> webdecoy.log
     |
     v
  shipper  ------->  JustDNS  ------->  public blocklist: justdns-threat-ips
```

The honeypot has no real service behind it. Every login fails on purpose and
every "vulnerable" page is a fixed fake, so each attempt is recorded and the
attacker never reaches anything real. The shipper tails the logs, batches what
is new, and sends it to JustDNS. If JustDNS is unreachable, nothing is lost: the
shipper picks up where it left off on the next run.

## What your node sends to us

This is the important part, so it is spelled out in full. For each attack
attempt the shipper submits exactly these fields:

| Field       | Example                 | Why |
|-------------|-------------------------|-----|
| `sensor_id` | `own-berlin-01`         | which node reported it |
| `ts`        | `2026-11-21T10:00:00Z`  | when it happened (UTC) |
| `src_ip`    | `203.0.113.7`           | the attacker's IP |
| `service`   | `SSH`                   | which service was hit |
| `dst_port`  | `2222`                  | the port on your node |
| `username`  | `root`                  | the username the attacker tried |
| `password`  | `123456`                | the password the attacker tried |

Yes, the attempted usernames and passwords are included. We keep them so the
credentials can go into abuse reports to the networks the attacks come from.
They are the attacker's guesses against a fake service, not anyone's real
login.

What we do **not** receive: anything about you or your machine. No hostnames,
no system data, no file contents, no traffic other than the honeypot login
attempts above.

What happens with it: the attacker IPs go into the public blocklist so others
can filter them, and the credentials go into abuse reports to the networks the
attacks come from.

## Requirements

- A Linux host you are comfortable exposing to the internet, ideally a small
  VPS or an isolated VM. Treat it as disposable.
- Docker and the Docker Compose plugin, or a plain host if you prefer the
  systemd route further down.
- Nothing to sign up for. Your node registers itself on first run.

## Registering your node

There is nothing to sign up for. On its first run the shipper registers itself
with JustDNS and starts sending. If you want us to know a node is yours, open an
issue in this repo or reach out through the contact on the JustDNS site.

## Quick start (Docker)

```bash
git clone https://github.com/bonderaustriaAT/justdns-honeypot-node.git
cd justdns-honeypot-node
cp .env.example .env
# optional: open .env and set a node name (SENSOR_ID). No token needed.
./scripts/randomize-node.sh   # one-off: roll the fingerprint (hostname, banners)
docker compose up -d
```

`randomize-node.sh` sets the hostname, SSH version, the FTP/MySQL banners and
the web-decoy persona to random, plausible values, so several nodes do not look
like the same fleet and are harder to spot as a honeypot. It is optional but
recommended, especially if you run more than one node.

The first run builds the OpenCanary image once, then starts Cowrie (SSH on
2222), OpenCanary (the other services), the shipper and the live view.
Check that they are up:

```bash
docker compose ps
docker compose logs -f shipper
```

The shipper prints how many events it sent on each run. On a fresh node it
will sit at zero until the first attacker shows up, which usually does not
take long on a public IP.

## Point attacks at it: port forwarding

Your node only catches what actually reaches it, so forward the service ports
from your WAN (home router or cloud firewall) to this host. Only SSH shifts
ports, because Cowrie listens on 2222; everything else maps straight through.

| Service       | Attackers hit (WAN) | Forward to this host | Handled by |
|---------------|---------------------|----------------------|------------|
| SSH           | tcp/22              | tcp/2222             | Cowrie     |
| FTP           | tcp/21              | tcp/21               | OpenCanary |
| Telnet        | tcp/23              | tcp/23               | OpenCanary |
| MySQL         | tcp/3306            | tcp/3306             | OpenCanary |
| RDP           | tcp/3389            | tcp/3389             | OpenCanary |
| VNC           | tcp/5900            | tcp/5900             | OpenCanary |
| Redis         | tcp/6379            | tcp/6379             | OpenCanary |
| HTTP          | tcp/80              | tcp/80               | web-decoy  |
| HTTP (alt)    | tcp/8080            | tcp/8080             | web-decoy  |
| Docker API    | tcp/2375            | tcp/2375             | web-decoy  |
| Elasticsearch | tcp/9200            | tcp/9200             | web-decoy  |

- **Home router:** add a port forward for each WAN port above to this host's
  LAN IP, pointing at the "forward to" port. SSH 22 goes to 2222, the rest go
  to the same number.
- **Cloud VPS:** open these ports in the firewall or security group. They are
  already published on the matching port, except SSH, which you send to 2222
  (or set `COWRIE_SSH_PORT=22`, see below).

You do not have to forward all of them. SSH alone already draws constant
traffic; add the others to catch more.

SSH on port 22 directly: if the host's port 22 is free (your own admin SSH is
on another port), set `COWRIE_SSH_PORT=22` in `.env`, run `docker compose up
-d` again, and forward WAN tcp/22 straight to 22.

Keep your own real services and real SSH on different ports, and never point a
forward at something real.

## Check it is working

```bash
# did the honeypot log anything yet?
docker compose exec cowrie tail -f var/log/cowrie/cowrie.json

# what did the shipper send?
docker compose logs --tail=20 shipper
```

Real attempts go to JustDNS right away. The attacker IPs show up in the public
blocklist shortly after.

## Live view on your node

The stack also runs a small local dashboard that shows the attacks on your own
node in real time: source IPs, the service that was hit, and the usernames and
passwords the attackers tried, with the busiest sources listed on the side. It
reads the same logs as the shipper and refreshes every few seconds.

With Docker it is already running and reachable from your internal network at
`http://<node-ip>:8090` (the node's LAN address; 8080 is an attacker-facing
decoy port).

It shows attacker credentials, so keep it on your internal network and do not
forward it from the WAN. If you do need remote access, set `NODEUI_TOKEN` in
`.env` and put a TLS reverse proxy in front.

On a bare host (systemd) run it the same way as the shipper: install
`nodeui/nodeui.py` to `/opt/justdns-nodeui/` and enable
`nodeui/systemd/justdns-nodeui.service`.

## Services on this node

Out of the box `docker compose up -d` runs all three decoys:

- **SSH** on 2222, via Cowrie.
- **FTP, Telnet, MySQL, RDP, VNC, Redis**, via OpenCanary, on their standard
  ports.
- **HTTP (80, 8080), Docker API (2375), Elasticsearch (9200)**, via the
  web-decoy. It shows a per-node "vulnerable" persona and answers the paths
  scanners probe, all as fixed fakes.

Every attempt on any of them is logged and shipped the same way. The OpenCanary
config is in [`opencanary/opencanary.conf`](opencanary/opencanary.conf) (set
`device.node_id` to your own name if you like); switch a protocol off by setting
its `*.enabled` to `false` and dropping its port from `docker-compose.yml`. The
web personas live in [`webdecoy/webdecoy.py`](webdecoy/webdecoy.py); the active
one is `WEBDECOY_PERSONA` in `.env`, rolled by `randomize-node.sh`. Notes on
running OpenCanary without Docker are in
[opencanary/README.md](opencanary/README.md).

## Safety

Everything here is a decoy. There is no real vulnerability to open, because
there is no real service behind any port:

- The "vulnerable" versions (old Apache, old Elasticsearch, an open Docker API,
  and so on) are just banners and fixed fake pages. They look exploitable to a
  scanner, but nothing runs behind them.
- The web-decoy never touches the filesystem. Every response comes from a fixed
  map in the code, so path traversal like `/../../etc/passwd` hits nothing real.
  It executes no uploaded code and stores no uploaded files.
- Cowrie and OpenCanary are isolated fake implementations; a login never
  succeeds into anything real.
- Still, run this on a disposable host and keep your own real services on other
  ports. A decoy is only safe as long as nothing real sits next to it.

## Without Docker (systemd)

If you already run Cowrie (and maybe OpenCanary) on the host, you can run the
shipper on its own:

```bash
sudo install -D shipper/shipper.py /opt/justdns-shipper/shipper.py
sudo cp shipper/shipper.conf.example /etc/justdns-shipper.conf
# edit /etc/justdns-shipper.conf: INTAKE_URL and your log paths (no token needed)
sudo install -d -o cowrie -g cowrie /var/lib/justdns-shipper
sudo cp shipper/systemd/justdns-shipper.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-shipper.timer
```

The shipper only needs the Python standard library, so no extra packages.

The web-decoy runs the same way (stdlib only). If port 80 is taken on the host,
drop it from `WEBDECOY_WEB_PORTS` in the unit and use 8080 alone:

```bash
sudo install -D webdecoy/webdecoy.py /opt/justdns-webdecoy/webdecoy.py
sudo cp webdecoy/systemd/justdns-webdecoy.service /etc/systemd/system/
# optional: edit the unit, set WEBDECOY_WEB_PORTS=8080 if 80 is in use
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-webdecoy.service
```

To keep a bare-metal node updated by itself, install the native self-update
timer. It pulls this repo once a day and reinstalls the shipper (Cowrie and
OpenCanary are upstream and stay untouched):

```bash
sudo cp scripts/systemd/justdns-update-native.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-update-native.timer
```

## Updating

By hand, from the repo root:

```bash
./scripts/self-update.sh
```

It pulls new commits and images and recreates only what changed. Your local
fingerprint edits from `randomize-node.sh` are kept. The old manual way still
works too (`git pull && docker compose pull && docker compose up -d`).

### Automatic updates

Let the node update itself, no extra container needed. Install the systemd timer
once (adjust the path in the unit if you cloned elsewhere than
`/opt/justdns-honeypot-node`):

```bash
sudo cp scripts/systemd/justdns-update.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now justdns-update.timer
```

It runs `self-update.sh` once a day with a random delay. Check it with
`systemctl list-timers justdns-update.timer` and
`journalctl -u justdns-update.service`. Image versions stay pinned, so an update
only brings what is in a new commit; nothing jumps versions on its own.

## Security notes

- Run this on a host you can throw away. It is a decoy, not a service you
  depend on.
- Do not run anything real on the forwarded port.
- The honeypot never lets anyone in, so there is no shell to break out of, but
  isolating the box is still good hygiene.

## Stopping or leaving

```bash
docker compose down
```

Tell us if you are done for good and we remove your node. Attacker IPs you
already contributed stay in the public list, there is no personal data in it.

## License

MIT, see [LICENSE](LICENSE).
