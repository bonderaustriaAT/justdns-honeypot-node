# JustDNS Honeypot Node

*Deutsch: [README.de.md](README.de.md)*

Run a small honeypot, help block the people who attack it. This repo gives you
a ready to run multi-service honeypot (Cowrie for SSH, plus OpenCanary for FTP,
Telnet, HTTP, MySQL, RDP and VNC) and a shipper that forwards every attempt to
JustDNS. From there the source IPs flow into the public blocklist
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
which anyone can use to filter known attackers.

Your node never gets write access to the list. It only submits what it sees.
It registers itself on first run, so there is nothing to sign up for. The list
itself is built centrally, after filtering and after JustDNS has approved your
node, so a new node cannot push anything to the public list on its own.

## How it works

```
  attacker
     |
     v
  Cowrie      SSH login attempts            -> cowrie.json
  OpenCanary  FTP/Telnet/HTTP/MySQL/RDP/VNC -> opencanary.log
     |
     v
  shipper  --HTTPS POST /events (your token)-->  JustDNS intake
                                                     |
                                                     v
                                      central processor + filters
                                                     |
                                                     v
                            public list: justdns-threat-ips
```

The honeypot has no real service behind it. Every login fails on purpose, so
each attempt is recorded and the attacker never reaches anything. The shipper
tails the logs, batches what is new, and posts it with your token. If the
intake is unreachable, nothing is lost: the shipper picks up where it left off
on the next run.

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
attempts above. The token identifies your node and nothing else.

A few more things worth knowing:

- Your node's IPs are not published until JustDNS has reviewed and approved
  your node. Until then, everything your node reports is stored and visible to
  us, but nothing is pushed to the public list. This is what keeps a bad actor
  from listing arbitrary IPs.
- Even after approval, central filters run before anything is published: known
  scanners and research crawlers (by reverse DNS), large shared infrastructure
  such as Cloudflare and Google ranges, carrier-grade NAT, and anything on the
  allowlist are dropped.
- The public list is cumulative. Once an IP is listed it stays listed.
- Your node's token is write-only. It can post events and do nothing else, and
  we can revoke it for your node alone at any time.

## Requirements

- A Linux host you are comfortable exposing to the internet, ideally a small
  VPS or an isolated VM. Treat it as disposable.
- Docker and the Docker Compose plugin, or a plain host if you prefer the
  systemd route further down.
- Nothing to sign up for. Your node registers itself on first run.

## Registering your node

There is no manual token step. On its first run the shipper calls the intake,
registers itself, and stores its own write-only token locally (in the state
file). From then on it sends attacker data right away.

What it does not do is publish anything yet. A freshly registered node sits in
a pending state until we approve it. Once we have seen that it reports real
attacker traffic, we approve it and its IPs start flowing into the public list
on the next run. If you want your node approved, open an issue in this repo or
reach out through the contact on the JustDNS site so we know it is yours and
can look for it.

## Quick start (Docker)

```bash
git clone https://github.com/bonderaustriaAT/justdns-honeypot-node.git
cd justdns-honeypot-node
cp .env.example .env
# optional: open .env and set a node name (SENSOR_ID). No token needed.
docker compose up -d
```

The first run builds the OpenCanary image once, then starts Cowrie (SSH on
2222), OpenCanary (the other services), the shipper and the local live view.
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

| Service | Attackers hit (WAN) | Forward to this host | Handled by |
|---------|---------------------|----------------------|------------|
| SSH     | tcp/22              | tcp/2222             | Cowrie     |
| FTP     | tcp/21              | tcp/21               | OpenCanary |
| Telnet  | tcp/23              | tcp/23               | OpenCanary |
| HTTP    | tcp/80              | tcp/80               | OpenCanary |
| MySQL   | tcp/3306            | tcp/3306             | OpenCanary |
| RDP     | tcp/3389            | tcp/3389             | OpenCanary |
| VNC     | tcp/5900            | tcp/5900             | OpenCanary |

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

Real attempts are stored by the intake right away. Once your node has been
approved, the source IPs appear in the public list a few minutes after the
central processor runs.

## Live view on your node

The stack also runs a small local dashboard that shows the attacks on your own
node in real time: source IPs, the service that was hit, and the usernames and
passwords the attackers tried, with the busiest sources listed on the side. It
reads the same logs as the shipper and refreshes every few seconds.

With Docker it is already running. Open it on the node itself at
`http://127.0.0.1:8080`.

It is bound to localhost on purpose, because it shows attacker credentials. To
look at it from your own machine, tunnel over SSH instead of opening the port:

```bash
ssh -L 8080:127.0.0.1:8080 you@your-node
# then open http://127.0.0.1:8080 on your machine
```

If you really need it reachable over the network, set `NODEUI_TOKEN` in `.env`
and put a TLS reverse proxy in front. Do not expose it in the clear.

On a bare host (systemd) run it the same way as the shipper: install
`nodeui/nodeui.py` to `/opt/justdns-nodeui/` and enable
`nodeui/systemd/justdns-nodeui.service`.

## Services on this node

Out of the box the node runs both honeypots, so `docker compose up -d` already
covers:

- **SSH** on 2222, via Cowrie.
- **FTP, Telnet, HTTP, MySQL, RDP, VNC**, via OpenCanary, on their standard
  ports.

Every attempt on any of them is logged and shipped the same way, and shows up
in the local live view. The OpenCanary config is in
[`opencanary/opencanary.conf`](opencanary/opencanary.conf); set
`device.node_id` to your own name if you like. To switch a service off, set its
`*.enabled` to `false` there and drop its port from `docker-compose.yml`. Notes
on the bare-metal (non-Docker) way to run OpenCanary are in
[opencanary/README.md](opencanary/README.md).

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

## Updating

```bash
git pull
docker compose pull
docker compose up -d
```

## Security notes

- Run this on a host you can throw away. It is a decoy, not a service you
  depend on.
- The node's token lives in the shipper state file. Keep it private. If it
  leaks, tell us and we revoke it.
- Do not run anything real on the forwarded port.
- The honeypot never lets anyone in, so there is no shell to break out of, but
  isolating the box is still good hygiene.

## Stopping or leaving

```bash
docker compose down
```

Tell us if you are done for good and we remove your node and revoke its token.
Data already contributed stays in the public list, since the list is
cumulative and there is no personal data in it, only attacker IPs.

## License

MIT, see [LICENSE](LICENSE).
