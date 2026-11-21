# JustDNS Honeypot Node

*Deutsch: [README.de.md](README.de.md)*

Run a small honeypot, help block the people who attack it. This repo gives you
a ready to run SSH honeypot (Cowrie) and a shipper that forwards every login
attempt to JustDNS. From there the source IPs flow into the public blocklist
[`justdns-threat-ips`](https://github.com/bonderaustriaAT/justdns-threat-ips),
which anyone can use to filter known attackers.

Your node never gets write access to the list. It only submits what it sees.
The list itself is built centrally, after filtering, by JustDNS.

## How it works

```
  attacker
     |
     v
  Cowrie (SSH honeypot)         every login attempt -> cowrie.json
  OpenCanary (optional)         FTP/Telnet/HTTP/... -> opencanary.log
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

- From an external node, an IP is only considered for the list after it has
  made at least **two** attempts on your node. A single stray hit is ignored.
- Before anything is published, central filters drop known scanners and
  research crawlers (by reverse DNS), large shared infrastructure such as
  Cloudflare and Google ranges, carrier-grade NAT, and anything on the
  allowlist.
- The public list is cumulative. Once an IP is listed it stays listed.
- Your submission token is write-only. It can post events and do nothing else,
  and we can revoke it for your node alone at any time.

## Requirements

- A Linux host you are comfortable exposing to the internet, ideally a small
  VPS or an isolated VM. Treat it as disposable.
- Docker and the Docker Compose plugin, or a plain host if you prefer the
  systemd route further down.
- A `SENSOR_ID` and `TOKEN` from JustDNS (see below).

## Get a token

Open an issue in this repo with a short note that you want to run a node, or
reach out through the contact listed on the JustDNS site. You will get a
`SENSOR_ID` and a `TOKEN` back. We hand the token over directly, not in a
public thread.

## Quick start (Docker)

```bash
git clone https://github.com/bonderaustriaAT/justdns-honeypot-node.git
cd justdns-honeypot-node
cp .env.example .env
# edit .env, set SENSOR_ID and TOKEN
docker compose up -d
```

That starts the Cowrie honeypot on port 2222 and the shipper beside it. Check
that both are up:

```bash
docker compose ps
docker compose logs -f shipper
```

The shipper prints how many events it sent on each run. On a fresh node it
will sit at zero until the first attacker shows up, which usually does not
take long on a public IP.

## Send attackers to it

Attackers knock on port 22. The honeypot listens on 2222, so you forward
traffic to it. Two common ways:

- At your router or cloud firewall, forward WAN `tcp/22` to this host's port
  `2222`.
- Or, on a box where port 22 is free, set `COWRIE_SSH_PORT=22` in `.env` and
  run `docker compose up -d` again. The honeypot then listens on 22 directly.

Keep your own real SSH on a different port, and do not point it at the
honeypot.

## Check it is working

```bash
# did the honeypot log anything yet?
docker compose exec cowrie tail -f var/log/cowrie/cowrie.json

# what did the shipper send?
docker compose logs --tail=20 shipper
```

Once real attempts show up, the source IPs appear in the public list within a
few minutes after the central processor runs.

## More services (optional)

Cowrie covers SSH, which is where most of the noise is. If you want FTP,
Telnet, HTTP, MySQL, RDP and VNC as well, add OpenCanary next to it. See
[opencanary/README.md](opencanary/README.md). The shipper reads its log
automatically.

## Without Docker (systemd)

If you already run Cowrie (and maybe OpenCanary) on the host, you can run the
shipper on its own:

```bash
sudo install -D shipper/shipper.py /opt/justdns-shipper/shipper.py
sudo cp shipper/shipper.conf.example /etc/justdns-shipper.conf
# edit /etc/justdns-shipper.conf: SENSOR_ID, TOKEN, INTAKE_URL, log paths
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
- Keep your token secret. If it leaks, tell us and we revoke it.
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
