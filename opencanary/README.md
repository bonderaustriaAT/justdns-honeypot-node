# OpenCanary (multi-service decoy)

This is the second honeypot on the node, next to Cowrie. It catches attacks on
FTP, Telnet, HTTP, MySQL, RDP and VNC. `opencanary.conf` in this folder is the
config our own node uses; it writes JSON to `/var/tmp/opencanary.log`, which is
where the shipper looks.

## With Docker (default)

Nothing extra to do. `docker-compose.yml` builds OpenCanary from the
[`Dockerfile`](Dockerfile) here (OpenCanary ships no official image) and runs
it alongside Cowrie, so `docker compose up -d` already starts it. The service
ports and how to forward them from the WAN are in the main README. To rebuild
after changing the version or config:

```bash
docker compose up -d --build opencanary
```

## Without Docker (bare metal)

If you run the node without Docker, install OpenCanary in a virtualenv on the
host:

```bash
sudo apt-get install -y python3-venv python3-dev libpcap-dev
python3 -m venv /opt/opencanary-env
/opt/opencanary-env/bin/pip install "opencanary==0.9.10" scapy
sudo install -D opencanary.conf /etc/opencanaryd/opencanary.conf
/opt/opencanary-env/bin/opencanaryd --start
```

It writes to `/var/tmp/opencanary.log`. Make sure that file is readable by
whatever runs the shipper (the shipper's `OC_LOG` points there by default).

## Config

Each service is a `*.enabled` flag in `opencanary.conf`. Turn one off by
setting it to `false` (and dropping its port from `docker-compose.yml`). Change
`device.node_id` to your own name. The portscan module stays off, so no raw
packet capture is needed. This is a decoy only: do not expose a real service or
the OpenCanary management on the box.
