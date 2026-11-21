# OpenCanary (optional, advanced)

The base node runs Cowrie, which covers SSH. If you want to catch attacks on
more services (FTP, Telnet, HTTP, MySQL, RDP, VNC), you can also run
[OpenCanary](https://github.com/thinkst/opencanary) next to it. The shipper
already picks up its log, so no extra wiring is needed.

`opencanary.conf` in this folder is the config our own node uses. It writes
JSON to `/var/tmp/opencanary.log`, which is exactly where the shipper looks
by default (`OC_LOG`).

## Run it

OpenCanary does not ship a maintained Docker image, so the simplest route is a
small virtualenv on the host:

```bash
sudo apt-get install -y python3-venv python3-dev libpcap-dev
python3 -m venv /opt/opencanary-env
/opt/opencanary-env/bin/pip install opencanary scapy
sudo cp opencanary.conf /etc/opencanaryd/opencanary.conf
/opt/opencanary-env/bin/opencanaryd --start
```

Make sure `/var/tmp/opencanary.log` is readable by whatever runs the shipper.
If you run the shipper in Docker, mount the log into the `opencanary-logs`
volume (or bind-mount `/var/tmp` into the shipper at `/logs/opencanary`).

Change `device.node_id` to your own name. Do not expose the OpenCanary
management or any real service on the box. This is a decoy only.
