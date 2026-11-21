# JustDNS honeypot node: OpenCanary, the multi-service decoy (FTP, Telnet,
# HTTP, MySQL, RDP, VNC). OpenCanary ships no official image, so we build a
# small pinned one. The build is a one-off; "docker compose up -d" does it.
FROM python:3.12-slim

# 0.9.4 is yanked (breaks in containers); pin a known-good release.
ARG OPENCANARY_VERSION=0.9.10

# scapy is an OpenCanary dependency. libpcap is only needed for the portscan
# module, which our config leaves off, so we keep the image lean.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "opencanary==${OPENCANARY_VERSION}" scapy

# The config is mounted at /etc/opencanaryd/opencanary.conf at runtime and
# writes its JSON log to /var/tmp/opencanary.log (a shared volume).
CMD ["opencanaryd", "--dev"]
