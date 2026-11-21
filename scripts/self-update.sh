#!/usr/bin/env bash
# Self-update for a Docker-based node: pull new commits and images, recreate the
# stack. No extra container (no Watchtower), the node updates itself. Run it by
# hand, or let the systemd timer below call it (default once a day).
#
#   ./scripts/self-update.sh
#
# What it does, from the repo root:
#   1. git pull   -> new config, code and pinned image tags. Local fingerprint
#                    edits from randomize-node.sh are kept (autostash).
#   2. docker compose pull  -> new images for the pinned tags.
#   3. docker compose up -d --build  -> rebuild OpenCanary if its Dockerfile
#                    changed, recreate only what actually changed.
#   4. docker image prune   -> drop the now-unused old images (stays lean).
#
# A lock stops two runs from overlapping. On a failed git pull it stops before
# touching the running stack, logs it, and the timer simply retries next time.
set -eu

cd "$(dirname "$0")/.."
REPO="$(pwd)"
LOCK="/tmp/justdns-selfupdate.lock"

log() { echo "[self-update] $*"; }

# Single run at a time (flock if available, else a mkdir lock).
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK"
  flock -n 9 || { log "laeuft bereits, breche ab"; exit 0; }
else
  mkdir "$LOCK.d" 2>/dev/null || { log "laeuft bereits, breche ab"; exit 0; }
  trap 'rmdir "$LOCK.d" 2>/dev/null || true' EXIT
fi

compose() { if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi; }

before="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

log "git pull (lokale Fingerprint-Aenderungen bleiben via autostash)"
if ! git pull --rebase --autostash --no-edit; then
  log "git pull fehlgeschlagen, Stack bleibt unveraendert. Naechster Lauf versucht es erneut."
  git rebase --abort 2>/dev/null || true
  exit 1
fi

after="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [ "$before" = "$after" ]; then
  log "schon aktuell ($after), nur Images pruefen"
fi

log "docker compose pull"
compose pull

log "docker compose up -d --build"
compose up -d --build

log "alte Images aufraeumen"
docker image prune -f >/dev/null 2>&1 || true

log "fertig: $before -> $after"
