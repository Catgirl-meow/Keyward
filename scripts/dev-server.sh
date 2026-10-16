#!/bin/sh
# Local test stack: Vaultwarden 1.37.2 + mailpit (SMTP sink for email 2FA) in one podman pod.
# Data lives on tmpfs, so every `up` starts from an empty server.
#   scripts/dev-server.sh up | down | status | logs
#   vault:   http://localhost:8087   (web vault included; WebAuthn RP ID = localhost)
#   mailpit: http://localhost:8025   (API: /api/v1/messages)
set -eu
POD=keyward-dev
VW_IMAGE=docker.io/vaultwarden/server:1.37.2
MP_IMAGE=docker.io/axllent/mailpit:latest

up() {
  if podman pod exists "$POD"; then
    echo "already running (use: $0 down)"; status; return
  fi
  podman pod create --name "$POD" \
    -p 127.0.0.1:8087:80 \
    -p 127.0.0.1:8025:8025 >/dev/null
  podman run -d --pod "$POD" --name "$POD-mail" "$MP_IMAGE" >/dev/null
  podman run -d --pod "$POD" --name "$POD-vw" --tmpfs /data:rw,size=256m \
    -e DOMAIN=http://localhost:8087 \
    -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
    -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    -e SMTP_HOST=127.0.0.1 -e SMTP_PORT=1025 -e SMTP_SECURITY=off -e SMTP_FROM=vault@localhost \
    -e EMAIL_2FA_AUTO_FALLBACK=false \
    -e LOGIN_RATELIMIT_MAX_BURST=1000000 -e LOGIN_RATELIMIT_SECONDS=1 \
    -e ADMIN_RATELIMIT_MAX_BURST=1000000 \
    -e LOG_LEVEL=warn \
    "$VW_IMAGE" >/dev/null
  i=0
  until curl -fsS http://127.0.0.1:8087/alive >/dev/null 2>&1; do
    i=$((i + 1)); [ $i -gt 60 ] && { echo "vaultwarden did not come up"; podman logs "$POD-vw" | tail -20; exit 1; }
    sleep 0.5
  done
  status
}

down() {
  podman pod exists "$POD" || { echo "not running"; return; }
  podman pod rm -f "$POD" >/dev/null && echo "stopped"
}

status() {
  if podman pod exists "$POD"; then
    printf 'vaultwarden: %s\n' "$(curl -fsS http://127.0.0.1:8087/api/config 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' || echo down)"
    printf 'mailpit:     %s\n' "$(curl -fsS http://127.0.0.1:8025/api/v1/info 2>/dev/null | sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' || echo down)"
  else
    echo "not running"
  fi
}

case "${1:-status}" in
  up) up ;;
  down) down ;;
  status) status ;;
  logs) podman logs --tail 50 "$POD-vw" ;;
  *) echo "usage: $0 up|down|status|logs"; exit 2 ;;
esac
