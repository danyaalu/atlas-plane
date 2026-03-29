#!/bin/sh
set -eu

mkdir -p /keys
chown app:app /keys
chmod 700 /keys

if [ -f /keys/index.json ]; then
  chown app:app /keys/index.json
  chmod 600 /keys/index.json
fi

find /keys -maxdepth 1 -type f -name '*.enc' -exec chown app:app {} +
find /keys -maxdepth 1 -type f -name '*.enc' -exec chmod 600 {} +

if [ -f /run/secrets/ca_ed25519 ]; then
  install -m 600 -o app -g app /run/secrets/ca_ed25519 /app/ca_ed25519
  export CA_KEY_PATH=/app/ca_ed25519
fi

if [ -f /run/secrets/pve_ssh_key ]; then
  install -m 600 -o app -g app /run/secrets/pve_ssh_key /app/pve_ssh_key
  export PVE_SSH_KEY=/app/pve_ssh_key
fi

exec su-exec app "$@"
