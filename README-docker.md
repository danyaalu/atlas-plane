# Atlas Plane Docker Migration Guide

This guide migrates existing encrypted SSH keys into Docker while keeping the master key out of the volume.

## 1) Prepare source vault directory

Your source directory should contain:
- `*.enc`
- `index.json`
- `masker.key` (or `master.key`)

## 2) Run one-time migration

```bash
python3 scripts/migrate_key_vault.py --source /keys --volume ssh_key_data --env-output .env.docker
```

What it does:
- Copies `*.enc` and `index.json` into Docker volume `ssh_key_data`
- Reads `masker.key`/`master.key` and writes `MASTER_ENCRYPTION_KEY=<hex>` into `.env.docker`
- Does **not** copy the master key file into the Docker volume

## 3) Start Docker services

```bash
docker compose --env-file .env.docker up -d --build
```

`docker-compose.yml` mounts your CA private key as a Docker secret from `./ca_ed25519`; backend startup stages it to `/app/ca_ed25519` and uses `CA_KEY_PATH=/app/ca_ed25519`.
It also mounts your Proxmox SSH private key from `${HOME}/.ssh/id_rsa` as a secret and uses `PVE_SSH_KEY=/app/pve_ssh_key` inside the backend container.

Services:
- `backend` mounts `ssh_key_data` at `/keys` (read/write)
- `ssh-bridge` mounts `ssh_key_data` at `/keys` (read-only)

Backend API/UI is exposed on `http://localhost:8080`.

## 4) Runtime env for ssh-bridge

Required for startup:
- `MASTER_ENCRYPTION_KEY`

Used by `ssh-bridge` (socket.io + ssh2):
- `MASTER_ENCRYPTION_KEY` (required)
- `ATLAS_BACKEND_URL` (defaults to `http://backend:8080`)
- `ATLAS_FRONTEND_ORIGIN` (defaults to `http://localhost:8080`)
- `SSH_USER` (optional default SSH user, defaults to `debian`)
- `SSH_PORT` (defaults to `22`)

The bridge resolves VM host/user metadata from backend endpoint `GET /api/vms/{id}/ssh-connect`, decrypts the per-VM `.enc` key from `/keys`, and never sends private keys to the browser.

## Browser Terminal UX

- In the VMs view, click **Connect** on a running VM with a provisioned key.
- The UI opens a floating WinBox window and initializes xterm.js.
- Keystrokes and resize events are sent over Socket.io to `ssh-bridge`.
- Closing the window immediately tears down SSH stream + socket session.

## Security Notes

- Keep `.env.docker` out of git.
- Restrict host file permissions: `chmod 600 .env.docker`.
- Rotate the master key using a planned key re-encryption process if compromise is suspected.
