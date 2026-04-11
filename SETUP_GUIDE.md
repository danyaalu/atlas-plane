# Atlas Plane Setup Guide

This guide helps new users get Atlas Plane running locally for the first time.

## Prerequisites

- **Go 1.22+** — Check with `go version`
- **OpenSSL** — For generating encryption keys and SSH CA keypair

## Step 1: Clone and Dependencies

```bash
git clone https://github.com/danyaalu/atlas-plane.git
cd atlas-plane
go mod tidy
```

## Step 2: Generate Encryption Key

Atlas Plane stores provisioned SSH private keys encrypted locally in `.atlas/keys/`. The encryption key must be 32 bytes.

Choose one format:

### Hex Format (Recommended — 64 characters, human-readable)

```bash
MASTER_ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "$MASTER_ENCRYPTION_KEY"
```

### Base64 Format (43 characters)

```bash
MASTER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
echo "$MASTER_ENCRYPTION_KEY"
```

## Step 3: Prepare SSH CA Keypair (for certificate-based SSH)

Atlas Plane uses SSH certificate-based authentication. Generate a CA keypair once:

```bash
ssh-keygen -t ed25519 -f ca_ed25519 -N "" -C "atlas-ca"
```

This creates:
- `ca_ed25519` — CA private key (keep this secret!)
- `ca_ed25519.pub` — CA public key (injected into VMs)

## Step 4: Create .env Configuration

Copy `.env.example` and fill in your Proxmox details:

```bash
cp .env.example .env
```

Edit `.env` and update:

```bash
PROXMOX_API_TOKEN=root@pam!atlas=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
PROXMOX_URL=https://192.168.1.100:8006
PROXMOX_NODE=pve
TEMPLATE_VMID=9000
MASTER_ENCRYPTION_KEY=<paste your key from Step 2>
```

### Common Issues

#### Error: "PROXMOX_API_TOKEN is required"

You didn't configure the Proxmox API token. See the main README.md under "Create a Proxmox API Token".

#### Error: "MASTER_ENCRYPTION_KEY is required"

You didn't set the encryption key. Run Step 2 above and paste it into `.env`.

## Step 5: Run

### Web UI (Recommended for first-time use)

```bash
go run . serve
```

Open http://localhost:8080 in your browser.

### Provision a Single VM

```bash
go run . provision
```

### Provision Multiple VMs

```bash
VM_COUNT=3 go run . provision
```

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `PROXMOX_API_TOKEN` | ✓ | `USER@REALM!TOKENID=SECRET` |
| `PROXMOX_URL` | ✓ | Proxmox API base URL (e.g., `https://192.168.1.100:8006`) |
| `PROXMOX_NODE` | ✓ | Target Proxmox node name (e.g., `pve`) |
| `TEMPLATE_VMID` | ✓ | VMID of your Cloud-Init template (e.g., `9000`) |
| `MASTER_ENCRYPTION_KEY` | ✓ | 32-byte encryption key (64-char hex, base64, or 32-byte raw string) |
| `VM_COUNT` | | Number of VMs to provision (default: `1`) |
| `CA_KEY_PATH` | | Path to CA private key (default: `./ca_ed25519`) |
| `ATLAS_SSH_KEY_DIR` | | Key vault directory (default: `./.atlas/keys`) |

For all variables, see README.md "Environment Variables" section.

## Troubleshooting

### "Failed to initialize SSH key vault"

This typically means either:

1. **Missing `MASTER_ENCRYPTION_KEY`** — Generate one with `openssl rand -hex 32`
2. **Invalid key format** — Must be exactly 32 bytes (64 hex chars or 43 base64 chars)
3. **Permission denied on `.atlas/keys/`** — Ensure the directory exists and is writable

### "Proxmox connection failed"

1. Verify `PROXMOX_URL` is correct (include the port, e.g., `:8006`)
2. Check `PROXMOX_API_TOKEN` format: `USER@REALM!TOKENID=SECRET`
3. Test connectivity: `curl -k https://192.168.1.100:8006/api2/json/version`

### Can't generate encryption key

If `openssl` is not available:

```bash
# macOS
brew install openssl

# Ubuntu/Debian
sudo apt-get install openssl

# Windows (use WSL or Git Bash)
# Already included with Git Bash
```

## Next Steps

1. Set up your Proxmox node and Cloud-Init template (see README.md)
2. Create a Proxmox API token (see README.md)
3. Run the web UI (`go run . serve`) or provision VMs
4. Download SSH keys from the web UI or use the provisioning output

## Support

For more details, see:
- `README.md` — Full documentation
- `README-docker.md` — Docker Compose deployment
