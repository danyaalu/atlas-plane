# Atlas Plane

A Go CLI that fully automates VM provisioning on a Proxmox homelab: clone a golden image, configure hardware, inject Cloud-Init with an **SSH Certificate Authority** for zero-trust access, boot the VM, and return a ready-to-use `ssh` command.

Supports **parallel provisioning** — spin up multiple VMs at once with `VM_COUNT=N`. Each VM gets a unique random name (e.g. `swift-nexus-a3f1b2`) and its own SSH key pair.

Provisioned private keys are now stored in an encrypted local key vault (`.atlas/keys` by default) instead of the repository root, and can be re-downloaded later from the VM panel in the web UI.

## Architecture

```
┌──────────────┐         HTTPS / API Token          ┌──────────────────┐
│  atlas-plane │ ──────────────────────────────────▶│  Proxmox VE API  │
│  (Go CLI)    │                                    │  /api2/json/...  │
└──────┬───────┘                                    └────────┬─────────┘
       │                                                     │
       │  1. Allocate N free VMIDs (scan cluster)            │
       │  2. Generate random names per VM                    │
       │  3. Clone template ──┐                              │
       │  4. Configure HW     │ × N VMs in parallel          │
       │  5. SSH cert + CI    │ (goroutines)                 │
       │  6. Boot + poll IP ──┘                              │
       │                                                     ▼
       │                                            ┌──────────────────┐
       └── ssh -i ./swift-nexus-a3f1b2_key ────────▶│   New VMs        │
                    debian@IP                       │   (Debian 12)    │
                                                    └──────────────────┘
```

## Prerequisites

| Requirement | Notes |
|---|---|
| **Go 1.22+** | `go version` to verify |
| **Proxmox VE 7+** | Tested on PVE 8.x |
| **Debian 12 Cloud-Init template** | With `qemu-guest-agent` installed |
| **SSH CA key pair** | Ed25519 recommended |
| **SSH access to Proxmox host** | Key-based auth as root (for writing snippet files) |

## Proxmox Node Preparation

### 1. Create the Cloud-Init Template (Golden Image)

Download the Debian 12 cloud image and create a template VM. Adjust the storage and VMID to match your environment:

```bash
# On the Proxmox host:
cd /var/lib/vz/template/iso

# Download Debian 12 generic cloud image
wget https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2

# Create a VM (VMID 9000 is the default template ID)
qm create 9000 --name debian12-cloud --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0

# Import the disk
qm importdisk 9000 debian-12-generic-amd64.qcow2 pve1-thin-dsk

# Attach the disk, add Cloud-Init drive, set boot order
qm set 9000 --scsihw virtio-scsi-pci --scsi0 pve1-thin-dsk:vm-9000-disk-0
qm set 9000 --ide2 pve1-thin-dsk:cloudinit
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1

# Convert to template
qm template 9000
```

> **Important:** The cloud image must have `qemu-guest-agent` pre-installed (Debian 12 generic images include it). The guest agent is required for IP address discovery.

### 2. Enable Snippets on Storage

Atlas Plane uploads a Cloud-Init user-data file as a **snippet**. Your Proxmox storage must have the `snippets` content type enabled.

**Via the UI:** Datacenter → Storage → `local` → Edit → Content → check **Snippets**

**Via the CLI:**
```bash
# Edit /etc/pve/storage.cfg — add "snippets" to the content line:
# content iso,vztmpl,backup,snippets
pvesm set local --content iso,vztmpl,backup,snippets
```

### 3. Create a Proxmox API Token

```bash
# On the Proxmox host (or via the UI → Datacenter → Permissions → API Tokens):
pveum user token add root@pam atlas --privsep=0
```

This prints a token value like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. The full token string you need is:

```
root@pam!atlas=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

> `--privsep=0` disables privilege separation so the token inherits the user's permissions. For production, create a dedicated user with minimal permissions (VM.Allocate, VM.Clone, VM.Config.*, VM.PowerMgmt, Datastore.AllocateTemplate on the relevant paths).

## SSH Certificate Authority Setup

Generate a dedicated CA key pair (do this once):

```bash
ssh-keygen -t ed25519 -f ca_ed25519 -N "" -C "atlas-ca"
```

This creates two files:
- `ca_ed25519` — CA private key (keep this secret, used by atlas-plane to sign certs)
- `ca_ed25519.pub` — CA public key (injected into VMs via Cloud-Init)

Place `ca_ed25519` in the project directory (or set `CA_KEY_PATH`).

## Environment Variables

Atlas Plane automatically loads variables from a `.env` file in the project root.

You can also point to a custom env file by setting `ATLAS_ENV_FILE`.

| Variable | Default | Description |
|---|---|---|
| `PROXMOX_API_TOKEN` | *(required)* | `USER@REALM!TOKENID=SECRET` |
| `PROXMOX_URL` | `https://192.168.1.100:8006` | Proxmox API base URL |
| `PROXMOX_NODE` | `pve` | Target Proxmox node name |
| `TEMPLATE_VMID` | `9000` | VMID of the Cloud-Init template |
| `VM_COUNT` | `1` | Number of VMs to provision in parallel |
| `VM_START_ID` | `500` | Lowest VMID to consider when auto-allocating |
| `VM_CORES` | `1` | Number of vCPUs |
| `VM_MEMORY` | `1024` | RAM in MiB |
| `VM_DISK_DEVICE` | `scsi0` | Proxmox disk identifier to resize |
| `VM_DISK_SIZE` | `5G` | Target disk size after clone |
| `CA_KEY_PATH` | `./ca_ed25519` | Path to the CA private key file |
| `ATLAS_SSH_KEY_DIR` | `./.atlas/keys` | Encrypted key vault directory (private keys + vault metadata) |
| `MASTER_ENCRYPTION_KEY` | *(required for encrypted key vault)* | 32-byte AES key (64-char hex, base64, or raw 32-byte string) |
| `ATLAS_SSH_BRIDGE_URL` | `http://localhost:3002` | Browser URL for the Socket.io SSH bridge used by in-app terminal |
| `SNIPPET_STORAGE` | `local` | Proxmox storage with snippets enabled |
| `SNIPPET_DIR` | `/var/lib/vz/snippets` | Filesystem path on PVE node for snippets |
| `VM_USER` | `debian` | Cloud-Init username |
| `PVE_SSH_USER` | `root` | SSH user on the Proxmox host |
| `PVE_SSH_KEY` | `~/.ssh/id_rsa` | SSH private key for the Proxmox host |
| `PVE_SSH_PORT` | `22` | SSH port on the Proxmox host |
| `ATLAS_AUTH_ENABLED` | `false` | Enable web/API authentication and RBAC when running `serve` mode |
| `ATLAS_AUTH_USERS` | *(optional)* | Semicolon-separated `username\|role\|password` entries (roles: `viewer`, `operator`, `admin`) |
| `ATLAS_AUTH_STORE_PATH` | `./.atlas/auth/users.json` | Secure on-disk auth user store used for first-time bootstrap and persisted credentials (Docker compose uses `/auth/users.json` on a named volume) |
| `ATLAS_AUTH_SESSION_TTL_MINUTES` | `480` | Session lifetime in minutes (sliding expiration) |
| `ATLAS_AUTH_LOGIN_MAX_ATTEMPTS` | `5` | Maximum failed login attempts per client IP within the configured window |
| `ATLAS_AUTH_LOGIN_WINDOW_MINUTES` | `15` | Login rate-limit window in minutes |

### Web Authentication Configuration

When `ATLAS_AUTH_ENABLED=true`, you can either:

1. Preconfigure users with `ATLAS_AUTH_USERS`, or
2. Leave `ATLAS_AUTH_USERS` empty and complete first-time bootstrap in the UI (set initial `admin` password; bcrypt hash is stored in `ATLAS_AUTH_STORE_PATH`).

Preconfigured user example:

```bash
ATLAS_AUTH_USERS='viewer|viewer|viewer-pass;ops|operator|ops-pass;admin|admin|admin-pass'
```

For production, prefer bcrypt hashes in `ATLAS_AUTH_USERS`:

```bash
ATLAS_AUTH_USERS='admin|admin|$2b$12$...'
# or explicitly:
ATLAS_AUTH_USERS='admin|admin|bcrypt:$2b$12$...'
```

> **VM naming** is automatic — each VM gets a random Docker-style name like `swift-nexus-a3f1b2`. VMIDs are auto-allocated starting from `VM_START_ID` by scanning the cluster for free IDs.

## Usage

```bash
# Install dependencies
go mod tidy

# Create .env in the project root (example)
cat > .env <<'EOF'
PROXMOX_API_TOKEN=root@pam!atlas=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
PROXMOX_URL=https://192.168.1.100:8006
PROXMOX_NODE=pve
TEMPLATE_VMID=9000
VM_COUNT=1
EOF

# Provision a single VM (default VM_COUNT=1)
go run main.go

# Provision 3 VMs in parallel
VM_COUNT=3 go run main.go

# Use a custom env file
ATLAS_ENV_FILE=.env.prod go run main.go
```

### Example Output (3 VMs)

```
════════════════════════════════════════
   Atlas Plane — VM Provisioner
════════════════════════════════════════
  Proxmox  : https://192.168.1.100:8006 (node: pve1)
  Template : 9000
  Specs    : 1 vCPU, 1024 MiB RAM, 5G disk
  VMs      : 3
             → 500  bold-falcon-e7a2c1
             → 501  swift-nexus-3f19b4
             → 502  keen-orbit-8dc0a5

[vm 500 / bold-falcon-e7a2c1] Cloning template 9000…
[vm 501 / swift-nexus-3f19b4] Cloning template 9000…
[vm 502 / keen-orbit-8dc0a5] Cloning template 9000…
[vm 500 / bold-falcon-e7a2c1] ✓ Clone complete
[vm 500 / bold-falcon-e7a2c1] Configuring hardware…
  ...
[vm 501 / swift-nexus-3f19b4] ✓ Ready at 10.0.10.130
[vm 500 / bold-falcon-e7a2c1] ✓ Ready at 10.0.10.128
[vm 502 / keen-orbit-8dc0a5] ✓ Ready at 10.0.10.131

════════════════════════════════════════
   Results
════════════════════════════════════════
  ✅  VM 500 (bold-falcon-e7a2c1) — 10.0.10.128
        ssh -i bold-falcon-e7a2c1_key debian@10.0.10.128
  ✅  VM 501 (swift-nexus-3f19b4) — 10.0.10.130
        ssh -i swift-nexus-3f19b4_key debian@10.0.10.130
  ✅  VM 502 (keen-orbit-8dc0a5) — 10.0.10.131
        ssh -i keen-orbit-8dc0a5_key debian@10.0.10.131

  3 succeeded, 0 failed
════════════════════════════════════════
```

## How It Works

### SSH Certificate Flow

Traditional SSH uses raw public key authorization. Atlas Plane implements **certificate-based SSH**, which is more scalable and auditable:

1. **CA Key** (`ca_ed25519`) — A long-lived signing key you generate once.
2. **User Key** (`temp_user_key`) — A fresh ephemeral Ed25519 key pair generated per provisioning run.
3. **Certificate** (`temp_user_key-cert.pub`) — The user's public key signed by the CA, valid for 4 hours, restricted to the `debian` principal.

The VM is configured (via Cloud-Init) to trust any certificate signed by the CA:

```
# Written to /etc/ssh/sshd_config.d/trusted_ca.conf
TrustedUserCAKeys /etc/ssh/ca.pub
```

When you run `ssh -i ./temp_user_key debian@<IP>`, OpenSSH automatically discovers the `-cert.pub` file alongside the private key and presents the certificate. The VM's sshd verifies the certificate against the CA public key — no `authorized_keys` management needed.

### Cloud-Init Snippet

The uploaded `vm-{id}-user-data.yml` contains:

```yaml
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - <user-public-key>      # fallback direct key auth

write_files:
  - path: /etc/ssh/ca.pub      # CA public key
  - path: /etc/ssh/sshd_config.d/trusted_ca.conf

runcmd:
  - systemctl restart sshd     # activate CA trust
```

## SSH Key Retrieval

- During provisioning, the pipeline card still shows a **Download Key** button.
- After deployment, use the **Download SSH Key** action directly on each VM card/list item in the VMs panel.
- API routes:
  - `GET /api/vms/{id}/ssh-key` (recommended, stable key lookup by VMID)
  - `GET /api/vms/{id}/ssh-connect` (returns host/user metadata for browser SSH terminal)
  - `POST /api/preflight` (validates provisioning readiness: API, node, template, snippet path/storage, key material, VMID availability)
  - `GET /api/keys/{filename}` (legacy filename route, still supported)

## Browser Terminal (WinBox + xterm.js)

- The **Connect** action on a running VM opens a draggable/resizable WinBox terminal window.
- The frontend streams keystrokes/resize events with Socket.io to `ssh-bridge`.
- `ssh-bridge` decrypts the VM key from `index.json` + `.enc` using `MASTER_ENCRYPTION_KEY`, then authenticates via `ssh2`.
- Private keys never leave server-side containers.

## Docker Migration

Docker artifacts are available for the split backend + SSH bridge architecture:

- `Dockerfile` (optimized Node.js/TypeScript backend image)
- `docker-compose.yml` (backend + `ssh-bridge` + `ssh_key_data` named volume)
- `scripts/migrate_key_vault.py` (one-time migration tool)

Runbook: see [README-docker.md](README-docker.md)

## Cleanup

```bash
# Delete the provisioned VMs
# (via Proxmox UI or API)

# Remove encrypted key vault (all stored SSH keys)
rm -rf ./.atlas/keys
```

## License

MIT
