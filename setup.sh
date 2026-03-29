#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: setup.sh KEY_NAME IP_ADDRESS VM_USER

Example:
  setup.sh eager-kite-2912ae_key 10.0.10.231 debian
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 3 ]]; then
  usage
  exit 1
fi

KEY_NAME="$1"
IP_ADDRESS="$2"
VM_USER="$3"
HOST_ALIAS="${KEY_NAME%_key}"

DOWNLOADS_DIR="$HOME/Downloads"
SSH_DIR="$HOME/.ssh"
PROVISIONED_DIR="$SSH_DIR/provisioned_keys"
SRC_KEY_PATH="$DOWNLOADS_DIR/$KEY_NAME"
DST_KEY_PATH="$PROVISIONED_DIR/$KEY_NAME"
SSH_CONFIG="$SSH_DIR/config"

mkdir -p "$SSH_DIR" "$PROVISIONED_DIR"
chmod 700 "$SSH_DIR"

if [[ -f "$SRC_KEY_PATH" ]]; then
  mv -f "$SRC_KEY_PATH" "$DST_KEY_PATH"
elif [[ ! -f "$DST_KEY_PATH" ]]; then
  echo "Error: key not found at '$SRC_KEY_PATH' or '$DST_KEY_PATH'." >&2
  exit 1
fi

chmod 600 "$DST_KEY_PATH"

touch "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG"

host_exists() {
  awk -v host_alias="$HOST_ALIAS" '
    tolower($1) == "host" {
      for (i = 2; i <= NF; i++) {
        if ($i == host_alias) {
          print "yes"
          exit
        }
      }
    }
  ' "$SSH_CONFIG"
}

update_hostname() {
  local tmp_file
  tmp_file="$(mktemp)"

  awk -v host_alias="$HOST_ALIAS" -v new_ip="$IP_ADDRESS" '
    function print_hostname_if_missing() {
      if (in_target_block && !hostname_updated) {
        print "    HostName " new_ip
      }
    }

    tolower($1) == "host" {
      print_hostname_if_missing()
      in_target_block = 0
      hostname_updated = 0

      for (i = 2; i <= NF; i++) {
        if ($i == host_alias) {
          in_target_block = 1
        }
      }

      print
      next
    }

    {
      if (in_target_block && tolower($1) == "hostname") {
        print "    HostName " new_ip
        hostname_updated = 1
        next
      }
      print
    }

    END {
      print_hostname_if_missing()
    }
  ' "$SSH_CONFIG" > "$tmp_file"

  mv "$tmp_file" "$SSH_CONFIG"
}

append_host_block() {
  {
    [[ -s "$SSH_CONFIG" ]] && printf '\n'
    printf 'Host %s\n' "$HOST_ALIAS"
    printf '    HostName %s\n' "$IP_ADDRESS"
    printf '    User %s\n' "$VM_USER"
    printf '    IdentityFile %s\n' "$DST_KEY_PATH"
    printf '    IdentitiesOnly yes\n'
  } >> "$SSH_CONFIG"
}

if [[ -n "$(host_exists)" ]]; then
  update_hostname
else
  append_host_block
fi

echo "SSH key setup complete. Connect with: ssh $HOST_ALIAS"
