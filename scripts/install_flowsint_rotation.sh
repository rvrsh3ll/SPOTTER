#!/usr/bin/env bash
# Install the Flowsint token rotation systemd timer.
#
# Usage:
#   sudo scripts/install_flowsint_rotation.sh
#
# This installs the systemd unit and timer and enables it. Credentials come from
# what bootstrap.sh stored; /etc/spotter/flowsint-admin.env can override them.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
CONF_DIR="/etc/spotter"

[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

echo "==> Installing Flowsint token rotation timer"

# Create config directory
mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"

# bootstrap.sh stores FLOWSINT_ADMIN_EMAIL (.env) and FLOWSINT_ADMIN_PASSWORD
# (machine tier), and the rotation script reads them from there. The env file
# below is only an override for installs that predate that.
resolve() {
    KEY="$1" ROOTD="$ROOT_DIR" python3 -c '
import os, sys
sys.path.insert(0, os.path.join(os.environ["ROOTD"], "scripts"))
import spotter_env
v = (spotter_env.get(os.environ["KEY"]) or "").strip()
print("set" if v and v != "CHANGE_ME" else "missing")
' 2>/dev/null || echo missing
}
env_file_value() { sed -n "s/^$1=//p" "$CONF_DIR/flowsint-admin.env" 2>/dev/null | tail -1; }

if [[ ! -f "$CONF_DIR/flowsint-admin.env" ]]; then
    cat > "$CONF_DIR/flowsint-admin.env" <<'EOF'
# Optional overrides for Flowsint token rotation. Leave empty to use the values
# bootstrap.sh stored (FLOWSINT_ADMIN_EMAIL in .env, FLOWSINT_ADMIN_PASSWORD in
# secrets/machine.sops.env).
FLOWSINT_ADMIN_EMAIL=
FLOWSINT_ADMIN_PASSWORD=
EOF
    chmod 600 "$CONF_DIR/flowsint-admin.env"
fi

for key in FLOWSINT_ADMIN_EMAIL FLOWSINT_ADMIN_PASSWORD; do
    v="$(env_file_value "$key")"
    if [[ "$v" == "CHANGE_ME" ]] || { [[ -z "$v" ]] && [[ "$(resolve "$key")" != "set" ]]; }; then
        echo "ERROR: $key is not set (or still CHANGE_ME)." >&2
        echo "       Re-run scripts/bootstrap.sh, or set it in $CONF_DIR/flowsint-admin.env" >&2
        exit 1
    fi
done

# Install systemd units (point WorkingDirectory to actual SPOTTER checkout)
sed "s|/home/user/SPOTTER|$ROOT_DIR|g" "$ROOT_DIR/deployment/spotter-flowsint-rotation.service" \
    > "$SYSTEMD_DIR/spotter-flowsint-rotation.service"
cp "$ROOT_DIR/deployment/spotter-flowsint-rotation.timer" \
    "$SYSTEMD_DIR/spotter-flowsint-rotation.timer"

# Reload and enable
systemctl daemon-reload
systemctl enable --now spotter-flowsint-rotation.timer

echo "    Timer enabled and started"
echo "    Next rotation: $(systemctl list-timers spotter-flowsint-rotation.timer --no-pager | tail -n +2 | awk '{print $1, $2, $3}')"
echo ""
echo "==> Check status:"
echo "    systemctl status spotter-flowsint-rotation.timer"
echo "    journalctl -u spotter-flowsint-rotation.service"
