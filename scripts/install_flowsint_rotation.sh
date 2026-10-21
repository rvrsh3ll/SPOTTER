#!/usr/bin/env bash
# Install the Flowsint token rotation systemd timer.
#
# Usage:
#   sudo scripts/install_flowsint_rotation.sh
#
# This installs the systemd unit and timer, creates /etc/spotter/flowsint-admin.env
# if it doesn't exist (where you put FLOWSINT_ADMIN_PASSWORD), and enables the timer.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
CONF_DIR="/etc/spotter"

[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root" >&2; exit 1; }

echo "==> Installing Flowsint token rotation timer"

# Create config directory
mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"

# Create env file template if it doesn't exist
if [[ ! -f "$CONF_DIR/flowsint-admin.env" ]]; then
    cat > "$CONF_DIR/flowsint-admin.env" <<'EOF'
# Flowsint admin password for token rotation
# Get this from your Flowsint admin account or .env FLOWSINT_ADMIN_PASSWORD
FLOWSINT_ADMIN_PASSWORD=CHANGE_ME
EOF
    chmod 600 "$CONF_DIR/flowsint-admin.env"
    echo "    Created $CONF_DIR/flowsint-admin.env — edit it to set FLOWSINT_ADMIN_PASSWORD"
fi

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
