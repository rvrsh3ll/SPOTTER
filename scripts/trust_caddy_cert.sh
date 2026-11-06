#!/usr/bin/env bash
# Install Caddy's local root CA into the OS trust store so browsers stop
# warning on *.localhost:5443. Root only. Idempotent.
#
#   sudo scripts/trust_caddy_cert.sh
#   sudo ./spotter trust-cert
#
# Handles Fedora/Nobara (update-ca-trust) and Debian/Ubuntu/Kali
# (update-ca-certificates). The leaf certs Caddy issues per hostname are
# signed by this CA; trusting the CA once covers every vhost.
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "trust_caddy_cert: run as root" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_NAME="spotter-caddy-root.crt"
CONTAINER="${SPOTTER_CADDY_CONTAINER:-spotter-caddy}"
CA_PATH_IN_CONTAINER="/data/caddy/pki/authorities/local/root.crt"

have() { command -v "$1" >/dev/null 2>&1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

extract_ca() {
    if have docker && docker inspect "$CONTAINER" >/dev/null 2>&1; then
        if docker exec "$CONTAINER" cat "$CA_PATH_IN_CONTAINER" >"$tmp" 2>/dev/null; then
            return 0
        fi
    fi

    # Fallback: read from the host bind/volume path recorded in .env, when present.
    local host_dir=""
    if [[ -f "$ROOT_DIR/.env" ]]; then
        host_dir="$(sed -n 's/^SPOTTER_CADDY_DATA_DIR=//p' "$ROOT_DIR/.env" | tail -1)"
    fi
    if [[ -n "$host_dir" && -f "$host_dir/caddy/pki/authorities/local/root.crt" ]]; then
        cat "$host_dir/caddy/pki/authorities/local/root.crt" >"$tmp"
        return 0
    fi
    if [[ -n "$host_dir" && -f "$host_dir/pki/authorities/local/root.crt" ]]; then
        cat "$host_dir/pki/authorities/local/root.crt" >"$tmp"
        return 0
    fi

    echo "trust_caddy_cert: could not read Caddy's local root CA" >&2
    echo "  Ensure the stack is up (sudo ./spotter up) so container '$CONTAINER' exists," >&2
    echo "  or set SPOTTER_CADDY_DATA_DIR in .env to the host data directory." >&2
    exit 1
}

extract_ca

if ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
    echo "trust_caddy_cert: extracted file does not look like a PEM certificate" >&2
    exit 1
fi

OS_ID=""
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
fi

install_fedora_family() {
    local dest="/etc/pki/ca-trust/source/anchors/${CERT_NAME}"
    install -m 0644 "$tmp" "$dest"
    update-ca-trust
    echo "trust_caddy_cert: installed $dest and ran update-ca-trust"
}

install_debian_family() {
    local dest="/usr/local/share/ca-certificates/${CERT_NAME}"
    # update-ca-certificates expects *.crt under /usr/local/share/ca-certificates/
    install -d -m 0755 /usr/local/share/ca-certificates
    install -m 0644 "$tmp" "$dest"
    update-ca-certificates
    echo "trust_caddy_cert: installed $dest and ran update-ca-certificates"
}

if [[ -d /etc/pki/ca-trust/source/anchors ]] && have update-ca-trust; then
    install_fedora_family
elif [[ -d /usr/local/share/ca-certificates ]] || have update-ca-certificates; then
    install_debian_family
else
    echo "trust_caddy_cert: unsupported distro '${OS_ID:-unknown}'" >&2
    echo "  Manual install: copy the PEM below into your OS trust store." >&2
    echo "  ---" >&2
    cat "$tmp" >&2
    exit 1
fi

echo "trust_caddy_cert: done — restart the browser (or its cert cache) if warnings persist"
