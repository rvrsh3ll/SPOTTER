#!/usr/bin/env bash
# Install and configure the host Docker stack bootstrap expects. Root only.
# Idempotent. NVIDIA runtime is configured only when nvidia-smi works.
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "install_host_deps: run as root" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

install_sops() {
    have sops && return 0
    local tag ver arch rpmarch url
    tag="$(curl -fsSL https://api.github.com/repos/getsops/sops/releases/latest | jq -r .tag_name)"
    ver="${tag#v}"
    case "$(uname -m)" in
        x86_64) arch=amd64; rpmarch=x86_64 ;;
        aarch64|arm64) arch=arm64; rpmarch=aarch64 ;;
        *) echo "install_host_deps: unsupported arch $(uname -m)" >&2; exit 1 ;;
    esac
    if have dnf; then
        dnf install -y "https://github.com/getsops/sops/releases/download/${tag}/sops-${ver}-1.${rpmarch}.rpm"
    elif have apt-get; then
        url="https://github.com/getsops/sops/releases/download/${tag}/sops_${ver}_${arch}.deb"
        curl -fsSL "$url" -o /tmp/sops.deb
        apt-get install -y /tmp/sops.deb
        rm -f /tmp/sops.deb
    else
        echo "install_host_deps: install sops ${tag} manually" >&2
        exit 1
    fi
}

install_docker() {
    have docker && docker compose version >/dev/null 2>&1 && return 0
    if have dnf; then
        dnf install -y dnf-plugins-core
        if dnf config-manager addrepo --help >/dev/null 2>&1; then
            dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
        else
            dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        fi
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif have apt-get; then
        apt-get update
        apt-get install -y ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        . /etc/os-release
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        echo "install_host_deps: install Docker Engine and the compose plugin manually" >&2
        exit 1
    fi
}

configure_docker() {
    systemctl enable --now docker
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        usermod -aG docker "${SUDO_USER}"
        echo "install_host_deps: ${SUDO_USER} added to docker; re-login before a non-root up" >&2
    fi
    # SPOTTER compose sets NVIDIA_VISIBLE_DEVICES and does not pass gpus:.
    # That variable is ignored unless the NVIDIA runtime is the default.
    if have nvidia-smi; then
        if ! have nvidia-ctk; then
            if have dnf; then
                curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
                    -o /etc/yum.repos.d/nvidia-container-toolkit.repo
                dnf install -y nvidia-container-toolkit
            elif have apt-get; then
                curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
                    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
                curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
                    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
                    > /etc/apt/sources.list.d/nvidia-container-toolkit.list
                apt-get update
                apt-get install -y nvidia-container-toolkit
            fi
        fi
        nvidia-ctk runtime configure --runtime=docker
        python3 - << 'PY'
import json
from pathlib import Path
p = Path("/etc/docker/daemon.json")
cfg = {}
if p.exists() and p.read_text().strip():
    cfg = json.loads(p.read_text())
cfg["default-runtime"] = "nvidia"
cfg.setdefault("runtimes", {}).setdefault("nvidia", {
    "path": "nvidia-container-runtime",
    "runtimeArgs": [],
})
p.write_text(json.dumps(cfg, indent=2) + "\n")
PY
        systemctl restart docker
    fi
    local net="${FLOWSINT_NETWORK:-flowsint_network_prod}"
    docker network inspect "$net" >/dev/null 2>&1 || docker network create "$net" >/dev/null
}

if have dnf; then
    dnf install -y git curl jq openssl python3 age
elif have apt-get; then
    apt-get update
    apt-get install -y git curl jq openssl python3 age
else
    echo "install_host_deps: no dnf or apt-get" >&2
    exit 1
fi

install_docker
configure_docker
install_sops
