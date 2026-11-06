#!/usr/bin/env bash
# Install and configure the host Docker stack bootstrap expects. Root only.
# Idempotent. NVIDIA runtime is configured only when nvidia-smi works.
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "install_host_deps: run as root" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Set after sourcing /etc/os-release (when present).
OS_ID=""
OS_ID_LIKE=""
OS_VERSION_CODENAME=""
OS_VERSION_ID=""

read_os_release() {
    OS_ID="" OS_ID_LIKE="" OS_VERSION_CODENAME="" OS_VERSION_ID=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_VERSION_CODENAME="${VERSION_CODENAME:-}"
        OS_VERSION_ID="${VERSION_ID:-}"
    fi
}

os_is() {
    # Match ID or a token in ID_LIKE (space-separated).
    local want="$1" tok
    [[ "$OS_ID" == "$want" ]] && return 0
    for tok in $OS_ID_LIKE; do
        [[ "$tok" == "$want" ]] && return 0
    done
    return 1
}

DOCKER_JUST_INSTALLED=0
DOCKER_DAEMON_CHANGED=0

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

docker_stack_ready() {
    have docker && docker compose version >/dev/null 2>&1
}

install_docker_ce_dnf() {
    # Fedora / Nobara / RHEL-family with dnf: official Fedora Docker CE repo.
    dnf install -y dnf-plugins-core
    if dnf config-manager addrepo --help >/dev/null 2>&1; then
        dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
    else
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    fi
    dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

install_docker_ce_apt() {
    # $1 = docker.com distro path segment: ubuntu | debian
    local distro_path="$1"
    local codename="${OS_VERSION_CODENAME:-}"
    if [[ -z "$codename" ]]; then
        echo "install_host_deps: /etc/os-release has no VERSION_CODENAME; cannot add the Docker apt repo" >&2
        exit 1
    fi
    apt-get update
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${distro_path}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${distro_path} ${codename} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

install_docker_distro_apt() {
    # Prefer packages shipped by the distro (docker.io + compose v2). Used for
    # Kali and other Debian-like systems where the Ubuntu Docker CE repo breaks apt.
    apt-get update
    if apt-cache show docker.io >/dev/null 2>&1; then
        # docker-compose-v2 is the Debian/Ubuntu/Kali package name for the v2 plugin.
        if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
            apt-get install -y docker.io docker-compose-v2
        elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
            apt-get install -y docker.io docker-compose-plugin
        else
            apt-get install -y docker.io
        fi
    else
        echo "install_host_deps: no docker.io package available from apt on ${OS_ID:-unknown}" >&2
        echo "install_host_deps: install Docker Engine and the compose plugin manually, then re-run" >&2
        exit 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "install_host_deps: docker.io installed but 'docker compose' is missing" >&2
        echo "install_host_deps: install docker-compose-v2 (or the compose plugin) and re-run" >&2
        exit 1
    fi
}

install_docker() {
    if docker_stack_ready; then
        return 0
    fi

    read_os_release

    if have dnf; then
        if os_is fedora || os_is rhel || os_is centos || [[ "$OS_ID" == "nobara" ]]; then
            install_docker_ce_dnf
        else
            echo "install_host_deps: unsupported dnf distro '${OS_ID:-unknown}' (ID_LIKE='${OS_ID_LIKE}')" >&2
            echo "install_host_deps: install Docker Engine and the compose plugin manually, then re-run" >&2
            exit 1
        fi
    elif have apt-get; then
        case "$OS_ID" in
            ubuntu)
                install_docker_ce_apt ubuntu
                ;;
            debian)
                install_docker_ce_apt debian
                ;;
            kali)
                # Kali is Debian-based; the Ubuntu Docker CE repo breaks its apt sources.
                echo "install_host_deps: Kali detected — installing docker.io from distro apt (not the Ubuntu Docker repo)" >&2
                install_docker_distro_apt
                ;;
            *)
                if os_is debian; then
                    echo "install_host_deps: Debian-like distro '${OS_ID}' — installing docker.io from distro apt" >&2
                    echo "install_host_deps: refusing to add the Ubuntu Docker apt repo (it breaks non-Ubuntu systems)" >&2
                    install_docker_distro_apt
                elif os_is ubuntu; then
                    install_docker_ce_apt ubuntu
                else
                    echo "install_host_deps: unsupported apt distro '${OS_ID:-unknown}' (ID_LIKE='${OS_ID_LIKE}')" >&2
                    echo "install_host_deps: install Docker Engine and the compose plugin manually, then re-run" >&2
                    echo "install_host_deps: do not add download.docker.com/linux/ubuntu on non-Ubuntu systems" >&2
                    exit 1
                fi
                ;;
        esac
    else
        echo "install_host_deps: install Docker Engine and the compose plugin manually" >&2
        exit 1
    fi

    DOCKER_JUST_INSTALLED=1
}

ensure_docker_running() {
    # Only enable/start when Docker was just installed or is not active.
    # Never restart a healthy daemon on every install_host_deps re-run.
    if [[ "$DOCKER_JUST_INSTALLED" -eq 1 ]]; then
        systemctl enable --now docker
        return 0
    fi
    if systemctl is-active --quiet docker; then
        systemctl enable docker >/dev/null 2>&1 || true
        return 0
    fi
    systemctl enable --now docker
}

configure_nvidia_runtime() {
    # SPOTTER compose sets NVIDIA_VISIBLE_DEVICES and does not pass gpus:.
    # That variable is ignored unless the NVIDIA runtime is the default.
    have nvidia-smi || return 0

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

    local changed
    changed="$(python3 - << 'PY'
import json
from pathlib import Path
p = Path("/etc/docker/daemon.json")
cfg = {}
if p.exists() and p.read_text().strip():
    cfg = json.loads(p.read_text())
before = json.dumps(cfg, sort_keys=True)
cfg["default-runtime"] = "nvidia"
cfg.setdefault("runtimes", {}).setdefault("nvidia", {
    "path": "nvidia-container-runtime",
    "runtimeArgs": [],
})
after = json.dumps(cfg, sort_keys=True)
if before != after or not p.exists():
    p.write_text(json.dumps(cfg, indent=2) + "\n")
    print("changed")
else:
    print("unchanged")
PY
)"
    if [[ "$changed" == "changed" ]]; then
        DOCKER_DAEMON_CHANGED=1
    fi
}

configure_docker() {
    ensure_docker_running

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        if ! id -nG "${SUDO_USER}" | tr ' ' '\n' | grep -qx docker; then
            usermod -aG docker "${SUDO_USER}"
            echo "install_host_deps: ${SUDO_USER} added to docker; re-login before a non-root up" >&2
        fi
    fi

    configure_nvidia_runtime

    if [[ "$DOCKER_DAEMON_CHANGED" -eq 1 ]]; then
        systemctl restart docker
    fi

    local net="${FLOWSINT_NETWORK:-flowsint_network_prod}"
    if ! docker network inspect "$net" >/dev/null 2>&1; then
        docker network create "$net" >/dev/null
    fi
}

if have dnf; then
    dnf install -y git curl jq openssl python3 python3-requests age
elif have apt-get; then
    apt-get update
    apt-get install -y git curl jq openssl python3 python3-requests age
else
    echo "install_host_deps: no dnf or apt-get" >&2
    exit 1
fi

install_docker
configure_docker
install_sops
