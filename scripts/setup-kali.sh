#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRO_NAME="${PRETTY_NAME:-unknown}"
else
  DISTRO_NAME="unknown"
fi

echo "[*] Preparing osint-cli on ${DISTRO_NAME}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 is required. On Kali run:"
  echo "    sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "[!] python3-venv is required. On Kali run:"
  echo "    sudo apt update && sudo apt install -y python3-venv"
  exit 1
fi

if [[ ! -d .venv ]]; then
  echo "[*] Creating virtual environment at .venv"
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

cat <<'EOF'

[+] osint-cli is ready.

Activate the environment:
    source .venv/bin/activate

Quick examples:
    osint-cli domain example.com
    osint-cli user johndoe --services github,gitlab
    osint-cli ip 8.8.8.8 --json

Optional API setup:
    export HIBP_API_KEY="your_hibp_api_key"
    export IPINFO_TOKEN="your_ipinfo_token"

EOF
