#!/usr/bin/env bash
#
# Install the Gramine runtime on a D1 acceptance instance.
#
# Idempotent: re-running refreshes the apt repository and the package.
# The D1 plan requires one minimal Gramine-SGX program on the SGX host
# before any model share is allowed near the machine.
#
# Usage:
#   sudo ./deploy/install_gramine_server.sh
#
set -euo pipefail

CODENAME="${CODENAME:-$(lsb_release -cs)}"
KEYRING=/usr/share/keyrings/gramine-keyring.gpg
LIST=/etc/apt/sources.list.d/gramine.list

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (sudo)" >&2
    exit 1
fi

echo "==> configuring Gramine apt repository for $CODENAME"
curl -fsSLo "$KEYRING" https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=$KEYRING] https://packages.gramineproject.io/ $CODENAME main" > "$LIST"

echo "==> updating apt metadata"
apt-get update -qq

echo "==> installing gramine"
DEBIAN_FRONTEND=noninteractive apt-get install -y gramine

echo "==> installed packages"
dpkg -l 'gramine*' 2>/dev/null | awk '/^ii/{print $2, $3}'

echo "==> loader version"
gramine-sgx --version
