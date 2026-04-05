#!/usr/bin/env bash
set -euo pipefail

# Install latest stable Xray binary on Linux runners.
# Designed for GitHub Actions (non-interactive).

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
  aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "Resolving latest Xray release asset: ${ASSET}"
XRAY_URL="$(
  curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" \
  | grep -Eo "\"browser_download_url\": *\"[^\"]*${ASSET}\"" \
  | head -n1 \
  | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/'
)"

if [ -z "${XRAY_URL}" ]; then
  echo "Could not resolve latest Xray download URL for ${ASSET}" >&2
  exit 1
fi

echo "Downloading: ${XRAY_URL}"
curl -fL "${XRAY_URL}" -o "${TMP_DIR}/${ASSET}"

unzip -o "${TMP_DIR}/${ASSET}" -d "${TMP_DIR}/xray" >/dev/null
${SUDO} install -m 0755 "${TMP_DIR}/xray/xray" /usr/local/bin/xray

echo "Installed Xray to /usr/local/bin/xray"
/usr/local/bin/xray version
