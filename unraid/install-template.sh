#!/bin/bash
# Install Zoraxy Guard for Unraid: user template + local Docker image
# Run on Unraid Terminal:
#   bash <(curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/unraid/install-template.sh)

set -euo pipefail

TEMPLATE_DIR="/boot/config/plugins/dockerMan/templates-user"
APP_DIR="/mnt/user/appdata/zoraxy-guard"
SRC_DIR="/mnt/user/appdata/zoraxy-guard-src"
IMAGE="ghcr.io/paulg67/zoraxy-guard:latest"
RAW_BASE="https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main"
REPO="https://github.com/PaulG67/zoraxy-guard.git"

echo "==> 1/4 Appdata"
mkdir -p "${APP_DIR}/data/lists" "${APP_DIR}/data/feed-cache"
if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
  curl -fsSL "${RAW_BASE}/config.example.yaml" -o "${APP_DIR}/config.yaml"
  echo "    created ${APP_DIR}/config.yaml"
else
  echo "    keep existing ${APP_DIR}/config.yaml"
fi

echo "==> 2/4 Unraid-Vorlage (Docker → Container hinzufügen → Template)"
mkdir -p "${TEMPLATE_DIR}"
curl -fsSL "${RAW_BASE}/unraid/my-zoraxy-guard.xml" -o "${TEMPLATE_DIR}/my-zoraxy-guard.xml"
echo "    wrote ${TEMPLATE_DIR}/my-zoraxy-guard.xml"

echo "==> 3/4 Docker-Image"
# Prefer pull (Force update later); build only if pull fails
if docker pull "${IMAGE}" 2>/dev/null; then
  echo "    pulled ${IMAGE}"
else
  echo "    pull failed — building locally from GitHub"
  if command -v git >/dev/null 2>&1; then
    if [[ -d "${SRC_DIR}/.git" ]]; then
      git -C "${SRC_DIR}" pull --ff-only || true
    else
      rm -rf "${SRC_DIR}"
      git clone --depth 1 "${REPO}" "${SRC_DIR}"
    fi
  else
    mkdir -p "${SRC_DIR}"
    curl -fsSL "https://codeload.github.com/PaulG67/zoraxy-guard/tar.gz/refs/heads/main" \
      | tar -xz -C "${SRC_DIR}" --strip-components=1
  fi
  docker build -t "${IMAGE}" "${SRC_DIR}"
  echo "    tagged ${IMAGE}"
fi

echo "==> 4/4 Fertig"
echo
echo "In der Unraid-WebUI:"
echo "  1) Docker → Container hinzufügen"
echo "  2) Template-Dropdown → zoraxy-guard wählen"
echo "  3) Zoraxy-Log-Pfad prüfen (Default: /mnt/user/appdata/zoraxy/log)"
echo "  4) WEB_PASSWORD setzen (empfohlen)"
echo "  5) Apply / Erstellen"
echo "  6) Web-GUI: http://UNRAID-IP:8787"
echo
echo "Bei Image-Updates: Docker → Force Update (ghcr.io/paulg67/zoraxy-guard:latest)."
echo "Vorlage/Icon aktualisieren: dieses Script erneut, dann Container Edit → Apply."
