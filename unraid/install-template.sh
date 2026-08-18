#!/bin/bash
# Install / update Zoraxy Guard Unraid user template + pull image
# Run on Unraid Terminal:
#   bash <(curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/unraid/install-template.sh)

set -euo pipefail

TEMPLATE_DIR="/boot/config/plugins/dockerMan/templates-user"
APP_DIR="/mnt/user/appdata/zoraxy-guard"
SRC_DIR="/mnt/user/appdata/zoraxy-guard-src"
IMAGE="ghcr.io/paulg67/zoraxy-guard:latest"
RAW_BASE="https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main"
REPO="https://github.com/PaulG67/zoraxy-guard.git"
USER_XML="${TEMPLATE_DIR}/my-zoraxy-guard.xml"

echo "==> 1/4 Appdata"
mkdir -p "${APP_DIR}/data/lists" "${APP_DIR}/data/feed-cache"
if [[ ! -f "${APP_DIR}/config.yaml" ]]; then
  curl -fsSL "${RAW_BASE}/config.example.yaml" -o "${APP_DIR}/config.yaml"
  echo "    created ${APP_DIR}/config.yaml"
else
  echo "    keep existing ${APP_DIR}/config.yaml"
fi

echo "==> 2/4 Unraid-Vorlage (bestehende Werte bleiben, neue Pfade/Vars kommen dazu)"
mkdir -p "${TEMPLATE_DIR}"
FRESH="$(mktemp)"
MERGE="$(mktemp)"
trap 'rm -f "${FRESH}" "${MERGE}"' EXIT
curl -fsSL "${RAW_BASE}/unraid/my-zoraxy-guard.xml" -o "${FRESH}"
curl -fsSL "${RAW_BASE}/unraid/merge-template.php" -o "${MERGE}"
if command -v php >/dev/null 2>&1; then
  php "${MERGE}" "${USER_XML}" "${FRESH}"
else
  echo "    php fehlt — Vorlage wird komplett ersetzt"
  cp "${FRESH}" "${USER_XML}"
fi
echo "    ${USER_XML}"

echo "==> 3/4 Docker-Image"
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
echo "Bestehender Container (zoraxy-guard schon da):"
echo "  1) Docker → zoraxy-guard → Edit"
echo "  2) Pfade prüfen:"
echo "       CrowdSec Config  → Host /mnt/user/appdata/crowdsec  (oder .../crowdsec/config)"
echo "       CrowdSec Bouncer → Host-Ordner mit der Plugin-config.yaml"
echo "         typisch: /mnt/user/appdata/zoraxy/plugin/zoraxy_crowdsec_bouncer"
echo "  3) Apply  (Force Update allein hängt KEINE neuen Volumes an)"
echo
echo "Neu installieren:"
echo "  Docker → Container hinzufügen → Template zoraxy-guard → Pfade prüfen → Apply"
echo "  GUI: http://UNRAID-IP:8787"
echo
echo "Nur neues Image, keine neuen Pfade: Docker → Force Update."
