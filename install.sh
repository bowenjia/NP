#!/bin/bash
#
# One-line installer.
#
# Usage:
#   curl -sSL <host>/install.sh | bash -s -- <CODE>
#   curl -sSL <host>/install.sh | bash -s -- <CODE> https://host.example.com
#
# Requirements: Docker on the target device.
# Supported: Linux (x86_64, ARM64), macOS, any Docker-capable device.
#

set -e

PAIRING_CODE="${1}"
CMS_URL="${2:-http://localhost:3000}"
MQTT_URL="${3:-mqtt://mqtt:1883}"
CONTAINER_NAME="np"
IMAGE="ghcr.io/bowenjia/np:latest"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$PAIRING_CODE" ]; then
    echo -e "${RED}Error: code is required.${NC}"
    echo "Usage: $0 <CODE> [URL] [MQTT_URL]"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    echo "Install Docker first: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

echo -e "${GREEN}✓${NC} Docker: $(docker --version | head -1)"

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}→${NC} Replacing existing instance..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

echo -e "${BLUE}→ Starting...${NC}"
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -e CMS_URL="$CMS_URL" \
    -e PAIRING_CODE="$PAIRING_CODE" \
    -e MQTT_BROKER_URL="$MQTT_URL" \
    -v np-cache:/app/cache \
    -p 4000:4000 \
    --health-cmd="wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/health || exit 1" \
    --health-interval=30s \
    "$IMAGE"

echo -e "${GREEN}✓ Running.${NC}"
echo "  docker logs -f $CONTAINER_NAME"
