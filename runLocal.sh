#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing root .env file." >&2
  exit 1
fi

set -a

# shellcheck disable=SC1091
source .env

set +a

if podman container exists mailpit; then
  if [[ "$(podman inspect --format '{{.State.Running}}' mailpit)" != "true" ]]; then
    podman start mailpit
  fi
else
  podman run --detach \
    --name mailpit \
    --publish 1025:1025 \
    --publish 8025:8025 \
    --restart unless-stopped \
    docker.io/axllent/mailpit:latest
fi

if podman container exists phoenix-redis; then
  if [[ "$(podman inspect --format '{{.State.Running}}' phoenix-redis)" != "true" ]]; then
    podman start phoenix-redis
  fi
else
  podman run --detach \
    --name phoenix-redis \
    --publish 6379:6379 \
    --restart unless-stopped \
    docker.io/library/redis:7-alpine
fi

./gradlew clean build

SPRING_PROFILES_ACTIVE=local ./gradlew bootRun