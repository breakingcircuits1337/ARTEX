#!/usr/bin/env bash
# Validate that the *active* Docker engine is rootless before deployment.
# Running Docker as an ordinary user is not proof: rootful dockerd can be
# accessed through docker group membership or DOCKER_HOST.
# The ARTEX binary separately enforces ARTEX_REQUIRE_USERNS=1 at startup.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

engine="${DOCKER_BIN:-docker}"
deployment="${1:-local}"
case "$deployment" in
  local) compose="docker-compose.yml" ;;
  ghcr) compose="docker-compose.ghcr.yml" ;;
  *) echo "usage: $0 [local|ghcr]" >&2; exit 2 ;;
esac

if ! security="$("$engine" info --format '{{json .SecurityOptions}}')"; then
  echo "refusing rootless deployment: Docker engine unavailable" >&2
  exit 1
fi

if ! printf '%s\n' "$security" | python3 -c '
import json, sys
try:
    options = json.load(sys.stdin)
except (ValueError, TypeError):
    sys.exit(1)
if not isinstance(options, list):
    sys.exit(1)
normalized = [v if isinstance(v, str) else v.get("name", "") for v in options if isinstance(v, (str, dict))]
if not any(v == "name=rootless" or v == "rootless" for v in normalized):
    sys.exit(1)
'; then
  echo "refusing rootless deployment: active Docker daemon is not marked rootless" >&2
  echo "Use a rootless Docker context, not merely an unprivileged docker client." >&2
  exit 1
fi

# Validate the same Compose configuration ARTEX uses without starting
# containers or changing the existing network policy.
if ! ARTEX_REQUIRE_EXEC_ISOLATION=1 ARTEX_REQUIRE_USERNS=1 "$engine" compose -f "$compose" config --quiet; then
  echo "refusing rootless deployment: invalid Compose configuration" >&2
  exit 1
fi

echo "ok: rootless Docker daemon and $compose configuration verified"
echo "Set ARTEX_REQUIRE_USERNS=1 in .env before deploying."
echo "The ARTEX binary will refuse startup if UID 0 is not remapped."
