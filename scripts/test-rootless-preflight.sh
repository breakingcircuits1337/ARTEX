#!/usr/bin/env bash
# No Docker daemon or network required: inject a fake Docker client and verify
# that rootless deployments fail closed on a rootful or misconfigured engine.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "info --format {{json .SecurityOptions}}")
    case "${MOCK_DOCKER_ENGINE:-rootful}" in
      rootless) printf '%s\n' '["name=seccomp,profile=builtin","name=rootless"]' ;;
      rootful) printf '%s\n' '["name=seccomp,profile=builtin","name=cgroupns"]' ;;
      malformed) printf '%s\n' 'not-json' ;;
      unavailable) exit 1 ;;
    esac
    ;;
  "compose -f docker-compose.yml config --quiet"|"compose -f docker-compose.ghcr.yml config --quiet")
    if [ "${ARTEX_REQUIRE_EXEC_ISOLATION:-}" != 1 ] || [ "${ARTEX_REQUIRE_USERNS:-}" != 1 ]; then
      exit 1
    fi
    [ "${MOCK_DOCKER_COMPOSE_FAIL:-0}" != 1 ]
    ;;
  *) echo "unexpected Docker command: $*" >&2; exit 2 ;;
esac
SH
chmod +x "$tmp/docker"
export DOCKER_BIN="$tmp/docker"

for mode in rootful malformed unavailable; do
  if MOCK_DOCKER_ENGINE="$mode" bash scripts/rootless-preflight.sh local >"$tmp/out" 2>"$tmp/err"; then
    echo "rootless preflight accepted $mode Docker engine" >&2
    exit 1
  fi
done

for compose in local ghcr; do
  if ! MOCK_DOCKER_ENGINE=rootless bash scripts/rootless-preflight.sh "$compose" >"$tmp/out" 2>"$tmp/err"; then
    cat "$tmp/err" >&2
    echo "rootless preflight rejected mocked rootless engine" >&2
    exit 1
  fi
done

if MOCK_DOCKER_ENGINE=rootless MOCK_DOCKER_COMPOSE_FAIL=1 bash scripts/rootless-preflight.sh local >"$tmp/out" 2>"$tmp/err"; then
  echo "rootless preflight accepted invalid Compose configuration" >&2
  exit 1
fi

if MOCK_DOCKER_ENGINE=rootless bash scripts/rootless-preflight.sh typo >"$tmp/out" 2>"$tmp/err"; then
  echo "rootless preflight accepted unknown deployment mode" >&2
  exit 1
fi

echo "ok: fail-closed rootless preflight with mocked Docker"
