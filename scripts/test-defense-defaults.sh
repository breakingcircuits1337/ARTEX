#!/usr/bin/env bash
# PR #9 regression checks: packaged defense defaults and fork-specific links.
set -euo pipefail
cd "$(dirname "$0")/.."
check() {
  if ! grep -Fq -- "$2" "$1"; then
    printf 'missing expected configuration in %s: %s\n' "$1" "$2" >&2
    exit 1
  fi
}
check .env.example 'ARTEX_MODE=defense'
# Direct binary and embedded callers must also default to restricted defense.
check defense/policy.go 'return "defense"'
check .env.example 'ARTEX_AUTO_CONTAIN_MODE=off'
check .env.example 'POSTGRES_PASSWORD='
if grep -Eq '^POSTGRES_PASSWORD=[^#[:space:]]+' .env.example; then
  echo '.env.example must not ship a shared database password' >&2
  exit 1
fi
check docker-compose.yml 'ARTEX_MODE: ${ARTEX_MODE:-defense}'
check docker-compose.yml 'ARTEX_AUTO_CONTAIN_MODE: ${ARTEX_AUTO_CONTAIN_MODE:-off}'
check docker-compose.ghcr.yml 'ARTEX_MODE: ${ARTEX_MODE:-defense}'
check docker-compose.ghcr.yml 'ARTEX_AUTO_CONTAIN_MODE: ${ARTEX_AUTO_CONTAIN_MODE:-off}'
check docker-compose.ghcr.yml 'ghcr.io/breakingcircuits1337/artex-defense'
check start.sh 'ARTEX_MODE=${ARTEX_MODE:-defense}'
check install.sh 'export ARTEX_MODE="${ARTEX_MODE:-defense}"'
check README.md '# ARTEX-DEFENSE'
check SECURITY.md 'breakingcircuits1337/ARTEX-DEFENSE/security/advisories/new'
check .github/workflows/bot.yml "github.actor != github.repository_owner"
check .github/scripts/bot.sh '${GITHUB_REPOSITORY%%/*}'
if grep -Eq 'breakingcircuits1337/ARTEX([/.]|$)' README.md; then
  echo 'README still links to the retired Breaking Circuits ARTEX repo' >&2
  exit 1
fi
if grep -q 'github.com/BaaRai/ARTEX/security/advisories/new' SECURITY.md; then
  echo 'SECURITY.md still sends fork reports upstream' >&2
  exit 1
fi
echo 'ok: ARTEX-DEFENSE packaged safety defaults, links, and maintainer bot'
