#!/usr/bin/env bash
# Validate the curated, alert-only detection pack. No sensor reload or deploy.
set -euo pipefail
cd "$(dirname "$0")/.."

for binary in suricata yara; do
  if ! command -v "$binary" >/dev/null 2>&1; then
    printf 'required syntax checker is missing: %s\n' "$binary" >&2
    exit 127
  fi
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

printf '==> Verify Suricata alert-only rules (syntax test, no deployment)\n'
suricata -T \
  -c detectionpack/suricata/validate.yaml \
  -S detectionpack/suricata/artex-alert-only.rules \
  -l "$tmpdir"

printf '==> Verify YARA syntax (scan empty fixture only)\n'
: > "$tmpdir/empty"
yara -w detectionpack/yara/artex-alert-only.yar "$tmpdir/empty"

printf '==> Check no duplicate Suricata SIDs\n'
duplicates="$(grep -oE 'sid:[0-9]+' detectionpack/suricata/artex-alert-only.rules | sort | uniq -d || true)"
if [ -n "$duplicates" ]; then
  printf 'duplicate SIDs: %s\n' "$duplicates" >&2
  exit 1
fi

printf 'Detection pack native syntax validation passed. No rules activated.\n'
