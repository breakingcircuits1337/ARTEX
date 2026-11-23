#!/usr/bin/env python3
"""Forward Suricata EVE / Wazuh JSON-lines to ARTEX Defense without dependencies.

Never prints credentials or raw event bodies. Existing ARTEX admin session bearer
tokens are accepted for the Phase 2 MVP; run only in a trusted network.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_LINE = 128 * 1024
MAX_BATCH = 50


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("collector URL must not have credentials, query or fragment")
    if parsed.path not in ("", "/"):
        raise ValueError("collector URL must be a service origin, without a path")
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError("collector URL requires an absolute http(s) origin")
    if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("remote collectors must use HTTPS")
    return url.rstrip("/") + "/api/defense/events"


def send_batch(endpoint: str, token: str, source: str, batch: list[dict]) -> dict:
    if not 1 <= len(batch) <= MAX_BATCH:
        raise ValueError("batch must contain 1..50 events")
    body = json.dumps({"source": source, "events": batch}, separators=(",", ":")).encode()
    if len(body) > (1 << 20):
        raise ValueError("batch exceeds the 1 MiB HTTP limit")
    req = urllib.request.Request(
        endpoint,
        body,
        {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=20) as resp:
            response = json.load(resp)
    except urllib.error.HTTPError as exc:
        # Do not include response body: it might echo an operator-owned payload.
        raise RuntimeError(f"ARTEX returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError("ARTEX is unreachable or its TLS certificate is untrusted") from exc
    if not isinstance(response, dict):
        raise RuntimeError("Unexpected ARTEX acknowledgment")
    return response


def iter_records(path: pathlib.Path, follow: bool):
    with path.open("r", encoding="utf-8") as stream:
        while True:
            line = stream.readline(MAX_LINE + 2)
            if not line:
                if not follow:
                    return
                time.sleep(1)
                yield None  # idle tick lets the forwarder flush partial batches
                continue
            if len(line.encode("utf-8")) > MAX_LINE:
                raise ValueError("log line exceeds 128 KiB; refusing to forward")
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError("invalid JSON record in source log") from None
            if not isinstance(obj, dict):
                raise ValueError("event record must be a JSON object")
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("suricata", "wazuh", "generic", "ocsf"), required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--file", type=pathlib.Path, required=True, help="newline-delimited event JSON file")
    parser.add_argument("--follow", action="store_true", help="keep reading appended lines")
    parser.add_argument("--batch-size", type=int, default=20)
    opts = parser.parse_args(argv)
    if not 1 <= opts.batch_size <= MAX_BATCH:
        parser.error("--batch-size must be 1..50")
    token = os.environ.get("ARTEX_DEFENSE_JWT", "")
    if not token:
        parser.error("set ARTEX_DEFENSE_JWT to a valid ARTEX session bearer token")
    try:
        endpoint = validate_endpoint(opts.url)
        pending: list[dict] = []
        last_flush = time.monotonic()
        for item in iter_records(opts.file, opts.follow):
            if item is not None:
                pending.append(item)
            if pending and (len(pending) >= opts.batch_size or time.monotonic() - last_flush >= 5):
                result = send_batch(endpoint, token, opts.source, pending)
                print(f"Accepted={result.get('ingested', 0)} duplicates={result.get('duplicates', 0)}")
                pending.clear()
                last_flush = time.monotonic()
        if pending:
            result = send_batch(endpoint, token, opts.source, pending)
            print(f"Accepted={result.get('ingested', 0)} duplicates={result.get('duplicates', 0)}")
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"forwarder failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
