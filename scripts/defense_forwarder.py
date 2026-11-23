#!/usr/bin/env python3
"""ARTEX-DEFENSE secure collector: durable JSONL to authenticated telemetry.

Credentials are restricted to ARTEX_COLLECTOR_TOKEN, not admin session JWTs.
The SQLite spool checkpoints source offsets atomically with queued records.
A crash or failed send can replay a batch; the server deduplicates per collector.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_LINE = 128 * 1024
MAX_BATCH = 50
MAX_BODY = 1 << 20
MAX_QUEUED = 10000
MAX_BATCH_BYTES = 850000


class DeliveryError(RuntimeError):
    """Transient delivery failure. Keep the spool for retry."""


class PermanentDeliveryError(DeliveryError):
    """Operator must fix the token, source, or data; spool is retained."""


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
    return url.rstrip("/") + "/api/defense/collector/events"


def send_batch(endpoint: str, token: str, source: str, batch: list[dict]) -> dict:
    if not 1 <= len(batch) <= MAX_BATCH:
        raise ValueError("batch must contain 1..50 events")
    body = json.dumps({"source": source, "events": batch}, separators=(",", ":")).encode()
    if len(body) > MAX_BODY:
        raise ValueError("batch exceeds the 1 MiB HTTP limit")
    req = urllib.request.Request(
        endpoint, body,
        {"Authorization": "Collector " + token, "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=20) as resp:
            raw = resp.read(8193)
            if len(raw) > 8192:
                raise DeliveryError("oversized server acknowledgment")
            result = json.loads(raw)
    except urllib.error.HTTPError as exc:
        # HTTP response bodies might reflect sensor data or secrets: never print.
        if exc.code in (400, 401, 403, 404, 405, 413):
            raise PermanentDeliveryError(f"ARTEX rejected collector request (HTTP {exc.code})") from None
        raise DeliveryError(f"ARTEX temporarily returned HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise DeliveryError("ARTEX unreachable or TLS certificate untrusted") from None
    except (ValueError, UnicodeDecodeError):
        raise DeliveryError("invalid server acknowledgment") from None
    if not isinstance(result, dict):
        raise DeliveryError("unexpected acknowledgment")
    return result


def iter_records(path: pathlib.Path, follow: bool):
    """Compatibility helper for offline validation; the live path uses Spool."""
    with path.open("rb") as stream:
        while True:
            line = stream.readline(MAX_LINE + 2)
            if not line:
                if not follow:
                    return
                time.sleep(1)
                yield None
                continue
            if len(line) > MAX_LINE:
                raise ValueError("log line exceeds 128 KiB")
            if not line.endswith(b"\n"):
                if not follow:
                    raise ValueError("incomplete final JSONL record")
                time.sleep(1)
                stream.seek(-len(line), 1)
                yield None
                continue
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("event record must be a JSON object")
            yield obj


class Spool:
    """One writer per local state file; lossless offset+queue commits."""

    def __init__(self, state: pathlib.Path, source: str):
        self.state = state.absolute()
        self.source = source
        self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state.parent.stat().st_mode & 0o077:
            raise ValueError("state directory must be owner-private (chmod 700)")
        if self.state.is_symlink():
            raise ValueError("state database must not be a symlink")
        self.lock_path = self.state.with_suffix(self.state.suffix + ".lock")
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "rb")
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            raise ValueError("another forwarder owns this spool") from exc
        fd = os.open(self.state, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.state.stat().st_mode & 0o077:
            self.lock.close()
            raise ValueError("state database must be owner-private (chmod 600)")
        self.db = sqlite3.connect(str(self.state), timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS source_cursors (
            path TEXT PRIMARY KEY, source TEXT NOT NULL,
            device INTEGER NOT NULL, inode INTEGER NOT NULL, offset INTEGER NOT NULL
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS pending (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL, payload TEXT NOT NULL
        )""")
        self.db.commit()
        other = self.db.execute("SELECT source FROM pending LIMIT 1").fetchone()
        if other and other[0] != self.source:
            self.close()
            raise ValueError("spool contains events for another source")

    def close(self):
        if hasattr(self, "db"):
            self.db.close()
            del self.db
        if hasattr(self, "lock"):
            self.lock.close()
            del self.lock

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM pending").fetchone()[0]

    def batch(self, size: int) -> list[tuple[int, dict]]:
        rows = self.db.execute(
            "SELECT seq,source,payload FROM pending ORDER BY seq LIMIT ?", (size,)
        ).fetchall()
        total = 0
        out = []
        for seq, source, raw in rows:
            if source != self.source:
                raise ValueError("spool contains another source; separate your state files")
            obj = json.loads(raw)
            n = len(raw.encode("utf-8"))
            if total + n > MAX_BATCH_BYTES:
                break
            out.append((seq, obj))
            total += n
        return out

    def ack(self, seqs: list[int]):
        # Acknowledgments are committed only after the server confirms every
        # event in the batch (either newly ingested or an idempotent duplicate).
        with self.db:
            self.db.executemany("DELETE FROM pending WHERE seq=?", ((n,) for n in seqs))

    def _pick_input(self, path: pathlib.Path):
        current = path.stat()
        row = self.db.execute(
            "SELECT source,device,inode,offset FROM source_cursors WHERE path=?",
            (str(path),),
        ).fetchone()
        if not row:
            return path, current, 0, False
        old_source, device, inode, offset = row
        if old_source != self.source:
            raise ValueError("source label changed for this file; use a separate state")
        if (device, inode) == (current.st_dev, current.st_ino):
            if current.st_size < offset:
                # copytruncate rotation: the old file was truncated in place.
                # A copy may have raced the writer: report uncertainty to operator.
                print("WARNING: source was truncated; copytruncate can lose events", file=sys.stderr)
                return path, current, 0, False
            return path, current, offset, False
        # Rename/create rotation: drain the old inode before switching to the
        # replacement, even if the path now points to a new file.
        for candidate in path.parent.iterdir():
            if candidate == path or not candidate.is_file() or candidate.is_symlink():
                continue
            st = candidate.stat()
            if (st.st_dev, st.st_ino) == (device, inode):
                return candidate, st, offset, True
        if offset == 0:
            return path, current, 0, False
        raise ValueError("rotated file with unread cursor is missing: manual review required")

    def stage(self, file: pathlib.Path, batch_size: int, follow: bool = True,
              max_queued: int = MAX_QUEUED) -> int:
        path = file.absolute()
        capacity = max_queued - self.count()
        if capacity <= 0:
            return 0
        selected, stat, offset, rotated = self._pick_input(path)
        records = []
        total_bytes = 0
        reached_eof = False
        last_offset = offset
        with selected.open("rb") as stream:
            st = os.fstat(stream.fileno())
            if (st.st_dev, st.st_ino) != (stat.st_dev, stat.st_ino):
                return 0  # file changed during rotation; retry with a fresh stat
            stream.seek(offset)
            while len(records) < min(batch_size, capacity):
                line = stream.readline(MAX_LINE + 2)
                if not line:
                    reached_eof = True
                    break
                if len(line) > MAX_LINE:
                    raise ValueError("source JSONL record exceeds 128 KiB; cursor unchanged")
                if not line.endswith(b"\n"):
                    if not follow or rotated:
                        raise ValueError("incomplete source record; cursor unchanged")
                    break
                if not line.strip():
                    last_offset = stream.tell()
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    raise ValueError("invalid JSONL source record; cursor unchanged") from None
                if not isinstance(obj, dict):
                    raise ValueError("source record must be an object; cursor unchanged")
                raw = json.dumps(obj, separators=(",", ":"))
                n = len(raw.encode("utf-8"))
                if total_bytes + n > MAX_BATCH_BYTES:
                    if not records:
                        raise ValueError("source record exceeds transport budget")
                    break
                total_bytes += n
                records.append((raw, stream.tell()))
                last_offset = stream.tell()
        if not records and not (rotated and reached_eof) and last_offset == offset:
            return 0
        new_offset = records[-1][1] if records else last_offset
        new_device, new_inode = stat.st_dev, stat.st_ino
        if rotated and reached_eof:
            replacement = path.stat()
            new_device, new_inode, new_offset = replacement.st_dev, replacement.st_ino, 0
        with self.db:
            self.db.executemany(
                "INSERT INTO pending(source,payload) VALUES(?,?)",
                ((self.source, raw) for raw, _ in records),
            )
            self.db.execute(
                """INSERT INTO source_cursors(path,source,device,inode,offset)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET
                   source=excluded.source,device=excluded.device,
                   inode=excluded.inode,offset=excluded.offset""",
                (str(path), self.source, new_device, new_inode, new_offset),
            )
        return len(records)


def flush_once(spool: Spool, endpoint: str, token: str, size: int,
               send=send_batch) -> int:
    batch = spool.batch(size)
    if not batch:
        return 0
    result = send(endpoint, token, spool.source, [v for _, v in batch])
    ingested, duplicates = result.get("ingested"), result.get("duplicates")
    if type(ingested) is not int or type(duplicates) is not int or (
        ingested < 0 or duplicates < 0 or ingested + duplicates != len(batch)
    ):
        raise DeliveryError("incomplete/untrusted server acknowledgment; retaining queued data")
    spool.ack([seq for seq, _ in batch])
    return len(batch)


def default_state_path(source: str, source_file: pathlib.Path) -> pathlib.Path:
    digest = hashlib.sha256(str(source_file.absolute()).encode()).hexdigest()[:16]
    return pathlib.Path.home() / ".local" / "state" / "artex-defense" / f"{source}-{digest}.sqlite3"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("suricata", "wazuh", "generic", "ocsf"), required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--file", type=pathlib.Path, required=True, help="JSONL sensor file")
    parser.add_argument("--follow", action="store_true", help="continue spooling, retrying and following logs")
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--state", type=pathlib.Path, help="SQLite spool path (private local directory)")
    parser.add_argument("--max-queued", type=int, default=MAX_QUEUED)
    opts = parser.parse_args(argv)
    if not 1 <= opts.batch_size <= MAX_BATCH:
        parser.error("--batch-size must be 1..50")
    if not 1 <= opts.max_queued <= MAX_QUEUED:
        parser.error("--max-queued must be 1..10000")
    token = os.environ.get("ARTEX_COLLECTOR_TOKEN", "")
    if not token or not token.startswith("dc1."):
        parser.error("set ARTEX_COLLECTOR_TOKEN to an issued collector token (not an admin JWT)")
    try:
        endpoint = validate_endpoint(opts.url)
        state = opts.state or default_state_path(opts.source, opts.file)
        with Spool(state, opts.source) as spool:
            failures = 0
            next_attempt = 0.0
            while True:
                staged = spool.stage(opts.file, opts.batch_size, opts.follow, opts.max_queued)
                if spool.count() and time.monotonic() >= next_attempt:
                    try:
                        sent = flush_once(spool, endpoint, token, opts.batch_size)
                        failures = 0
                        next_attempt = 0
                        print(f"Forwarded={sent} queued={spool.count()}", flush=True)
                    except PermanentDeliveryError:
                        raise
                    except (DeliveryError, OSError) as exc:
                        failures += 1
                        delay = min(30, 2 ** min(failures, 5))
                        if not opts.follow:
                            raise DeliveryError(f"{exc}; queued events retained") from None
                        print(f"delivery deferred ({exc}), retrying with backoff", file=sys.stderr)
                        next_attempt = time.monotonic() + delay
                if not opts.follow and not staged and not spool.count():
                    return 0
                if not opts.follow and spool.count() and next_attempt:
                    raise DeliveryError("queued events awaiting retry; rerun the forwarder")
                if staged == 0:
                    time.sleep(0.5 if opts.follow else 0.01)
    except (ValueError, OSError, sqlite3.Error, DeliveryError) as exc:
        print(f"forwarder failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
