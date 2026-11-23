#!/usr/bin/env python3
"""Offline regression tests for the durable ARTEX-DEFENSE sensor spool."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("defense_forwarder.py")
spec = importlib.util.spec_from_file_location("defense_forwarder", SCRIPT)
forwarder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(forwarder)


class ForwarderTests(unittest.TestCase):
    def test_transport_security(self):
        self.assertEqual(
            forwarder.validate_endpoint("http://127.0.0.1:8787"),
            "http://127.0.0.1:8787/api/defense/collector/events",
        )
        self.assertEqual(
            forwarder.validate_endpoint("https://soc.example.org"),
            "https://soc.example.org/api/defense/collector/events",
        )
        for value in (
            "http://soc.example.org", "https://user:password@soc.example.org",
            "https://soc.example.org/collector", "https://soc.example.org?token=abc",
            "file:///etc/passwd",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                forwarder.validate_endpoint(value)

    def test_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.json"
            path.write_text(json.dumps({"event_type":"alert"}) + "\n\n" +
                            json.dumps({"kind":"authentication"}) + "\n")
            self.assertEqual(len(list(forwarder.iter_records(path, False))), 2)

    def test_reject_unsafe_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.json"
            path.write_text("[]\n")
            with self.assertRaises(ValueError):
                list(forwarder.iter_records(path, False))
            path.write_text("{" + "x" * forwarder.MAX_LINE + "\n")
            with self.assertRaises(ValueError):
                list(forwarder.iter_records(path, False))

    def test_batch_limits(self):
        with self.assertRaises(ValueError):
            forwarder.send_batch("https://example.org", "opaque", "generic", [])
        with self.assertRaises(ValueError):
            forwarder.send_batch("https://example.org", "opaque", "generic", [{}] * 51)

    def test_durable_restart_and_acknowledgment(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            state = folder / "state.db"
            log = folder / "sensor.jsonl"
            log.write_text("\n".join(json.dumps({"kind":"other","event_id":str(i)}) for i in range(3))+"\n")
            with forwarder.Spool(state, "generic") as spool:
                self.assertEqual(spool.stage(log, 20, False), 3)
                with self.assertRaises(forwarder.DeliveryError):
                    forwarder.flush_once(spool, "", "redacted", 20,
                        send=lambda *_: {"ingested":2, "duplicates":0})
                self.assertEqual(spool.count(), 3)
            with forwarder.Spool(state, "generic") as spool:
                self.assertEqual(spool.stage(log, 20, False), 0)
                self.assertEqual(spool.count(), 3)
                got = forwarder.flush_once(spool, "", "redacted", 20,
                    send=lambda *_: {"ingested":2,"duplicates":1})
                self.assertEqual(got, 3)
                self.assertEqual(spool.count(), 0)
                self.assertEqual(spool.stage(log, 20, False), 0)

    def test_partial_line_not_checkpointed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            log = folder / "sensor.jsonl"
            log.write_text('{"kind":"other","event_id":"a"}\n{"kind":"oth')
            with forwarder.Spool(folder/"state.db", "generic") as spool:
                self.assertEqual(spool.stage(log, 20, True), 1)
                self.assertEqual(spool.count(), 1)
                with log.open("a") as f:
                    f.write('er","event_id":"b"}\n')
                self.assertEqual(spool.stage(log, 20, True), 1)
                self.assertEqual(spool.count(), 2)

    def test_log_rotation_drains_old_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            log = folder / "sensor.jsonl"
            log.write_text('{"kind":"other","event_id":"a"}\n')
            with forwarder.Spool(folder/"state.db", "generic") as spool:
                self.assertEqual(spool.stage(log, 1), 1)
                with log.open("a") as f:
                    f.write('{"kind":"other","event_id":"b"}\n')
                log.rename(folder/"sensor.jsonl.1")
                log.write_text('{"kind":"other","event_id":"c"}\n')
                self.assertEqual(spool.stage(log, 1), 1)
                self.assertEqual(spool.stage(log, 1), 0)  # finishes old inode
                self.assertEqual(spool.stage(log, 1), 1)
                ids = [record["event_id"] for _,record in spool.batch(20)]
                self.assertEqual(ids, ["a","b","c"])

    def test_invalid_record_does_not_advance_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            log = folder/"sensor.jsonl"
            log.write_text('{"kind":"other"}\n[]\n')
            with forwarder.Spool(folder/"state.db", "generic") as spool:
                with self.assertRaises(ValueError):
                    spool.stage(log, 20)
                self.assertEqual(spool.count(),0)
                log.write_text('{"kind":"other"}\n')
                self.assertEqual(spool.stage(log, 20, False),1)

    def test_backpressure_and_private_spool(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            state = folder/"state.db"
            log = folder/"events.jsonl"
            log.write_text("".join(json.dumps({"kind":"other","event_id":str(i)})+"\n" for i in range(4)))
            with forwarder.Spool(state, "generic") as spool:
                self.assertEqual(spool.stage(log, 20, max_queued=2),2)
                self.assertEqual(spool.stage(log, 20, max_queued=2),0)
                self.assertEqual(spool.count(),2)
                self.assertEqual(os.stat(state).st_mode & 0o077,0)
                with self.assertRaises(ValueError):
                    with forwarder.Spool(state, "generic"):
                        pass
                spool.ack([x for x,_ in spool.batch(20)])
                self.assertEqual(spool.stage(log,20,max_queued=2),2)

    def test_credential_from_env_only(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                forwarder.main(["--source","generic","--file","/does/not/matter"])
        # User-friendly failure without network or secret contents
        with mock.patch.dict(os.environ, {"ARTEX_COLLECTOR_TOKEN":"admin-jwt"}):
            with self.assertRaises(SystemExit):
                forwarder.main(["--source","generic","--file","/does/not/matter"])


if __name__ == "__main__":
    unittest.main()
