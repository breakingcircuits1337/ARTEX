#!/usr/bin/env python3
"""Unit checks for the defensive log forwarder. Does not use the network."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("defense_forwarder.py")
spec = importlib.util.spec_from_file_location("defense_forwarder", SCRIPT)
forwarder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(forwarder)


class ForwarderTests(unittest.TestCase):
    def test_transport_security(self):
        self.assertEqual(
            forwarder.validate_endpoint("http://127.0.0.1:8787"),
            "http://127.0.0.1:8787/api/defense/events",
        )
        self.assertEqual(
            forwarder.validate_endpoint("https://soc.example.org"),
            "https://soc.example.org/api/defense/events",
        )
        for value in (
            "http://soc.example.org",
            "https://user:password@soc.example.org",
            "https://soc.example.org/collector",
            "https://soc.example.org?token=abc",
            "file:///etc/passwd",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                forwarder.validate_endpoint(value)

    def test_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.json"
            with path.open("w", encoding="utf-8") as out:
                out.write(json.dumps({"event_type": "alert", "src_ip": "192.0.2.9"}) + "\n")
                out.write("\n")
                out.write(json.dumps({"kind": "authentication"}) + "\n")
            records = list(forwarder.iter_records(path, follow=False))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["event_type"], "alert")

    def test_reject_unsafe_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "events.json"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                list(forwarder.iter_records(path, follow=False))
            path.write_text("{" + "x" * forwarder.MAX_LINE + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                list(forwarder.iter_records(path, follow=False))

    def test_batch_limits(self):
        with self.assertRaises(ValueError):
            forwarder.send_batch("https://example.org/api/defense/events", "opaque", "generic", [])
        with self.assertRaises(ValueError):
            forwarder.send_batch("https://example.org/api/defense/events", "opaque", "generic", [{}] * 51)


if __name__ == "__main__":
    unittest.main()
