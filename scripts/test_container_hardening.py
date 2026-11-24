#!/usr/bin/env python3
"""Validate effective Docker Compose isolation rather than grepping YAML text."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

REPO = Path(__file__).resolve().parent.parent
EXPECTED_DROPS = {
    "NET_RAW",
    "MKNOD",
    "SYS_CHROOT",
    "SETPCAP",
    "SETFCAP",
    "NET_BIND_SERVICE",
}


def configured_services(file: str) -> dict:
    env = os.environ.copy()
    # Only for docker compose config interpolation; no database is started.
    env["POSTGRES_PASSWORD"] = "unit-test-placeholder-not-for-deployment"
    env["ARTEX_BIND_ADDR"] = "127.0.0.1"
    cmd = ["docker", "compose", "-f", file, "config", "--format", "json"]
    try:
        result = subprocess.run(
            cmd, cwd=REPO, env=env, capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        raise AssertionError("Docker Compose must be installed to verify security") from exc
    if result.returncode:
        raise AssertionError(f"invalid {file}: {result.stderr}")
    try:
        return json.loads(result.stdout)["services"]
    except (ValueError, KeyError) as exc:
        raise AssertionError(f"cannot read effective Compose config: {exc}") from exc


class ContainerHardeningTests(unittest.TestCase):
    def test_both_deployments(self) -> None:
        for compose in ("docker-compose.yml", "docker-compose.ghcr.yml"):
            with self.subTest(compose=compose):
                services = configured_services(compose)
                self.assertIn("artex", services)
                app = services["artex"]
                self.assertNotIn("privileged", app)
                self.assertNotEqual(app.get("network_mode"), "host")
                self.assertNotEqual(app.get("pid"), "host")
                self.assertNotEqual(app.get("ipc"), "host")
                self.assertTrue(app.get("init"), "PID 1 must reap orphans")
                self.assertEqual(app.get("pids_limit"), 1024)
                options = app.get("security_opt", [])
                self.assertIn("no-new-privileges:true", options)
                drops = set(app.get("cap_drop", []))
                self.assertTrue(EXPECTED_DROPS.issubset(drops),
                                f"{compose}: missing capabilities: {EXPECTED_DROPS - drops}")
                mounts = app.get("tmpfs", [])
                self.assertTrue(any(
                    (m if isinstance(m, str) else m.get("target", "")).startswith("/tmp")
                    for m in mounts
                ), f"{compose}: /tmp must be ephemeral")
                ports = app.get("ports", [])
                self.assertTrue(ports, "the API must retain a published port")
                for port in ports:
                    self.assertEqual(port.get("host_ip"), "127.0.0.1",
                                     "published ports must be localhost-bound by default")
                if compose == "docker-compose.yml":
                    skills = [v for v in app.get("volumes", [])
                              if v.get("target") == "/app/skills"]
                    self.assertEqual(len(skills), 1)
                    self.assertTrue(skills[0].get("read_only"), "skills bind must be read-only")

    def test_no_unprotected_docker_socket(self) -> None:
        for compose in ("docker-compose.yml", "docker-compose.ghcr.yml"):
            services = configured_services(compose)
            for service in services.values():
                self.assertFalse(any(
                    "/var/run/docker.sock" in str(mount)
                    for mount in service.get("volumes", [])
                ), f"{compose}: Docker socket must not be passed into app services")


if __name__ == "__main__":
    unittest.main()
