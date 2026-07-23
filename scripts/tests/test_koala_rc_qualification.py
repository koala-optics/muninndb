#!/usr/bin/env python3
"""Safety and contract tests for the Koala RC qualification harness."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "koala_rc_qualification.py"
SPEC = importlib.util.spec_from_file_location("koala_rc_qualification", MODULE_PATH)
assert SPEC and SPEC.loader
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)


class QualificationSafetyTests(unittest.TestCase):
    def test_image_refs_must_be_digest_pinned(self) -> None:
        valid = "ghcr.io/koala-optics/muninndb@sha256:" + "a" * 64
        self.assertEqual(qualification.validate_image_ref(valid), valid)
        for invalid in (
            "ghcr.io/koala-optics/muninndb:latest",
            "ghcr.io/koala-optics/muninndb:koala-v0.9.0-rc.1-amd64",
            "docker.io/library/alpine@sha256:" + "a" * 64,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(qualification.QualificationError):
                    qualification.validate_image_ref(invalid)

    def test_container_command_only_publishes_mcp_on_loopback(self) -> None:
        image = "ghcr.io/koala-optics/muninndb@sha256:" + "b" * 64
        command = qualification.build_container_command(
            name="rc-test", image=image, data_dir=Path("/tmp/rc-data"),
            network="rc-internal", host_port=43123, env_file=Path("/tmp/rc.env"),
        )
        self.assertIn("127.0.0.1:43123:8750", command)
        self.assertNotIn("0.0.0.0:43123:8750", command)
        self.assertEqual(command[command.index("--network") + 1], "rc-internal")
        published = [command[index + 1] for index, value in enumerate(command) if value == "--publish"]
        self.assertEqual(published, ["127.0.0.1:43123:8750"])
        self.assertIn("--listen-host", command)
        self.assertEqual(command[command.index("--listen-host") + 1], "0.0.0.0")

    def test_baseline_image_is_allowed_for_fixture_container(self) -> None:
        image = "ghcr.io/scrypster/muninndb@sha256:" + "c" * 64
        command = qualification.build_container_command(
            name="baseline", image=image, data_dir=Path("/tmp/rc-data"),
            network="rc-internal", host_port=43124, env_file=Path("/tmp/rc.env"),
        )
        self.assertIn(image, command)

    def test_docker_subprocess_environment_drops_production_credentials(self) -> None:
        old = os.environ.copy()
        try:
            os.environ.update({key: "production-secret" for key in qualification.PRODUCTION_ENV_KEYS})
            os.environ["PATH"] = "/usr/bin"
            os.environ["HOME"] = "/tmp/home"
            env = qualification.docker_subprocess_environment()
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HOME"], "/tmp/home")
        self.assertTrue(qualification.PRODUCTION_ENV_KEYS.isdisjoint(env))

    def test_synthetic_manifest_is_deterministic_and_non_production(self) -> None:
        first = qualification.synthetic_manifest()
        second = qualification.synthetic_manifest()
        self.assertEqual(first, second)
        self.assertEqual(qualification.manifest_hash(first), qualification.manifest_hash(second))
        encoded = str(first).lower()
        self.assertIn("synthetic", encoded)
        for marker in qualification.PRODUCTION_MARKERS:
            self.assertNotIn(marker, encoded)

    def test_loopback_http_disables_environment_proxies(self) -> None:
        client = qualification.MCPClient("http://127.0.0.1:43123/mcp", "synthetic", 1)
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(qualification.urllib.request, "build_opener", return_value=opener) as build:
            client._post({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        proxy_handler = build.call_args.args[0]
        self.assertEqual(proxy_handler.proxies, {})

    def test_mcp_client_rejects_non_loopback_endpoint(self) -> None:
        with self.assertRaises(qualification.QualificationError):
            qualification.MCPClient("https://production.example/mcp", "synthetic", 1)

    def test_mcp_client_rejects_application_error_payload(self) -> None:
        client = qualification.MCPClient("http://127.0.0.1:43123/mcp", "synthetic", 1)
        with self.assertRaisesRegex(qualification.QualificationError, "application error"):
            client.decode_tool_result("muninn_test", {"error": "synthetic failure"})

    def test_exact_concept_assertion_requires_newest_first_ids(self) -> None:
        expected = ["new", "middle", "old"]
        qualification.assert_exact_concept_result(
            {"concept": "rc/exact", "count": 2, "engrams": [{"id": "new"}, {"id": "middle"}]},
            "rc/exact",
            expected[:2],
        )
        with self.assertRaises(qualification.QualificationError):
            qualification.assert_exact_concept_result(
                {"concept": "rc/exact", "count": 2, "engrams": [{"id": "middle"}, {"id": "new"}]},
                "rc/exact",
                expected[:2],
            )

    def test_entity_assertion_requires_newest_first_ids(self) -> None:
        qualification.assert_entity_result(
            {"entity": "RC Synthetic Entity", "count": 2, "engrams": [{"id": "new"}, {"id": "old"}]},
            ["new", "old"],
        )
        with self.assertRaises(qualification.QualificationError):
            qualification.assert_entity_result(
                {"entity": "RC Synthetic Entity", "count": 2, "engrams": [{"id": "old"}, {"id": "new"}]},
                ["new", "old"],
            )

    def test_disposable_data_directory_is_container_writable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            args = mock.Mock(
                candidate_image="ghcr.io/koala-optics/muninndb@sha256:" + "a" * 64,
                baseline_image="ghcr.io/scrypster/muninndb@sha256:" + "b" * 64,
                work_dir=Path(root) / "work",
                source_commit="c" * 40,
                source_tag="koala-v0.9.0-rc.1",
                go_version="", model_sha256="", tokenizer_sha256="",
                onnxruntime_sha256="", startup_timeout=1, call_timeout=1,
                keep_work_dir=True, output=Path(root) / "receipt.json",
            )
            with mock.patch.object(qualification, "run_command", side_effect=qualification.QualificationError("stop")):
                with self.assertRaises(qualification.QualificationError):
                    qualification.qualify(args)
            self.assertEqual((args.work_dir / "data").stat().st_mode & 0o777, 0o777)

    def test_explicit_work_directory_must_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            occupied = Path(root) / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            with self.assertRaises(qualification.QualificationError):
                qualification.prepare_work_directory(occupied)

    def test_log_capture_preserves_first_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            log_path = Path(root) / "container.log"
            container = qualification.Container(
                "rc-test", "image", Path(root), "network", 43123,
                Path(root) / "env", log_path,
            )
            responses = [
                subprocess.CompletedProcess([], 0, "startup failure\n", ""),
                subprocess.CompletedProcess([], 1, "", "No such container\n"),
            ]
            with mock.patch.object(qualification, "run_command", side_effect=responses):
                self.assertEqual(container.capture_logs(), "startup failure\n")
                self.assertEqual(container.capture_logs(), "startup failure\n")
            self.assertEqual(log_path.read_text(encoding="utf-8"), "startup failure\n")

    def test_receipt_validation_rejects_missing_gate(self) -> None:
        receipt = {
            "schema_version": 1,
            "status": "passed",
            "isolation": {"synthetic_only": True, "host_bind": "127.0.0.1", "internal_network": True},
            "images": {"candidate": {"ref": "x@sha256:" + "a" * 64}, "baseline": {"ref": "y@sha256:" + "b" * 64}},
            "gates": {name: {"passed": True} for name in qualification.REQUIRED_GATES},
        }
        qualification.validate_receipt(receipt)
        del receipt["gates"]["backup_restore"]
        with self.assertRaises(qualification.QualificationError):
            qualification.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
