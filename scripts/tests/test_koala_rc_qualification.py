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

    def test_container_command_publishes_no_host_ports(self) -> None:
        image = "ghcr.io/koala-optics/muninndb@sha256:" + "b" * 64
        command = qualification.build_container_command(
            name="rc-test", image=image, data_dir=Path("/tmp/rc-data"),
            network="rc-internal", env_file=Path("/tmp/rc.env"),
        )
        self.assertNotIn("--publish", command)
        self.assertEqual(command[command.index("--network") + 1], "rc-internal")
        self.assertIn("--listen-host", command)
        self.assertEqual(command[command.index("--listen-host") + 1], "0.0.0.0")

    def test_baseline_image_is_allowed_for_fixture_container(self) -> None:
        image = "ghcr.io/scrypster/muninndb@sha256:" + "c" * 64
        command = qualification.build_container_command(
            name="baseline", image=image, data_dir=Path("/tmp/rc-data"),
            network="rc-internal", env_file=Path("/tmp/rc.env"),
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

    def test_container_readiness_uses_verified_internal_address(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            container = qualification.Container(
                "rc-test", "ghcr.io/koala-optics/muninndb@sha256:" + "a" * 64,
                Path(root), "network", Path(root) / "env", Path(root) / "container.log",
            )
            connection = mock.MagicMock()
            connection.__enter__.return_value = connection
            network = [{
                "Internal": True,
                "Containers": {"container-id": {"IPv4Address": "172.20.0.2/16"}},
            }]
            with mock.patch.object(qualification, "run_command") as run, \
                    mock.patch.object(qualification.socket, "create_connection", return_value=connection) as connect:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, "container-id\n", ""),
                    subprocess.CompletedProcess([], 0, qualification.json.dumps(network), ""),
                    subprocess.CompletedProcess([], 0, "container-id\n", ""),
                    subprocess.CompletedProcess([], 0, "running 0\n", ""),
                ]
                container.start(timeout=1)
            self.assertEqual(container.container_ip, "172.20.0.2")
            connect.assert_called_once_with(("172.20.0.2", 8750), timeout=1.0)

    def test_container_start_rejects_non_internal_network(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            container = qualification.Container(
                "rc-test", "ghcr.io/koala-optics/muninndb@sha256:" + "a" * 64,
                Path(root), "network", Path(root) / "env", Path(root) / "container.log",
            )
            responses = [
                subprocess.CompletedProcess([], 0, "container-id\n", ""),
                subprocess.CompletedProcess([], 0, '[{"Internal": false}]', ""),
                subprocess.CompletedProcess([], 0, "startup log\n", ""),
                subprocess.CompletedProcess([], 0, "", ""),
            ]
            with mock.patch.object(qualification, "run_command", side_effect=responses), \
                    mock.patch.object(qualification.socket, "create_connection") as connect:
                with self.assertRaisesRegex(qualification.QualificationError, "is not internal"):
                    container.start(timeout=1)
            connect.assert_not_called()

    def test_internal_mcp_url_requires_exact_verified_address(self) -> None:
        qualification.MCPClient(
            "http://172.20.0.2:8750/mcp", "synthetic", 1,
            internal_address="172.20.0.2",
        )
        with self.assertRaises(qualification.QualificationError):
            qualification.MCPClient(
                "http://172.20.0.3:8750/mcp", "synthetic", 1,
                internal_address="172.20.0.2",
            )

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

    def test_vault_count_requires_integer_status_count(self) -> None:
        client = mock.Mock()
        client.call.return_value = ({"total_memories": 3}, 1.0)
        self.assertEqual(qualification.vault_count(client, "rc-synthetic"), 3)
        client.call.assert_called_once_with("muninn_status", {"vault": "rc-synthetic"})
        for result in ({}, {"total_memories": "3"}, []):
            client.call.return_value = (result, 1.0)
            with self.assertRaises(qualification.QualificationError):
                qualification.vault_count(client, "rc-synthetic")

    def test_v5_count_gate_is_required(self) -> None:
        self.assertIn("migration_v5_counts", qualification.REQUIRED_GATES)
        self.assertIn("muninn_status", qualification.REQUIRED_TOOLS)

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

    def test_backup_destination_is_container_writable_before_offline_backup(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        prepare = source.index("backup_parent.mkdir(mode=0o700)")
        chmod = source.index("backup_parent.chmod(0o777)", prepare)
        invoke = source.index("backup = offline_command", chmod)
        self.assertLess(prepare, chmod)
        self.assertLess(chmod, invoke)
        self.assertIn('"--output", "/work/backup-output/backup"', source[invoke:])

    def test_backup_validation_uses_restore_container_not_host_traversal(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('(backup_dir / "pebble").is_dir()', source)
        restore = source.index('name="koala-rc-restore"')
        verification = source.index("verify_lookup_state", restore)
        self.assertLess(restore, verification)

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
                "rc-test", "image", Path(root), "network",
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
            "isolation": {"synthetic_only": True, "host_ports_published": [], "internal_network": True},
            "images": {"candidate": {"ref": "x@sha256:" + "a" * 64}, "baseline": {"ref": "y@sha256:" + "b" * 64}},
            "gates": {name: {"passed": True} for name in qualification.REQUIRED_GATES},
        }
        qualification.validate_receipt(receipt)
        del receipt["gates"]["backup_restore"]
        with self.assertRaises(qualification.QualificationError):
            qualification.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
