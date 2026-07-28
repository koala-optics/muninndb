#!/usr/bin/env python3
"""Contract tests for the non-executing Koala Stage B packet."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "koala_stage_b_packet.py"
SPEC = importlib.util.spec_from_file_location("koala_stage_b_packet", MODULE_PATH)
assert SPEC and SPEC.loader
packet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packet
SPEC.loader.exec_module(packet)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
EVIDENCE_SHA = "a" * 64


class StageBPacketTests(unittest.TestCase):
    def complete_packet(self):
        value = packet.build_template()
        value["readiness_status"] = packet.READY
        value["public_summary"] = {
            "change_label": "MuninnDB RC2 Stage B readiness",
            "window_label": "SCHEDULED",
        }
        for name in (
            "target_binding",
            "preflight",
            "writer_control",
            "backup_restore",
            "routing_acceptance",
            "rollback",
            "observation",
        ):
            value[name]["evidence"] = {
                "status": "PASSED",
                "sha256": EVIDENCE_SHA,
                "observed_at": "2026-07-27T10:00:00Z",
                "expires_at": "2026-07-28T10:00:00Z",
                "coverage": "COMPLETE",
                "source": "PRIMARY_RECEIPT",
            }
            for key, item in list(value[name].items()):
                if isinstance(item, bool):
                    value[name][key] = True
        value["target_binding"].update(
            {
                "target_fingerprint_sha256": "b" * 64,
                "maintenance_window_start": "2026-07-27T13:00:00Z",
                "maintenance_window_end": "2026-07-27T14:00:00Z",
            }
        )
        value["rollback"]["image_only_data_reversal"] = False
        return value

    def assert_not_ready(self, value, expected_error):
        status, errors = packet.validate_packet(value, now=NOW)
        self.assertEqual(status, packet.NOT_READY)
        self.assertIn(expected_error, errors)

    def test_template_pins_exact_stage_a_manifest_and_cannot_authorize(self):
        value = packet.build_template()
        self.assertEqual(value["schema_version"], "koala-stage-b-packet-v1")
        self.assertEqual(value["readiness_status"], "NOT_READY")
        self.assertEqual(value["authorization"]["status"], "NOT_AUTHORIZED")
        self.assertIsNone(value["authorization"]["authorization_receipt_sha256"])
        self.assertEqual(
            value["qualification"]["source_commit"],
            "acef6bedbbd839f9616415e6a7559ad149dc8bc8",
        )
        self.assertEqual(
            value["qualification"]["candidate_image"],
            "ghcr.io/koala-optics/muninndb@sha256:"
            "5cc1546b854e6b173181ceed139ade783751c1e58bea504bc57cb0a7fa4019df",
        )
        self.assertEqual(
            value["qualification"]["rollback_rescue_image"],
            "ghcr.io/koala-optics/muninndb@sha256:"
            "52cad8cce1a0dca7b6e64f5bffafe1a0c677667c49112513cc3ad463a953594b",
        )
        self.assertEqual(value["qualification"]["accepted_records"], 502_385)
        self.assertEqual(value["qualification"]["passed_gates"], 16)
        self.assertNotIn("AUTHORIZED", packet.READY)
        self.assertNotEqual(packet.READY, "READY_TO_DEPLOY")

    def test_template_write_is_private_atomic_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "stage-b.json"
            digest = packet.write_template(path)
            payload = path.read_bytes()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])
            with self.assertRaises(FileExistsError):
                packet.write_template(path)
            self.assertEqual(path.read_bytes(), payload)

    def test_complete_synthetic_packet_is_ready_with_stable_private_digest(self):
        value = self.complete_packet()
        status, errors = packet.validate_packet(value, now=NOW)
        self.assertEqual((status, errors), (packet.READY, []))
        first = packet.packet_bytes(value)
        second = packet.packet_bytes(json.loads(first))
        self.assertEqual(first, second)
        expected_digest = hashlib.sha256(first).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_bytes(first)
            path.chmod(0o600)
            with mock.patch.object(packet, "datetime") as clock:
                clock.now.return_value = NOW
                clock.fromisoformat.side_effect = datetime.fromisoformat
                path_status, digest, path_errors = packet.validate_path(path)
        self.assertEqual((path_status, path_errors), (packet.READY, []))
        self.assertEqual(digest, expected_digest)

    def test_each_required_evidence_group_fails_closed_when_missing(self):
        for name in (
            "target_binding",
            "preflight",
            "writer_control",
            "backup_restore",
            "routing_acceptance",
            "rollback",
            "observation",
        ):
            with self.subTest(group=name):
                value = self.complete_packet()
                del value[name]
                self.assert_not_ready(value, name)

    def test_unknown_sampled_self_attested_stale_and_invalid_evidence_fail_closed(self):
        cases = (
            ("status", "UNKNOWN"),
            ("coverage", "SAMPLED"),
            ("source", "SELF_ATTESTED"),
            ("expires_at", "2026-07-27T11:59:59Z"),
            ("sha256", "not-a-hash"),
        )
        for field, replacement in cases:
            with self.subTest(field=field):
                value = self.complete_packet()
                value["preflight"]["evidence"][field] = replacement
                self.assert_not_ready(value, f"preflight.evidence.{field}")

    def test_expired_maintenance_window_is_rejected(self):
        value = self.complete_packet()
        value["target_binding"]["maintenance_window_start"] = (
            "2026-07-27T10:00:00Z"
        )
        value["target_binding"]["maintenance_window_end"] = (
            "2026-07-27T11:00:00Z"
        )
        self.assert_not_ready(
            value,
            "target_binding.maintenance_window_end",
        )

    def test_candidate_and_rescue_digest_drift_are_rejected(self):
        for field in ("candidate_image", "rollback_rescue_image"):
            with self.subTest(field=field):
                value = self.complete_packet()
                value["qualification"][field] = value["qualification"][field][:-1] + "0"
                self.assert_not_ready(value, f"qualification.{field}")

    def test_image_only_data_reversal_is_rejected(self):
        value = self.complete_packet()
        value["rollback"]["image_only_data_reversal"] = True
        self.assert_not_ready(value, "rollback.image_only_data_reversal")

    def test_writer_freeze_queue_replay_and_restore_witness_are_required(self):
        cases = (
            ("writer_control", "freeze_tested"),
            ("writer_control", "queue_tested"),
            ("writer_control", "replay_tested"),
            ("writer_control", "write_boundary_proved"),
            ("backup_restore", "writers_frozen_during_checkpoint"),
            ("backup_restore", "application_checkpoint_verified"),
            ("backup_restore", "auxiliary_state_inventory_complete"),
            ("backup_restore", "required_auxiliary_state_captured"),
            ("backup_restore", "authentication_continuity_verified"),
            ("backup_restore", "independent_restore_query_verified"),
            ("backup_restore", "auxiliary_restore_verified"),
        )
        for group, field in cases:
            with self.subTest(group=group, field=field):
                value = self.complete_packet()
                value[group][field] = False
                self.assert_not_ready(value, f"{group}.{field}")

    def test_unknown_keys_are_rejected_at_every_schema_boundary(self):
        value = self.complete_packet()
        value["deploy"] = True
        self.assert_not_ready(value, "$.deploy")
        value = self.complete_packet()
        value["preflight"]["unexpected"] = True
        self.assert_not_ready(value, "preflight.unexpected")
        value = self.complete_packet()
        value["preflight"]["evidence"]["body"] = "hidden"
        self.assert_not_ready(value, "preflight.evidence.body")

    def test_free_form_public_summary_is_rejected(self):
        value = self.complete_packet()
        value["public_summary"]["window_label"] = "maintenance-next-week"
        self.assert_not_ready(value, "public_summary.window_label")

    def test_secret_or_url_shaped_public_summary_is_rejected_without_echo(self):
        cases = (
            "https://private.example.invalid",
            "token=private-value",
            "Bearer private-value",
            "-----BEGIN PRIVATE KEY-----",
            "flyv1 private-value",
        )
        for secret in cases:
            with self.subTest(secret=secret):
                value = self.complete_packet()
                value["public_summary"]["window_label"] = secret
                status, errors = packet.validate_packet(value, now=NOW)
                output = f"{status} {','.join(errors)}"
                self.assertEqual(status, packet.NOT_READY)
                self.assertIn("public_summary.window_label", errors)
                self.assertNotIn(secret, output)

    def test_authorization_must_remain_not_authorized_and_empty(self):
        for field, replacement in (
            ("status", "AUTHORIZED"),
            ("authorization_receipt_sha256", "c" * 64),
        ):
            with self.subTest(field=field):
                value = self.complete_packet()
                value["authorization"][field] = replacement
                self.assert_not_ready(value, f"authorization.{field}")

    def test_private_mode_is_required_for_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_bytes(packet.packet_bytes(self.complete_packet()))
            path.chmod(0o644)
            status, _, errors = packet.validate_path(path)
        self.assertEqual(status, packet.NOT_READY)
        self.assertIn("packet.mode", errors)

    def test_cli_output_never_prints_packet_content_or_private_fields(self):
        value = self.complete_packet()
        private_marker = "private-marker-never-print"
        value["public_summary"]["change_label"] = private_marker
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_bytes(packet.packet_bytes(value))
            path.chmod(0o600)
            stdout = io.StringIO()
            with mock.patch.object(packet, "datetime") as clock, \
                 contextlib.redirect_stdout(stdout):
                clock.now.return_value = NOW
                clock.fromisoformat.side_effect = datetime.fromisoformat
                result = packet.main(["--validate", str(path)])
        rendered = stdout.getvalue()
        self.assertEqual(result, 1)
        self.assertIn(packet.NOT_READY, rendered)
        self.assertIn("public_summary.change_label", rendered)
        self.assertRegex(rendered, r"sha256=[0-9a-f]{64}")
        self.assertNotIn(private_marker, rendered)
        self.assertNotIn("qualification", rendered)

    def test_ready_cli_output_is_compact_and_content_free(self):
        value = self.complete_packet()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_bytes(packet.packet_bytes(value))
            path.chmod(0o600)
            stdout = io.StringIO()
            with mock.patch.object(packet, "datetime") as clock, \
                 contextlib.redirect_stdout(stdout):
                clock.now.return_value = NOW
                clock.fromisoformat.side_effect = datetime.fromisoformat
                result = packet.main(["--validate", str(path)])
        rendered = stdout.getvalue()
        self.assertEqual(result, 0)
        self.assertIn(packet.READY, rendered)
        self.assertRegex(rendered, r"sha256=[0-9a-f]{64}")
        self.assertNotIn("qualification", rendered)
        self.assertNotIn(packet.QUALIFICATION["candidate_image"], rendered)

    def test_cli_has_no_execute_deploy_preflight_or_network_surface(self):
        parser = packet.build_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertEqual(options, {"-h", "--help", "--template", "--validate"})
        source = MODULE_PATH.read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("os.getenv", source)
        self.assertNotIn("FLY_API_TOKEN", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("--execute", source)
        self.assertNotIn("--deploy", source)
        self.assertNotIn("--preflight", source)

    def test_template_cli_error_does_not_reveal_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-target-name.json"
            path.write_text("existing")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = packet.main(["--template", str(path)])
        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue().strip(), "TEMPLATE_NOT_WRITTEN")
        self.assertNotIn(str(path), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
