#!/usr/bin/env python3
"""Contract tests for the Koala Stage A synthetic rehearsal harness."""
from __future__ import annotations
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "koala_stage_a_rehearsal.py"
SPEC = importlib.util.spec_from_file_location("koala_stage_a_rehearsal", MODULE_PATH)
assert SPEC and SPEC.loader
stage = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = stage; SPEC.loader.exec_module(stage)

class FakeClient:
    def __init__(self, fail_index=None): self.calls, self.next_id, self.fail_index = [], 0, fail_index
    def call(self, method, arguments):
        self.calls.append((method, arguments)); results = []
        for index, _ in enumerate(arguments["memories"]):
            results.append({"index": index, "status": "error" if self.fail_index == self.next_id else "ok", "id": f"id-{self.next_id}"})
            self.next_id += 1
        return {"total": len(results), "results": results}, 1.0

class StageAContractTests(unittest.TestCase):
    def small_spec(self, count=53):
        return stage.CorpusSpec(count=count, batch_size=50, payload_bytes=1000, seed="test-seed")

    def test_qualified_identities_are_immutable(self):
        self.assertEqual(stage.validate_image(stage.BASELINE_IMAGE, "baseline"), stage.BASELINE_IMAGE)
        self.assertEqual(stage.validate_image(stage.CANDIDATE_IMAGE, "candidate"), stage.CANDIDATE_IMAGE)
        self.assertRegex(stage.BASELINE_DIGEST, r"^sha256:[0-9a-f]{64}$")
        for role, bad in (
            ("baseline", stage.CANDIDATE_IMAGE),
            ("baseline", f"registry.fly.io/koala-muninndb@{stage.BASELINE_DIGEST}"),
            ("candidate", "ghcr.io/koala-optics/muninndb:latest"),
        ):
            with self.assertRaises(stage.RehearsalUnknown): stage.validate_image(bad, role)

    def test_identity_is_run_owned_and_production_name_is_refused(self):
        identity = stage.build_identity("contract-123")
        self.assertTrue(identity.app_name.startswith("koala-stage-a-contract-123"))
        self.assertEqual(identity.confirmation, stage.build_identity("contract-123").confirmation)
        bad = stage.RunIdentity("x", stage.PRODUCTION_APP, "ksa_1234567890_src", "ksa_1234567890_bak", "ksa_1234567890_rst", "ksa_1234567890_rbk", "x")
        with self.assertRaises(stage.RehearsalUnknown): stage.assert_not_production(bad)

    def test_volume_names_follow_fly_contract_and_are_deterministic(self):
        first = stage.build_identity("contract-123")
        repeated = stage.build_identity("contract-123")
        other = stage.build_identity("contract-456")
        first_names = (
            first.volume_name,
            first.backup_volume_name,
            first.restore_volume_name,
            first.rollback_volume_name,
        )
        other_names = (
            other.volume_name,
            other.backup_volume_name,
            other.restore_volume_name,
            other.rollback_volume_name,
        )
        self.assertEqual(first_names, (
            repeated.volume_name,
            repeated.backup_volume_name,
            repeated.restore_volume_name,
            repeated.rollback_volume_name,
        ))
        self.assertEqual(len(set(first_names)), 4)
        self.assertNotEqual(first_names, other_names)
        self.assertTrue(all(stage.FLY_VOLUME_NAME_RE.fullmatch(name) for name in first_names))

    def test_volume_name_guard_rejects_invalid_duplicate_and_unowned_names(self):
        identity = stage.build_identity("contract-123")
        invalid = stage.RunIdentity(
            identity.run_id,
            identity.app_name,
            "koala-stage-a-invalid-source",
            identity.backup_volume_name,
            identity.restore_volume_name,
            identity.rollback_volume_name,
            identity.confirmation,
        )
        duplicate = stage.RunIdentity(
            identity.run_id,
            identity.app_name,
            identity.volume_name,
            identity.volume_name,
            identity.restore_volume_name,
            identity.rollback_volume_name,
            identity.confirmation,
        )
        with self.assertRaises(stage.RehearsalUnknown): stage.assert_not_production(invalid)
        with self.assertRaises(stage.RehearsalUnknown): stage.assert_not_production(duplicate)
        with self.assertRaises(stage.RehearsalUnknown): stage.assert_owned("ksa_deadbeef00_src", identity, "volume-name")

    def test_defaults_are_production_scale_and_twenty_gb(self):
        self.assertEqual(stage.DEFAULT_RECORD_COUNT, 502_385)
        self.assertEqual(stage.DEFAULT_BATCH_SIZE, 50)
        self.assertEqual(stage.VOLUME_SIZE_GB, 20)
        with self.assertRaises(stage.RehearsalUnknown): stage.validate_spec(self.small_spec())

    def test_calibration_contract_is_fixed_and_two_point(self):
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT,
            50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES,
            "test-seed",
        )
        stage.validate_calibration_spec(spec)
        self.assertEqual(
            (stage.CALIBRATION_LOW_PAYLOAD_BYTES, stage.CALIBRATION_HIGH_PAYLOAD_BYTES),
            (1000, 4000),
        )
        with self.assertRaises(stage.RehearsalUnknown):
            stage.validate_calibration_spec(stage.CorpusSpec(spec.count + 1, 50, spec.payload_bytes, spec.seed))
        with self.assertRaises(stage.RehearsalUnknown):
            stage.validate_calibration_spec(stage.CorpusSpec(spec.count, 50, spec.payload_bytes + 1, spec.seed))

    def test_calibration_projection_separates_fixed_and_payload_costs(self):
        gib = 1024**3
        sample = stage.CALIBRATION_SAMPLE_COUNT
        empty = stage.DiskSample("empty", 100 * 1024**2, 19 * gib, 20 * gib)
        fixed, amplification = 7000, 1.0
        low_used = empty.used_bytes + round(sample * (fixed + amplification * stage.CALIBRATION_LOW_PAYLOAD_BYTES))
        high_used = low_used + round(sample * (fixed + amplification * stage.CALIBRATION_HIGH_PAYLOAD_BYTES))
        projection = stage.calibration_projection(
            empty,
            stage.DiskSample("low", low_used, 18 * gib, 20 * gib),
            stage.DiskSample("high", high_used, 17 * gib, 20 * gib),
        )
        self.assertAlmostEqual(projection["fixed_bytes_per_record"], fixed, places=2)
        self.assertAlmostEqual(projection["bytes_per_payload_byte"], amplification, places=4)
        self.assertIsInstance(projection["recommended_payload_bytes"], int)

    def test_calibration_projection_rejects_non_growth(self):
        sample = stage.DiskSample("same", 1000, 9000, 10000)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.calibration_projection(sample, sample, sample)

    def test_records_are_deterministic_valid_and_synthetic(self):
        spec = self.small_spec()
        one, two = stage.record_for(spec, 42), stage.record_for(spec, 42)
        self.assertEqual(one, two); self.assertEqual(len(json.loads(one["memory"]["content"])["payload"]), 1000)
        self.assertTrue(json.loads(one["memory"]["content"])["synthetic"])
        self.assertNotIn("padding", one["memory"]["content"].lower())

    def test_collision_pair_has_same_fnv_hash_but_different_strings(self):
        left, right = stage.COLLISION_CONCEPTS
        self.assertNotEqual(left, right); self.assertEqual(stage.fnv1a_32(left), stage.fnv1a_32(right))

    def test_isolation_records_use_concepts_absent_from_primary_vault(self):
        isolated = stage.record_for(self.small_spec(), 97)
        primary = stage.record_for(self.small_spec(), 98)
        self.assertEqual(isolated["vault"], "stage-a-isolation")
        self.assertTrue(isolated["memory"]["concept"].startswith("stage-a/isolation/"))
        self.assertEqual(primary["vault"], "stage-a-primary")

    def test_entity_ordering_requires_complete_retained_ids_newest_first(self):
        stage.verify_entity_ordering({"engrams": [{"id": "new"}, {"id": "old"}]}, ["new", "old"])
        with self.assertRaises(stage.RehearsalFailed):
            stage.verify_entity_ordering({"engrams": [{"id": "old"}, {"id": "new"}]}, ["new", "old"])
        with self.assertRaises(stage.RehearsalFailed):
            stage.verify_entity_ordering({"engrams": [{"id": "new"}]}, ["new", "old"])

    def test_batch_iterator_never_exceeds_fifty(self):
        batches = list(stage.iter_batches(({"i": i} for i in range(123)), 50))
        self.assertEqual([len(x) for x in batches], [50, 50, 23])
        with self.assertRaises(stage.RehearsalUnknown): list(stage.iter_batches([], 51))

    def test_streaming_ingest_validates_every_item_and_hashes_canonically(self):
        spec = self.small_spec(); client = FakeClient()
        with mock.patch.object(stage, "validate_spec"):
            first = stage.ingest_corpus(client, spec)
        self.assertEqual((first.submitted, first.accepted), (53, 53))
        self.assertTrue(all(len(args["memories"]) <= 50 for _, args in client.calls))
        client2 = FakeClient()
        with mock.patch.object(stage, "validate_spec"):
            second = stage.ingest_corpus(client2, spec)
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)

    def test_streaming_ingest_emits_bounded_progress(self):
        progress = []
        spec = self.small_spec()
        with mock.patch.object(stage, "validate_spec"):
            receipt = stage.ingest_corpus(
                FakeClient(), spec, progress=progress.append, progress_interval=1,
            )
        self.assertGreaterEqual(len(progress), 2)
        self.assertEqual(progress[-1].accepted, receipt.accepted)
        self.assertEqual(progress[-1].batch_latency["count"], receipt.batches)
        self.assertFalse(hasattr(progress[-1], "retained_ids"))
        with self.assertRaises(stage.RehearsalUnknown):
            stage.ingest_corpus(FakeClient(), spec, progress_interval=0)

    def test_progress_receipt_is_unknown_bounded_and_incomplete(self):
        identity = stage.build_identity("progress-test")
        spec = stage.CorpusSpec()
        progress = stage.IngestProgress(5000, 5000, 100, 12.3, {"count": 100, "p50_ms": 1.0, "p95_ms": 2.0, "max_ms": 3.0})
        document = stage.receipt_document(
            identity, spec, status="UNKNOWN", exit_code=2, detail="baseline ingestion in progress",
            ledger=stage.ResourceLedger(app=identity.app_name, volume_id="vol_owned"),
            measurements={"latest_disk_sample": {"used_bytes": 123}}, gates={},
            cleanup_result={}, orphans=[], corpus=progress,
        )
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertFalse(document["corpus"]["complete"])
        self.assertNotIn("manifest_sha256", document["corpus"])
        self.assertNotIn("retained_ids", document["corpus"])

    def test_ingestion_disk_safety_fails_fast(self):
        safe = stage.DiskSample("safe", stage.MAX_PEAK_BYTES, 7, 10)
        stage.require_disk_safety(safe)
        with self.assertRaises(stage.RehearsalFailed):
            stage.require_disk_safety(stage.DiskSample("peak", stage.MAX_PEAK_BYTES + 1, 7, 10))
        with self.assertRaises(stage.RehearsalFailed):
            stage.require_disk_safety(stage.DiskSample("free", 1, 2, 10))

    def test_partial_batch_error_fails_closed(self):
        with mock.patch.object(stage, "validate_spec"):
            with self.assertRaises(stage.RehearsalFailed): stage.ingest_corpus(FakeClient(fail_index=7), self.small_spec())

    def test_thresholds_distinguish_failed_and_unknown(self):
        self.assertEqual(stage.threshold_gate("x", None, 1).status, "UNKNOWN")
        self.assertEqual(stage.threshold_gate("x", 2, 1).status, "FAILED")
        self.assertEqual(stage.threshold_gate("x", 1, 1).status, "PASSED")
        samples = [stage.DiskSample("peak", stage.MAX_PEAK_BYTES + 1, 1, 100)]
        self.assertEqual(stage.disk_gate(samples).status, "FAILED")
        self.assertEqual(stage.combine_status({"a": stage.Gate("PASSED", "ok")}, ["orphan"]), "UNKNOWN")

    def test_volume_command_is_encrypted_twenty_gb_and_unscheduled(self):
        identity = stage.build_identity("volume-test")
        calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, json.dumps({"id": "vol_stagea"}), "")
        volume = stage.FlyRuntime(runner=runner).create_volume(identity, identity.volume_name)
        self.assertEqual(volume, "vol_stagea"); command = calls[0]
        self.assertEqual(command[command.index("--size") + 1], "20")
        self.assertIn("--scheduled-snapshots=false", command); self.assertNotIn("--no-encryption", command)

    def test_machine_has_no_services_or_dns_and_is_production_shaped(self):
        identity = stage.build_identity("machine-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        stage.FlyRuntime(runner=runner).create_machine(identity, "vol_test", stage.CANDIDATE_IMAGE, "candidate")
        command = calls[0]; config = json.loads(command[command.index("--machine-config") + 1])
        self.assertEqual(config["services"], []); self.assertEqual(config["guest"], {"cpu_kind": "performance", "cpus": 16, "memory_mb": 32768})
        self.assertIn("--skip-dns-registration", command)

    def test_migration_sampler_captures_disk_and_process_resources(self):
        identity = stage.build_identity("sample-test"); runtime = mock.Mock()
        runtime.machine_status.side_effect = [{"state": "starting"}, {"state": "started"}]
        runtime.disk_sample.side_effect = [stage.DiskSample("migration", 1, 9, 10), stage.DiskSample("migration", 2, 8, 10)]
        runtime.resource_sample.side_effect = [stage.ResourceSample("migration", 25.0, 1024), stage.ResourceSample("migration", 50.0, 2048)]
        with mock.patch.object(stage.time, "sleep"):
            _, disks, resources = stage.FlyRuntime.migration_samples(runtime, identity, "machine", 30)
        self.assertEqual([sample.used_bytes for sample in disks], [1, 2])
        self.assertEqual([sample.rss_bytes for sample in resources], [1024, 2048])

    def test_resource_sample_parses_cpu_and_rss_without_procfs_guessing(self):
        identity = stage.build_identity("resource-test")
        runtime = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "37.500 2048\n", ""))
        sample = runtime.resource_sample(identity, "machine", "migration")
        self.assertEqual(sample, stage.ResourceSample("migration", 37.5, 2 * 1024 * 1024))

    def test_proxy_is_loopback_only(self):
        identity = stage.build_identity("proxy-test")
        runtime = stage.FlyRuntime(popen=mock.Mock(return_value="proc"))
        runtime.machine_status = mock.Mock(return_value={"private_ip": "fdaa::1"})
        self.assertEqual(runtime.proxy(identity, "machine", 18750), "proc")
        command = runtime.popen.call_args.args[0]
        self.assertEqual(command[command.index("--bind-addr") + 1], "127.0.0.1")

    def test_initialize_waits_for_proxy_readiness_and_then_succeeds(self):
        client = stage.MCPClient("http://127.0.0.1:18750/mcp", "synthetic")
        client._post = mock.Mock(side_effect=[stage.RehearsalUnknown("not ready"), {}])
        with mock.patch.object(stage.time, "sleep"):
            client.initialize(timeout_s=10)
        self.assertEqual(client._post.call_count, 2)

    def test_initialize_fails_closed_at_readiness_deadline(self):
        client = stage.MCPClient("http://127.0.0.1:18750/mcp", "synthetic")
        client._post = mock.Mock(side_effect=stage.RehearsalUnknown("not ready"))
        with mock.patch.object(stage.time, "monotonic", side_effect=[0, 0, 2]), mock.patch.object(stage.time, "sleep"):
            with self.assertRaisesRegex(stage.RehearsalUnknown, "readiness deadline"):
                client.initialize(timeout_s=1)

    def test_dry_run_makes_no_runtime_or_network_calls(self):
        with mock.patch.object(stage, "FlyRuntime", side_effect=AssertionError("runtime constructed")), mock.patch.object(stage.urllib.request, "urlopen", side_effect=AssertionError("network")):
            self.assertEqual(stage.main(["--run-id", "dry-run-test", "--json"]), 0)

    def test_execute_refuses_without_exact_confirmation(self):
        with mock.patch.object(stage, "execute", side_effect=AssertionError("must not execute")):
            self.assertEqual(stage.main(["--run-id", "refusal-test", "--execute", "--confirm", "wrong"]), 2)

    def test_old_image_is_only_allowed_for_baseline_and_rollback_roles(self):
        identity = stage.build_identity("role-test")
        runtime = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", ""))
        with self.assertRaises(stage.RehearsalUnknown): runtime.create_machine(identity, "vol_test", stage.BASELINE_IMAGE, "candidate")
        runtime.create_machine(identity, "vol_test", stage.BASELINE_IMAGE, "rollback")

    def test_offline_helper_requires_stopped_zero_exit(self):
        identity = stage.build_identity("wait-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            output = "state = stopped\nexit_code = 0\n" if "status" in cmd else ""
            return subprocess.CompletedProcess(cmd, 0, output, "")
        stage.FlyRuntime(runner=runner).wait_stopped(identity, "abc123", 30)
        self.assertIn("stopped", calls[0]); self.assertIn("status", calls[1])
        bad = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "exit_code = 7\n" if "status" in cmd else "", ""))
        with self.assertRaises(stage.RehearsalFailed): bad.wait_stopped(identity, "abc123", 30)
        unknown = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "state = stopped\n" if "status" in cmd else "", ""))
        with self.assertRaises(stage.RehearsalUnknown): unknown.wait_stopped(identity, "abc123", 30)

    def test_restore_helper_uses_backup_archive_and_separate_empty_volume(self):
        identity = stage.build_identity("restore-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        runtime.create_restore(identity, "vol_backup", "vol_restore", stage.CANDIDATE_IMAGE, "/backup/stage-a-backup.tgz")
        command = calls[0]; config = json.loads(command[command.index("--machine-config") + 1])
        self.assertEqual(config["mounts"], [{"path": "/backup", "volume": "vol_backup"}, {"path": "/restore", "volume": "vol_restore"}])
        restore_command = config["init"]["exec"][2]
        self.assertIn("/backup/stage-a-backup.tgz", restore_command)
        self.assertIn("sha256sum", restore_command); self.assertIn("tar -xzf", restore_command)
        self.assertEqual(config["services"], [])

    def test_hard_delete_helper_is_offline_and_scoped(self):
        identity = stage.build_identity("delete-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        stage.FlyRuntime(runner=runner).hard_delete(identity, "vol_source", stage.CANDIDATE_IMAGE, "stage-a-primary", "01ABC_def")
        config = json.loads(calls[0][calls[0].index("--machine-config") + 1]); command = config["init"]["exec"][2]
        self.assertEqual(config["services"], []); self.assertIn("exec forget", command)
        self.assertIn("--vault stage-a-primary", command); self.assertIn("--id 01ABC_def", command)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.FlyRuntime(runner=runner).hard_delete(identity, "vol_source", stage.CANDIDATE_IMAGE, "stage-a-primary;bad", "id")

    def test_backup_helper_persists_archive_receipts_on_source_volume(self):
        identity = stage.build_identity("backup-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        _, path = stage.FlyRuntime(runner=runner).create_backup(identity, "vol_source", "vol_backup", stage.CANDIDATE_IMAGE)
        config = json.loads(calls[0][calls[0].index("--machine-config") + 1]); command = config["init"]["exec"][2]
        self.assertEqual(path, "/backup/stage-a-backup.tgz")
        self.assertEqual(config["mounts"], [{"path": "/data", "volume": "vol_source"}, {"path": "/backup", "volume": "vol_backup"}])
        self.assertIn("muninndb-server backup", command); self.assertIn("$A.sha256", command); self.assertIn("$A.bytes", command)

    def test_receipt_is_allowlisted_redacted_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "receipt.json"
            receipt = {key: None for key in stage.RECEIPT_KEYS}; receipt.update({"schema_version": 1, "status": "UNKNOWN", "detail": "request failed for https://example.invalid", "orphans": []})
            digest = stage.write_receipt(path, receipt)
            self.assertEqual(digest, (path.with_suffix(".json.sha256")).read_text().strip())
            self.assertNotIn("example.invalid", path.read_text()); self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cleanup_uncertainty_forces_orphan(self):
        identity = stage.build_identity("cleanup-test"); runtime = mock.Mock()
        runtime.destroy_machine.side_effect = RuntimeError("fail"); runtime.list_owned_resources.return_value = []
        _, orphans = stage.cleanup(runtime, identity, stage.ResourceLedger(machine_id="owned-machine"))
        self.assertEqual(orphans, ["owned-machine"])

    def test_cleanup_discovery_is_exact_and_absent_is_idempotent(self):
        identity = stage.build_identity("discover-test")
        absent = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, "", "missing"))
        self.assertEqual(absent.discover_owned_resources(identity), stage.ResourceLedger())

        calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            if cmd[1] == "status": return subprocess.CompletedProcess(cmd, 0, "ok", "")
            if "machines" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{
                    "id": "ownedmachine", "config": {"metadata": {"koala_stage_a_run": identity.run_id}},
                }]), "")
            if "volumes" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{
                    "id": "vol_owned", "name": identity.volume_name,
                }]), "")
            raise AssertionError(cmd)
        discovered = stage.FlyRuntime(runner=runner).discover_owned_resources(identity)
        self.assertEqual(discovered.machine_id, "ownedmachine")
        self.assertEqual(discovered.volume_id, "vol_owned")
        self.assertEqual(discovered.app, identity.app_name)

    def test_cleanup_discovery_refuses_wrong_metadata_or_volume_name(self):
        identity = stage.build_identity("discover-bad")
        def wrong_machine(cmd, **kwargs):
            if cmd[1] == "status": return subprocess.CompletedProcess(cmd, 0, "ok", "")
            if "machines" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{
                    "id": "ownedmachine", "config": {"metadata": {"koala_stage_a_run": "other"}},
                }]), "")
            return subprocess.CompletedProcess(cmd, 0, "[]", "")
        with self.assertRaises(stage.RehearsalUnknown):
            stage.FlyRuntime(runner=wrong_machine).discover_owned_resources(identity)

        def wrong_volume(cmd, **kwargs):
            if cmd[1] == "status": return subprocess.CompletedProcess(cmd, 0, "ok", "")
            if "machines" in cmd: return subprocess.CompletedProcess(cmd, 0, "[]", "")
            return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "vol_owned", "name": "not_owned"}]), "")
        with self.assertRaises(stage.RehearsalUnknown):
            stage.FlyRuntime(runner=wrong_volume).discover_owned_resources(identity)

    def test_cleanup_only_writes_pass_for_absent_app(self):
        identity = stage.build_identity("cleanup-only")
        runtime = mock.Mock()
        runtime.discover_owned_resources.return_value = stage.ResourceLedger()
        runtime.list_owned_resources.return_value = []
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "cleanup.json"
            self.assertEqual(stage.cleanup_only(identity, path, runtime=runtime), 0)
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt["status"], "PASSED")
        self.assertEqual(receipt["measurements"]["mode"], "cleanup-only")
        self.assertEqual(receipt["orphans"], [])

    def test_calibration_plan_is_fixed_and_non_mutating(self):
        identity = stage.build_identity("calibrate-plan")
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT, 50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed",
        )
        with mock.patch.object(stage, "FlyRuntime", side_effect=AssertionError("runtime constructed")):
            rendered = stage.plan(identity, spec, mode="calibrate")
        self.assertEqual(rendered["mode"], "calibrate-plan")
        self.assertEqual(rendered["record_count"], stage.CALIBRATION_SAMPLE_COUNT)
        self.assertEqual(rendered["payload_bytes"], stage.CALIBRATION_LOW_PAYLOAD_BYTES)

    def test_calibration_plan_cli_uses_calibration_validation_without_mutation(self):
        with mock.patch.object(stage, "FlyRuntime", side_effect=AssertionError("runtime constructed")):
            self.assertEqual(stage.main([
                "--dry-run", "--plan-mode", "calibrate", "--run-id", "calibrate-cli",
                "--record-count", "25000", "--payload-bytes", "1000", "--json",
            ]), 0)

    def test_calibration_interruption_writes_unknown_receipt_and_cleans_up(self):
        identity = stage.build_identity("calibrate-stop")
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT, 50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed",
        )
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.return_value = "vol_owned"
        runtime.create_machine.return_value = "machine_owned"
        runtime.proxy.return_value = mock.Mock(poll=mock.Mock(return_value=0))
        runtime.disk_sample.return_value = stage.DiskSample("empty", 100, 900, 1000)
        runtime.list_owned_resources.return_value = []
        client = mock.Mock()
        client.initialize.side_effect = stage.RehearsalUnknown("rehearsal terminated by signal 15")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "interrupted.json"
            self.assertEqual(stage.calibrate(
                identity, spec, path, runtime=runtime,
                client_factory=lambda _url, _auth: client,
            ), 2)
            document = json.loads(path.read_text())
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertIn("signal 15", document["detail"])
        self.assertEqual(document["orphans"], [])
        runtime.destroy_machine.assert_called_once_with(identity, "machine_owned")
        runtime.destroy_volume.assert_called_once_with(identity, "vol_owned")
        runtime.destroy_app.assert_called_once_with(identity)

    def test_proxy_termination_failure_does_not_skip_resource_cleanup(self):
        identity = stage.build_identity("calibrate-proxy")
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT, 50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed",
        )
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.return_value = "vol_owned"
        runtime.create_machine.return_value = "machine_owned"
        runtime.proxy.return_value = mock.Mock(
            terminate=mock.Mock(side_effect=OSError("stop failed")),
            kill=mock.Mock(side_effect=OSError("kill failed")),
        )
        runtime.disk_sample.return_value = stage.DiskSample("empty", 100, 900, 1000)
        runtime.list_owned_resources.return_value = []
        client = mock.Mock()
        client.initialize.side_effect = stage.RehearsalUnknown("interrupted")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "proxy-failure.json"
            self.assertEqual(stage.calibrate(
                identity, spec, path, runtime=runtime,
                client_factory=lambda _url, _auth: client,
            ), 2)
            document = json.loads(path.read_text())
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertEqual(document["detail"], "local proxy cleanup uncertain")
        runtime.destroy_machine.assert_called_once_with(identity, "machine_owned")
        runtime.destroy_volume.assert_called_once_with(identity, "vol_owned")
        runtime.destroy_app.assert_called_once_with(identity)

    def test_calibration_orchestration_uses_baseline_only_and_cleans_up(self):
        identity = stage.build_identity("calibrate-fake")
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT, 50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed",
        )
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.return_value = "vol_owned"
        runtime.create_machine.return_value = "machine_owned"
        runtime.proxy.return_value = mock.Mock(poll=mock.Mock(return_value=0))
        gib = 1024**3
        runtime.disk_sample.side_effect = [
            stage.DiskSample("empty", 100 * 1024**2, 19 * gib, 20 * gib),
            stage.DiskSample("low", 300 * 1024**2, 18 * gib, 20 * gib),
            stage.DiskSample("high", 575 * 1024**2, 17 * gib, 20 * gib),
        ]
        runtime.list_owned_resources.return_value = []
        client = mock.Mock()
        receipts = [
            stage.CorpusReceipt(submitted=25000, accepted=25000, batches=500, manifest_sha256="a" * 64),
            stage.CorpusReceipt(submitted=25000, accepted=25000, batches=500, manifest_sha256="b" * 64),
        ]
        seen_specs = []
        def fake_ingest(_client, cohort, **_kwargs):
            seen_specs.append(cohort)
            return receipts[len(seen_specs) - 1]
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(stage, "ingest_corpus", side_effect=fake_ingest):
            path = Path(root) / "calibration.json"
            self.assertEqual(stage.calibrate(
                identity, spec, path, runtime=runtime,
                client_factory=lambda _url, _auth: client,
            ), 0)
            document = json.loads(path.read_text())
        self.assertEqual([item.payload_bytes for item in seen_specs], [1000, 4000])
        runtime.create_machine.assert_called_once_with(
            identity, "vol_owned", stage.BASELINE_IMAGE, "baseline",
        )
        self.assertNotIn(stage.CANDIDATE_IMAGE, repr(runtime.mock_calls))
        self.assertEqual(document["status"], "PASSED")
        self.assertEqual(document["measurements"]["mode"], "calibrate")
        runtime.destroy_machine.assert_called_once_with(identity, "machine_owned")
        runtime.destroy_volume.assert_called_once_with(identity, "vol_owned")
        runtime.destroy_app.assert_called_once_with(identity)

    def test_workflow_reserves_cleanup_headroom_and_uploads_both_receipts(self):
        workflow = (MODULE_PATH.parents[1] / ".github" / "workflows" / "koala-stage-a-rehearse.yml").read_text()
        self.assertIn("timeout-minutes: 360", workflow)
        self.assertIn("deadline=300m", workflow)
        self.assertIn("deadline=120m", workflow)
        self.assertIn("if: inputs.mode != 'plan'", workflow)
        self.assertIn("plan_mode=calibrate", workflow)
        self.assertIn("plan_mode=execute", workflow)
        self.assertIn('--dry-run --plan-mode "$plan_mode"', workflow)
        self.assertLess(workflow.index("Clean up exact run-owned resources"), workflow.index("Upload redacted evidence"))
        self.assertIn("--cleanup-only", workflow)
        self.assertIn("cleanup.json.sha256", workflow)
        self.assertIn("cleanup-exit-code", workflow)

if __name__ == "__main__": unittest.main()
