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

if __name__ == "__main__": unittest.main()
