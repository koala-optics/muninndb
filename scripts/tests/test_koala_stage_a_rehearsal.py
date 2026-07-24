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
        return stage.CorpusSpec(count=count, batch_size=50, payload_bytes=1000, seed="test-seed", payload_shape="opaque")

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

    def test_defaults_are_production_scale_lexical_and_twenty_gb(self):
        self.assertEqual(stage.DEFAULT_RECORD_COUNT, 502_385)
        self.assertEqual(stage.DEFAULT_BATCH_SIZE, 50)
        self.assertEqual(stage.DEFAULT_PAYLOAD_BYTES, 4000)
        self.assertEqual(stage.DEFAULT_PAYLOAD_SHAPE, "lexical")
        self.assertEqual(stage.CorpusSpec().payload_shape, "opaque")
        self.assertEqual(stage.VOLUME_SIZE_GB, 20)
        stage.validate_execute_spec(stage.CorpusSpec(payload_shape=stage.DEFAULT_PAYLOAD_SHAPE))
        with self.assertRaises(stage.RehearsalUnknown): stage.validate_spec(self.small_spec())

    def test_execute_contract_refuses_obsolete_or_unmeasured_shapes(self):
        for spec in (
            stage.CorpusSpec(payload_shape="opaque"),
            stage.CorpusSpec(payload_bytes=1000),
        ):
            with self.assertRaisesRegex(stage.RehearsalUnknown, "qualified lexical contract"):
                stage.validate_execute_spec(spec)

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

    def test_calibration_projection_separates_independent_store_costs(self):
        gib = 1024**3
        sample = stage.CALIBRATION_SAMPLE_COUNT
        low_empty = stage.DiskSample("low-empty", 100 * 1024**2, 19 * gib, 20 * gib)
        high_empty = stage.DiskSample("high-empty", 110 * 1024**2, 19 * gib, 20 * gib)
        fixed, amplification = 7000, 1.0
        low_used = low_empty.used_bytes + round(sample * (fixed + amplification * stage.CALIBRATION_LOW_PAYLOAD_BYTES))
        high_used = high_empty.used_bytes + round(sample * (fixed + amplification * stage.CALIBRATION_HIGH_PAYLOAD_BYTES))
        projection = stage.calibration_projection(
            low_empty,
            stage.DiskSample("low", low_used, 18 * gib, 20 * gib),
            high_empty,
            stage.DiskSample("high", high_used, 17 * gib, 20 * gib),
        )
        self.assertAlmostEqual(projection["fixed_bytes_per_record"], fixed, places=2)
        self.assertAlmostEqual(projection["bytes_per_payload_byte"], amplification, places=4)
        self.assertEqual(projection["low_net_growth_bytes"], low_used - low_empty.used_bytes)
        self.assertEqual(projection["high_net_growth_bytes"], high_used - high_empty.used_bytes)
        self.assertEqual(projection["projection_empty_used_bytes"], high_empty.used_bytes)
        self.assertIsInstance(projection["recommended_payload_bytes"], int)

    def test_calibration_projection_rejects_non_growth(self):
        sample = stage.DiskSample("same", 1000, 9000, 10000)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.calibration_projection(sample, sample, sample, sample)

    def test_calibration_projection_rejects_non_positive_independent_slope(self):
        low_empty = stage.DiskSample("low-empty", 1000, 9000, 10000)
        low = stage.DiskSample("low", 3000, 7000, 10000)
        high_empty = stage.DiskSample("high-empty", 2000, 8000, 10000)
        high = stage.DiskSample("high", 3500, 6500, 10000)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.calibration_projection(low_empty, low, high_empty, high)

    def test_records_are_deterministic_valid_and_synthetic(self):
        spec = self.small_spec()
        one, two = stage.record_for(spec, 42), stage.record_for(spec, 42)
        self.assertEqual(one, two); self.assertEqual(len(json.loads(one["memory"]["content"])["payload"]), 1000)
        self.assertTrue(json.loads(one["memory"]["content"])["synthetic"])
        self.assertNotIn("padding", one["memory"]["content"].lower())

    def test_bulk_records_are_lean_and_probe_records_are_rich(self):
        spec = self.small_spec()
        bulk = stage.record_for(spec, 44)
        probe = stage.record_for(spec, 42)
        self.assertIsNone(bulk["probe_kind"])
        self.assertFalse({"summary", "tags", "entities"} & bulk["memory"].keys())
        self.assertEqual(probe["probe_kind"], "ordering")
        self.assertTrue({"summary", "tags", "entities"} <= probe["memory"].keys())

    def test_probe_contract_is_sparse_and_covers_semantic_targets(self):
        self.assertEqual([stage.probe_kind(i) for i in (0, 1)], ["collision", "collision"])
        self.assertEqual(stage.probe_kind(43), "hard-delete")
        self.assertEqual(stage.probe_kind(97), "isolation")
        self.assertEqual(stage.probe_kind(42), "ordering")
        self.assertEqual([stage.probe_kind(i) for i in (50, 51, 57)], ["fuzzy", "fuzzy", "fuzzy"])
        counts = stage.shape_counts(stage.DEFAULT_RECORD_COUNT)
        self.assertEqual(counts["shape_version"], stage.CORPUS_SHAPE_VERSION)
        self.assertEqual(counts["bulk_records"] + counts["probe_records"], stage.DEFAULT_RECORD_COUNT)
        self.assertLess(counts["probe_records"], stage.DEFAULT_RECORD_COUNT // 500)

    def test_calibration_and_full_generation_share_shape_selection(self):
        for index in (0, 42, 43, 44, 50, 51, 57, 97, 10042):
            low = stage.record_for(stage.CorpusSpec(25000, 50, 1000, "low"), index)
            high = stage.record_for(stage.CorpusSpec(25000, 50, 4000, "high"), index)
            full = stage.record_for(stage.CorpusSpec(), index)
            self.assertEqual(low["probe_kind"], high["probe_kind"])
            self.assertEqual(low["probe_kind"], full["probe_kind"])
            self.assertEqual(low["vault"], full["vault"])

    def test_fuzzy_probe_entities_cover_runtime_queries(self):
        spec = self.small_spec()
        entity_names = {
            entity["name"]
            for index in (50, 51, 57)
            for entity in stage.record_for(spec, index)["memory"]["entities"]
        }
        self.assertTrue({"Stage A Entity 00", "Stage A Entity 07", "Stage A Group 2"} <= entity_names)

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

    def test_disk_sample_retries_only_transient_408(self):
        identity = stage.build_identity("disk-retry")
        responses = [
            subprocess.CompletedProcess([], 1, "", "request returned non-2xx status: 408"),
            subprocess.CompletedProcess([], 0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/data 1000 100 900 10% /data\n", ""),
        ]
        runtime = stage.FlyRuntime(runner=mock.Mock(side_effect=responses))
        with mock.patch.object(stage.time, "sleep") as sleep:
            sample = runtime.disk_sample(identity, "machine", "settled")
        self.assertEqual(sample, stage.DiskSample("settled", 100 * 1024, 900 * 1024, 1000 * 1024))
        self.assertEqual(runtime.runner.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_disk_sample_fails_non_408_without_retry(self):
        identity = stage.build_identity("disk-fail")
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "permission denied"))
        runtime = stage.FlyRuntime(runner=runner)
        with self.assertRaises(stage.RehearsalUnknown):
            runtime.disk_sample(identity, "machine", "settled")
        runner.assert_called_once()

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

    def test_execute_refuses_opaque_spec_before_fly_mutation(self):
        identity = stage.build_identity("opaque-refusal")
        runtime = mock.Mock()
        runtime.list_owned_resources.return_value = []
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "refusal.json"
            self.assertEqual(stage.execute(
                identity,
                stage.CorpusSpec(payload_shape="opaque"),
                path,
                runtime=runtime,
            ), 2)
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertIn("qualified lexical contract", receipt["detail"])
        runtime.preflight.assert_not_called()
        runtime.create_app.assert_not_called()
        runtime.create_volume.assert_not_called()
        runtime.create_machine.assert_not_called()

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

    def test_execute_plan_is_lexical_evidence_backed_and_non_mutating(self):
        identity = stage.build_identity("execute-plan")
        with mock.patch.object(stage, "FlyRuntime", side_effect=AssertionError("runtime constructed")):
            rendered = stage.plan(identity, stage.CorpusSpec(payload_shape="lexical"))
        self.assertEqual(rendered["mode"], "execute-plan")
        self.assertEqual(rendered["record_count"], 502_385)
        self.assertEqual(rendered["payload_bytes"], 4000)
        self.assertEqual(rendered["payload_shape"], "lexical")
        self.assertEqual(rendered["expected_net_store_bytes"], 6_043_996_679)
        self.assertEqual(rendered["store_footprint_gate_bytes"], {
            "minimum": stage.MIN_STORE_BYTES,
            "maximum": stage.MAX_STORE_BYTES,
        })
        self.assertEqual(rendered["storage_evidence"], {
            "ablation_run_id": "30102233910",
            "receipt_sha256": stage.ABLATION_RECEIPT_SHA256,
        })
        self.assertTrue(any("asynchronous FTS" in item for item in rendered["limitations"]))

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
        runtime.create_volume.side_effect = ["vol_low", "vol_high"]
        runtime.create_machine.side_effect = ["machine_low", "machine_high"]
        runtime.proxy.side_effect = [
            mock.Mock(poll=mock.Mock(return_value=0)),
            mock.Mock(poll=mock.Mock(return_value=0)),
        ]
        gib = 1024**3
        runtime.disk_sample.side_effect = [
            stage.DiskSample("low-empty", 100 * 1024**2, 19 * gib, 20 * gib),
            stage.DiskSample("low", 300 * 1024**2, 18 * gib, 20 * gib),
            stage.DiskSample("high-empty", 110 * 1024**2, 19 * gib, 20 * gib),
            stage.DiskSample("high", 385 * 1024**2, 17 * gib, 20 * gib),
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
        self.assertEqual(runtime.create_volume.call_args_list, [
            mock.call(identity, identity.volume_name),
            mock.call(identity, identity.volume_name),
        ])
        self.assertEqual(runtime.create_machine.call_args_list, [
            mock.call(identity, "vol_low", stage.BASELINE_IMAGE, "baseline"),
            mock.call(identity, "vol_high", stage.BASELINE_IMAGE, "baseline"),
        ])
        self.assertNotIn(stage.CANDIDATE_IMAGE, repr(runtime.mock_calls))
        self.assertEqual(document["status"], "PASSED")
        self.assertEqual(document["measurements"]["mode"], "calibrate")
        self.assertEqual(document["measurements"]["calibration"]["low_empty_used_bytes"], 100 * 1024**2)
        self.assertEqual(document["measurements"]["calibration"]["high_empty_used_bytes"], 110 * 1024**2)
        self.assertEqual(runtime.destroy_machine.call_args_list, [
            mock.call(identity, "machine_low"),
            mock.call(identity, "machine_high"),
        ])
        self.assertEqual(runtime.destroy_volume.call_args_list, [
            mock.call(identity, "vol_low"),
            mock.call(identity, "vol_high"),
        ])
        runtime.destroy_app.assert_called_once_with(identity)

    def test_opaque_payload_remains_backward_compatible(self):
        expected = stage.deterministic_payload("test-seed", 42, 1000)
        self.assertEqual(stage.payload_for("opaque", "test-seed", 42, 1000), expected)
        opaque = stage.record_for(self.small_spec(), 42)
        self.assertEqual(json.loads(opaque["memory"]["content"])["payload"], expected)

    def test_lexical_payload_is_exact_deterministic_unique_and_synthetic(self):
        first = stage.payload_for("lexical", "test-seed", 42, 1000)
        repeated = stage.payload_for("lexical", "test-seed", 42, 1000)
        other = stage.payload_for("lexical", "test-seed", 43, 1000)
        self.assertEqual(first, repeated)
        self.assertEqual(len(first), 1000)
        self.assertNotEqual(first, other)
        self.assertRegex(first, r"^[a-z0-9 -]+$")
        self.assertIn("synthetic", first)
        self.assertNotIn("koala", first)

    def test_payload_shapes_preserve_sparse_probe_contract(self):
        opaque = stage.CorpusSpec(25000, 50, 1000, "shape", "opaque")
        lexical = stage.CorpusSpec(25000, 50, 1000, "shape", "lexical")
        for index in (0, 42, 43, 44, 50, 51, 57, 97, 10042):
            left, right = stage.record_for(opaque, index), stage.record_for(lexical, index)
            self.assertEqual(left["probe_kind"], right["probe_kind"])
            self.assertEqual(left["vault"], right["vault"])
            self.assertEqual(left["memory"]["concept"], right["memory"]["concept"])
            self.assertEqual(left["memory"]["created_at"], right["memory"]["created_at"])
            self.assertEqual(set(left["memory"]) - {"content"}, set(right["memory"]) - {"content"})

    def test_storage_quiet_deadline_allows_async_index_settlement(self):
        self.assertEqual(stage.STORAGE_QUIET_TIMEOUT_S, 20 * 60)

    def test_quiet_window_requires_stable_samples(self):
        identity = stage.build_identity("settle-test")
        runtime = mock.Mock()
        runtime.disk_sample.side_effect = [
            stage.DiskSample("x", 100, 900, 1000),
            stage.DiskSample("x", 110, 890, 1000),
            stage.DiskSample("x", 110, 890, 1000),
            stage.DiskSample("x", 110, 890, 1000),
        ]
        with mock.patch.object(stage.time, "sleep"):
            result = stage.wait_for_storage_quiet(
                runtime, identity, "machine", "cohort", timeout_s=10,
                interval_s=1, stable_samples=2, tolerance_bytes=0,
            )
        self.assertEqual(result["settled"].used_bytes, 110)
        self.assertEqual(len(result["samples"]), 4)
        self.assertEqual(result["witness"], "bounded-df-quiet-window")

    def test_quiet_window_accepts_small_bidirectional_settlement(self):
        identity = stage.build_identity("settle-decrease")
        runtime = mock.Mock()
        runtime.disk_sample.side_effect = [
            stage.DiskSample("x", 100, 900, 1000),
            stage.DiskSample("x", 90, 910, 1000),
            stage.DiskSample("x", 95, 905, 1000),
        ]
        with mock.patch.object(stage.time, "sleep"):
            result = stage.wait_for_storage_quiet(
                runtime, identity, "machine", "cohort", timeout_s=10,
                interval_s=1, stable_samples=2, tolerance_bytes=10,
            )
        self.assertEqual(result["settled"].used_bytes, 95)
        self.assertEqual(len(result["samples"]), 3)

    def test_quiet_window_timeout_is_unknown(self):
        identity = stage.build_identity("settle-fail")
        runtime = mock.Mock()
        runtime.disk_sample.side_effect = [
            stage.DiskSample("x", 100, 900, 1000),
            stage.DiskSample("x", 110, 890, 1000),
        ]
        with mock.patch.object(stage.time, "monotonic", side_effect=[0, 0, 1, 2]), \
             mock.patch.object(stage.time, "sleep"):
            with self.assertRaises(stage.RehearsalUnknown):
                stage.wait_for_storage_quiet(
                    runtime, identity, "machine", "cohort", timeout_s=1,
                    interval_s=1, tolerance_bytes=0,
                )

    def test_ablation_models_are_separate_and_expose_shape_delta(self):
        empty = 1000
        samples = {
            "opaque-1k": (empty, empty + 25000 * 12000),
            "opaque-4k": (empty, empty + 25000 * 15000),
            "lexical-1k": (empty, empty + 25000 * 5000),
            "lexical-4k": (empty, empty + 25000 * 6500),
        }
        result = stage.ablation_projection(samples)
        self.assertAlmostEqual(result["opaque"]["fixed_bytes_per_record"], 11000)
        self.assertAlmostEqual(result["opaque"]["bytes_per_payload_byte"], 1.0)
        self.assertAlmostEqual(result["lexical"]["fixed_bytes_per_record"], 4500)
        self.assertAlmostEqual(result["lexical"]["bytes_per_payload_byte"], 0.5)
        self.assertEqual(result["fixed_shape_delta_bytes_per_record"], 6500)

    def test_ablation_orchestration_uses_four_fresh_baseline_stores(self):
        identity = stage.build_identity("ablate-fake")
        spec = stage.CorpusSpec(25000, 50, 1000, "test-seed")
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.side_effect = [f"vol_{i}" for i in range(4)]
        runtime.create_machine.side_effect = [f"machine_{i}" for i in range(4)]
        runtime.proxy.side_effect = [mock.Mock(poll=mock.Mock(return_value=0)) for _ in range(4)]
        runtime.disk_sample.side_effect = [
            sample
            for _ in range(4)
            for sample in (
                stage.DiskSample("empty", 100, 900, 1000),
                stage.DiskSample("immediate", 150, 850, 1000),
            )
        ]
        runtime.list_owned_resources.return_value = []
        receipt = stage.CorpusReceipt(submitted=25000, accepted=25000, batches=500, manifest_sha256="a" * 64)
        settled = iter([
            {"settled": stage.DiskSample(name, used, 1000, 2000), "samples": [], "witness": "bounded-df-quiet-window"}
            for name, used in (("opaque-1k", 300), ("opaque-4k", 450), ("lexical-1k", 200), ("lexical-4k", 275))
        ])
        seen = []
        def fake_ingest(_client, cohort, **_kwargs):
            seen.append((cohort.payload_shape, cohort.payload_bytes))
            return receipt
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(stage, "ingest_corpus", side_effect=fake_ingest), \
             mock.patch.object(stage, "wait_for_storage_quiet", side_effect=lambda *_a, **_k: next(settled)):
            path = Path(root) / "ablation.json"
            self.assertEqual(stage.ablate(identity, spec, path, runtime=runtime, client_factory=lambda *_a: mock.Mock()), 0)
            document = json.loads(path.read_text())
        self.assertEqual(seen, [("opaque", 1000), ("opaque", 4000), ("lexical", 1000), ("lexical", 4000)])
        self.assertEqual(runtime.create_volume.call_count, 4)
        self.assertEqual(runtime.create_machine.call_count, 4)
        self.assertTrue(all(call.args[2:] == (stage.BASELINE_IMAGE, "baseline") for call in runtime.create_machine.call_args_list))
        self.assertNotIn(stage.CANDIDATE_IMAGE, repr(runtime.mock_calls))
        self.assertEqual(runtime.destroy_machine.call_count, 4)
        self.assertEqual(runtime.destroy_volume.call_count, 4)
        self.assertEqual(document["measurements"]["mode"], "ablate")
        self.assertEqual(document["corpus"]["payload_shape"], "lexical")
        self.assertEqual(document["corpus"]["payload_bytes"], 4000)
        self.assertEqual(document["status"], "PASSED")

    def test_ablation_partial_failure_receipt_uses_active_cohort_metadata(self):
        identity = stage.build_identity("ablate-partial")
        spec = stage.CorpusSpec(25000, 50, 1000, "test-seed")
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.side_effect = ["vol_0", "vol_1"]
        runtime.create_machine.side_effect = ["machine_0", "machine_1"]
        runtime.proxy.side_effect = [mock.Mock(), mock.Mock()]
        runtime.disk_sample.side_effect = [
            stage.DiskSample("empty", 100, 900, 1000),
            stage.DiskSample("immediate", 150, 850, 1000),
            stage.DiskSample("empty", 100, 900, 1000),
        ]
        runtime.list_owned_resources.return_value = []
        complete = stage.CorpusReceipt(25000, 25000, 500, "a" * 64)
        progress = stage.IngestProgress(100, 100, 2, 1.0, {"count": 2})
        def fake_ingest(_client, cohort, **kwargs):
            if cohort.payload_bytes == 1000:
                return complete
            kwargs["progress"](progress)
            raise stage.RehearsalUnknown("synthetic interruption")
        quiet = {"settled": stage.DiskSample("settled", 300, 700, 1000), "samples": [], "witness": "bounded-df-quiet-window"}
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(stage, "ingest_corpus", side_effect=fake_ingest), \
             mock.patch.object(stage, "wait_for_storage_quiet", return_value=quiet):
            path = Path(root) / "partial.json"
            self.assertEqual(stage.ablate(identity, spec, path, runtime=runtime, client_factory=lambda *_a: mock.Mock()), 2)
            document = json.loads(path.read_text())
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertEqual(document["corpus"]["payload_shape"], "opaque")
        self.assertEqual(document["corpus"]["payload_bytes"], 4000)
        self.assertEqual(document["corpus"]["submitted"], 100)

    def test_ablation_cli_is_distinct_and_plan_only_is_non_mutating(self):
        with mock.patch.object(stage, "FlyRuntime", side_effect=AssertionError("runtime constructed")):
            self.assertEqual(stage.main([
                "--dry-run", "--plan-mode", "ablate", "--run-id", "ablate-cli",
                "--record-count", "25000", "--payload-bytes", "1000", "--json",
            ]), 0)
        parser = stage.build_parser()
        self.assertTrue(parser.parse_args(["--run-id", "x123", "--ablate"]).ablate)

    def test_workflow_reserves_cleanup_headroom_and_uploads_both_receipts(self):
        workflow = (MODULE_PATH.parents[1] / ".github" / "workflows" / "koala-stage-a-rehearse.yml").read_text()
        self.assertIn("timeout-minutes: 360", workflow)
        self.assertIn("deadline=300m", workflow)
        self.assertIn("deadline=120m", workflow)
        self.assertIn("deadline=180m", workflow)
        self.assertIn("if: inputs.mode != 'plan'", workflow)
        self.assertIn("- ablate", workflow)
        self.assertIn("plan_mode=calibrate", workflow)
        self.assertIn("plan_mode=ablate", workflow)
        self.assertIn("plan_mode=execute", workflow)
        self.assertIn("payload_bytes=4000", workflow)
        self.assertNotIn("payload_bytes=10900", workflow)
        self.assertIn('--dry-run --plan-mode "$plan_mode"', workflow)
        self.assertLess(workflow.index("Clean up exact run-owned resources"), workflow.index("Upload redacted evidence"))
        self.assertIn("--cleanup-only", workflow)
        self.assertIn("cleanup.json.sha256", workflow)
        self.assertIn("cleanup-exit-code", workflow)

if __name__ == "__main__": unittest.main()
