#!/usr/bin/env python3
"""Contract tests for the Koala Stage A synthetic rehearsal harness."""
from __future__ import annotations
import importlib.util
import inspect
import json
import os
import shlex
import shutil
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

    def test_direct_store_growth_requires_positive_bounded_same_volume_growth(self):
        empty = stage.DiskSample("empty", 100, 900, 1000)
        self.assertEqual(
            stage.direct_store_growth_gate(
                empty,
                stage.DiskSample("settled", 200, 800, 1000),
            ).status,
            "PASSED",
        )
        for settled_used in (100, 99, 100 + stage.MAX_STORE_BYTES + 1):
            self.assertEqual(
                stage.direct_store_growth_gate(
                    empty,
                    stage.DiskSample("settled", settled_used, 800, 1000),
                ).status,
                "FAILED",
            )

    def test_count_contract_separates_logical_candidate_from_exact_legacy_baseline(self):
        spec = stage.CorpusSpec(payload_shape="lexical")
        logical = stage.logical_vault_counts(spec)
        legacy = stage.legacy_baseline_counts(spec)
        self.assertEqual(logical, {"stage-a-primary": 502_375, "stage-a-isolation": 10})
        self.assertEqual(legacy, {"stage-a-primary": 502_425, "stage-a-isolation": 11})
        stage.require_legacy_baseline_counts(legacy, spec)
        for wrong in (
            logical,
            {"stage-a-primary": 502_424, "stage-a-isolation": 11},
            {"stage-a-primary": 502_425, "stage-a-isolation": 12},
        ):
            with self.assertRaises(stage.RehearsalFailed):
                stage.require_legacy_baseline_counts(wrong, spec)

    def test_execute_receipt_discloses_async_queue_observability_limit(self):
        document = stage.receipt_document(
            stage.build_identity("execute-limit"),
            stage.CorpusSpec(payload_shape="lexical"),
            status="UNKNOWN",
            exit_code=2,
            detail="test",
            ledger=stage.ResourceLedger(),
            measurements={},
            gates={},
            cleanup_result={},
            orphans=[],
            corpus=None,
            mode="execute",
        )
        self.assertEqual(document["limitations"], [
            "Synthetic rehearsal is not production deployment authorization.",
            "Production data, backups, volumes, machines, app, and credentials are prohibited.",
            "The bounded df quiet-window witnesses disk settlement; it does not prove asynchronous FTS or provenance queues are empty.",
            "The candidate mirror is written to the run-owned Fly app repository; registry-repository retention is not covered by the machine and volume orphan scan.",
            "Fly machine-create rejects a digest-pinned config.image, so the candidate launches from the run-owned mirror tag; identity rests on the digest assertion taken before launch, not on the launch reference itself.",
            "The pre-ingestion provisioning probe is mountless, so it proves candidate image and guest provisioning and the machine exec shell transport only; volume attachment, readiness, the resource measurement itself, and every measured gate remain first exercised by the real machines.",
            "query_latency is judged net of a transport baseline because every query crosses a WireGuard tunnel to the guest; the 150ms net limit is bounded above four observed readings (117.5/82.5/77.8/90.1), which is a thin basis, and the baseline is inferred from the cheapest query classes rather than measured server-side.",
            "restore_cold_query_s and rollback_cold_query_s are now measured, and they REFUTE the premise the cold-query budget was built on: run 30283211992 returned 0.0398s and 0.0387s for a concept lookup against a freshly forked store. A cold fork is not slow on its metadata call (0.077s/0.159s on run 30270851093) or on its data call. COLD_QUERY_LIMIT_S therefore stands at roughly 23,000 times the only observed cost of the thing it bounds. It is retained as a bound below the phase gate it feeds, not as a calibrated figure, and nothing here explains why a 60-second socket budget expired three times on calls now measured in tens of milliseconds.",
            "WITHDRAWN, and the withdrawal is the finding. The previous text here attributed muninn_read(stage-a-primary): MCP JSON-RPC error code=-32000 message=tool error: engram not found to the rollback fork failing to read its own snapshot. That was wrong. Runs 30290534176 and 30302595011 both carried that detail from the HARD-DELETE CHECK, where a failed read is the PASS condition, and neither run ever reached the rollback phase: hard_delete_cleanup, backup_restore and pre_migration_rollback are all ABSENT from both receipts, and cleanup records backup_volume_id, restore_volume_id and rollback_volume_id as not_created. The cause was this harness, not MuninnDB. #74 raised RehearsalProtocolFailed for every JSON-RPC error object regardless of code, and the hard-delete check re-raises protocol errors rather than counting them as proof of deletion, so the server correctly reporting a purged record became fatal. Fixed by classifying -32000..-32099 as RehearsalToolFailed in _post. The analytical error is worth recording separately: the receipts were read for the gates PRESENT and not for the gates MISSING, and the missing three named the phase. What the rollback failure IS remains open. Run 30283211992 failed pre_migration_rollback at 502385 records with the opaque pre-#74 detail MCP JSON-RPC error, while run 30225846042, a tail probe at 2000 records on the same image acef6be, PASSED pre_migration_rollback in 30.07s against an 1800s limit with rollback_counts matching the exact known legacy fingerprint. So the rollback failure does not reproduce at probe scale and no tail probe can settle it; only a full execute run can. baseline_read_witness PASSED at ok=2/2 on the live baseline machine, which establishes only that the legacy image point-reads its own retained ordering ids, and cannot discriminate whether a fork inherits or introduces an inconsistency, because these runs never build a fork. Not established either: which call exhausted the 60-second socket budget in runs 30228878183, 30235793478 and 30270851093, nor why it ever expired on calls now measured in tens of milliseconds.",
        ])

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

    def test_resource_sample_reads_procfs_and_never_shells_out_to_ps(self):
        """/proc is present on any Linux image, so it needs no procps binary and no
        assumption about which ps variant the candidate ships. The original ps form was
        also unrunnable for a second and more basic reason (see the word-split test
        below): its pipe was consumed as a literal argv word. Reverting to a piped ps
        reintroduces both faults at once."""
        identity = stage.build_identity("procfs-test")
        captured = []
        def runner(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "37.500 2048\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        runtime.resource_sample(identity, "machine", "migration")
        command = captured[-1][-1]
        self.assertIn("/proc/[0-9]*/stat", command)
        self.assertIn("/proc/uptime", command)
        self.assertNotIn("ps -eo", command)
        self.assertNotRegex(command, r"(?<![a-z])ps\s")

    def test_resource_sample_failure_quotes_the_output_it_actually_saw(self):
        """Run 30173477457 cost a full ~1.5 hour cycle and then a second one because the
        error named no command and quoted no output, so the cause could not be read off
        the receipt. A failure must diagnose itself."""
        identity = stage.build_identity("procfs-diagnostic")
        runtime = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "ps: unrecognized option\n", ""))
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            runtime.resource_sample(identity, "machine", "migration")
        self.assertIn("ps: unrecognized option", str(caught.exception))

    def test_migration_retries_while_muninndb_is_still_starting(self):
        """Fly reports "started" when the VM boots, not when MuninnDB is serving, so the
        first poll routinely finds no MuninnDB process. Run 30183128792 failed on exactly
        that: a successful exec returning a real reading of zero. That is a retry
        condition until the deadline, never a measurement."""
        identity = stage.build_identity("migration-race")
        readings = ["0.000 0\n", "0.000 0\n", "37.500 2048\n"]
        def runner(cmd, **kwargs):
            if "machines" in cmd and "list" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "m1", "state": "started"}]), "")
            if "exec" in cmd and "df -Pk /data" in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, "F 1K a a a M\n/d 100 40 60 40% /data\n", "")
            return subprocess.CompletedProcess(cmd, 0, readings.pop(0) if readings else "37.500 2048\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "sleep"):
            _, disks, resources = runtime.migration_samples(identity, "m1", 600.0, interval_s=0.0)
        self.assertEqual(len(resources), 1)
        self.assertEqual(len(disks), len(resources))
        self.assertEqual(resources[0].rss_bytes, 2048 * 1024)

    def test_migration_still_fails_when_muninndb_never_appears(self):
        """Tolerating the startup race must not become tolerating an absent process: an
        unmeasurable candidate still ends the run UNKNOWN rather than recording a zero."""
        identity = stage.build_identity("migration-never")
        def runner(cmd, **kwargs):
            if "machines" in cmd and "list" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "m1", "state": "started"}]), "")
            if "exec" in cmd and "df -Pk /data" in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, "F 1K a a a M\n/d 100 40 60 40% /data\n", "")
            return subprocess.CompletedProcess(cmd, 0, "0.000 0\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "sleep"):
            with self.assertRaisesRegex(stage.RehearsalUnknown, "deadline expired"):
                runtime.migration_samples(identity, "m1", 0.5, interval_s=0.0)

    def test_migration_fails_fast_when_the_candidate_dies(self):
        """The retry loop must not paper over a crashed candidate for the full window."""
        identity = stage.build_identity("migration-dead")
        runner = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "m1", "state": "failed"}]), "")
        with self.assertRaises(stage.RehearsalFailed):
            stage.FlyRuntime(runner=runner).migration_samples(identity, "m1", 600.0, interval_s=0.0)

    def test_missing_process_measurement_names_the_processes_it_did_see(self):
        """A reading of zero is either "not started yet" or "wrong name". The receipt must
        distinguish them, because guessing wrong costs a full ~1.5 hour cycle."""
        identity = stage.build_identity("process-inventory")
        def runner(cmd, **kwargs):
            if "exec" in cmd and "RSTART+1" in cmd[-1] and "cpu" not in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, "init\nsh\nsome-other-daemon\n", "")
            return subprocess.CompletedProcess(cmd, 0, "0.000 0\n", "")
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            stage.FlyRuntime(runner=runner).resource_sample(identity, "m1", "migration")
        self.assertIn("some-other-daemon", str(caught.exception))

    def test_shell_command_survives_the_word_split_that_machine_exec_performs(self):
        """`flyctl machine exec` accepts ONE command string (cobra.RangeArgs(1, 2), sent as
        fly.MachineExecRequest{Cmd: string}) and the API word-splits it and execs directly,
        with no shell. A wrapper must therefore survive that split as exactly /bin/sh, -c,
        and one intact script word. `df -Pk /data` always worked because it needs no shell;
        every measurement command returned empty stdout because it did."""
        script = "awk 'BEGIN{print 6*7}' /proc/uptime /proc/[0-9]*/stat"
        self.assertEqual(shlex.split(stage.shell_command(script)), ["/bin/sh", "-c", script])

    def test_shell_command_refuses_a_double_quote_rather_than_mangling_it(self):
        """A double quote would terminate the wrapper's own quoting and silently truncate
        the script mid-word, which is precisely the silent-mangling failure this wrapper
        exists to end. Refusing loudly is the only safe behaviour."""
        with self.assertRaises(stage.RehearsalUnknown):
            stage.shell_command('echo "hello"')

    def test_resource_sample_command_survives_the_word_split_intact(self):
        """The measurement is worthless if the transport mangles it, so assert the real
        command, not a stand-in: it must arrive as one shell invocation carrying the glob,
        the command substitutions and the awk program intact."""
        identity = stage.build_identity("wordsplit-test")
        captured = []
        def runner(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "37.500 2048\n", "")
        stage.FlyRuntime(runner=runner).resource_sample(identity, "machine", "migration")
        tokens = shlex.split(captured[-1][-1])
        self.assertEqual(tokens[:2], ["/bin/sh", "-c"])
        self.assertEqual(len(tokens), 3)
        self.assertIn("/proc/[0-9]*/stat", tokens[2])
        self.assertIn(stage.PROCFS_RESOURCE_AWK, tokens[2])

    def test_procfs_awk_program_carries_no_quote_of_either_kind(self):
        """Single quotes delimit the program for /bin/sh and double quotes would break the
        wrapper, so the program must avoid both. This is why it matches the comm field by
        regex and prints without a printf format string."""
        self.assertNotIn('"', stage.PROCFS_RESOURCE_AWK)
        self.assertNotIn("'", stage.PROCFS_RESOURCE_AWK)

    def test_shell_command_refuses_a_backslash_because_transport_drops_it(self):
        """Runs 30183128792 and 30185035316 both reported a missing process measurement
        while the shell canary passed. The canary carries no backslash and the measurement
        carried two, so the wrapper must refuse one rather than ship a program that arrives
        subtly different from the one that was written."""
        with self.assertRaises(stage.RehearsalUnknown):
            stage.shell_command("awk '/\\(/{print}'")

    def test_procfs_awk_program_carries_no_backslash(self):
        """The parenthesis literals are bracket expressions for this reason. An escape that
        does not survive transport turns the comm match into a whole-line match, which is
        the exact shape of both lost runs' receipts."""
        self.assertNotIn("\\", stage.PROCFS_RESOURCE_AWK)

    def procfs_fixture(self, root):
        """Write a /proc-shaped fixture: uptime, one MuninnDB process, one unrelated
        daemon, one kernel thread."""
        def stat(pid, comm, utime, stime, starttime, rss, ppid=1):
            fields = ["S", str(ppid)] + ["0"] * 9 + [str(utime), str(stime)] + ["0"] * 6 + [str(starttime), "0", str(rss)]
            return f"{pid} ({comm}) " + " ".join(fields) + "\n"
        (root / "uptime").write_text("1000.00 900.00\n")
        (root / "stat-muninndb").write_text(stat(42, "muninndb-server", 45000, 45000, 10000, 1000))
        (root / "stat-other").write_text(stat(43, "some-other-daemon", 99000, 99000, 10000, 5000))
        (root / "stat-kernel").write_text(stat(9, "cpuhp/0", 10, 10, 0, 0, ppid=2))
        return [str(root / "uptime"), str(root / "stat-muninndb"),
                str(root / "stat-other"), str(root / "stat-kernel")]

    def test_procfs_awk_program_measures_a_real_process_table(self):
        """The constant was only ever asserted as text. Runs 30183128792 and 30185035316
        each paid a full corpus ingest to discover it could not read a process, so it is
        executed here against a fixture with a known answer: 100% of one core and 4000 KiB
        for the MuninnDB process, with the unrelated daemon and the kernel thread ignored."""
        awk = shutil.which("mawk") or shutil.which("gawk") or shutil.which("awk")
        if not awk: self.skipTest("no awk available")
        with tempfile.TemporaryDirectory() as root:
            inputs = self.procfs_fixture(Path(root))
            proc = subprocess.run([awk, "-v", "hz=100", "-v", "pg=4096", stage.PROCFS_RESOURCE_AWK] + inputs,
                                  capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.split(), ["100", "4000"])

    def test_procfs_awk_program_reads_nothing_if_its_parenthesis_match_is_weakened(self):
        """The regression witness for both lost runs. Dropping the escape, which is what the
        transport did to the previous program, makes the comm match swallow the whole line
        and the field split behind it return nothing, so every process is skipped and the
        measurement reports zero rather than failing loudly."""
        awk = shutil.which("mawk") or shutil.which("gawk") or shutil.which("awk")
        if not awk: self.skipTest("no awk available")
        weakened = stage.PROCFS_RESOURCE_AWK.replace("/[(].*[)]/", "/(.*)/")
        self.assertNotEqual(weakened, stage.PROCFS_RESOURCE_AWK)
        with tempfile.TemporaryDirectory() as root:
            inputs = self.procfs_fixture(Path(root))
            proc = subprocess.run([awk, "-v", "hz=100", "-v", "pg=4096", weakened] + inputs,
                                  capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.split(), ["0", "0"])

    def test_process_inventory_excludes_kernel_threads_and_announces_truncation(self):
        """Run 30185035316's inventory sorted sixteen cpuhp threads ahead of everything and
        then cut the line mid-token at a silent 200 character cap, so the one name it
        existed to look for could not have appeared. Both faults are the point of this
        test: kernel threads are filtered at the source, and a cut says it is a cut."""
        identity = stage.build_identity("inventory-shape")
        names = "\n".join(f"daemon-with-a-long-name-{index:03d}" for index in range(60))
        def runner(cmd, **kwargs):
            if "exec" in cmd and "RSTART+1" in cmd[-1] and "cpu" not in cmd[-1]:
                return subprocess.CompletedProcess(cmd, 0, names + "\n", "")
            return subprocess.CompletedProcess(cmd, 0, "0.000 0\n", "")
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            stage.FlyRuntime(runner=runner).resource_sample(identity, "m1", "migration")
        detail = str(caught.exception)
        self.assertIn("60 names, truncated", detail)
        self.assertIn("daemon-with-a-long-name-000", detail)

    def test_resource_measurement_is_witnessed_on_the_serving_baseline_before_ingestion(self):
        """resource_sample was only ever called from migration_samples, so a broken
        measurement could not surface until a run had already spent a corpus ingest and a
        45 minute migration window reaching the candidate. Runs 30183128792 and 30185035316
        were spent that way. Taking one sample against the serving baseline, where a
        MuninnDB process is known to exist, fails a broken measurement before the ingest
        starts and separates it from a candidate that never starts."""
        identity = stage.build_identity("baseline-witness")
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.mirror_candidate.return_value = f"{stage.FLY_REGISTRY}/{identity.app_name}:{stage.CANDIDATE_MIRROR_TAG}"
        runtime.create_volume.return_value = "vol_owned"
        runtime.create_machine.return_value = "machine_owned"
        runtime.provisioning_probe.return_value = "machine_probe"
        runtime.proxy.return_value = mock.Mock(poll=mock.Mock(return_value=0))
        runtime.disk_sample.return_value = stage.DiskSample("empty", 100, 900, 1000)
        runtime.list_owned_resources.return_value = []
        runtime.resource_sample.side_effect = stage.RehearsalUnknown("missing MuninnDB process measurement; processes present: init,hallpass")
        client = mock.Mock()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "witness.json"
            self.assertEqual(stage.execute(identity, stage.CorpusSpec(payload_shape="lexical"), path,
                                           runtime=runtime, client_factory=lambda _url, _auth: client), 2)
            document = json.loads(path.read_text())
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertIn("missing MuninnDB process measurement", document["detail"])
        client.call.assert_not_called()
        runtime.migration_samples.assert_not_called()
        self.assertEqual(runtime.resource_sample.call_args.args[2], "baseline-serving")
        self.assertEqual(document["orphans"], [])

    def test_process_inventory_probe_filters_kernel_threads_by_parentage(self):
        """Filtering has to happen on the machine, not in the receipt string, or a busy
        kernel thread table crowds the answer out before it is ever transmitted."""
        awk = shutil.which("mawk") or shutil.which("gawk") or shutil.which("awk")
        if not awk: self.skipTest("no awk available")
        identity = stage.build_identity("inventory-filter")
        captured = []
        def runner(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "0.000 0\n", "")
        with self.assertRaises(stage.RehearsalUnknown):
            stage.FlyRuntime(runner=runner).resource_sample(identity, "m1", "migration")
        probe = [c for c in captured if "RSTART+1" in c[-1] and "cpu" not in c[-1]][-1][-1]
        self.assertNotIn("\\", probe)
        program = shlex.split(probe)[2].split("'")[1]
        with tempfile.TemporaryDirectory() as root:
            inputs = self.procfs_fixture(Path(root))[1:]
            proc = subprocess.run([awk, program] + inputs, capture_output=True, text=True, check=True)
        self.assertEqual(sorted(proc.stdout.split()), ["muninndb-server", "some-other-daemon"])

    def test_exec_canary_rejects_output_that_is_not_the_expected_token(self):
        """Empty stdout is the exact signature of the three lost runs, so the canary must
        treat anything other than the expected token as a failure rather than a pass."""
        identity = stage.build_identity("canary-test")
        for output in ("", "\n", "sh: awk: not found\n", "6*7\n"):
            runtime = stage.FlyRuntime(runner=lambda cmd, _o=output, **kw: subprocess.CompletedProcess(cmd, 0, _o, ""))
            with self.assertRaises(stage.RehearsalUnknown):
                runtime.exec_canary(identity, "machine")

    def test_exec_canary_exercises_the_same_wrapping_as_the_resource_sample(self):
        """The canary only forecloses a ~1.5 hour ingest if it fails whenever the real
        measurement would, so it must use the same wrapper and the same quoting shape."""
        identity = stage.build_identity("canary-shape")
        captured = []
        def runner(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, f"{stage.EXEC_CANARY_TOKEN}\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        self.assertEqual(runtime.exec_canary(identity, "machine"), stage.EXEC_CANARY_TOKEN)
        canary = shlex.split(captured[-1][-1])
        self.assertEqual(canary[:2], ["/bin/sh", "-c"])
        self.assertEqual(len(canary), 3)
        self.assertIn("awk '", canary[2])

    def test_resource_sample_treats_a_missing_muninndb_process_as_failure_not_zero(self):
        """An empty reading is an application error, never a valid zero measurement."""
        identity = stage.build_identity("procfs-zero")
        runtime = stage.FlyRuntime(runner=lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, "0.000 0\n", ""))
        with self.assertRaises(stage.RehearsalUnknown):
            runtime.resource_sample(identity, "machine", "migration")

    def test_json_retries_malformed_output_with_fresh_invocation(self):
        responses = [
            subprocess.CompletedProcess([], 0, "temporary warning\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"id": "vol_test"}]), ""),
        ]
        runtime = stage.FlyRuntime(runner=mock.Mock(side_effect=responses))
        with mock.patch.object(stage.time, "sleep") as sleep:
            result = runtime.json(["volumes", "list", "-a", "test-app"])
        self.assertEqual(result, [{"id": "vol_test"}])
        self.assertEqual(runtime.runner.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_json_fails_after_three_malformed_responses(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "not-json\n", ""))
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "sleep") as sleep:
            with self.assertRaisesRegex(stage.RehearsalUnknown, "returned invalid JSON"):
                runtime.json(["volumes", "list", "-a", "test-app"])
        self.assertEqual(runner.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_json_does_not_retry_command_failure(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "permission denied"))
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "sleep") as sleep:
            with self.assertRaisesRegex(stage.RehearsalUnknown, "flyctl volumes failed"):
                runtime.json(["volumes", "list", "-a", "test-app"])
        runner.assert_called_once()
        sleep.assert_not_called()

    def test_execute_plan_discloses_snapshot_convergence_contract(self):
        rendered = stage.plan(stage.build_identity("snapshot-plan"), stage.CorpusSpec(payload_shape="lexical"))
        self.assertEqual(rendered["snapshot_qualification"], {
            "method": "completed-id-set-difference",
            "success_status": "created",
            "timeout_s": stage.SNAPSHOT_LIMIT_S,
            "poll_interval_s": stage.SNAPSHOT_POLL_INTERVAL_S,
            "already_scheduled_policy": "adopt-exactly-one-observed-in-flight-snapshot",
        })

    def test_snapshot_creates_once_and_waits_for_observed_created_id(self):
        identity = stage.build_identity("snapshot-create")
        responses = [
            subprocess.CompletedProcess([], 0, "[]", ""),
            subprocess.CompletedProcess([], 0, "Scheduled\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"id": "", "status": "waiting", "created_at": "2026-07-25T01:00:00Z"}]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"id": "", "status": "running", "created_at": "2026-07-25T01:01:00Z"}]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"id": "vs_new", "status": "created", "created_at": "2026-07-25T01:02:00Z"}]), ""),
        ]
        runtime = stage.FlyRuntime(runner=mock.Mock(side_effect=responses))
        with mock.patch.object(stage.time, "sleep") as sleep:
            self.assertEqual(runtime.snapshot(identity, "vol_test"), "vs_new")
        commands = [call.args[0] for call in runtime.runner.call_args_list]
        self.assertEqual(sum("create" in command for command in commands), 1)
        self.assertEqual(sleep.call_count, 2)

    def test_snapshot_adopts_one_existing_pending_operation_without_create(self):
        identity = stage.build_identity("snapshot-pending")
        pending = {"id": "", "status": "running", "created_at": "2026-07-25T01:00:00Z"}
        created = {"id": "vs_pending", "status": "created", "created_at": pending["created_at"]}
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps([pending]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([created]), ""),
        ])
        runtime = stage.FlyRuntime(runner=runner)
        self.assertEqual(runtime.snapshot(identity, "vol_test"), "vs_pending")
        self.assertFalse(any("create" in call.args[0] for call in runner.call_args_list))

    def test_snapshot_adopts_pending_operation_after_create_collision(self):
        identity = stage.build_identity("snapshot-collision")
        pending = {"id": "", "status": "waiting", "created_at": "2026-07-25T01:00:00Z"}
        created = {"id": "vs_collision", "status": "created", "created_at": pending["created_at"]}
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, "[]", ""),
            subprocess.CompletedProcess([], 1, "", "failed_precondition: snapshot is already scheduled"),
            subprocess.CompletedProcess([], 0, json.dumps([pending]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([created]), ""),
        ])
        runtime = stage.FlyRuntime(runner=runner)
        self.assertEqual(runtime.snapshot(identity, "vol_test"), "vs_collision")
        self.assertEqual(sum("create" in call.args[0] for call in runner.call_args_list), 1)

    def test_snapshot_accepts_completion_observed_after_create_collision(self):
        identity = stage.build_identity("snapshot-collision-completed")
        created = {"id": "vs_collision", "status": "created", "created_at": "2026-07-25T01:01:00Z"}
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, "[]", ""),
            subprocess.CompletedProcess([], 1, "", "failed_precondition: snapshot is already scheduled"),
            subprocess.CompletedProcess([], 0, json.dumps([created]), ""),
        ])
        self.assertEqual(stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test"), "vs_collision")
        self.assertEqual(runner.call_count, 3)

    def test_snapshot_does_not_retry_unrelated_create_failure(self):
        identity = stage.build_identity("snapshot-failure")
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, "[]", ""),
            subprocess.CompletedProcess([], 1, "", "permission denied"),
        ])
        with self.assertRaisesRegex(stage.RehearsalUnknown, "permission denied"):
            stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test")
        self.assertEqual(runner.call_count, 2)

    def test_snapshot_rejects_multiple_pending_operations(self):
        identity = stage.build_identity("snapshot-ambiguous")
        pending = [
            {"id": "", "status": "waiting", "created_at": "2026-07-25T01:00:00Z"},
            {"id": "", "status": "running", "created_at": "2026-07-25T01:01:00Z"},
        ]
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(pending), ""))
        with self.assertRaisesRegex(stage.RehearsalUnknown, "multiple snapshots"):
            stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test")
        runner.assert_called_once()

    def test_snapshot_does_not_reuse_preexisting_completed_snapshot(self):
        identity = stage.build_identity("snapshot-fresh")
        old = {"id": "vs_old", "status": "created", "created_at": "2026-07-24T01:00:00Z"}
        new = {"id": "vs_new", "status": "created", "created_at": "2026-07-25T01:00:00Z"}
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps([old]), ""),
            subprocess.CompletedProcess([], 0, "Scheduled\n", ""),
            subprocess.CompletedProcess([], 0, json.dumps([old, new]), ""),
        ])
        self.assertEqual(stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test"), "vs_new")

    def test_snapshot_tolerates_pending_disappearance_before_completion(self):
        identity = stage.build_identity("snapshot-disappeared")
        pending = {"id": "", "status": "waiting", "created_at": "2026-07-25T01:00:00Z"}
        created = {"id": "vs_completed", "status": "created", "created_at": "2026-07-25T01:02:00Z"}
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps([pending]), ""),
            subprocess.CompletedProcess([], 0, "[]", ""),
            subprocess.CompletedProcess([], 0, json.dumps([created]), ""),
        ])
        with mock.patch.object(stage.time, "sleep") as sleep:
            self.assertEqual(stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test"), "vs_completed")
        sleep.assert_called_once_with(stage.SNAPSHOT_POLL_INTERVAL_S)

    def test_snapshot_rejects_multiple_new_completed_ids(self):
        identity = stage.build_identity("snapshot-two-completed")
        pending = {"id": "", "status": "waiting", "created_at": "2026-07-25T01:00:00Z"}
        completed = [
            {"id": "vs_one", "status": "created", "created_at": "2026-07-25T01:01:00Z"},
            {"id": "vs_two", "status": "created", "created_at": "2026-07-25T01:01:01Z"},
        ]
        runner = mock.Mock(side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps([pending]), ""),
            subprocess.CompletedProcess([], 0, json.dumps(completed), ""),
        ])
        with self.assertRaisesRegex(stage.RehearsalUnknown, "identity is ambiguous"):
            stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test")

    def test_snapshot_rejects_malformed_or_terminal_list_entries(self):
        identity = stage.build_identity("snapshot-invalid")
        cases = (
            ({}, "invalid shape"),
            (["bad"], "entry invalid"),
            ([{"id": "vs_bad", "status": "created"}], "missing identity"),
            ([{"id": "", "status": "created", "created_at": "now"}], "ID missing"),
            ([{"id": "vs_bad", "status": "failed", "created_at": "now"}], "non-success status"),
        )
        for payload, message in cases:
            with self.subTest(payload=payload):
                runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ""))
                with self.assertRaisesRegex(stage.RehearsalUnknown, message):
                    stage.FlyRuntime(runner=runner).snapshot(identity, "vol_test")

    def test_snapshot_wait_is_bounded(self):
        identity = stage.build_identity("snapshot-timeout")
        pending = {"id": "", "status": "running", "created_at": "2026-07-25T01:00:00Z"}
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps([pending]), ""))
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "monotonic", side_effect=[0.0, 0.0, 2.0]), mock.patch.object(stage.time, "sleep") as sleep:
            with self.assertRaisesRegex(stage.RehearsalUnknown, "deadline expired"):
                runtime.snapshot(identity, "vol_test", timeout_s=1.0, interval_s=0.25)
        sleep.assert_called_once_with(0.25)
        self.assertEqual(runner.call_count, 2)

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

    def mirror_runner(self, reported_digest, *, copy_code=0):
        calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["crane", "copy"]: return subprocess.CompletedProcess(cmd, copy_code, "", "copy diagnostic")
            if cmd[:2] == ["crane", "digest"]: return subprocess.CompletedProcess(cmd, 0, f"{reported_digest}\n", "")
            return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        return runner, calls

    def test_candidate_mirror_preserves_qualified_digest_and_binds_run_owned_repository(self):
        identity = stage.build_identity("mirror-test")
        runner, calls = self.mirror_runner(stage.CANDIDATE_DIGEST)
        runtime = stage.FlyRuntime(runner=runner)
        self.assertEqual(stage.CANDIDATE_DIGEST, stage.CANDIDATE_IMAGE.split("@", 1)[1])
        mirrored = runtime.mirror_candidate(identity)
        self.assertEqual(mirrored, f"{stage.FLY_REGISTRY}/{identity.app_name}:{stage.CANDIDATE_MIRROR_TAG}")
        self.assertEqual(runtime.candidate_ref, mirrored)
        self.assertEqual(calls[0], ["crane", "copy", stage.CANDIDATE_IMAGE, mirrored])
        self.assertEqual(calls[1], ["crane", "digest", mirrored])
        runtime.create_machine(identity, "vol_test", mirrored, "candidate")
        substitutions = (
            stage.CANDIDATE_IMAGE,
            f"{stage.FLY_REGISTRY}/{identity.app_name}@{stage.CANDIDATE_DIGEST}",
            f"{stage.FLY_REGISTRY}/{stage.PRODUCTION_APP}@{stage.CANDIDATE_DIGEST}",
            f"{stage.FLY_REGISTRY}/{stage.PRODUCTION_APP}:{stage.CANDIDATE_MIRROR_TAG}",
            f"{stage.FLY_REGISTRY}/koala-stage-a-other-run:{stage.CANDIDATE_MIRROR_TAG}",
        )
        for substituted in substitutions:
            with self.assertRaises(stage.RehearsalUnknown): runtime.create_machine(identity, "vol_test", substituted, "candidate")

    def test_launch_reference_is_a_tag_because_fly_rejects_digest_pinned_config_image(self):
        """Run 30165273639 observed: Fly resolves a digest-pinned config.image, then refuses
        to boot it with "invalid image identifier". The launch reference must therefore be a
        tag, and the qualified digest must not be accepted as a launch reference."""
        identity = stage.build_identity("tag-launch")
        runner, _ = self.mirror_runner(stage.CANDIDATE_DIGEST)
        runtime = stage.FlyRuntime(runner=runner)
        mirrored = runtime.mirror_candidate(identity)
        self.assertTrue(stage.MIRROR_REF.fullmatch(mirrored))
        self.assertIsNone(stage.DIGEST_REF.fullmatch(mirrored))
        self.assertTrue(stage.MIRROR_REF.fullmatch(runtime.candidate_ref))

    def test_provisioning_probe_launches_candidate_mountless_with_the_real_guest_spec(self):
        """The probe only forecloses a ~1.5 hour ingest if it provisions what the real
        machines provision, so guest-spec parity is the property that makes it
        representative. Mountlessness is what stops it initialising a store on the
        measured volume before that volume's empty disk sample is taken."""
        identity = stage.build_identity("probe-test")
        runner, calls = self.mirror_runner(stage.CANDIDATE_DIGEST)
        runtime = stage.FlyRuntime(runner=runner)
        mirrored = runtime.mirror_candidate(identity)
        self.assertEqual(runtime.provisioning_probe(identity, mirrored), "abcdef12345678")
        probe_cmd = calls[-1]
        self.assertEqual(probe_cmd[:4], ["flyctl", "machine", "run", mirrored])
        probe_config = json.loads(probe_cmd[probe_cmd.index("--machine-config") + 1])
        self.assertEqual(probe_config["mounts"], [])
        runtime.create_machine(identity, "vol_test", mirrored, "candidate")
        real_config = json.loads(calls[-1][calls[-1].index("--machine-config") + 1])
        self.assertEqual(probe_config["guest"], real_config["guest"])
        self.assertEqual(probe_config["image"], real_config["image"])
        self.assertNotEqual(real_config["mounts"], [])

    def test_provisioning_probe_refuses_a_substituted_image(self):
        identity = stage.build_identity("probe-substitute")
        runner, _ = self.mirror_runner(stage.CANDIDATE_DIGEST)
        runtime = stage.FlyRuntime(runner=runner)
        runtime.mirror_candidate(identity)
        for substituted in (stage.CANDIDATE_IMAGE, stage.BASELINE_IMAGE,
                            f"{stage.FLY_REGISTRY}/{stage.PRODUCTION_APP}:{stage.CANDIDATE_MIRROR_TAG}"):
            with self.assertRaises(stage.RehearsalUnknown): runtime.provisioning_probe(identity, substituted)

    def test_candidate_mirror_refuses_digest_drift(self):
        identity = stage.build_identity("drift-test")
        runner, _ = self.mirror_runner("sha256:" + "0" * 64)
        runtime = stage.FlyRuntime(runner=runner)
        with self.assertRaises(stage.RehearsalUnknown): runtime.mirror_candidate(identity)
        self.assertEqual(runtime.candidate_ref, stage.CANDIDATE_IMAGE)

    def test_candidate_mirror_refuses_copy_failure_without_reading_digest(self):
        identity = stage.build_identity("copy-fail-test")
        runner, calls = self.mirror_runner(stage.CANDIDATE_DIGEST, copy_code=1)
        runtime = stage.FlyRuntime(runner=runner)
        with self.assertRaises(stage.RehearsalUnknown): runtime.mirror_candidate(identity)
        self.assertEqual([cmd[:2] for cmd in calls], [["crane", "copy"]])
        self.assertEqual(runtime.candidate_ref, stage.CANDIDATE_IMAGE)

    def test_candidate_mirror_refuses_production_repository(self):
        production = stage.RunIdentity("x", stage.PRODUCTION_APP, "ksa_1234567890_src", "ksa_1234567890_bak",
                                       "ksa_1234567890_rst", "ksa_1234567890_rbk", "x")
        runner, calls = self.mirror_runner(stage.CANDIDATE_DIGEST)
        with self.assertRaises(stage.RehearsalUnknown): stage.FlyRuntime(runner=runner).mirror_candidate(production)
        self.assertEqual(calls, [])

    def test_execute_mirrors_candidate_before_provisioning_or_ingestion(self):
        identity = stage.build_identity("mirror-order")
        runtime = mock.Mock()
        runtime.list_owned_resources.return_value = []
        runtime.owned_machine_ids.return_value = []
        runtime.create_app.return_value = identity.app_name
        runtime.mirror_candidate.side_effect = stage.RehearsalUnknown("candidate mirror unavailable")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "mirror-order.json"
            self.assertEqual(stage.execute(identity, stage.CorpusSpec(payload_shape="lexical"), path, runtime=runtime), 2)
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertEqual(receipt["images"]["candidate_ref_executed"], stage.CANDIDATE_IMAGE)
        self.assertTrue(any("registry-repository retention" in item for item in receipt["limitations"]))
        runtime.create_volume.assert_not_called()
        runtime.create_machine.assert_not_called()
        runtime.proxy.assert_not_called()

    def test_plan_discloses_candidate_mirror_only_for_execute(self):
        identity = stage.build_identity("mirror-plan")
        rendered = stage.plan(identity, stage.CorpusSpec(payload_shape="lexical"))
        access = rendered["candidate_image_access"]
        self.assertEqual(access["source"], stage.CANDIDATE_IMAGE)
        self.assertEqual(access["required_digest"], stage.CANDIDATE_DIGEST)
        self.assertEqual(access["target"], f"{stage.FLY_REGISTRY}/{identity.app_name}:{stage.CANDIDATE_MIRROR_TAG}")
        self.assertEqual(access["executed_reference"], f"{stage.FLY_REGISTRY}/{identity.app_name}:{stage.CANDIDATE_MIRROR_TAG}")
        self.assertEqual(access["digest_mismatch_policy"], "UNKNOWN")
        self.assertEqual(access["launch_reference_form"], "tag")
        self.assertIn("invalid image identifier", access["launch_reference_reason"])
        self.assertIn("must equal the qualified digest", access["identity_binding"])
        calibration = stage.CorpusSpec(stage.CALIBRATION_SAMPLE_COUNT, 50, stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed")
        self.assertNotIn("candidate_image_access", stage.plan(identity, calibration, mode="calibrate"))

    def test_offline_helper_requires_stopped_zero_exit(self):
        identity = stage.build_identity("wait-test"); calls = []
        def runner_for(status_output, log=False):
            def runner(cmd, **kwargs):
                if log: calls.append(cmd)
                if "list" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "abc123", "state": "stopped"}]), "")
                return subprocess.CompletedProcess(cmd, 0, status_output if "status" in cmd else "", "")
            return runner
        stage.FlyRuntime(runner=runner_for("state = stopped\nexit_code = 0\n", log=True)).wait_stopped(identity, "abc123", 30)
        self.assertIn("list", calls[0]); self.assertIn("status", calls[1])
        with self.assertRaises(stage.RehearsalFailed):
            stage.FlyRuntime(runner=runner_for("exit_code = 7\n")).wait_stopped(identity, "abc123", 30)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.FlyRuntime(runner=runner_for("state = stopped\n")).wait_stopped(identity, "abc123", 30)

    def test_a_dropped_state_reading_no_longer_ends_the_rehearsal(self):
        """Run 30212272430 lost a 45 minute budget to one failed long-lived wait call while
        the helper was still working: the archive was growing and tar and gzip were both
        alive. State is read in short independent polls now, so one unreadable reading is
        absorbed and the helper still gets its deadline."""
        identity = stage.build_identity("wait-transient"); states = ["started", None, "started", "stopped"]
        def runner(cmd, **kwargs):
            if "list" in cmd:
                state = states.pop(0)
                if state is None: return subprocess.CompletedProcess(cmd, 1, "", "connection reset by peer")
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "abc123", "state": state}]), "")
            return subprocess.CompletedProcess(cmd, 0, "state = stopped\nexit_code = 0\n" if "status" in cmd else "", "")
        with mock.patch.object(stage, "HELPER_POLL_INTERVAL_S", 0):
            stage.FlyRuntime(runner=runner).wait_stopped(identity, "abc123", 45 * 60)
        self.assertEqual(states, [])   # it polled through the dropped reading rather than giving up

    def test_an_unreadable_helper_state_fails_instead_of_spinning_out_the_deadline(self):
        """Absorbing transient errors must not turn a persistent fault into a 45 minute
        silence, so the run of consecutive failures is bounded and only resets on a read."""
        identity = stage.build_identity("wait-blind"); attempts = []
        def runner(cmd, **kwargs):
            attempts.append(cmd); return subprocess.CompletedProcess(cmd, 1, "", "api unavailable")
        with mock.patch.object(stage, "HELPER_POLL_INTERVAL_S", 0):
            with self.assertRaises(stage.RehearsalUnknown) as caught:
                stage.FlyRuntime(runner=runner).wait_stopped(identity, "abc123", 45 * 60)
        self.assertIn("helper state unreadable", str(caught.exception))
        self.assertLessEqual(len(attempts), stage.HELPER_STATUS_RETRIES + 1)

    def test_restore_helper_rebuilds_from_the_archive_alone_on_one_volume(self):
        """The restore volume is a fork of the volume the archive sits on, so it arrives
        already holding a copy of the original store. If that copy survived, every query
        downstream would prove only that a Fly volume fork works. The wipe has to happen
        after the checksum is verified and before the extraction, and the archive itself
        may only be removed after the receipt recording its size and checksum is written."""
        identity = stage.build_identity("restore-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        runtime.create_restore(identity, "vol_restore", stage.CANDIDATE_IMAGE, "/data/stage-a-backup.tgz")
        command = calls[0]; config = json.loads(command[command.index("--machine-config") + 1])
        self.assertEqual(config["mounts"], [{"path": "/data", "volume": "vol_restore"}])
        restore_command = config["init"]["exec"][2]
        self.assertIn("/data/stage-a-backup.tgz", restore_command)
        self.assertEqual(config["services"], [])
        order = [restore_command.index(fragment) for fragment in
                 ("sha256sum", "-exec rm -rf {} +", "tar -xzf", ".stage-a-restore-receipt", "rm -f")]
        self.assertEqual(order, sorted(order),
                         "verify, wipe, extract, receipt, remove archive must stay in that order")
        self.assertIn("! -name 'stage-a-backup.tgz*'", restore_command)

    def test_restore_helper_hands_muninndb_a_data_directory_without_the_tarball(self):
        """The two mount version extracted into a pristine volume. The fork does not give
        that for free: without the final removal MuninnDB would be asked to open a store
        with a 1.8 GB tarball sitting in it. set -eu means the removal is reached only on
        success, so a failure still leaves the archive behind for diagnosis."""
        identity = stage.build_identity("restore-clean"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        stage.FlyRuntime(runner=runner).create_restore(identity, "vol_restore", stage.CANDIDATE_IMAGE, "/data/stage-a-backup.tgz")
        command = json.loads(calls[0][calls[0].index("--machine-config") + 1])["init"]["exec"][2]
        self.assertTrue(command.startswith("set -eu;"))
        self.assertIn("rm -f \"$A\" \"$A.sha256\" \"$A.bytes\"", command)
        self.assertLess(command.index(".stage-a-restore-receipt"), command.index("rm -f \"$A\""))
        self.assertTrue(command.rstrip().endswith("-print -quit)\""),
                        "the command must end by proving no archive remains")

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
        """One mount, so the archive is written beside the store rather than to a second
        volume. MuninnDB's own backup subcommand still runs against the live store and the
        size and checksum sidecars the restore side verifies are still produced."""
        identity = stage.build_identity("backup-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd); return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        _, path = stage.FlyRuntime(runner=runner).create_backup(identity, "vol_source", stage.CANDIDATE_IMAGE)
        config = json.loads(calls[0][calls[0].index("--machine-config") + 1]); command = config["init"]["exec"][2]
        self.assertEqual(path, "/data/stage-a-backup.tgz")
        self.assertEqual(config["mounts"], [{"path": "/data", "volume": "vol_source"}])
        self.assertIn("muninndb-server backup", command); self.assertIn("$A.sha256", command); self.assertIn("$A.bytes", command)

    def test_no_machine_config_may_request_a_second_volume(self):
        """Run 30202877942 passed every substantive gate, then died at the backup helper on
        Fly's "invalid config.mounts, only 1 volume supported". create_backup mounted the
        source and backup volumes together and create_restore mounted the backup and
        restore volumes together, so both had been unlaunchable since the day they were
        written; nothing before that run had ever reached them. The guard belongs at every
        config construction site so the next such mistake fails here instead of two hours
        into a rehearsal."""
        identity = stage.build_identity("mount-guard")
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        runtime = stage.FlyRuntime(runner=runner)
        two = [{"volume": "vol_a", "path": "/data"}, {"volume": "vol_b", "path": "/backup"}]
        with self.assertRaisesRegex(stage.RehearsalUnknown, "Fly machines take one"):
            runtime._offline_helper(identity, stage.CANDIDATE_IMAGE, "backup", two, "true")
        with self.assertRaisesRegex(stage.RehearsalUnknown, "requests 2 volumes"):
            stage.require_single_mount(two, "restore-copy")
        stage.require_single_mount(two[:1], "backup")
        stage.require_single_mount([], "preflight-probe")
        configs = []
        def recording(cmd, **kwargs):
            if "--machine-config" in cmd:
                configs.append(json.loads(cmd[cmd.index("--machine-config") + 1]))
            return subprocess.CompletedProcess(cmd, 0, "Machine ID: abcdef12345678\n", "")
        live = stage.FlyRuntime(runner=recording)
        live.create_backup(identity, "vol_source", stage.CANDIDATE_IMAGE)
        live.create_restore(identity, "vol_restore", stage.CANDIDATE_IMAGE, "/data/stage-a-backup.tgz")
        live.create_machine(identity, "vol_source", stage.BASELINE_IMAGE, "baseline")
        self.assertEqual(len(configs), 3)
        self.assertTrue(all(len(config["mounts"]) == 1 for config in configs),
                        f"every launched config must mount one volume: {[c['mounts'] for c in configs]}")

    def test_volume_fork_threads_a_snapshot_id_into_the_new_volume(self):
        """The archive reaches the restore volume by fork, not by a second mount, so the
        snapshot id has to survive into flyctl's argument list. The rollback path has always
        relied on this and it was never covered."""
        identity = stage.build_identity("fork-test"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            if "snapshots" in cmd and "list" in cmd:
                body = "[]" if len(calls) < 3 else json.dumps(
                    [{"id": "vs_new", "status": "created", "created_at": "2026-07-26T00:00:00Z"}])
                return subprocess.CompletedProcess(cmd, 0, body, "")
            if "volumes" in cmd and "create" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps({"id": "vol_forked"}), "")
            if "volumes" in cmd and "list" in cmd:
                # A fork is created hydrating and is only mountable once it reads `created`,
                # so create_volume now polls it and the fake has to answer that poll.
                state = "restoring" if volume_polls.append(1) or len(volume_polls) < 2 else "created"
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "vol_forked", "state": state}]), "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        volume_polls: list[int] = []
        runtime = stage.FlyRuntime(runner=runner)
        with mock.patch.object(stage.time, "sleep"):
            snapshot_id = runtime.snapshot(identity, "vol_source", timeout_s=30, interval_s=1)
            self.assertEqual(snapshot_id, "vs_new")
            self.assertEqual(runtime.create_volume(identity, identity.restore_volume_name, snapshot_id=snapshot_id), "vol_forked")
        self.assertGreaterEqual(len(volume_polls), 2, "a hydrating fork must be waited out, not mounted")
        created = [c for c in calls if "volumes" in c and "create" in c and "snapshots" not in c][0]
        self.assertEqual(created[created.index("--snapshot-id") + 1], "vs_new")
        self.assertIn("--scheduled-snapshots=false", created)

    def _stalling_runtime(self, log_text="starting backup\ncheckpoint written", artifacts="4096 /data/stage-a-backup"):
        """A runtime whose helper never stops, with every diagnostic probe answering."""
        def runner(cmd, **kwargs):
            joined = " ".join(cmd)
            if "list" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "7844153a692078", "state": "started"}]), "")
            if "logs" in cmd:
                return subprocess.CompletedProcess(cmd, 0, log_text, "")
            if "exec" in cmd and "du -sk" in joined:
                return subprocess.CompletedProcess(cmd, 0, artifacts, "")
            if "exec" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "muninndb-server tar", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return stage.FlyRuntime(runner=runner)

    def test_a_stalled_helper_is_described_before_it_is_destroyed(self):
        """Run 30206002340 waited 45 minutes for the backup helper, destroyed it during
        cleanup, and left the deadline message as the only evidence. The helper is still
        running when the deadline expires, so the reading has to happen there or not at
        all."""
        identity = stage.build_identity("stall-test")
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            self._stalling_runtime().wait_stopped(identity, "7844153a692078", 0)
        detail = str(caught.exception)
        self.assertIn("did not reach stopped", detail)          # the original failure survives
        self.assertIn("currently started", detail)              # with the state it was left in
        self.assertIn("checkpoint written", detail)             # what the command last said
        self.assertIn("/data/stage-a-backup", detail)           # how far the archive got
        self.assertIn("processes=muninndb-server,tar", detail)  # which step is still live

    def test_stall_diagnostics_redact_per_line_without_blanking_the_capture(self):
        """safe_detail blanks its whole input on one match, and a real capture reliably
        contains one: the store holds a file named auth_secret and server lines carry a URL.
        Whole-blob redaction would return [REDACTED] in exactly the case being explained, so
        the matching line must redact alone."""
        identity = stage.build_identity("stall-redact")
        runtime = self._stalling_runtime(log_text="opening store\nlistening on http://10.0.0.1:8080\ntar: write error")
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            runtime.wait_stopped(identity, "7844153a692078", 0)
        detail = str(caught.exception)
        self.assertNotIn("10.0.0.1", detail)          # the matching line never escapes
        self.assertIn("[REDACTED", detail)            # and announces that it was dropped
        self.assertIn("opening store", detail)        # its neighbours are still readable
        self.assertIn("tar: write error", detail)

    def test_stall_diagnostics_never_replace_the_failure_they_describe(self):
        """A probe that fails must not become the reported cause. Every one of them is dead
        here and the deadline is still what surfaces."""
        identity = stage.build_identity("stall-blind")
        def runner(cmd, **kwargs):
            if "list" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "7844153a692078", "state": "started"}]), "")
            raise subprocess.TimeoutExpired(cmd, 60)
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            stage.FlyRuntime(runner=runner).wait_stopped(identity, "7844153a692078", 0)
        detail = str(caught.exception)
        self.assertIn("did not reach stopped", detail)
        self.assertEqual(detail.count("<unavailable"), 3)

    def test_every_fuzzy_context_actually_matches_a_primary_vault_record(self):
        """A context matching nothing still returns a latency, and a fast one, so a stale
        name would quietly drag the tail down instead of failing. The set is pinned to what
        record_for actually emits rather than to a comment."""
        spec, live = stage.CorpusSpec(), set()
        for index in range(stage.MIN_RECORD_COUNT):
            if stage.probe_kind(index) is None: continue   # only probe records carry entities
            record = stage.record_for(spec, index)
            if record["vault"] != "stage-a-primary": continue
            for entity in record["memory"].get("entities", []): live.add(entity["name"])
        self.assertTrue(live, "corpus emitted no primary-vault entity names at all")
        for context in stage.FUZZY_CONTEXTS:
            for term in context:
                self.assertIn(term, live, f"fuzzy context {term!r} matches no primary-vault record")

    def test_fuzzy_latency_is_sampled_enough_times_to_be_a_percentile(self):
        """Two samples made the gate's p95 the slower of two readings. Run 30206002340
        failed at 263.191 and run 30202877942 passed at 214.356 on that same instrument;
        neither measured a distribution."""
        self.assertGreaterEqual(stage.FUZZY_PASSES * len(stage.FUZZY_CONTEXTS), 20)
        order = [c for _ in range(stage.FUZZY_PASSES) for c in stage.FUZZY_CONTEXTS]
        self.assertEqual(len(set(order)), len(stage.FUZZY_CONTEXTS))       # every context used
        self.assertTrue(all(a != b for a, b in zip(order, order[1:])),     # repeats interleaved,
                        "a context repeats back to back and would read warm")  # never consecutive
        self.assertEqual(stage.QUERY_P95_LIMIT_MS, 250.0)                  # threshold NOT relaxed

    def test_query_latency_is_judged_net_of_the_tunnel_rather_than_gross(self):
        """Run 30228878183 failed at a gross 257.278 while its own `exact` p50 - a 1-2
        record lookup - read 167.165. Every query crosses a flyctl WireGuard tunnel, so a
        gross reading is WAN round-trip plus server time. Across runs 13-16, on an identical
        corpus and identical guests, that floor swung 3.83x while fuzzy's marginal cost held
        within 1.35x, which is an additive per-request term rather than a slow guest. The
        gate grades the marginal cost now, and both terms stay in the receipt."""
        observed = {13: (126.536, 113.997, 231.493), 14: (62.133, 61.911, 144.410),
                    15: (43.581, 43.477, 121.256), 16: (167.165, 167.612, 257.278)}
        nets = {}
        for run, (exact, read, fuzzy) in observed.items():
            summaries = {"exact": {"count": 2, "p50_ms": exact}, "read": {"count": 10, "p50_ms": read},
                         "fuzzy": {"count": 24, "p50_ms": None, "p95_ms": fuzzy}}
            baseline = stage.transport_baseline_ms(summaries)
            self.assertEqual(baseline, min(exact, read))     # the min subtracts the least
            nets[run] = round(fuzzy - baseline, 3)
        gross = [reading[2] for reading in observed.values()]
        self.assertGreater(max(gross) / min(gross), 2.0)     # gross swings on the runner
        self.assertLess(max(nets.values()) / min(nets.values()), 1.6)   # net does not
        for run, net in nets.items():                        # incl. the one gross failed
            self.assertEqual(stage.threshold_gate("net", net, stage.QUERY_NET_P95_LIMIT_MS).status,
                             "PASSED", f"run {run} net {net} failed the net limit")
        self.assertGreater(stage.QUERY_NET_P95_LIMIT_MS, max(nets.values()))  # bound, not a fit
        slow = {"exact": {"count": 2, "p50_ms": 43.5}, "read": {"count": 10, "p50_ms": 43.5},
                "fuzzy": {"count": 24, "p95_ms": 323.5}}     # fast tunnel, 3x marginal cost
        self.assertEqual(stage.threshold_gate(
            "net", round(323.5 - stage.transport_baseline_ms(slow), 3),
            stage.QUERY_NET_P95_LIMIT_MS).status, "FAILED")
        self.assertIsNone(stage.transport_baseline_ms({"fuzzy": {"count": 24, "p95_ms": 999.0}}))
        self.assertEqual(stage.threshold_gate("net", None,   # no baseline is UNKNOWN,
                         stage.QUERY_NET_P95_LIMIT_MS).status, "UNKNOWN")   # never a pass
        self.assertEqual(stage.QUERY_P95_LIMIT_MS, 250.0)    # gross limit still recorded
        self.assertEqual(stage.QUERY_NET_P95_LIMIT_MS, 150.0)

    def test_a_read_survives_one_transport_hiccup_but_a_mutation_is_never_replayed(self):
        """Run 30228878183 lost its rollback verdict to a single TimeoutError about two
        hours in. `initialize` already retried to a deadline and every flyctl surface
        retries three times, but `call` had exactly one attempt, so one tunnel hiccup was
        fatal. Reads retry now. Mutations must not - a timed-out write may already have
        landed - and an application error must surface rather than be replayed away."""
        ok = {"result": {"content": [{"text": '{"ok": true}'}]}}
        def client_with(outcomes):
            client, seen = stage.MCPClient("http://127.0.0.1:8750/mcp", "token"), []
            def fake_post(payload, timeout_s=None):
                seen.append(payload["params"]["name"])
                outcome = outcomes.pop(0)
                if isinstance(outcome, Exception): raise outcome
                return outcome
            client._post = fake_post
            return client, seen
        with mock.patch.object(stage.time, "sleep"):
            client, seen = client_with([stage.RehearsalUnknown("MCP transport failed: TimeoutError"), ok])
            result, latency = client.call("muninn_read", {"vault": "v", "id": "x"})
            self.assertEqual(result, {"ok": True})
            self.assertEqual(len(seen), 2)                   # the read was retried
            self.assertEqual(client.transport_retries, 1)    # and the hiccup is recorded
            self.assertLess(latency, 60_000)                 # timed from the good attempt only

            client, seen = client_with([stage.RehearsalUnknown("MCP transport failed: TimeoutError"), ok])
            with self.assertRaises(stage.RehearsalUnknown):
                client.call("muninn_forget", {"vault": "v", "id": "x"})
            self.assertEqual(len(seen), 1, "a mutation was replayed and could double-apply")

            client, seen = client_with([stage.RehearsalFailed("muninn_read application error"), ok])
            with self.assertRaises(stage.RehearsalFailed):
                client.call("muninn_read", {"vault": "v", "id": "x"})
            self.assertEqual(len(seen), 1, "an application error was retried away")

            client, seen = client_with([stage.RehearsalUnknown("t")] * stage.MCP_CALL_ATTEMPTS)
            with self.assertRaises(stage.RehearsalUnknown):
                client.call("muninn_read", {"vault": "v", "id": "x"})
            self.assertEqual(len(seen), stage.MCP_CALL_ATTEMPTS)      # retries are bounded
        for mutation in ("muninn_remember_batch", "muninn_state", "muninn_restore", "muninn_forget"):
            self.assertNotIn(mutation, stage.IDEMPOTENT_METHODS)

    def _recording_client(self, outcomes):
        """An MCPClient whose transport is scripted, recording (method, vault, budget) per post."""
        client, calls = stage.MCPClient("http://127.0.0.1:8750/mcp", "token"), []
        def fake_post(payload, timeout_s=None):
            params = payload["params"]
            calls.append((params["name"], params["arguments"].get("vault"), timeout_s))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception): raise outcome
            return outcome
        client._post = fake_post
        return client, calls

    def test_a_cold_store_gets_the_whole_remaining_budget_for_its_first_data_query(self):
        """Runs 30228878183, 30235793478 and 30270851093 all lost the rollback verdict to an
        identical `MCP transport failed: TimeoutError`, on tunnels whose transport baselines
        differed 2x (167.165 vs 85.775 ms p50) - a duration problem, not a flaky one, because
        an incidental 60-second socket timeout stood in for ROLLBACK_LIMIT_S. Each attempt now
        gets the WHOLE remaining budget: slicing a slow store's work into fixed retries aborts
        and restarts the same work forever."""
        ok = {"result": {"content": [{"text": '{"total_memories": 7}'}]}}
        stalls = lambda n: [stage.RehearsalUnknown("MCP transport failed: TimeoutError")] * n + [ok]

        # Pre-fix behaviour: the bare call is exactly what runs 16-18 made, and on this same
        # store it still loses the run, on the default socket budget.
        client, calls = self._recording_client(stalls(stage.MCP_CALL_ATTEMPTS))
        with mock.patch.object(stage.time, "sleep"):
            with self.assertRaises(stage.RehearsalUnknown) as lost:
                client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "c"})
        self.assertIn("MCP transport failed", str(lost.exception))            # LOST THE RUN
        self.assertTrue(all(budget is None for _, _, budget in calls))        # on the 60s default

        # Post-fix: the same store answers, and no attempt was capped at that default.
        client, calls = self._recording_client(stalls(stage.MCP_CALL_ATTEMPTS))
        with mock.patch.object(stage.time, "sleep"):
            elapsed = stage.wait_cold_query(client, "stage-a-primary", timeout_s=600.0, interval_s=1.0)
        self.assertIsInstance(elapsed, float)
        budgets = [budget for _, _, budget in calls]
        self.assertEqual(len(budgets), stage.MCP_CALL_ATTEMPTS + 1)           # one post per try
        for budget in budgets:
            self.assertIsNotNone(budget, "an attempt fell back to the client's default socket budget")
            self.assertGreater(budget, 60.0, "an attempt was capped at the socket default it replaces")
            self.assertLessEqual(budget, 600.0, "an attempt outran the deadline")
        self.assertTrue(all(a >= b for a, b in zip(budgets, budgets[1:])), "the remaining budget did not shrink")

        # THE #72 DEFECT, encoded. #72 probed muninn_status and measured 0.077s and 0.159s on
        # run 30270851093 - because status reads metadata, and because it is the exact call
        # query_count issues. So the wait warmed the one call that was already fast. The probe
        # must be a DATA query, and must NOT be the metadata call query_count makes.
        client, calls = self._recording_client([ok])
        stage.wait_cold_query(client, "stage-a-primary", timeout_s=600.0, interval_s=1.0)
        probe_method, probe_vault, _ = calls[0]
        self.assertEqual(probe_method, "muninn_find_by_concept", "the wait probes a metadata call again")
        self.assertEqual(probe_vault, "stage-a-primary")
        counts_client, counts_calls = self._recording_client([ok, ok])
        stage.query_counts(counts_client)
        self.assertEqual(counts_calls[0][0], "muninn_status", "query_count stopped issuing muninn_status")
        self.assertNotEqual(probe_method, counts_calls[0][0],
                            "the wait probes the same call query_count issues, so it warms nothing new")

        self.assertEqual(stage.COLD_QUERY_LIMIT_S, 15 * 60)
        self.assertLess(stage.COLD_QUERY_LIMIT_S, stage.ROLLBACK_LIMIT_S,
                        "the wait outlives the gate it feeds, so it would decide the phase again")

    def test_a_store_that_never_answers_fails_naming_the_deadline(self):
        """The bare TimeoutError said nothing about how long the harness waited or for what,
        so two runs' receipts carried the same eight-word detail. A store that accepts the
        connection and never answers must fail with the deadline in the message. An
        application error must NOT be waited out: the store answered and said no, and that
        is a result, not a transport problem."""
        client, _ = self._recording_client([])
        client._post = lambda payload, timeout_s=None: (_ for _ in ()).throw(
            stage.RehearsalUnknown("MCP transport failed: TimeoutError"))
        with self.assertRaises(stage.RehearsalUnknown) as silent:
            stage.wait_cold_query(client, "stage-a-primary", timeout_s=0.2, interval_s=0.05)
        self.assertIn("cold data query did not answer within", str(silent.exception))

        client, calls = self._recording_client([stage.RehearsalFailed("store said no")])
        with self.assertRaises(stage.RehearsalFailed):
            stage.wait_cold_query(client, "stage-a-primary", timeout_s=600.0, interval_s=1.0)
        self.assertEqual(len(calls), 1, "an application error was waited out instead of surfacing")

        for bad_timeout, bad_interval in ((0.0, 5.0), (600.0, 0.0)):
            with self.assertRaises(stage.RehearsalUnknown):
                stage.wait_cold_query(client, "stage-a-primary", timeout_s=bad_timeout, interval_s=bad_interval)

    def test_the_attempts_override_can_only_lower_a_retry_count_never_raise_it(self):
        """wait_cold_query needs a single-attempt call, so `call` gained an attempts knob.
        A knob able to RAISE the count would hand a mutation the replay IDEMPOTENT_METHODS
        exists to deny it, so the override is clamped to the method's own default."""
        def failing_client():
            client, seen = stage.MCPClient("http://127.0.0.1:8750/mcp", "token"), []
            def fake_post(payload, timeout_s=None):
                seen.append(payload["params"]["name"]); raise stage.RehearsalUnknown("t")
            client._post = fake_post
            return client, seen
        with mock.patch.object(stage.time, "sleep"):
            for method, override, expected, complaint in (
                ("muninn_forget", 99, 1, "a mutation was granted a replay by the override"),
                ("muninn_read", 1, 1, "the override did not lower a read's retry count"),
                ("muninn_read", 99, stage.MCP_CALL_ATTEMPTS, "the override raised a read above its default"),
                ("muninn_read", None, stage.MCP_CALL_ATTEMPTS, "the default retry count regressed"),
            ):
                client, seen = failing_client()
                with self.assertRaises(stage.RehearsalUnknown):
                    client.call(method, {"vault": "v", "id": "x"}, attempts=override)
                self.assertEqual(len(seen), expected, complaint)

    def test_a_transport_failure_names_the_call_that_died(self):
        """Runs 30228878183, 30235793478 and 30270851093 each left the byte-identical detail
        `MCP transport failed: TimeoutError`, and not one of them said WHICH call died - so #71
        blamed a flaky tunnel and #72 blamed the first query, both wrongly. A failed run's
        receipt detail is the only forensic surface it leaves, so it must name the method."""
        with mock.patch.object(stage.time, "sleep"):
            client, _ = self._recording_client(
                [stage.RehearsalUnknown("MCP transport failed: TimeoutError")] * stage.MCP_CALL_ATTEMPTS)
            with self.assertRaises(stage.RehearsalUnknown) as died:
                client.call("muninn_recall", {"vault": "stage-a-primary", "context": ["c"]})
        detail = str(died.exception)
        self.assertIn("muninn_recall", detail, "the detail does not name the call that died")
        self.assertIn("MCP transport failed", detail, "the transport cause was dropped")
        self.assertLessEqual(len(stage.safe_detail(detail, stage.RECEIPT_DETAIL_CHARS)),
                             stage.RECEIPT_DETAIL_CHARS, "the named detail cannot reach the receipt")

    def _error_response_client(self, error):
        """A real-_post client whose HTTP layer returns one JSON-RPC error envelope."""
        client = stage.MCPClient("http://127.0.0.1:8750/mcp", "token")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": error}).encode()
        response = mock.MagicMock()
        response.read.return_value = body
        response.__enter__ = lambda self_: self_
        response.__exit__ = lambda *_: False
        opener = mock.MagicMock()
        opener.open.return_value = response
        return client, opener

    def test_a_json_rpc_error_carries_the_servers_own_code_message_and_data(self):
        """Run 30283211992 spent 66 minutes to produce the detail `MCP JSON-RPC error` and
        nothing else. The store had returned a JSON-RPC error object, so the server had already
        said exactly what was wrong, and the raise site discarded the whole object in favour of
        a constant. The server's own words are the cheapest diagnosis available."""
        error = {"code": -32602, "message": "unknown vault", "data": {"vault": "stage-a-isolation"}}
        client, opener = self._error_response_client(error)
        with mock.patch.object(stage.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(stage.RehearsalProtocolFailed) as died:
                client._post({"jsonrpc": "2.0", "method": "tools/call", "id": 1})
        detail = str(died.exception)
        self.assertIn("-32602", detail, "the server's error code was discarded")
        self.assertIn("unknown vault", detail, "the server's error message was discarded")
        self.assertIn("stage-a-isolation", detail, "the server's error data was discarded")

        # FAILED, not UNKNOWN: the server responded, and a response saying no is a result.
        self.assertEqual(died.exception.status, "FAILED")

        # Server-controlled and arbitrarily large, so every field is capped independently and
        # the composed detail still has to fit the receipt.
        client, opener = self._error_response_client(
            {"code": -1, "message": "m" * 5000, "data": "d" * 5000})
        with mock.patch.object(stage.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(stage.RehearsalProtocolFailed) as huge:
                client._post({"jsonrpc": "2.0", "method": "tools/call", "id": 1})
        self.assertNotIn("m" * (stage.JSON_RPC_DETAIL_CHARS + 1), str(huge.exception),
                         "an unbounded server message reached the detail")
        self.assertNotIn("d" * (stage.JSON_RPC_DETAIL_CHARS + 1), str(huge.exception),
                         "an unbounded server data blob reached the detail")
        self.assertLessEqual(len(stage.safe_detail(str(huge.exception), stage.RECEIPT_DETAIL_CHARS)),
                             stage.RECEIPT_DETAIL_CHARS)

        # A server that violates the JSON-RPC shape is itself the finding, so a non-dict error
        # is carried rather than dropped - and the helper must not raise inside the error path.
        self.assertIn("boom", stage.json_rpc_detail("boom"))
        self.assertIn("code=None", stage.json_rpc_detail("boom"))
        self.assertIn("data=", stage.json_rpc_detail({"code": 1, "data": object()}),
                      "an unserializable data payload was dropped instead of degrading to repr")

    def test_a_protocol_error_names_its_method_and_vault_and_is_never_retried(self):
        """_post raises at the JSON-RPC protocol layer, where the method is not in scope, which
        is why run 30283211992's detail named neither. query_counts walks stage-a-primary AND
        stage-a-isolation, so the method alone would still not say which store said no."""
        client, calls = self._recording_client(
            [stage.RehearsalProtocolFailed("MCP JSON-RPC error code=-32602 message=unknown vault")])
        with self.assertRaises(stage.RehearsalProtocolFailed) as died:
            client.call("muninn_status", {"vault": "stage-a-isolation"})
        detail = str(died.exception)
        self.assertIn("muninn_status", detail, "the detail does not name the call that failed")
        self.assertIn("stage-a-isolation", detail, "the detail does not name the vault that said no")
        self.assertIn("-32602", detail, "the server's own error was dropped by the re-raise")

        # muninn_status IS idempotent, so a retry WOULD have fired had this been caught by the
        # transport clause. An application error is a real answer and must never be replayed.
        self.assertIn("muninn_status", stage.IDEMPOTENT_METHODS)
        self.assertEqual(len(calls), 1, "an application error was retried")
        self.assertEqual(client.transport_retries, 0, "an application error counted as transport")

    def test_a_protocol_error_is_never_evidence_that_a_record_was_deleted(self):
        """The hard-delete check reads a purged record and treats the resulting RehearsalFailed
        as proof the record is gone - the one place in the harness where an error is deliberately
        evidence. A protocol error there means the question was never answered, so counting it
        as proof would pass the gate on a server fault."""
        self.assertTrue(issubclass(stage.RehearsalProtocolFailed, stage.RehearsalFailed),
                        "the hazard this ordering guards no longer exists")
        # Structural, because the swallow sits mid-phase in execute() behind a live Fly runtime.
        # assertTrue on a precomputed boolean rather than assertIn on the source: a failure here
        # must print a sentence, not 20KB of execute(), which is the readability this PR exists
        # to defend.
        source = inspect.getsource(stage.execute)
        narrowed, general = "except RehearsalProtocolFailed: raise", "except RehearsalFailed: pass"
        self.assertTrue(narrowed in source,
                        "the hard-delete swallow no longer re-raises protocol errors")
        self.assertTrue(general in source, "the hard-delete swallow itself is gone")
        self.assertTrue(source.index(narrowed) < source.index(general),
                        "the general clause precedes the protocol clause, so it swallows it")

    def test_a_purged_record_reads_as_gone_rather_than_as_a_protocol_fault(self):
        """The regression that killed runs 30290534176 and 30302595011, as a test.

        #74's tests witnessed the re-raise MECHANISM and never once exercised the hard-delete
        check's happy path against a realistic server error, so nothing failed until two live
        dispatches did. A purged record reads back `code=-32000 message=tool error: engram not
        found`, which IS that check's PASS condition; #74 raised RehearsalProtocolFailed for
        every error object, the narrowed clause re-raised the PASS condition, and both runs
        stopped three gates short of the rollback phase they were dispatched to measure.

        So this asserts the OUTCOME at the site, not the classifier in isolation. The clause
        order is mirrored from execute() and the mirror is pinned against the real source, so
        the test cannot quietly stop describing the site it claims to cover."""
        source = inspect.getsource(stage.execute)
        narrowed, general = "except RehearsalProtocolFailed: raise", "except RehearsalFailed: pass"
        self.assertTrue(source.index(narrowed) < source.index(general),
                        "the mirrored clause order below no longer matches execute()")

        def hard_delete_outcome(error):
            """execute()'s two clauses, applied to one server error object."""
            try: raise stage.json_rpc_failure(error)
            except stage.RehearsalProtocolFailed: return "re-raised"
            except stage.RehearsalFailed: return "counted as deleted"

        self.assertEqual(
            hard_delete_outcome({"code": -32000, "message": "tool error: engram not found"}),
            "counted as deleted",
            "the server reporting the record purged is fatal again, which is the #74 regression")

        # The reserved protocol codes still re-raise: the question was never answered, so
        # counting it as proof would pass hard_delete_cleanup on a server fault.
        for code in (-32700, -32600, -32601, -32602, -32603):
            self.assertEqual(hard_delete_outcome({"code": code, "message": "x"}), "re-raised",
                             f"protocol code {code} was counted as proof of deletion")

        # Unrecognised shapes re-raise too. The two mistakes are not symmetric: a false PASS is a
        # qualification defect, a false re-raise costs one dispatch.
        for unknown in ({"message": "no code at all"}, {"code": "-32000"}, {"code": -1}, "boom"):
            self.assertEqual(hard_delete_outcome(unknown), "re-raised",
                             f"an unrecognised error shape was counted as proof: {unknown!r}")

        # Band edges, since the band is the whole mechanism.
        for inside in (-32000, -32050, -32099):
            self.assertIsInstance(stage.json_rpc_failure({"code": inside}), stage.RehearsalToolFailed)
        for outside in (-31999, -32100):
            self.assertIsInstance(stage.json_rpc_failure({"code": outside}), stage.RehearsalProtocolFailed)

        # A tool error is an ordinary RehearsalFailed everywhere else: FAILED not UNKNOWN, and it
        # must still carry the server's own words or the next receipt is opaque again.
        tool = stage.json_rpc_failure({"code": -32000, "message": "tool error: engram not found"})
        self.assertEqual(tool.status, "FAILED")
        self.assertNotIsInstance(tool, stage.RehearsalProtocolFailed,
                                 "a tool error is a protocol error again, so the swallow re-raises it")
        self.assertIn("-32000", str(tool))
        self.assertIn("engram not found", str(tool))

        # And _post must actually USE the classifier. Everything above tests json_rpc_failure in
        # isolation, so without this the raise site could revert to #74's unconditional
        # RehearsalProtocolFailed and every assertion here would still pass - which is #74's own
        # failure repeated one level down: it proved the mechanism and never proved the wiring,
        # so two live dispatches were the first thing to fail.
        client, opener = self._error_response_client(
            {"code": -32000, "message": "tool error: engram not found"})
        with mock.patch.object(stage.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(stage.RehearsalToolFailed):
                client._post({"jsonrpc": "2.0", "method": "tools/call", "id": 1})

    def _read_client(self, denied=frozenset()):
        """A client whose muninn_read answers, or refuses with the server's own tool error."""
        class ReadClient:
            def __init__(self): self.reads = []
            def call(inner, method, arguments, **kwargs):
                inner.reads.append((method, arguments))
                if arguments["id"] in denied:
                    # RehearsalToolFailed, matching what _post now raises for a -32000: a fixture
                    # that raised the wrong class would stop mirroring production.
                    raise stage.RehearsalToolFailed(
                        f"{method}({arguments['vault']}): MCP JSON-RPC error code=-32000 "
                        "message=tool error: engram not found")
                return {"id": arguments["id"]}, 1.0
        return ReadClient()

    def test_the_baseline_witness_reads_the_same_records_run_query_probes_reads(self):
        """run_query_probes point-reads retained_ids["ordering"][:10] on the restore and rollback
        forks. A witness that asked about a DIFFERENT set, vault or method would not be comparable
        with it, and comparability is the only value this gate has.

        (The claim this test carried when written - that run 30290534176 failed on that same read
        against the rollback fork - was wrong. That run failed at the hard-delete check and never
        built a fork. The mirroring requirement below is unaffected.)"""
        receipt = stage.CorpusReceipt(retained_ids={"ordering": [f"ord-{i:02d}" for i in range(25)]})
        client = self._read_client()
        gate = stage.baseline_read_witness(client, receipt)
        self.assertEqual(gate.status, "PASSED")
        self.assertEqual([method for method, _ in client.reads], ["muninn_read"] * 10)
        self.assertEqual([args["id"] for _, args in client.reads],
                         [f"ord-{i:02d}" for i in range(10)],
                         "the witness reads a different id set than run_query_probes")
        self.assertTrue(all(args["vault"] == "stage-a-primary" for _, args in client.reads),
                        "the witness reads a different vault than the one that failed")
        self.assertEqual(stage.BASELINE_READ_WITNESS_IDS, 10,
                         "the witness slice no longer mirrors run_query_probes' [:10]")

    def test_a_denied_baseline_read_fails_the_gate_and_carries_the_servers_message(self):
        """A gate rather than a raise, so ONE run reports both the baseline and the fork; but a
        FAILED gate still fails the run via receipt_status, so it can never pass quietly. The
        count distinguishes a read path that resolves nothing from one absent record."""
        ordering = [f"ord-{i:02d}" for i in range(10)]
        receipt = stage.CorpusReceipt(retained_ids={"ordering": ordering})
        one = stage.baseline_read_witness(self._read_client(denied={"ord-03"}), receipt)
        self.assertEqual(one.status, "FAILED")
        self.assertIn("ok=9/10", one.detail)
        self.assertIn("engram not found", one.detail,
                      "the gate discards the server's own explanation")
        self.assertIn("-32000", one.detail)
        allden = stage.baseline_read_witness(self._read_client(denied=set(ordering)), receipt)
        self.assertEqual(allden.status, "FAILED")
        self.assertIn("ok=0/10", allden.detail)
        # A FAILED gate has to be load-bearing or the non-raising design hides the defect.
        # Asserted at probe scale too, since the probe is where this witness will first run.
        self.assertEqual(stage.combine_status({"w": allden}, []), "FAILED",
                         "a failed witness no longer fails the run, so it reports nothing")
        self.assertEqual(stage.combine_status({"w": allden}, [], probe=True), "FAILED",
                         "a failed witness is swallowed at probe scale")
        # An absent id set must not read as evidence: 0 == 0 would otherwise PASS.
        empty = stage.baseline_read_witness(self._read_client(), stage.CorpusReceipt(retained_ids={"ordering": []}))
        self.assertEqual(empty.status, "FAILED",
                         "a witness that could not run is being counted as a pass")

    def test_the_baseline_witness_runs_on_the_baseline_before_the_snapshot(self):
        """Placement IS the experiment. After the snapshot, or on the candidate, it answers a
        question nobody asked: whether the LEGACY image could ever point-read these ids is only
        observable on the live baseline machine, before its volume is forked."""
        source = inspect.getsource(stage.execute)
        witness, snapshot = 'gates["baseline_read_witness"]', "ledger.snapshot_id = runtime.snapshot("
        self.assertTrue(witness in source, "the baseline read witness is not wired into execute")
        self.assertTrue(snapshot in source, "the pre-migration snapshot moved; re-check placement")
        self.assertTrue(source.index(witness) < source.index(snapshot),
                        "the witness runs after the snapshot, so it no longer tests the baseline")

    def _probe_fixture(self):
        """A receipt plus exactly the scripted responses run_query_probes consumes, in order."""
        ordering = [f"ord-{index:02d}" for index in range(10)]
        collision = ["col-0", "col-1"]
        receipt = stage.CorpusReceipt(retained_ids={"ordering": ordering, "collision": collision})
        def engrams(ids):
            return {"result": {"content": [{"text": json.dumps({"engrams": [{"id": i} for i in ids]})}]}}
        responses = [engrams([collision[0]]), engrams([collision[1]]),          # exact concepts
                     engrams([]), engrams([]), engrams(list(reversed(ordering)))]   # entities
        responses += [engrams([]) for _ in ordering]                            # reads
        responses += [engrams([]) for _ in range(len(stage.FUZZY_CONTEXTS) * stage.FUZZY_PASSES)]
        responses += [engrams([]), engrams(["iso-0"])]                          # isolation pair
        return receipt, responses

    def test_only_the_cold_paths_raise_the_probe_socket_budget(self):
        """Three runs died INSIDE run_query_probes on the client's 60-second default, so the
        restore and rollback paths now pass COLD_QUERY_LIMIT_S per probe. Warming one concept
        lookup cannot warm the entity, read, or fuzzy paths, which is why the wait alone is not
        the fix. The GATED candidate path must keep the default: query_latency is judged from
        its samples, and this change is about when the harness gives up, never about what it
        measures or judges."""
        receipt, responses = self._probe_fixture()

        client, calls = self._recording_client(list(responses))
        stage.run_query_probes(client, receipt)
        self.assertTrue(calls, "run_query_probes issued no calls")
        self.assertTrue(all(budget is None for _, _, budget in calls),
                        "the gated candidate path stopped using the client's default socket budget")

        client, calls = self._recording_client(list(responses))
        stage.run_query_probes(client, receipt, timeout_s=stage.COLD_QUERY_LIMIT_S)
        for method, _, budget in calls:
            self.assertEqual(budget, stage.COLD_QUERY_LIMIT_S,
                             f"{method} kept the 60s default that lost three runs")
        self.assertGreater(len({method for method, _, _ in calls}), 1,
                           "the fixture exercised only one probe class")
        self.assertGreater(stage.COLD_QUERY_LIMIT_S, 60.0)
        self.assertLessEqual(stage.COLD_QUERY_LIMIT_S, stage.ROLLBACK_LIMIT_S,
                             "one probe may outlive the phase gate that is supposed to bound it")

    def test_safe_detail_keeps_both_ends_and_never_relaxes_the_predicate(self):
        """Run 30212272430's receipt described what the helper was doing without saying what
        had failed, because a tail-only budget dropped the head. Both ends survive now, and
        the budget stays a verbosity bound: a match in what is emitted still blanks it."""
        head, tail = "flyctl machine wait failed", "processes=gzip,tar"
        reading = f"{head} {'z' * 2000} {tail}"
        for limit in (stage.SAFE_DETAIL_CHARS, stage.RECEIPT_DETAIL_CHARS):
            excerpt = stage.safe_detail(reading, limit)
            self.assertIn(head, excerpt)                                  # what actually failed
            self.assertIn(tail, excerpt)                                  # and what it was doing
            self.assertIn(stage.TRUNCATION_MARKER.strip(), excerpt)       # the gap is declared
            self.assertLessEqual(len(excerpt), limit)                     # the budget still binds
            self.assertEqual(stage.safe_detail("z" * 300 + " bearer abc", limit),
                             "[REDACTED: sensitive diagnostic omitted]")
        self.assertEqual(stage.safe_detail("short reading"), "short reading")   # untruncated text is untouched

    def test_receipt_detail_keeps_the_whole_stall_reading_and_still_redacts(self):
        """A 400 character tail truncated the stalled-helper reading back to its last probe,
        discarding both the deadline message and the logs. The wider budget is verbosity
        only, so a secret inside it must still blank the field."""
        with tempfile.TemporaryDirectory() as root:
            base = {key: None for key in stage.RECEIPT_KEYS}
            path = Path(root) / "wide.json"
            detail = 'did not reach "stopped" ' + "logs=" + "x" * 900 + " processes=muninndb-server"
            stage.write_receipt(path, {**base, "schema_version": 1, "status": "UNKNOWN", "detail": detail, "orphans": []})
            written = json.loads(path.read_text())["detail"]
            self.assertIn('did not reach "stopped"', written)   # the head is no longer cut off
            self.assertIn("processes=muninndb-server", written)  # and the tail still survives
            self.assertLessEqual(len(written), stage.RECEIPT_DETAIL_CHARS)
            over = Path(root) / "over.json"
            composed = "flyctl machine wait failed: connection reset " + "x" * 4000 + " processes=gzip,tar"
            stage.write_receipt(over, {**base, "schema_version": 1, "status": "UNKNOWN", "detail": composed, "orphans": []})
            written_over = json.loads(over.read_text())["detail"]
            self.assertIn("flyctl machine wait failed", written_over)   # run 30212272430 lost exactly this
            self.assertIn("processes=gzip,tar", written_over)           # without losing the reading
            self.assertLessEqual(len(written_over), stage.RECEIPT_DETAIL_CHARS)
            leaky = Path(root) / "leaky.json"
            stage.write_receipt(leaky, {**base, "schema_version": 1, "status": "UNKNOWN", "orphans": [],
                                        "detail": "y" * 500 + " authorization=abc"})
            self.assertEqual(json.loads(leaky.read_text())["detail"], "[REDACTED: sensitive diagnostic omitted]")

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
        with mock.patch.object(stage, "DESTROY_RETRY_DELAY_S", 0):
            results, orphans = stage.cleanup(runtime, identity, stage.ResourceLedger(machine_id="owned-machine"))
        self.assertEqual(orphans, ["owned-machine"])
        self.assertEqual(runtime.destroy_machine.call_count, stage.DESTROY_ATTEMPTS)
        self.assertIn("fail", results["machine_id_error"])

    def test_a_transient_destroy_failure_is_retried_instead_of_leaking(self):
        identity = stage.build_identity("cleanup-retry"); runtime = mock.Mock()
        runtime.destroy_volume.side_effect = [RuntimeError("volume still attached"), None]
        runtime.list_owned_resources.return_value = []
        with mock.patch.object(stage, "DESTROY_RETRY_DELAY_S", 0):
            results, orphans = stage.cleanup(
                runtime, identity, stage.ResourceLedger(restore_volume_id="vol_restore"))
        self.assertEqual(orphans, [])
        self.assertEqual(results["restore_volume_id"], "destroyed")
        self.assertNotIn("restore_volume_id_error", results)
        self.assertEqual(runtime.destroy_volume.call_count, 2)

    def test_cleanup_destroys_a_machine_the_ledger_never_learned_of(self):
        identity = stage.build_identity("cleanup-recover"); runtime = mock.Mock()
        runtime.owned_machine_ids.return_value = ["6835102a46d3e8"]
        runtime.list_owned_resources.return_value = []
        results, orphans = stage.cleanup(
            runtime, identity,
            stage.ResourceLedger(app=identity.app_name, restore_volume_id="vol_restore"))
        self.assertEqual(orphans, [])
        self.assertEqual(results["machine_recovered"], "6835102a46d3e8")
        self.assertEqual(results["machine_id"], "destroyed")
        runtime.destroy_machine.assert_called_once_with(identity, "6835102a46d3e8")
        self.assertEqual(results["restore_volume_id"], "destroyed")

    def test_owned_machine_ids_reports_only_this_run_and_never_production(self):
        identity = stage.build_identity("owned-machines")
        production = next(iter(stage.PRODUCTION_MACHINE_IDS))
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, json.dumps([
                {"id": "mine", "config": {"metadata": {"koala_stage_a_run": identity.run_id}}},
                {"id": "theirs", "config": {"metadata": {"koala_stage_a_run": "other-run"}}},
                {"id": production, "config": {"metadata": {"koala_stage_a_run": identity.run_id}}},
                {"id": "nometa", "config": None},
            ]), "")
        self.assertEqual(stage.FlyRuntime(runner=runner).owned_machine_ids(identity), ["mine"])

    def test_a_helper_that_never_starts_reports_its_state_and_its_volume(self):
        identity = stage.build_identity("launch-fail")
        def runner(cmd, **kwargs):
            if cmd[1] == "machine" and cmd[2] == "run":
                return subprocess.CompletedProcess(cmd, 1, "", "failed to reach desired start state")
            if cmd[1] == "machines":
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{
                    "id": "6835102a46d3e8",
                    "name": f"koala-stage-a-{identity.run_id}-restore-copy",
                    "state": "created",
                    "events": [{"type": "exit", "status": "stopped",
                                "request": {"exit_event": {"exit_code": 1}}}],
                }]), "")
            if cmd[1] == "logs":
                return subprocess.CompletedProcess(cmd, 0, "extraction did not begin\n", "")
            if cmd[1] == "volumes":
                return subprocess.CompletedProcess(cmd, 0, json.dumps([
                    {"id": "vol_restore", "state": "pending"}]), "")
            raise AssertionError(cmd)
        with self.assertRaises(stage.RehearsalUnknown) as caught:
            stage.FlyRuntime(runner=runner)._offline_helper(
                identity, "img", "restore-copy",
                [{"volume": "vol_restore", "path": "/data"}], "true")
        detail = str(caught.exception)
        self.assertIn("machine=6835102a46d3e8 state=created", detail)
        self.assertIn("exit=1", detail)
        self.assertIn("volume=vol_restore state=pending", detail)

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
        self.assertEqual(rendered["storage_qualification"], {
            "method": "direct-same-volume-empty-to-settled-net-growth",
            "maximum_net_growth_bytes": stage.MAX_STORE_BYTES,
            "maximum_peak_bytes": stage.MAX_PEAK_BYTES,
            "minimum_free_percent": stage.MIN_FREE_PERCENT,
        })
        self.assertEqual(rendered["falsification_evidence"], {
            "run_id": "30108034677",
            "receipt_sha256": stage.FALSIFICATION_RECEIPT_SHA256,
            "finding": "fixed-record-count payload cohorts cannot identify fixed per-record overhead",
        })
        self.assertEqual(
            rendered["count_qualification"]["logical_counts"],
            {"stage-a-primary": 502_375, "stage-a-isolation": 10},
        )
        self.assertEqual(
            rendered["count_qualification"]["baseline_exact_legacy_fingerprint"],
            {"stage-a-primary": 502_425, "stage-a-isolation": 11},
        )
        self.assertTrue(rendered["count_qualification"]["candidate_requires_exact_logical_counts"])
        self.assertNotIn("expected_net_store_bytes", rendered)
        self.assertNotIn("store_footprint_gate_bytes", rendered)
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

    def test_an_orphan_no_longer_erases_the_reason_the_run_ended(self):
        identity = stage.build_identity("calibrate-orphan")
        spec = stage.CorpusSpec(
            stage.CALIBRATION_SAMPLE_COUNT, 50,
            stage.CALIBRATION_LOW_PAYLOAD_BYTES, "test-seed",
        )
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.create_volume.return_value = "vol_owned"
        runtime.create_machine.return_value = "machine_owned"
        runtime.disk_sample.return_value = stage.DiskSample("empty", 100, 900, 1000)
        runtime.list_owned_resources.return_value = []
        runtime.destroy_volume.side_effect = RuntimeError("volume still attached")
        client = mock.Mock()
        client.initialize.side_effect = stage.RehearsalUnknown("candidate never answered")
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(stage, "DESTROY_RETRY_DELAY_S", 0):
            path = Path(root) / "orphan-detail.json"
            self.assertEqual(stage.calibrate(
                identity, spec, path, runtime=runtime,
                client_factory=lambda _url, _auth: client,
            ), 2)
            document = json.loads(path.read_text())
        self.assertEqual(document["status"], "UNKNOWN")
        self.assertEqual(document["orphans"], ["vol_owned"])
        self.assertIn("candidate never answered", document["detail"])
        self.assertIn("cleanup", document["detail"])
        self.assertIn("volume still attached", document["cleanup"]["volume_id_error"])
        self.assertEqual(runtime.destroy_volume.call_count, stage.DESTROY_ATTEMPTS)
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
        self.assertTrue(all(call.args[2] == "cohort-settling" for call in runtime.disk_sample.call_args_list))
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
        runtime.owned_machine_ids.return_value = []
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

    def _volume_runtime(self, states):
        """A runtime whose volume listing walks the given states, one per poll."""
        seen = iter(states)
        def runner(cmd, **kwargs):
            if "volumes" in cmd and "list" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps([{"id": "vol_f", "state": next(seen)}]), "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return stage.FlyRuntime(runner=runner)

    def test_a_hydrating_fork_is_waited_out_rather_than_mounted(self):
        """Runs 30217281791 and 30220383793 both mounted a fork still in `restoring`.

        Measured on a disposable app: a 14 GB fork reported `restoring`, flyctl abandoned
        its start-wait at ~62s with "machine failed to reach desired start state", and the
        machine then started unaided at 3m13s with the data intact. The volume was never
        broken and neither was the machine - the harness simply mounted too early.
        """
        identity = stage.build_identity("hydrate")
        runtime = self._volume_runtime(["restoring", "restoring", "created"])
        with mock.patch.object(stage.time, "sleep"):
            self.assertIsInstance(runtime.wait_volume_hydrated(identity, "vol_f", interval_s=1), float)

    def test_an_unexpected_volume_state_is_reported_not_waited_out(self):
        """A terminal state must not be polled to the deadline and reported as a timeout."""
        identity = stage.build_identity("hydrate-bad")
        runtime = self._volume_runtime(["restoring", "failed"])
        with mock.patch.object(stage.time, "sleep"):
            with self.assertRaises(stage.RehearsalUnknown) as caught:
                runtime.wait_volume_hydrated(identity, "vol_f", interval_s=1)
        self.assertIn("unexpected state", str(caught.exception))

    def test_a_fresh_volume_is_not_polled_for_hydration(self):
        """Only a fork hydrates, so an unforked volume must not pay for a listing call."""
        identity = stage.build_identity("fresh-vol"); calls = []
        def runner(cmd, **kwargs):
            calls.append(cmd)
            if "volumes" in cmd and "create" in cmd:
                return subprocess.CompletedProcess(cmd, 0, json.dumps({"id": "vol_plain"}), "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        runtime = stage.FlyRuntime(runner=runner)
        self.assertEqual(runtime.create_volume(identity, identity.volume_name), "vol_plain")
        self.assertFalse([c for c in calls if "volumes" in c and "list" in c])

    def test_a_probe_may_skip_a_corpus_scale_gate_and_a_real_run_may_not(self):
        """The probe's whole licence is skipping four gates, so the licence is bounded here.

        A SKIPPED gate is neither FAILED nor UNKNOWN, so without this it would reduce to
        PASSED and read exactly like a gate that was measured and cleared - which is the
        shape of quietly weakening a gate to fit a smaller corpus.
        """
        gates = {
            "semantic_probes": stage.Gate("PASSED", "probes passed"),
            "store_footprint": stage.Gate("SKIPPED", "not judged at probe scale"),
        }
        self.assertEqual(stage.combine_status(gates, [], probe=True), "PASSED")
        self.assertEqual(stage.combine_status(gates, []), "UNKNOWN")
        self.assertEqual(stage.scale_gate(False, stage.Gate("FAILED", "over"), "store footprint").status, "FAILED")
        self.assertEqual(stage.scale_gate(True, stage.Gate("FAILED", "over"), "store footprint").status, "SKIPPED")

    def test_the_probe_corpus_and_the_qualification_corpus_cannot_be_swapped(self):
        """Neither contract will accept the other's corpus, in either direction."""
        probe_spec = stage.CorpusSpec(stage.TAIL_PROBE_SAMPLE_COUNT, 50, stage.DEFAULT_PAYLOAD_BYTES, "test-seed", "lexical")
        full_spec = stage.CorpusSpec(payload_shape="lexical")
        stage.validate_tail_probe_spec(probe_spec)
        stage.validate_execute_spec(full_spec)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.validate_execute_spec(probe_spec)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.validate_tail_probe_spec(full_spec)
        with self.assertRaises(stage.RehearsalUnknown):
            stage.validate_tail_probe_spec(
                stage.CorpusSpec(stage.TAIL_PROBE_SAMPLE_COUNT, 50, stage.MIN_PAYLOAD_BYTES, "test-seed", "opaque"))

    def test_a_probe_refuses_the_full_corpus_before_it_provisions_anything(self):
        """The probe is a mode, not a smaller run of the same mode, and it proves that early."""
        identity = stage.build_identity("probe-corpus")
        runtime = mock.Mock()
        runtime.list_owned_resources.return_value = []
        runtime.owned_machine_ids.return_value = []
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "probe-corpus.json"
            self.assertEqual(
                stage.execute(identity, stage.CorpusSpec(payload_shape="lexical"), path, runtime=runtime, probe=True), 2)
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertIn("probe contract", receipt["detail"])
        self.assertEqual(receipt["measurements"]["mode"], "tail_probe")
        runtime.create_app.assert_not_called()
        runtime.create_volume.assert_not_called()

    def test_the_workflow_verdict_admits_only_the_qualification_pass(self):
        """The probe's safety rests on these comparisons, so they are asserted, not assumed.

        `execute` renames a probe success to TAIL_PROBE_PASS. That only protects anything
        while the workflow decides the accepted status from the DISPATCHED mode and
        compares by equality - a later loosening to a substring or prefix test, or an
        unconditional acceptance of TAIL_PROBE_PASS, would silently admit every probe
        receipt into a qualification run.
        """
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/koala-stage-a-rehearse.yml"
        if not workflow.exists(): self.skipTest("workflow not present in this checkout")
        text = workflow.read_text()
        # The probe status is reachable ONLY through the probe dispatch mode.
        self.assertIn('expected_status = "TAIL_PROBE_PASS" if mode == "tail-probe" else "PASSED"', text)
        # Both comparisons stay equalities.
        self.assertIn('receipt.get("status") != expected_status', text)
        self.assertIn('receipt.get("measurements", {}).get("mode") != expected_mode', text)
        self.assertIn('expected_mode = "tail_probe" if mode == "tail-probe" else mode', text)
        # The dispatched mode reaches the verdict as an environment variable, never
        # interpolated into the script body where it would be a shell-injection vector.
        self.assertIn('mode = os.environ["MODE"]', text)
        self.assertNotIn("${{ inputs.mode }} ", text)

    def test_the_probe_ingests_its_own_corpus_rather_than_the_qualification_floor(self):
        """The probe corpus must clear the INGEST floor, not just the entry contract.

        `validate_tail_probe_spec` admits the 2,000-record corpus at the top of `execute`,
        but `ingest_corpus` re-validates through `iter_records`, whose own `minimum_count`
        defaults to the full qualification count. Run 30225546284 provisioned, launched the
        baseline, and then refused its own corpus one call later with "record count below
        required scale". Nothing caught it because every full-path test patches
        `ingest_corpus` out and swallows its kwargs, so the floor it was handed was never
        asserted anywhere. It is asserted here, in both halves: the trap itself, and the
        value `execute` actually threads.
        """
        spec = stage.CorpusSpec(stage.TAIL_PROBE_SAMPLE_COUNT, 50, stage.DEFAULT_PAYLOAD_BYTES, "seed", stage.DEFAULT_PAYLOAD_SHAPE)
        stage.validate_tail_probe_spec(spec)
        with self.assertRaises(stage.RehearsalError): next(stage.iter_records(spec))
        self.assertEqual(
            sum(1 for _ in stage.iter_records(spec, minimum_count=stage.TAIL_PROBE_SAMPLE_COUNT)),
            stage.TAIL_PROBE_SAMPLE_COUNT,
        )
        identity = stage.build_identity("probe-ingest-floor")
        gib = 1024**3
        runtime = mock.Mock()
        runtime.create_app.return_value = identity.app_name
        runtime.mirror_candidate.return_value = "registry.fly.io/probe:mirror"
        runtime.create_volume.return_value = "vol_probe"
        runtime.create_machine.return_value = "machine_probe"
        runtime.disk_sample.return_value = stage.DiskSample("baseline-empty", 100 * 1024**2, 19 * gib, 20 * gib)
        runtime.resource_sample.return_value = stage.ResourceSample("baseline-serving", 5.0, 1024)
        runtime.list_owned_resources.return_value = []
        seen: dict[str, object] = {}
        def fake_ingest(_client, _cohort, **kwargs):
            seen.update(kwargs)
            raise stage.RehearsalUnknown("halted once the ingest floor was observed")
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(stage, "ingest_corpus", side_effect=fake_ingest):
            stage.execute(identity, spec, Path(root) / "probe.json", runtime=runtime,
                          client_factory=lambda *_a: mock.Mock(), probe=True)
        self.assertEqual(seen.get("minimum_count"), stage.TAIL_PROBE_SAMPLE_COUNT)

    def test_the_probe_plan_mode_pins_the_probe_corpus(self):
        """A plan must be held to the same corpus contract as the run it describes.

        `--plan-mode execute` refuses the probe corpus and `--plan-mode tail-probe`
        refuses the qualification corpus, so neither mode can render a plan for a
        corpus its own run would reject.
        """
        identity = stage.build_identity("plan-corpus-guard")
        probe_spec = stage.CorpusSpec(stage.TAIL_PROBE_SAMPLE_COUNT, stage.DEFAULT_BATCH_SIZE, stage.DEFAULT_PAYLOAD_BYTES, "seed", stage.DEFAULT_PAYLOAD_SHAPE)
        full_spec = stage.CorpusSpec(stage.DEFAULT_RECORD_COUNT, stage.DEFAULT_BATCH_SIZE, stage.DEFAULT_PAYLOAD_BYTES, "seed", stage.DEFAULT_PAYLOAD_SHAPE)
        self.assertEqual(stage.plan(identity, probe_spec, mode="tail-probe")["record_count"], stage.TAIL_PROBE_SAMPLE_COUNT)
        with self.assertRaises(stage.RehearsalError): stage.plan(identity, probe_spec, mode="execute")
        with self.assertRaises(stage.RehearsalError): stage.plan(identity, full_spec, mode="tail-probe")

if __name__ == "__main__": unittest.main()
