#!/usr/bin/env python3
"""Contract tests for the exact-revision legacy FTS witness."""
from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "koala_legacy_fts_witness.py"
SPEC = importlib.util.spec_from_file_location("koala_legacy_fts_witness", MODULE_PATH)
assert SPEC and SPEC.loader
witness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = witness
SPEC.loader.exec_module(witness)


class LegacyFTSWitnessContractTests(unittest.TestCase):
    def test_contract_matches_stage_a_and_exact_baseline(self):
        self.assertEqual(witness.BASELINE_SOURCE_REVISION, "be975fb1215e75208adf4b340ba95e21415f04cb")
        self.assertEqual(witness.TOTAL_RECORD_COUNT, 502_385)
        self.assertEqual(witness.PRIMARY_RECORD_COUNT, 502_375)
        self.assertEqual(witness.PAYLOAD_BYTES, 4_000)
        self.assertEqual(witness.TOP_K, 30)
        self.assertEqual(witness.SERVER_CONTEXT_S, 30.0)
        self.assertEqual(
            witness.QUERY_CONTEXTS,
            (
                "Stage A Entity 00",
                "Stage A Entity 01",
                "Stage A Entity 07",
                "Stage A Entity 42",
                "Stage A Entity 43",
                "Stage A Group 0",
                "Stage A Group 1",
                "Stage A Group 2",
            ),
        )

    def test_injected_go_fixture_uses_only_real_fts_fields(self):
        self.assertIn('"concept", "createdBy", "content", "tags"', witness.GO_TEST_SOURCE)
        self.assertNotIn("FTSPostingKey([8]byte{}, \"entity\"", witness.GO_TEST_SOURCE)
        self.assertNotIn("FTSPostingKey([8]byte{}, \"group\"", witness.GO_TEST_SOURCE)
        self.assertIn('FTSPostingKey([8]byte{}, "stage"', witness.GO_TEST_SOURCE)
        self.assertIn("witnessPrimaryRecords = 502375", witness.GO_TEST_SOURCE)
        self.assertIn("witnessExactDocLen(index)", witness.GO_TEST_SOURCE)
        self.assertIn("visible := witnessPayloadBytes - length - 1", witness.GO_TEST_SOURCE)
        self.assertIn("if index == 43", witness.GO_TEST_SOURCE)

    def test_child_environment_is_allowlisted_and_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            go = Path(directory) / "go"
            env = witness.sanitized_env(go, Path(directory))
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOENV"], "off")
        self.assertNotIn("FLY_API_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertFalse(set(os.environ) - set(env) <= {"PATH"})

    def test_classification_selects_scan_or_ranking_mechanically(self):
        phases = {
            "scan_first": {"scan_s": 31.0},
            "scan_warm": {"scan_s": 25.0},
            "rank": {"status": "timeout", "budget_s": 30.0},
            "whole_first": {"status": "timeout"},
            "whole_warm": {"status": "timeout"},
            "pre-cancel": {"status": "timeout"},
            "mid-cancel": {"status": "timeout"},
        }
        verdict = witness.classify(phases)
        self.assertEqual(verdict["bottleneck"], "posting-scan")
        self.assertTrue(verdict["posting_scan_exceeds_server_context"])
        phases["scan_first"]["scan_s"] = 3.0
        phases["scan_warm"]["scan_s"] = 2.0
        self.assertEqual(witness.classify(phases)["bottleneck"], "ranking")

    def test_classification_requires_measured_latency_and_cancellation_errors(self):
        completed_cancel = {
            "status": "completed",
            "elapsed_s": 1.5,
            "search_error": "context canceled",
            "ctx_error": "context canceled",
        }
        phases = {
            "scan_first": {"scan_s": 0.2},
            "scan_warm": {"scan_s": 0.1},
            "rank": {"status": "completed", "elapsed_s": 31.0},
            "whole_first": {"status": "completed", "elapsed_s": 31.0},
            "whole_warm": {"status": "completed", "elapsed_s": 0.2},
            "pre-cancel": dict(completed_cancel),
            "mid-cancel": dict(completed_cancel),
        }
        verdict = witness.classify(phases)
        self.assertTrue(verdict["ranking_exceeds_server_context"])
        self.assertTrue(verdict["whole_search_exceeds_server_context"])
        self.assertTrue(verdict["pre_cancel_returned_within_2s"])
        self.assertTrue(verdict["mid_scan_cancel_returned_within_2s"])

        phases["pre-cancel"]["elapsed_s"] = 2.0
        phases["mid-cancel"]["search_error"] = ""
        verdict = witness.classify(phases)
        self.assertFalse(verdict["pre_cancel_returned_within_2s"])
        self.assertFalse(verdict["mid_scan_cancel_returned_within_2s"])

    def test_timeout_kills_the_process_group_and_returns_a_receipt(self):
        fake_process = mock.Mock()
        fake_process.pid = 1234
        fake_process.poll.return_value = None
        fake_process.communicate.side_effect = [subprocess.TimeoutExpired("witness", 0.1), ("tail", None)]
        fake_process.returncode = -9
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(witness.subprocess, "Popen", return_value=fake_process), \
             mock.patch.object(witness.os, "killpg") as killpg:
            path = Path(directory)
            receipt = witness.run_phase(
                path / "binary",
                path,
                {"PATH": "/usr/bin:/bin"},
                path,
                "rank",
                budget_s=0.1,
            )
        self.assertEqual(receipt["status"], "timeout")
        killpg.assert_called_once_with(1234, witness.signal.SIGKILL)

    def test_fixture_generation_is_linear_and_full_corpus_is_required(self):
        self.assertIn("var payload strings.Builder", witness.GO_TEST_SOURCE)
        self.assertNotIn('len(strings.Join(words, " "))', witness.GO_TEST_SOURCE)
        self.assertIn("fixture posting count=%d want=%d", witness.GO_TEST_SOURCE)
        source = MODULE_PATH.read_text()
        self.assertIn("fixture build did not complete", source)
        self.assertIn("fixture posting count mismatch", source)

    def test_patch_is_applied_only_after_exact_source_extraction(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(witness, "run_checked") as run_checked, \
             mock.patch.object(witness.subprocess, "run") as run:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            destination = root / "source"
            patch = root / "legacy.patch"
            patch.write_text("patch")
            archive = root / "legacy-source.tar"
            with tarfile.open(archive, "w"):
                pass
            run.return_value = subprocess.CompletedProcess([], 0, "", "")

            witness.extract_revision(repo, destination, {"PATH": "/usr/bin:/bin"}, patch)

        commands = [call.args[0] for call in run_checked.call_args_list]
        self.assertEqual(commands[-2], ["git", "apply", "--check", str(patch.resolve())])
        self.assertEqual(commands[-1], ["git", "apply", str(patch.resolve())])

    def test_rescue_workflow_keeps_exact_source_patch_and_artifact_identities_distinct(self):
        workflow = (MODULE_PATH.parents[1] / ".github" / "workflows" / "koala-rollback-rescue-build.yml").read_text()
        self.assertIn(f"LEGACY_SOURCE_COMMIT: {witness.BASELINE_SOURCE_REVISION}", workflow)
        self.assertIn("LEGACY_BASELINE_DIGEST: sha256:c06842", workflow)
        self.assertIn("RESCUE_IMAGE: ghcr.io/koala-optics/muninndb:rollback-", workflow)
        self.assertIn(
            "EXPECTED_PATCH_SHA256: b5c480af5896ceda6739c055326b13f0ec40c42cab2e29dbbc1de3a9a913e74d",
            workflow,
        )
        self.assertIn(
            'git worktree add --detach "$RECEIPT_DIR/source" "$LEGACY_SOURCE_COMMIT"',
            workflow,
        )
        self.assertIn('git -C "$RECEIPT_DIR/source" apply --check', workflow)
        self.assertIn('git -C "$RECEIPT_DIR/source" apply --reverse --check', workflow)
        self.assertIn(
            'test "$(git -C "$RECEIPT_DIR/source" diff --name-only)" = "internal/index/fts/fts.go"',
            workflow,
        )
        self.assertIn('git -C "$RECEIPT_DIR/source" diff -- internal/index/fts/fts.go', workflow)
        self.assertIn(
            "uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
            workflow,
        )
        self.assertIn(
            "go-version-file: /tmp/koala-rollback-rescue/source/go.mod",
            workflow,
        )
        self.assertIn("not the untouched deployed baseline and not RC2", workflow)
        self.assertNotIn("ref: ${{ inputs.harness_commit }}", workflow)
        self.assertNotIn('git archive "$LEGACY_SOURCE_COMMIT"', workflow)

    def test_rescue_image_build_pins_and_verifies_every_remote_input(self):
        root = MODULE_PATH.parents[1]
        workflow = (root / ".github" / "workflows" / "koala-rollback-rescue-build.yml").read_text()
        dockerfile = (root / "scripts" / "patches" / "legacy-be975fb-rescue.Dockerfile").read_text()

        dockerfile_sha256 = hashlib.sha256(dockerfile.encode()).hexdigest()
        self.assertIn(
            f"EXPECTED_RESCUE_DOCKERFILE_SHA256: {dockerfile_sha256}",
            workflow,
        )
        self.assertIn('test "$rescue_dockerfile_sha256" = "$EXPECTED_RESCUE_DOCKERFILE_SHA256"', workflow)
        self.assertIn("file: ${{ github.workspace }}/${{ env.RESCUE_DOCKERFILE_PATH }}", workflow)
        self.assertIn("no-cache: true", workflow)
        self.assertNotIn("cache-from:", workflow)
        self.assertNotIn("cache-to:", workflow)
        self.assertIn("rescue_dockerfile_sha256", workflow)

        for image in ("node:20-bookworm-slim", "golang:1.25-bookworm", "debian:bookworm-slim"):
            self.assertRegex(dockerfile, rf"FROM {image}@sha256:[0-9a-f]{{64}}")
        self.assertNotIn("nodesource.com", dockerfile)
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("resolve/main", dockerfile)
        self.assertIn("ea104dacec62c0de699686887e3f920caeb4f3e3", dockerfile)
        self.assertIn("5c38ec7c405ec4b44b94cc5a9bb96e735b38267a", dockerfile)
        for digest in (
            "bf64d05457cb391fa88d045faf5927a15ea36d96228ddf23ea970087afdc1197",
            "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
            "43725474ba5663642e17684717946693850e2005efbd724ac72da278fead25e6",
        ):
            self.assertIn(digest, dockerfile)
        self.assertEqual(dockerfile.count("sha256sum --check --strict"), 3)
        self.assertIn("npm ci --ignore-scripts", dockerfile)
        self.assertIn("RUN --network=none npm run build", dockerfile)
        self.assertIn("RUN go mod download", dockerfile)
        self.assertIn("RUN --network=none go build -mod=readonly", dockerfile)

    def test_mid_cancel_starts_after_measured_section_marker(self):
        marker = 'witnessMarker(t, "KOALA_WITNESS_MARKER")'
        cancellation = 'if cancellation == "during" {'
        search = 'idx.Search(ctx, [8]byte{}, "Stage A Entity 00", witnessTopK)'
        marker_offset = witness.GO_TEST_SOURCE.index(marker, witness.GO_TEST_SOURCE.index("func witnessWhole"))
        cancellation_offset = witness.GO_TEST_SOURCE.index(cancellation, marker_offset)
        search_offset = witness.GO_TEST_SOURCE.index(search, cancellation_offset)
        self.assertLess(marker_offset, cancellation_offset)
        self.assertLess(cancellation_offset, search_offset)


if __name__ == "__main__":
    unittest.main()
