#!/usr/bin/env python3
"""Static contract tests for the inert PR 84 qualification workflow mode."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
QUALIFICATION_WORKFLOW = (
    ROOT / ".github/workflows/koala-stage-b-checkpoint-proof-build.yml"
)
QUALIFICATION_COMMIT = "a9c1f785b86195975cbc1c8f8611ac78d5871d87"


class PR84QualificationWorkflowTests(unittest.TestCase):
    def qualification_job(self) -> str:
        text = QUALIFICATION_WORKFLOW.read_text(encoding="utf-8")
        marker = "  qualify-pr84:\n"
        self.assertEqual(text.count(marker), 1)
        return marker + text.split(marker, 1)[1]

    def test_ci_runs_for_compatibility_branch_pull_requests(self):
        text = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "pull_request:\n    branches: [main, develop, koala/v0.9.0-compat]",
            text,
        )

    def test_qualification_mode_is_explicit_and_helper_mode_is_default(self):
        text = QUALIFICATION_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("mode:\n        description: Operation to run", text)
        self.assertIn("default: checkpoint-proof-helper", text)
        self.assertIn("- pr84-payload-receipt-qualification", text)
        self.assertIn("build:\n    if: inputs.mode == 'checkpoint-proof-helper'", text)
        self.assertIn(
            "qualify-pr84:\n    if: inputs.mode == "
            "'pr84-payload-receipt-qualification'",
            text,
        )

    def test_qualification_is_pinned_to_the_authorized_commit(self):
        job = self.qualification_job()
        self.assertIn(f"AUTHORIZED_COMMIT: {QUALIFICATION_COMMIT}", job)
        self.assertIn('test "$QUALIFICATION_COMMIT" = "$AUTHORIZED_COMMIT"', job)
        self.assertIn("ref: ${{ env.AUTHORIZED_COMMIT }}", job)
        self.assertNotIn("ref: ${{ inputs.qualification_commit }}", job)
        self.assertIn('test "$(git rev-parse HEAD)" = "$AUTHORIZED_COMMIT"', job)
        self.assertIn("persist-credentials: false", job)
        self.assertNotRegex(job, r"uses: [^\n]+@v[0-9]")

    def test_qualification_assets_are_immutable_and_hash_checked(self):
        job = self.qualification_job()
        self.assertIn(
            "resolve/ea104dacec62c0de699686887e3f920caeb4f3e3/onnx/model_int8.onnx",
            job,
        )
        self.assertIn(
            "resolve/5c38ec7c405ec4b44b94cc5a9bb96e735b38267a/tokenizer.json",
            job,
        )
        for digest in (
            "bf64d05457cb391fa88d045faf5927a15ea36d96228ddf23ea970087afdc1197",
            "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
            "43725474ba5663642e17684717946693850e2005efbd724ac72da278fead25e6",
        ):
            self.assertIn(digest, job)
        self.assertEqual(job.count("sha256sum --check --strict"), 3)
        self.assertNotIn("make fetch-model _ort-linux-amd64", job)
        self.assertNotIn("resolve/main", job)

    def test_qualification_runs_its_exact_dispatch_contract(self):
        job = self.qualification_job()
        for path in (
            ".github/workflows/ci.yml",
            ".github/workflows/koala-stage-b-checkpoint-proof-build.yml",
            "scripts/tests/test_koala_pr84_qualification_workflow.py",
        ):
            self.assertIn(f'git show "$GITHUB_SHA:{path}" >', job)
        self.assertIn(
            'python3 "$contract_root/scripts/tests/'
            'test_koala_pr84_qualification_workflow.py"',
            job,
        )

    def test_qualification_runs_only_the_authorized_gates(self):
        job = self.qualification_job()
        for command in (
            "go build -tags localassets -o muninndb-server ./cmd/muninn/...",
            "go vet -tags localassets ./...",
            "go test -tags localassets ./... -timeout 300s -race",
            "go test -tags localassets,integration -v -timeout 120s ./cmd/muninn/...",
            "go test -tags localassets,integration -v -timeout 120s ./internal/plugin/embed/...",
        ):
            self.assertIn(command, job)
        self.assertIn("permissions:\n      contents: read", job)
        for forbidden in (
            "FLY_API_TOKEN",
            "flyctl",
            "registry.fly.io",
            "ghcr.io",
            "docker ",
            "packages: write",
            "actions/upload-artifact",
        ):
            self.assertNotIn(forbidden, job)

    def test_qualification_checkout_and_setup_actions_are_sha_pinned(self):
        job = self.qualification_job()
        uses = re.findall(r"^\s*uses:\s*(\S+)$", job, flags=re.MULTILINE)
        self.assertEqual(
            uses,
            [
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
            ],
        )


if __name__ == "__main__":
    unittest.main()
