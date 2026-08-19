package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

func TestExecuteProofScansEveryKeyAndWritesPrivateReceipt(t *testing.T) {
	source := newSourceFixture(t, 25)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	summary, err := executeProof(proofConfig{
		SourceRoot:                  source,
		CheckpointRoot:              checkpoint,
		ReceiptPath:                 receiptPath,
		BaselineBinary:              binary,
		ExpectedBaselineBinarySHA:   binarySHA,
		ExpectedBaselineImageDigest: baselineImageDigest,
		BaselineSourceCommit:        baselineSourceCommit,
		HelperSourceCommit:          strings.Repeat("a", 40),
		Now:                         func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}, fixtureBackupRunner(t, nil))
	if err != nil {
		t.Fatalf("executeProof() error = %v", err)
	}
	if !summary.Valid || !summary.SourceStable || !summary.DatabaseEqual || !summary.AuxiliaryEqual {
		t.Fatalf("unexpected public summary: %+v", summary)
	}
	if len(summary.ReceiptSHA256) != 64 {
		t.Fatalf("receipt SHA length = %d", len(summary.ReceiptSHA256))
	}

	info, err := os.Stat(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("receipt mode = %04o, want 0600", got)
	}

	var receipt proofReceipt
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SourceBefore.Pebble.KeyCount != 25 || receipt.SourceAfter.Pebble.KeyCount != 25 || receipt.Checkpoint.Pebble.KeyCount != 25 {
		t.Fatalf("proof did not scan all keys: before=%d after=%d checkpoint=%d", receipt.SourceBefore.Pebble.KeyCount, receipt.SourceAfter.Pebble.KeyCount, receipt.Checkpoint.Pebble.KeyCount)
	}
	if receipt.SourceBefore.AuthSecret.SHA256 == "" || receipt.SourceBefore.WAL.ManifestSHA256 == "" {
		t.Fatal("private receipt omitted auxiliary fingerprints")
	}
	if receipt.Equality.AuthSecretEqual != true || receipt.Equality.WALEqual != true || receipt.Equality.All != true {
		t.Fatalf("unexpected equality receipt: %+v", receipt.Equality)
	}

	publicData, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	publicText := string(publicData)
	for _, forbidden := range []string{source, checkpoint, receiptPath, "fixture-auth-secret", receipt.SourceBefore.AuthSecret.SHA256, "wal-entry-001"} {
		if strings.Contains(publicText, forbidden) {
			t.Fatalf("public summary exposed private data %q: %s", forbidden, publicText)
		}
	}
}

func TestExecuteProofDetectsMismatchAfterTenthKey(t *testing.T) {
	source := newSourceFixture(t, 25)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	runner := fixtureBackupRunner(t, func(checkpointRoot string) {
		db, err := pebble.Open(filepath.Join(checkpointRoot, "pebble"), &pebble.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Set([]byte("key-000024"), []byte("changed-after-the-old-ten-key-ceiling"), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), runner)
	if !errors.Is(err, errProofMismatch) {
		t.Fatalf("executeProof() error = %v, want errProofMismatch", err)
	}
	if summary.Valid || summary.DatabaseEqual || summary.ReceiptSHA256 == "" {
		t.Fatalf("mismatch summary = %+v", summary)
	}

	var receipt proofReceipt
	readJSON(t, receiptPath, &receipt)
	if receipt.Checkpoint.Pebble.KeyCount != 25 {
		t.Fatalf("checkpoint key count = %d, want 25", receipt.Checkpoint.Pebble.KeyCount)
	}
	if receipt.SourceBefore.Pebble.StreamSHA256 == receipt.Checkpoint.Pebble.StreamSHA256 {
		t.Fatal("tail mutation did not change stream digest")
	}
}

func TestExecuteProofRejectsMissingRequiredAuxiliaryState(t *testing.T) {
	for _, missing := range []string{"wal", "auth_secret"} {
		t.Run(missing, func(t *testing.T) {
			source := newSourceFixture(t, 3)
			if err := os.RemoveAll(filepath.Join(source, missing)); err != nil {
				t.Fatal(err)
			}
			checkpoint := filepath.Join(t.TempDir(), "checkpoint")
			receiptPath := filepath.Join(t.TempDir(), "proof.json")
			binary, binarySHA := fakeBaselineBinary(t)
			called := false
			_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), func(_, _, _ string) (backupExecution, error) {
				called = true
				return backupExecution{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("executeProof() error = %v, want required %s error", err, missing)
			}
			if called {
				t.Fatal("backup ran before source validation completed")
			}
			if _, statErr := os.Stat(receiptPath); !os.IsNotExist(statErr) {
				t.Fatalf("receipt should not exist after preflight failure: %v", statErr)
			}
		})
	}
}

func TestExecuteProofRejectsUnexpectedPathsBeforeBackup(t *testing.T) {
	source := newSourceFixture(t, 3)
	if err := os.WriteFile(filepath.Join(source, "unexpected"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)
	called := false

	_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), func(_, _, _ string) (backupExecution, error) {
		called = true
		return backupExecution{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected top-level path") {
		t.Fatalf("executeProof() error = %v, want unexpected-path error", err)
	}
	if called {
		t.Fatal("backup ran with an unexpected source path")
	}
}

func TestExecuteProofRejectsSymlinks(t *testing.T) {
	source := newSourceFixture(t, 3)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(source, "wal", "linked")); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("executeProof() error = %v, want symlink error", err)
	}
}

func TestExecuteProofRejectsPartialAuxiliaryManifest(t *testing.T) {
	source := newSourceFixture(t, 3)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	runner := fixtureBackupRunner(t, func(checkpointRoot string) {
		if err := os.Remove(filepath.Join(checkpointRoot, "wal", "wal-entry-002")); err != nil {
			t.Fatal(err)
		}
	})
	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), runner)
	if !errors.Is(err, errProofMismatch) {
		t.Fatalf("executeProof() error = %v, want errProofMismatch", err)
	}
	if summary.AuxiliaryEqual || summary.Valid {
		t.Fatalf("partial manifest passed: %+v", summary)
	}
}

func TestExecuteProofRejectsAuxiliaryModeMismatch(t *testing.T) {
	source := newSourceFixture(t, 3)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	runner := fixtureBackupRunner(t, func(checkpointRoot string) {
		if err := os.Chmod(filepath.Join(checkpointRoot, "wal", "wal-entry-002"), 0640); err != nil {
			t.Fatal(err)
		}
	})
	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), runner)
	if !errors.Is(err, errProofMismatch) {
		t.Fatalf("executeProof() error = %v, want errProofMismatch", err)
	}
	if summary.AuxiliaryEqual || summary.Valid {
		t.Fatalf("mode mismatch passed: %+v", summary)
	}
}

func TestExecuteProofDetectsSourceMovementDuringBackup(t *testing.T) {
	source := newSourceFixture(t, 3)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	runner := fixtureBackupRunner(t, func(_ string) {
		db, err := pebble.Open(filepath.Join(source, "pebble"), &pebble.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Set([]byte("late-write"), []byte("must-be-detected"), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), runner)
	if !errors.Is(err, errProofMismatch) {
		t.Fatalf("executeProof() error = %v, want errProofMismatch", err)
	}
	if summary.SourceStable || summary.Valid {
		t.Fatalf("moving source passed: %+v", summary)
	}
}

func TestExecuteProofRejectsWrongBaselineBinary(t *testing.T) {
	source := newSourceFixture(t, 1)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, _ := fakeBaselineBinary(t)
	called := false

	_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, strings.Repeat("f", 64)), func(_, _, _ string) (backupExecution, error) {
		called = true
		return backupExecution{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "baseline binary digest") {
		t.Fatalf("executeProof() error = %v, want digest error", err)
	}
	if called {
		t.Fatal("backup ran with the wrong baseline binary")
	}
}

func TestExecuteProofSupportsNestedCheckpointForSingleVolumeOperation(t *testing.T) {
	source := newSourceFixture(t, 25)
	checkpoint := filepath.Join(source, "stage-b-checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
	if err != nil {
		t.Fatalf("executeProof() error = %v", err)
	}
	if !summary.Valid || !summary.SourceStable || !summary.DatabaseEqual || !summary.AuxiliaryEqual {
		t.Fatalf("nested checkpoint failed: %+v", summary)
	}
}

func TestExecuteProofRejectsNestedCheckpointBelowImmediateChild(t *testing.T) {
	source := newSourceFixture(t, 1)
	checkpoint := filepath.Join(source, "nested", "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)
	called := false
	_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), func(_, _, _ string) (backupExecution, error) {
		called = true
		return backupExecution{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "immediate child") {
		t.Fatalf("executeProof() error = %v, want nested-path error", err)
	}
	if called {
		t.Fatal("backup ran for unsafe nested checkpoint path")
	}
}

func TestExecuteProofRefusesExistingCheckpointAndReceipt(t *testing.T) {
	t.Run("checkpoint", func(t *testing.T) {
		source := newSourceFixture(t, 1)
		checkpoint := t.TempDir()
		receiptPath := filepath.Join(t.TempDir(), "proof.json")
		binary, binarySHA := fakeBaselineBinary(t)
		_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
		if err == nil || !strings.Contains(err.Error(), "checkpoint path already exists") {
			t.Fatalf("executeProof() error = %v", err)
		}
	})

	t.Run("receipt", func(t *testing.T) {
		source := newSourceFixture(t, 1)
		checkpoint := filepath.Join(t.TempDir(), "checkpoint")
		receiptPath := filepath.Join(t.TempDir(), "proof.json")
		if err := os.WriteFile(receiptPath, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		binary, binarySHA := fakeBaselineBinary(t)
		_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
		if err == nil || !strings.Contains(err.Error(), "receipt path already exists") {
			t.Fatalf("executeProof() error = %v", err)
		}
		got, readErr := os.ReadFile(receiptPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != "keep" {
			t.Fatalf("existing receipt changed to %q", got)
		}
	})
}

func TestPublicFailureIsPayloadFree(t *testing.T) {
	privateErr := errors.New("open /data/private-production-path/auth_secret: permission denied for token-value")
	summary := failureSummary(privateErr)
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"/data/private-production-path", "auth_secret", "token-value", "permission denied"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("failure summary leaked %q: %s", forbidden, text)
		}
	}
	if summary.Valid || summary.Error != "checkpoint_proof_failed" {
		t.Fatalf("unexpected failure summary: %+v", summary)
	}
}

func TestRunCLIRecoversPrivateFatalWithoutPayload(t *testing.T) {
	originalSHA := baselineBinarySHA256
	originalCommit := helperSourceCommit
	t.Cleanup(func() {
		baselineBinarySHA256 = originalSHA
		helperSourceCommit = originalCommit
	})

	source := newSourceFixture(t, 1)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)
	baselineBinarySHA256 = binarySHA
	helperSourceCommit = strings.Repeat("c", 40)

	if err := os.WriteFile(filepath.Join(source, "pebble", "CURRENT"), []byte("MANIFEST-private-payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	exitCode := runCLI([]string{
		"--source-root", source,
		"--checkpoint-root", checkpoint,
		"--receipt", receiptPath,
		"--baseline-binary", binary,
	}, &output)
	if exitCode != 1 {
		t.Fatalf("runCLI() exit = %d, want 1", exitCode)
	}
	var summary publicSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Valid || summary.Error != "checkpoint_proof_failed" {
		t.Fatalf("unexpected recovered summary: %+v", summary)
	}
	for _, forbidden := range []string{source, checkpoint, receiptPath, "MANIFEST-private-payload"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("recovered output leaked %q: %s", forbidden, output.String())
		}
	}
}

func TestStreamDigestUsesLengthFraming(t *testing.T) {
	left := streamHasher()
	left.add([]byte("ab"), []byte("c"))
	right := streamHasher()
	right.add([]byte("a"), []byte("bc"))
	if left.sum() == right.sum() {
		t.Fatal("ambiguous key/value concatenations produced the same digest")
	}
}

func TestWriteNonProductionWitnessFixture(t *testing.T) {
	root := os.Getenv("KOALA_CHECKPOINT_WITNESS_FIXTURE")
	if root == "" {
		t.Skip("set KOALA_CHECKPOINT_WITNESS_FIXTURE to write the workflow-only fixture")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("witness fixture path must not exist: %v", err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeSourceFixture(t, root, 502385)
	// The build witness must exercise the exact production /data layout, not a
	// bare store: the serving daemon also leaves a model cache, an addrs file,
	// and the volume carries an ext4 lost+found.
	writeIgnoredProductionEntries(t, root)
}

func TestExecuteProofIgnoresKnownProductionVolumeEntries(t *testing.T) {
	source := newSourceFixture(t, 25)
	writeIgnoredProductionEntries(t, source)
	checkpoint := filepath.Join(source, "stage-b-checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
	if err != nil {
		t.Fatalf("executeProof() error = %v", err)
	}
	if !summary.Valid || !summary.SourceStable || !summary.DatabaseEqual || !summary.AuxiliaryEqual {
		t.Fatalf("production layout failed: %+v", summary)
	}

	var receipt proofReceipt
	readJSON(t, receiptPath, &receipt)
	if receipt.SourceBefore.Pebble.KeyCount != 25 || receipt.Checkpoint.Pebble.KeyCount != 25 {
		t.Fatalf("ignored entries perturbed the proof: %+v", receipt)
	}
}

func TestExecuteProofIgnoredEntriesNeverEnterTheProof(t *testing.T) {
	plain := newSourceFixture(t, 5)
	decorated := newSourceFixture(t, 5)
	writeIgnoredProductionEntries(t, decorated)

	run := func(source string) proofReceipt {
		checkpoint := filepath.Join(t.TempDir(), "checkpoint")
		receiptPath := filepath.Join(t.TempDir(), "proof.json")
		binary, binarySHA := fakeBaselineBinary(t)
		if _, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil)); err != nil {
			t.Fatalf("executeProof() error = %v", err)
		}
		var receipt proofReceipt
		readJSON(t, receiptPath, &receipt)
		return receipt
	}

	plainReceipt := run(plain)
	decoratedReceipt := run(decorated)
	if !equalState(plainReceipt.SourceBefore, decoratedReceipt.SourceBefore) {
		t.Fatal("ignored production entries changed the source state proof")
	}
}

func TestExecuteProofStillRejectsUnknownTopLevelPaths(t *testing.T) {
	// The ignore set is exact: anything outside it (for example a stray
	// muninn.pid from a CLI-managed store) remains an abort-worthy anomaly.
	for _, unexpected := range []string{"muninn.pid", "muninn.yaml", "unexpected"} {
		t.Run(unexpected, func(t *testing.T) {
			source := newSourceFixture(t, 3)
			writeIgnoredProductionEntries(t, source)
			if err := os.WriteFile(filepath.Join(source, unexpected), []byte("data"), 0600); err != nil {
				t.Fatal(err)
			}
			checkpoint := filepath.Join(t.TempDir(), "checkpoint")
			receiptPath := filepath.Join(t.TempDir(), "proof.json")
			binary, binarySHA := fakeBaselineBinary(t)
			called := false
			_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), func(_, _, _ string) (backupExecution, error) {
				called = true
				return backupExecution{}, nil
			})
			if err == nil || !strings.Contains(err.Error(), "unexpected top-level path") {
				t.Fatalf("executeProof() error = %v, want unexpected-path error", err)
			}
			if called {
				t.Fatal("backup ran with an unexpected source path")
			}
		})
	}
}

func TestExecuteProofRejectsIgnoredNamesInsideCheckpoint(t *testing.T) {
	// Checkpoint inspection stays strict: the baseline backup writes only the
	// three store entries, so an ignored-name file inside the checkpoint is
	// evidence of interference, not of a serving daemon.
	source := newSourceFixture(t, 3)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	receiptPath := filepath.Join(t.TempDir(), "proof.json")
	binary, binarySHA := fakeBaselineBinary(t)

	runner := fixtureBackupRunner(t, func(checkpointRoot string) {
		if err := os.WriteFile(filepath.Join(checkpointRoot, "muninn.addrs"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	_, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), runner)
	if err == nil || !strings.Contains(err.Error(), "unexpected top-level path") {
		t.Fatalf("executeProof() error = %v, want unexpected-path error", err)
	}
}

func TestExecuteProofSupportsReceiptAsImmediateChildOfSource(t *testing.T) {
	// The production run has exactly one durable write surface - the mounted
	// volume - so the private receipt must be storable beside the nested
	// checkpoint at the source root.
	source := newSourceFixture(t, 25)
	writeIgnoredProductionEntries(t, source)
	checkpoint := filepath.Join(source, "stage-b-checkpoint")
	receiptPath := filepath.Join(source, "stage-b-checkpoint.private-receipt.json")
	binary, binarySHA := fakeBaselineBinary(t)

	summary, err := executeProof(baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA), fixtureBackupRunner(t, nil))
	if err != nil {
		t.Fatalf("executeProof() error = %v", err)
	}
	if !summary.Valid || !summary.SourceStable || !summary.DatabaseEqual || !summary.AuxiliaryEqual {
		t.Fatalf("nested receipt run failed: %+v", summary)
	}
	info, err := os.Stat(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("receipt mode = %04o, want 0600", got)
	}

	var receipt proofReceipt
	readJSON(t, receiptPath, &receipt)
	if receipt.SourceBefore.Pebble.KeyCount != 25 || receipt.SourceAfter.Pebble.KeyCount != 25 {
		t.Fatalf("nested receipt perturbed the proof: %+v", receipt)
	}
	if !equalState(receipt.SourceBefore, receipt.SourceAfter) {
		t.Fatal("source stability was lost with a nested receipt")
	}
}

func TestExecuteProofRejectsUnsafeNestedReceiptPlacements(t *testing.T) {
	cases := []struct {
		name       string
		checkpoint func(t *testing.T, source string) string
		receipt    func(source string) string
	}{
		{
			name:       "receipt below immediate child of source",
			checkpoint: func(_ *testing.T, source string) string { return filepath.Join(source, "stage-b-checkpoint") },
			receipt:    func(source string) string { return filepath.Join(source, "nested", "proof.json") },
		},
		{
			name:       "receipt inside nested checkpoint",
			checkpoint: func(_ *testing.T, source string) string { return filepath.Join(source, "stage-b-checkpoint") },
			receipt:    func(source string) string { return filepath.Join(source, "stage-b-checkpoint", "proof.json") },
		},
		{
			name:       "receipt inside source with independent checkpoint",
			checkpoint: func(t *testing.T, _ string) string { return filepath.Join(t.TempDir(), "checkpoint") },
			receipt:    func(source string) string { return filepath.Join(source, "proof.json") },
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := newSourceFixture(t, 1)
			binary, binarySHA := fakeBaselineBinary(t)
			called := false
			_, err := executeProof(baseTestConfig(source, testCase.checkpoint(t, source), testCase.receipt(source), binary, binarySHA), func(_, _, _ string) (backupExecution, error) {
				called = true
				return backupExecution{}, nil
			})
			if err == nil {
				t.Fatal("executeProof() accepted an unsafe receipt placement")
			}
			if called {
				t.Fatal("backup ran with an unsafe receipt placement")
			}
		})
	}
}

// writeIgnoredProductionEntries decorates a source fixture with the exact
// non-store entries a production volume carries: the daemon's model cache and
// addrs file, plus the filesystem's lost+found.
func writeIgnoredProductionEntries(t *testing.T, root string) {
	t.Helper()
	modelDir := filepath.Join(root, "models", "bge-small")
	if err := os.MkdirAll(modelDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modelDir, "model.onnx"), []byte("model-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "muninn.addrs"), []byte(`{"mcp":"127.0.0.1:8750"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "lost+found"), 0700); err != nil {
		t.Fatal(err)
	}
}

func baseTestConfig(source, checkpoint, receiptPath, binary, binarySHA string) proofConfig {
	return proofConfig{
		SourceRoot:                  source,
		CheckpointRoot:              checkpoint,
		ReceiptPath:                 receiptPath,
		BaselineBinary:              binary,
		ExpectedBaselineBinarySHA:   binarySHA,
		ExpectedBaselineImageDigest: baselineImageDigest,
		BaselineSourceCommit:        baselineSourceCommit,
		HelperSourceCommit:          strings.Repeat("b", 40),
		Now:                         func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
}

func newSourceFixture(t *testing.T, count int) string {
	t.Helper()
	root := t.TempDir()
	writeSourceFixture(t, root, count)
	return root
}

func writeSourceFixture(t *testing.T, root string, count int) {
	t.Helper()
	pebbleDir := filepath.Join(root, "pebble")
	walDir := filepath.Join(root, "wal")
	if err := os.MkdirAll(walDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(walDir, "wal-entry-001"), []byte("wal-one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(walDir, "wal-entry-002"), []byte("wal-two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "auth_secret"), []byte("fixture-auth-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := pebble.Open(pebbleDir, &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	batch := db.NewBatch()
	for i := 0; i < count; i++ {
		key := []byte(formatFixtureNumber("key", i))
		value := []byte(formatFixtureNumber("value", i))
		if err := batch.Set(key, value, nil); err != nil {
			t.Fatal(err)
		}
		if batch.Len() >= 4*1024*1024 {
			if err := batch.Commit(pebble.Sync); err != nil {
				t.Fatal(err)
			}
			if err := batch.Close(); err != nil {
				t.Fatal(err)
			}
			batch = db.NewBatch()
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := batch.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func formatFixtureNumber(prefix string, value int) string {
	const digits = "000000"
	n := []byte(digits)
	for i := len(n) - 1; i >= 0; i-- {
		n[i] = byte('0' + value%10)
		value /= 10
	}
	return prefix + "-" + string(n)
}

func fixtureBackupRunner(t *testing.T, after func(checkpointRoot string)) backupRunner {
	t.Helper()
	return func(sourceRoot, checkpointRoot, _ string) (backupExecution, error) {
		if err := os.Mkdir(checkpointRoot, 0700); err != nil {
			return backupExecution{}, err
		}
		db, err := pebble.Open(filepath.Join(sourceRoot, "pebble"), &pebble.Options{})
		if err != nil {
			return backupExecution{}, err
		}
		if err := db.Checkpoint(filepath.Join(checkpointRoot, "pebble")); err != nil {
			db.Close()
			return backupExecution{}, err
		}
		if err := db.Close(); err != nil {
			return backupExecution{}, err
		}
		if err := copyFixtureTree(filepath.Join(sourceRoot, "wal"), filepath.Join(checkpointRoot, "wal")); err != nil {
			return backupExecution{}, err
		}
		secret, err := os.ReadFile(filepath.Join(sourceRoot, "auth_secret"))
		if err != nil {
			return backupExecution{}, err
		}
		if err := os.WriteFile(filepath.Join(checkpointRoot, "auth_secret"), secret, 0600); err != nil {
			return backupExecution{}, err
		}
		if after != nil {
			after(checkpointRoot)
		}
		return backupExecution{ExitCode: 0, StdoutSHA256: digestString("fixture backup complete"), StderrSHA256: digestString("")}, nil
	}
}

func copyFixtureTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0600)
	})
}

func fakeBaselineBinary(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "muninndb-server")
	data := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}
