package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
)

const (
	proofSchemaVersion   = "koala-muninn-stage-b-checkpoint-proof-v1"
	baselineImageDigest  = "sha256:fca31180b5acf13e57d5cc4e1662124834d1c338c96baab329178cf860525c27"
	baselineSourceCommit = "c8f205dc3f86ff9c9b785ee8e3cd45ce55fe3877"
	backupTimeout        = 30 * time.Minute
)

var (
	baselineBinarySHA256 string
	helperSourceCommit   string
	errProofMismatch     = errors.New("checkpoint proof mismatch")
)

type proofConfig struct {
	SourceRoot                  string
	CheckpointRoot              string
	ReceiptPath                 string
	BaselineBinary              string
	ExpectedBaselineBinarySHA   string
	ExpectedBaselineImageDigest string
	BaselineSourceCommit        string
	HelperSourceCommit          string
	Now                         func() time.Time
}

type backupRunner func(sourceRoot, checkpointRoot, baselineBinary string) (backupExecution, error)

type backupExecution struct {
	ExitCode     int    `json:"exit_code"`
	StdoutSHA256 string `json:"stdout_sha256"`
	StderrSHA256 string `json:"stderr_sha256"`
}

type pebbleProof struct {
	KeyCount     uint64 `json:"key_count"`
	KeyBytes     uint64 `json:"key_bytes"`
	ValueBytes   uint64 `json:"value_bytes"`
	StreamSHA256 string `json:"stream_sha256"`
}

type manifestEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Bytes  uint64 `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type treeProof struct {
	DirectoryCount uint64          `json:"directory_count"`
	FileCount      uint64          `json:"file_count"`
	Bytes          uint64          `json:"bytes"`
	ManifestSHA256 string          `json:"manifest_sha256"`
	Entries        []manifestEntry `json:"entries"`
}

type fileProof struct {
	Mode   uint32 `json:"mode"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type stateProof struct {
	Pebble     pebbleProof `json:"pebble"`
	WAL        treeProof   `json:"wal"`
	AuthSecret fileProof   `json:"auth_secret"`
}

type equalityProof struct {
	SourceStable    bool `json:"source_stable"`
	PebbleEqual     bool `json:"pebble_equal"`
	WALEqual        bool `json:"wal_equal"`
	AuthSecretEqual bool `json:"auth_secret_equal"`
	All             bool `json:"all"`
}

type proofIdentity struct {
	BaselineImageDigest  string `json:"baseline_image_digest"`
	BaselineSourceCommit string `json:"baseline_source_commit"`
	BaselineBinarySHA256 string `json:"baseline_binary_sha256"`
	HelperSourceCommit   string `json:"helper_source_commit"`
}

type privatePaths struct {
	SourceRoot     string `json:"source_root"`
	CheckpointRoot string `json:"checkpoint_root"`
	ReceiptPath    string `json:"receipt_path"`
	BaselineBinary string `json:"baseline_binary"`
}

type proofReceipt struct {
	SchemaVersion string          `json:"schema_version"`
	CreatedAt     string          `json:"created_at"`
	Identity      proofIdentity   `json:"identity"`
	Paths         privatePaths    `json:"paths"`
	Backup        backupExecution `json:"backup"`
	SourceBefore  stateProof      `json:"source_before"`
	Checkpoint    stateProof      `json:"checkpoint"`
	SourceAfter   stateProof      `json:"source_after"`
	Equality      equalityProof   `json:"equality"`
}

type publicSummary struct {
	Valid          bool   `json:"valid"`
	SourceStable   bool   `json:"source_stable"`
	DatabaseEqual  bool   `json:"database_equal"`
	AuxiliaryEqual bool   `json:"auxiliary_equal"`
	ReceiptSHA256  string `json:"receipt_sha256,omitempty"`
	Error          string `json:"error,omitempty"`
}

type framedHasher struct {
	h hash.Hash
}

type privatePebbleLogger struct{}

func (privatePebbleLogger) Infof(string, ...interface{}) {}

func (privatePebbleLogger) Fatalf(string, ...interface{}) {
	panic("checkpoint proof internal fatal")
}

func streamHasher() *framedHasher {
	return &framedHasher{h: sha256.New()}
}

func (f *framedHasher) add(key, value []byte) {
	writeFrame(f.h, key)
	writeFrame(f.h, value)
}

func (f *framedHasher) sum() string {
	return hex.EncodeToString(f.h.Sum(nil))
}

func writeFrame(destination io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}

func executeProof(config proofConfig, runBackup backupRunner) (publicSummary, error) {
	if err := validateConfig(config); err != nil {
		return failureSummary(err), err
	}
	relation, err := classifyPaths(config)
	if err != nil {
		return failureSummary(err), err
	}
	if relation.checkpointInsideSource {
		return executeProofWithNestedCheckpoint(config, runBackup)
	}
	return executeProofWithIndependentCheckpoint(config, runBackup)
}

type pathRelation struct {
	checkpointInsideSource bool
}

func classifyPaths(config proofConfig) (pathRelation, error) {
	source, err := filepath.Abs(config.SourceRoot)
	if err != nil {
		return pathRelation{}, errors.New("source path could not be normalized")
	}
	checkpoint, err := filepath.Abs(config.CheckpointRoot)
	if err != nil {
		return pathRelation{}, errors.New("checkpoint path could not be normalized")
	}
	receipt, err := filepath.Abs(config.ReceiptPath)
	if err != nil {
		return pathRelation{}, errors.New("receipt path could not be normalized")
	}
	if source == checkpoint || source == receipt || checkpoint == receipt {
		return pathRelation{}, errors.New("source, checkpoint, and receipt paths must be distinct")
	}
	checkpointInsideSource := pathInside(source, checkpoint)
	if pathInside(checkpoint, source) {
		return pathRelation{}, errors.New("source path cannot be inside the checkpoint path")
	}
	if pathInside(checkpoint, receipt) || pathInside(receipt, source) || pathInside(receipt, checkpoint) {
		return pathRelation{}, errors.New("receipt path cannot contain or be contained by source or checkpoint")
	}
	if pathInside(source, receipt) {
		// Single-volume operation: the mounted data volume is the only durable
		// write surface, so the private receipt may sit directly beside the
		// nested checkpoint at the source root. Both outputs are written only
		// after the corresponding source inspections, so neither perturbs the
		// proof; any deeper or independent-mode nesting still refuses.
		if !checkpointInsideSource {
			return pathRelation{}, errors.New("receipt path may nest inside source only when the checkpoint does")
		}
		if filepath.Dir(receipt) != source {
			return pathRelation{}, errors.New("receipt path must be an immediate child of source when nested")
		}
	}
	if checkpointInsideSource && filepath.Dir(checkpoint) != source {
		return pathRelation{}, errors.New("checkpoint path must be an immediate child of source when nested")
	}
	return pathRelation{checkpointInsideSource: checkpointInsideSource}, nil
}

func pathInside(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil || relative == "." {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func executeProofWithIndependentCheckpoint(config proofConfig, runBackup backupRunner) (publicSummary, error) {
	if err := requireAbsent(config.CheckpointRoot, "checkpoint path"); err != nil {
		return failureSummary(err), err
	}
	if err := requireAbsent(config.ReceiptPath, "receipt path"); err != nil {
		return failureSummary(err), err
	}
	if err := validateOutputParent(config.CheckpointRoot); err != nil {
		return failureSummary(err), err
	}
	if err := validateOutputParent(config.ReceiptPath); err != nil {
		return failureSummary(err), err
	}

	sourceBefore, err := inspectSourceRoot(config.SourceRoot)
	if err != nil {
		return failureSummary(err), err
	}

	backup, err := runBackup(config.SourceRoot, config.CheckpointRoot, config.BaselineBinary)
	if err != nil {
		return failureSummary(err), err
	}
	if backup.ExitCode != 0 {
		err := errors.New("baseline backup command failed")
		return failureSummary(err), err
	}

	checkpoint, err := inspectDataRoot(config.CheckpointRoot)
	if err != nil {
		return failureSummary(err), err
	}
	sourceAfter, err := inspectSourceRoot(config.SourceRoot)
	if err != nil {
		return failureSummary(err), err
	}

	return finishProof(config, backup, sourceBefore, checkpoint, sourceAfter)
}

func executeProofWithNestedCheckpoint(config proofConfig, runBackup backupRunner) (publicSummary, error) {
	if err := requireAbsent(config.CheckpointRoot, "checkpoint path"); err != nil {
		return failureSummary(err), err
	}
	if err := requireAbsent(config.ReceiptPath, "receipt path"); err != nil {
		return failureSummary(err), err
	}
	if err := validateOutputParent(config.CheckpointRoot); err != nil {
		return failureSummary(err), err
	}
	if err := validateOutputParent(config.ReceiptPath); err != nil {
		return failureSummary(err), err
	}

	sourceBefore, err := inspectSourceRoot(config.SourceRoot)
	if err != nil {
		return failureSummary(err), err
	}
	backup, err := runBackup(config.SourceRoot, config.CheckpointRoot, config.BaselineBinary)
	if err != nil {
		return failureSummary(err), err
	}
	if backup.ExitCode != 0 {
		err := errors.New("baseline backup command failed")
		return failureSummary(err), err
	}
	checkpoint, err := inspectDataRoot(config.CheckpointRoot)
	if err != nil {
		return failureSummary(err), err
	}
	// No receipt exclusion is needed even when the receipt nests inside
	// source: requireAbsent proved it absent at entry and finishProof writes
	// it only after this inspection, so a file under that name here is a
	// foreign artifact and correctly refuses as unexpected.
	sourceAfter, err := inspectSourceRoot(config.SourceRoot, filepath.Base(config.CheckpointRoot))
	if err != nil {
		return failureSummary(err), err
	}
	return finishProof(config, backup, sourceBefore, checkpoint, sourceAfter)
}

func finishProof(config proofConfig, backup backupExecution, sourceBefore, checkpoint, sourceAfter stateProof) (publicSummary, error) {
	equality := compareStates(sourceBefore, checkpoint, sourceAfter)
	receipt := proofReceipt{
		SchemaVersion: proofSchemaVersion,
		CreatedAt:     config.Now().UTC().Format(time.RFC3339),
		Identity: proofIdentity{
			BaselineImageDigest:  config.ExpectedBaselineImageDigest,
			BaselineSourceCommit: config.BaselineSourceCommit,
			BaselineBinarySHA256: config.ExpectedBaselineBinarySHA,
			HelperSourceCommit:   config.HelperSourceCommit,
		},
		Paths: privatePaths{
			SourceRoot:     config.SourceRoot,
			CheckpointRoot: config.CheckpointRoot,
			ReceiptPath:    config.ReceiptPath,
			BaselineBinary: config.BaselineBinary,
		},
		Backup:       backup,
		SourceBefore: sourceBefore,
		Checkpoint:   checkpoint,
		SourceAfter:  sourceAfter,
		Equality:     equality,
	}

	receiptSHA, err := writePrivateReceipt(config.ReceiptPath, receipt)
	if err != nil {
		return failureSummary(err), err
	}
	summary := publicSummary{
		Valid:          equality.All,
		SourceStable:   equality.SourceStable,
		DatabaseEqual:  equality.PebbleEqual,
		AuxiliaryEqual: equality.WALEqual && equality.AuthSecretEqual,
		ReceiptSHA256:  receiptSHA,
	}
	if !equality.All {
		summary.Error = "checkpoint_proof_mismatch"
		return summary, errProofMismatch
	}
	return summary, nil
}

func validateConfig(config proofConfig) error {
	if config.SourceRoot == "" || config.CheckpointRoot == "" || config.ReceiptPath == "" || config.BaselineBinary == "" {
		return errors.New("all paths are required")
	}
	if config.Now == nil {
		return errors.New("clock is required")
	}
	if config.ExpectedBaselineImageDigest != baselineImageDigest {
		return errors.New("baseline image digest does not match the qualified identity")
	}
	if config.BaselineSourceCommit != baselineSourceCommit {
		return errors.New("baseline source commit does not match the qualified identity")
	}
	if !isLowerHex(config.ExpectedBaselineBinarySHA, 64) {
		return errors.New("baseline binary digest is malformed")
	}
	if !isLowerHex(config.HelperSourceCommit, 40) {
		return errors.New("helper source commit is malformed")
	}
	if err := validateExistingRegularFile(config.BaselineBinary); err != nil {
		return fmt.Errorf("baseline binary is unsafe: %w", err)
	}
	actualSHA, _, err := hashFile(config.BaselineBinary)
	if err != nil {
		return errors.New("baseline binary could not be hashed")
	}
	if actualSHA != config.ExpectedBaselineBinarySHA {
		return errors.New("baseline binary digest does not match the pinned helper identity")
	}
	return nil
}

// ignoredVolumeEntries are the exact non-store names a production data volume
// carries beside the store: the serving daemon's embedding-model cache and
// address file, plus the filesystem's lost+found. Source-root inspections skip
// them without hashing or walking them; any other unexpected name (for example
// a stray muninn.pid from a CLI-managed store) still refuses. Checkpoint and
// restored-root inspections stay strict because the baseline backup writes
// only the three store entries.
var ignoredVolumeEntries = map[string]bool{
	"lost+found":   true,
	"models":       true,
	"muninn.addrs": true,
}

func inspectDataRoot(root string) (stateProof, error) {
	return inspectRoot(root, nil, nil)
}

func inspectSourceRoot(root string, excluded ...string) (stateProof, error) {
	return inspectRoot(root, ignoredVolumeEntries, excluded)
}

func inspectRoot(root string, ignored map[string]bool, excluded []string) (stateProof, error) {
	if err := validateExistingDirectory(root); err != nil {
		return stateProof{}, fmt.Errorf("data root is unsafe: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return stateProof{}, errors.New("data root is unreadable")
	}
	allowed := map[string]bool{"pebble": true, "wal": true, "auth_secret": true}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if excludedName(name, excluded) {
			continue
		}
		if ignored[name] {
			continue
		}
		if !allowed[name] {
			return stateProof{}, fmt.Errorf("unexpected top-level path %q", name)
		}
		seen[name] = true
	}
	for _, required := range []string{"pebble", "wal", "auth_secret"} {
		if !seen[required] {
			return stateProof{}, fmt.Errorf("required %s is missing", required)
		}
	}

	pebbleResult, err := scanPebble(filepath.Join(root, "pebble"))
	if err != nil {
		return stateProof{}, fmt.Errorf("pebble proof failed: %w", err)
	}
	walResult, err := hashTree(filepath.Join(root, "wal"))
	if err != nil {
		return stateProof{}, fmt.Errorf("wal proof failed: %w", err)
	}
	secretResult, err := proveFile(filepath.Join(root, "auth_secret"))
	if err != nil {
		return stateProof{}, fmt.Errorf("auth_secret proof failed: %w", err)
	}
	return stateProof{Pebble: pebbleResult, WAL: walResult, AuthSecret: secretResult}, nil
}

func excludedName(name string, excluded []string) bool {
	for _, candidate := range excluded {
		if candidate != "" && name == candidate {
			return true
		}
	}
	return false
}

func scanPebble(path string) (pebbleProof, error) {
	if err := validateTree(path); err != nil {
		return pebbleProof{}, err
	}
	db, err := pebble.Open(path, &pebble.Options{ReadOnly: true, Logger: privatePebbleLogger{}})
	if err != nil {
		return pebbleProof{}, errors.New("read-only open failed")
	}
	defer db.Close()

	iterator, err := db.NewIter(nil)
	if err != nil {
		return pebbleProof{}, errors.New("iterator creation failed")
	}
	defer iterator.Close()

	hasher := streamHasher()
	var result pebbleProof
	for iterator.First(); iterator.Valid(); iterator.Next() {
		key := iterator.Key()
		value := iterator.Value()
		if err := addUint64(&result.KeyCount, 1); err != nil {
			return pebbleProof{}, err
		}
		if err := addUint64(&result.KeyBytes, uint64(len(key))); err != nil {
			return pebbleProof{}, err
		}
		if err := addUint64(&result.ValueBytes, uint64(len(value))); err != nil {
			return pebbleProof{}, err
		}
		hasher.add(key, value)
	}
	if err := iterator.Error(); err != nil {
		return pebbleProof{}, errors.New("iterator scan failed")
	}
	result.StreamSHA256 = hasher.sum()
	return result, nil
}

func hashTree(root string) (treeProof, error) {
	if err := validateExistingDirectory(root); err != nil {
		return treeProof{}, err
	}
	var entries []manifestEntry
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("tree is unreadable")
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("tree entry could not be inspected")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink is not allowed")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("tree path could not be normalized")
		}
		relative = filepath.ToSlash(relative)
		switch {
		case info.IsDir():
			if !directoryModeReadable(info.Mode().Perm()) {
				return errors.New("directory permissions are unreadable")
			}
			entries = append(entries, manifestEntry{Path: relative, Kind: "directory", Mode: uint32(info.Mode().Perm())})
		case info.Mode().IsRegular():
			if !fileModeReadable(info.Mode().Perm()) {
				return errors.New("file permissions are unreadable")
			}
			digest, size, err := hashFile(path)
			if err != nil {
				return errors.New("tree file could not be read")
			}
			entries = append(entries, manifestEntry{Path: relative, Kind: "file", Mode: uint32(info.Mode().Perm()), Bytes: size, SHA256: digest})
		default:
			return errors.New("non-regular tree entry is not allowed")
		}
		return nil
	})
	if err != nil {
		return treeProof{}, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Path < entries[j].Path
	})

	manifestHasher := sha256.New()
	var result treeProof
	result.Entries = entries
	for _, entry := range entries {
		writeFrame(manifestHasher, []byte(entry.Kind))
		writeFrame(manifestHasher, []byte(entry.Path))
		var mode [4]byte
		binary.BigEndian.PutUint32(mode[:], entry.Mode)
		_, _ = manifestHasher.Write(mode[:])
		if entry.Kind == "directory" {
			if err := addUint64(&result.DirectoryCount, 1); err != nil {
				return treeProof{}, err
			}
			continue
		}
		if err := addUint64(&result.FileCount, 1); err != nil {
			return treeProof{}, err
		}
		if err := addUint64(&result.Bytes, entry.Bytes); err != nil {
			return treeProof{}, err
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], entry.Bytes)
		_, _ = manifestHasher.Write(size[:])
		writeFrame(manifestHasher, []byte(entry.SHA256))
	}
	result.ManifestSHA256 = hex.EncodeToString(manifestHasher.Sum(nil))
	return result, nil
}

func proveFile(path string) (fileProof, error) {
	if err := validateExistingRegularFile(path); err != nil {
		return fileProof{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fileProof{}, errors.New("file could not be inspected")
	}
	digest, size, err := hashFile(path)
	if err != nil {
		return fileProof{}, errors.New("file could not be read")
	}
	return fileProof{Mode: uint32(info.Mode().Perm()), Bytes: size, SHA256: digest}, nil
}

func compareStates(sourceBefore, checkpoint, sourceAfter stateProof) equalityProof {
	sourceStable := equalState(sourceBefore, sourceAfter)
	pebbleEqual := sourceBefore.Pebble == checkpoint.Pebble
	walEqual := equalTree(sourceBefore.WAL, checkpoint.WAL)
	secretEqual := sourceBefore.AuthSecret == checkpoint.AuthSecret
	return equalityProof{
		SourceStable:    sourceStable,
		PebbleEqual:     pebbleEqual,
		WALEqual:        walEqual,
		AuthSecretEqual: secretEqual,
		All:             sourceStable && pebbleEqual && walEqual && secretEqual,
	}
}

func equalState(left, right stateProof) bool {
	return left.Pebble == right.Pebble && equalTree(left.WAL, right.WAL) && left.AuthSecret == right.AuthSecret
}

func equalTree(left, right treeProof) bool {
	return left.DirectoryCount == right.DirectoryCount &&
		left.FileCount == right.FileCount &&
		left.Bytes == right.Bytes &&
		left.ManifestSHA256 == right.ManifestSHA256
}

func validateTree(root string) error {
	if err := validateExistingDirectory(root); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("tree is unreadable")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("tree entry could not be inspected")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink is not allowed")
		}
		if info.IsDir() {
			if !directoryModeReadable(info.Mode().Perm()) {
				return errors.New("directory permissions are unreadable")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular tree entry is not allowed")
		}
		if !fileModeReadable(info.Mode().Perm()) {
			return errors.New("file permissions are unreadable")
		}
		return nil
	})
}

func validateExistingDirectory(path string) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("directory does not exist")
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if !directoryModeReadable(info.Mode().Perm()) {
		return errors.New("directory permissions are unreadable")
	}
	return nil
}

func validateExistingRegularFile(path string) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("file does not exist")
	}
	if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	if !fileModeReadable(info.Mode().Perm()) {
		return errors.New("file permissions are unreadable")
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("path could not be normalized")
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	current := volume + string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(os.PathSeparator)), string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("path component does not exist")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink path component is not allowed")
		}
	}
	return nil
}

func requireAbsent(path, label string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("%s already exists", label)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("%s could not be inspected", label)
	}
	return nil
}

func validateOutputParent(path string) error {
	parent := filepath.Dir(path)
	if err := validateExistingDirectory(parent); err != nil {
		return errors.New("output parent is unsafe")
	}
	return nil
}

func hashFile(path string) (string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	count, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), uint64(count), nil
}

func addUint64(target *uint64, increment uint64) error {
	if ^uint64(0)-*target < increment {
		return errors.New("proof counter overflow")
	}
	*target += increment
	return nil
}

func fileModeReadable(mode fs.FileMode) bool {
	return mode&0444 != 0
}

func directoryModeReadable(mode fs.FileMode) bool {
	for _, shift := range []uint{6, 3, 0} {
		if mode&(4<<shift) != 0 && mode&(1<<shift) != 0 {
			return true
		}
	}
	return false
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func writePrivateReceipt(path string, receipt proofReceipt) (string, error) {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", errors.New("private receipt could not be encoded")
	}
	data = append(data, '\n')
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".checkpoint-proof-*.tmp")
	if err != nil {
		return "", errors.New("private receipt temporary file could not be created")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return "", errors.New("private receipt permissions could not be set")
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", errors.New("private receipt could not be written")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", errors.New("private receipt could not be synchronized")
	}
	if err := temporary.Close(); err != nil {
		return "", errors.New("private receipt could not be closed")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", errors.New("receipt path already exists")
		}
		return "", errors.New("private receipt could not be published")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return "", errors.New("receipt directory could not be opened")
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return "", errors.New("receipt directory could not be synchronized")
	}
	if err := directory.Close(); err != nil {
		return "", errors.New("receipt directory could not be closed")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func runBaselineBackup(sourceRoot, checkpointRoot, baselineBinary string) (backupExecution, error) {
	ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
	defer cancel()
	stdoutHasher := sha256.New()
	stderrHasher := sha256.New()
	command := exec.CommandContext(ctx, baselineBinary, "backup", "--data-dir", sourceRoot, "--output", checkpointRoot)
	command.Env = []string{"HOME=/nonexistent", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdout = stdoutHasher
	command.Stderr = stderrHasher
	err := command.Run()
	execution := backupExecution{
		ExitCode:     0,
		StdoutSHA256: hex.EncodeToString(stdoutHasher.Sum(nil)),
		StderrSHA256: hex.EncodeToString(stderrHasher.Sum(nil)),
	}
	if ctx.Err() == context.DeadlineExceeded {
		execution.ExitCode = -1
		return execution, errors.New("baseline backup command timed out")
	}
	if err == nil {
		return execution, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		execution.ExitCode = exitError.ExitCode()
		return execution, errors.New("baseline backup command failed")
	}
	execution.ExitCode = -1
	return execution, errors.New("baseline backup command could not start")
}

func failureSummary(_ error) publicSummary {
	return publicSummary{Valid: false, Error: "checkpoint_proof_failed"}
}

func runCLI(args []string, output io.Writer) (exitCode int) {
	if len(args) > 0 && args[0] == ownerEvidenceMode {
		return runOwnerEvidenceCLI(args[1:], output)
	}
	defer func() {
		if recover() != nil {
			_ = json.NewEncoder(output).Encode(failureSummary(errors.New("checkpoint proof internal fatal")))
			exitCode = 1
		}
	}()
	flags := flag.NewFlagSet("koala-stage-b-checkpoint-proof", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourceRoot := flags.String("source-root", "", "offline source data root")
	checkpointRoot := flags.String("checkpoint-root", "", "new checkpoint directory")
	receiptPath := flags.String("receipt", "", "new private receipt path")
	baselineBinary := flags.String("baseline-binary", "/usr/local/bin/muninndb-server", "pinned baseline binary")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		_ = json.NewEncoder(output).Encode(failureSummary(errors.New("invalid arguments")))
		return 2
	}
	config := proofConfig{
		SourceRoot:                  *sourceRoot,
		CheckpointRoot:              *checkpointRoot,
		ReceiptPath:                 *receiptPath,
		BaselineBinary:              *baselineBinary,
		ExpectedBaselineBinarySHA:   baselineBinarySHA256,
		ExpectedBaselineImageDigest: baselineImageDigest,
		BaselineSourceCommit:        baselineSourceCommit,
		HelperSourceCommit:          helperSourceCommit,
		Now:                         time.Now,
	}
	summary, err := executeProof(config, runBaselineBackup)
	_ = json.NewEncoder(output).Encode(summary)
	if err != nil {
		return 1
	}
	return 0
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout))
}
