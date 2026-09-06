package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cockroachdb/pebble"
	"github.com/dchest/siphash"
	"github.com/klauspost/compress/zstd"
	"github.com/oklog/ulid/v2"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sys/unix"
	"golang.org/x/text/unicode/norm"
)

const (
	ownerBindingSchema        = "koala-muninn-stage-b-owner-binding-v1"
	ownerManifestSchema       = "koala-muninn-stage-b-owner-bundle-v1"
	ownerAuthenticationSchema = "koala-muninn-stage-b-authentication-owner-v1"
	ownerEvidenceMode         = "owner-evidence"
	ownerVault                = "default"
	ownerPageSize             = 200
	ownerMaxRecords           = 1_000_000
	ownerMaxPages             = 10_000
	ownerMaxRecordBytes       = 1 * 1024 * 1024
	ownerMaxPageBytes         = 16 * 1024 * 1024
	ownerMaxInventoryBytes    = uint64(4) * 1024 * 1024 * 1024
	ownerMaxAuthKeys          = 10_000
	ownerMaxAuthBytes         = 4 * 1024 * 1024
	ownerMaxAge               = 5 * time.Minute
	ownerExpectedTarget       = "41014c46a482839a3e1761bbc397873898591bb3b8195bef27be9629a49ccee2"
	ownerERFFixedOverhead     = 152
	ownerERFVariableStart     = 152
	ownerERFTrailerSize       = 4
	ownerERFMaxConcept        = 512
	ownerERFMaxCreatedBy      = 64
	ownerERFMaxContent        = 16 * 1024
	ownerERFAssociationSize   = 40
)

var ownerCRC32Table = crc32.MakeTable(crc32.Castagnoli)

type ownerEvidenceConfig struct {
	DataRoot              string
	CheckpointReceiptPath string
	BindingPath           string
	OutputDir             string
	Now                   func() time.Time
}

type ownerBinding struct {
	SchemaVersion               string `json:"schema_version"`
	ObservedAt                  string `json:"observed_at"`
	SourceAppSHA256             string `json:"source_app_sha256"`
	SourceMachineSHA256         string `json:"source_machine_sha256"`
	SourceVolumeSHA256          string `json:"source_volume_sha256"`
	IntendedMachineConfigSHA256 string `json:"intended_machine_config_sha256"`
	ImageDigest                 string `json:"image_digest"`
	SourceCommit                string `json:"source_commit"`
	TargetFingerprint           string `json:"target_fingerprint"`
	SnapshotMetadataSHA256      string `json:"snapshot_metadata_sha256"`
	SnapshotSourceVolumeSHA256  string `json:"snapshot_source_volume_sha256"`
	SnapshotCreatedAt           string `json:"snapshot_created_at"`
	SnapshotRegion              string `json:"snapshot_region"`
	SnapshotSizeBytes           int64  `json:"snapshot_size_bytes"`
	SnapshotStatus              string `json:"snapshot_status"`
	RestoreMachineSHA256        string `json:"restore_machine_sha256"`
	RestoreVolumeSHA256         string `json:"restore_volume_sha256"`
	RestorePrivate              bool   `json:"restore_private"`
	StaticTokenPresent          bool   `json:"static_token_present"`
	StaticTokenReceiptSHA256    string `json:"static_token_receipt_sha256"`
	QuiescenceReceiptSHA256     string `json:"quiescence_receipt_sha256"`
	CheckpointReceiptSHA256     string `json:"checkpoint_receipt_sha256"`
	SnapshotReceiptSHA256       string `json:"snapshot_receipt_sha256"`
	ReceiptSHA256               string `json:"receipt_sha256"`
}

type ownerBindingBody struct {
	SchemaVersion               string `json:"schema_version"`
	ObservedAt                  string `json:"observed_at"`
	SourceAppSHA256             string `json:"source_app_sha256"`
	SourceMachineSHA256         string `json:"source_machine_sha256"`
	SourceVolumeSHA256          string `json:"source_volume_sha256"`
	IntendedMachineConfigSHA256 string `json:"intended_machine_config_sha256"`
	ImageDigest                 string `json:"image_digest"`
	SourceCommit                string `json:"source_commit"`
	TargetFingerprint           string `json:"target_fingerprint"`
	SnapshotMetadataSHA256      string `json:"snapshot_metadata_sha256"`
	SnapshotSourceVolumeSHA256  string `json:"snapshot_source_volume_sha256"`
	SnapshotCreatedAt           string `json:"snapshot_created_at"`
	SnapshotRegion              string `json:"snapshot_region"`
	SnapshotSizeBytes           int64  `json:"snapshot_size_bytes"`
	SnapshotStatus              string `json:"snapshot_status"`
	RestoreMachineSHA256        string `json:"restore_machine_sha256"`
	RestoreVolumeSHA256         string `json:"restore_volume_sha256"`
	RestorePrivate              bool   `json:"restore_private"`
	StaticTokenPresent          bool   `json:"static_token_present"`
	StaticTokenReceiptSHA256    string `json:"static_token_receipt_sha256"`
	QuiescenceReceiptSHA256     string `json:"quiescence_receipt_sha256"`
	CheckpointReceiptSHA256     string `json:"checkpoint_receipt_sha256"`
	SnapshotReceiptSHA256       string `json:"snapshot_receipt_sha256"`
}

type ownerInventoryRecord struct {
	ID         string   `json:"id"`
	Concept    string   `json:"concept"`
	Content    string   `json:"content"`
	Confidence float32  `json:"confidence"`
	Tags       []string `json:"tags"`
	Vault      string   `json:"vault"`
	CreatedAt  int64    `json:"created_at"`
	EmbedDim   uint8    `json:"embed_dim"`
}

type ownerInventoryPage struct {
	Engrams        []ownerInventoryRecord `json:"engrams"`
	Total          int                    `json:"total"`
	Limit          int                    `json:"limit"`
	Offset         int                    `json:"offset"`
	EntityCount    int                    `json:"entity_count"`
	ObservedAt     string                 `json:"observed_at"`
	SnapshotSHA256 string                 `json:"snapshot_sha256"`
}

type ownerAuthenticationKey struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Mode              string `json:"mode"`
	VaultPinned       bool   `json:"vault_pinned"`
}

type ownerAuthentication struct {
	SchemaVersion      string                   `json:"schema_version"`
	ObservedAt         string                   `json:"observed_at"`
	Complete           bool                     `json:"complete"`
	Truncated          bool                     `json:"truncated"`
	AuthenticationMode string                   `json:"authentication_mode"`
	Vault              string                   `json:"vault"`
	VaultPinned        bool                     `json:"vault_pinned"`
	StaticTokenPresent bool                     `json:"static_token_present"`
	AuthSecretPresent  bool                     `json:"auth_secret_present"`
	Keys               []ownerAuthenticationKey `json:"keys"`
}

type ownerArtifact struct {
	Path   string `json:"path"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type ownerManifest struct {
	SchemaVersion           string          `json:"schema_version"`
	ObservedAt              string          `json:"observed_at"`
	SnapshotSHA256          string          `json:"snapshot_sha256"`
	TargetFingerprint       string          `json:"target_fingerprint"`
	ImageDigest             string          `json:"image_digest"`
	SourceCommit            string          `json:"source_commit"`
	EngramCount             int             `json:"engram_count"`
	EntityCount             int             `json:"entity_count"`
	PageCount               int             `json:"page_count"`
	AuthenticationKeyCount  int             `json:"authentication_key_count"`
	Pages                   []ownerArtifact `json:"pages"`
	Authentication          ownerArtifact   `json:"authentication"`
	BindingReceiptSHA256    string          `json:"binding_receipt_sha256"`
	CheckpointReceiptSHA256 string          `json:"checkpoint_receipt_sha256"`
	RestoredStateSHA256     string          `json:"restored_state_sha256"`
	ReceiptSHA256           string          `json:"receipt_sha256"`
}

type ownerManifestBody struct {
	SchemaVersion           string          `json:"schema_version"`
	ObservedAt              string          `json:"observed_at"`
	SnapshotSHA256          string          `json:"snapshot_sha256"`
	TargetFingerprint       string          `json:"target_fingerprint"`
	ImageDigest             string          `json:"image_digest"`
	SourceCommit            string          `json:"source_commit"`
	EngramCount             int             `json:"engram_count"`
	EntityCount             int             `json:"entity_count"`
	PageCount               int             `json:"page_count"`
	AuthenticationKeyCount  int             `json:"authentication_key_count"`
	Pages                   []ownerArtifact `json:"pages"`
	Authentication          ownerArtifact   `json:"authentication"`
	BindingReceiptSHA256    string          `json:"binding_receipt_sha256"`
	CheckpointReceiptSHA256 string          `json:"checkpoint_receipt_sha256"`
	RestoredStateSHA256     string          `json:"restored_state_sha256"`
}

type ownerPublicSummary struct {
	Valid                  bool   `json:"valid"`
	EngramCount            int    `json:"engram_count,omitempty"`
	EntityCount            int    `json:"entity_count,omitempty"`
	PageCount              int    `json:"page_count,omitempty"`
	AuthenticationKeyCount int    `json:"authentication_key_count,omitempty"`
	ManifestSHA256         string `json:"manifest_sha256,omitempty"`
	ReceiptSHA256          string `json:"receipt_sha256,omitempty"`
	Error                  string `json:"error,omitempty"`
}

type ownerAPIKey struct {
	ID          string     `json:"id"`
	Vault       string     `json:"vault"`
	Label       string     `json:"label"`
	Mode        string     `json:"mode"`
	CreatedAt   time.Time  `json:"created_at"`
	StorageHash []byte     `json:"storage_hash"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type ownerEntityRecord struct {
	Name         string  `msgpack:"name"`
	Type         string  `msgpack:"type"`
	Confidence   float32 `msgpack:"confidence"`
	Source       string  `msgpack:"source"`
	UpdatedAt    int64   `msgpack:"updated_at"`
	FirstSeen    int64   `msgpack:"first_seen"`
	MentionCount int32   `msgpack:"mention_count"`
	State        string  `msgpack:"state"`
	MergedInto   string  `msgpack:"merged_into"`
}

type ownerRecordRef struct {
	CreatedAt int64
	ID        [16]byte
	Offset    int64
	Length    uint32
}

func runOwnerEvidenceCLI(args []string, output io.Writer) (exitCode int) {
	defer func() {
		if recover() != nil {
			_ = json.NewEncoder(output).Encode(ownerFailureSummary())
			exitCode = 1
		}
	}()
	flags := flag.NewFlagSet("koala-stage-b-checkpoint-proof owner-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dataRoot := flags.String("data-root", "", "restored offline data root")
	checkpointReceipt := flags.String("checkpoint-receipt", "", "prior checkpoint proof receipt")
	binding := flags.String("owner-binding", "", "strict owner binding document")
	outputDir := flags.String("output-dir", "", "new private owner evidence directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		_ = json.NewEncoder(output).Encode(ownerFailureSummary())
		return 2
	}
	summary, err := executeOwnerEvidence(ownerEvidenceConfig{
		DataRoot:              *dataRoot,
		CheckpointReceiptPath: *checkpointReceipt,
		BindingPath:           *binding,
		OutputDir:             *outputDir,
		Now:                   time.Now,
	})
	_ = json.NewEncoder(output).Encode(summary)
	if err != nil {
		return 1
	}
	return 0
}

func executeOwnerEvidence(config ownerEvidenceConfig) (ownerPublicSummary, error) {
	if err := validateOwnerConfig(config); err != nil {
		return ownerFailureSummary(), err
	}
	binding, err := readOwnerBinding(config.BindingPath, config.Now().UTC())
	if err != nil {
		return ownerFailureSummary(), err
	}
	checkpoint, checkpointSHA, err := readCheckpointReceipt(config.CheckpointReceiptPath)
	if err != nil {
		return ownerFailureSummary(), err
	}
	if checkpointSHA != binding.CheckpointReceiptSHA256 {
		return ownerFailureSummary(), errors.New("checkpoint receipt binding mismatch")
	}
	restored, err := inspectDataRoot(config.DataRoot)
	if err != nil {
		return ownerFailureSummary(), errors.New("restored data root proof failed")
	}
	if !equalState(restored, checkpoint.Checkpoint) {
		return ownerFailureSummary(), errors.New("restored data root does not match checkpoint")
	}
	if restored.AuthSecret.Bytes == 0 {
		return ownerFailureSummary(), errors.New("restored auth secret is absent")
	}

	parent := filepath.Dir(config.OutputDir)
	temporary, err := os.MkdirTemp(parent, ".owner-evidence-*.tmp")
	if err != nil {
		return ownerFailureSummary(), errors.New("private output temporary directory could not be created")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0700); err != nil {
		return ownerFailureSummary(), errors.New("private output directory permissions could not be set")
	}

	db, err := pebble.Open(filepath.Join(config.DataRoot, "pebble"), &pebble.Options{ReadOnly: true, Logger: privatePebbleLogger{}})
	if err != nil {
		return ownerFailureSummary(), errors.New("restored database read-only open failed")
	}
	defer db.Close()
	vaultPrefix, err := resolveOwnerVault(db, ownerVault)
	if err != nil {
		return ownerFailureSummary(), err
	}
	entityCount, err := countOwnerEntities(db, vaultPrefix)
	if err != nil {
		return ownerFailureSummary(), err
	}
	inventoryDir := filepath.Join(temporary, "inventory")
	if err := os.Mkdir(inventoryDir, 0700); err != nil {
		return ownerFailureSummary(), errors.New("private inventory directory could not be created")
	}
	refs, spoolPath, aggregateBytes, err := spoolOwnerInventory(db, vaultPrefix, temporary)
	if err != nil {
		return ownerFailureSummary(), err
	}
	if aggregateBytes > ownerMaxInventoryBytes {
		return ownerFailureSummary(), errors.New("inventory aggregate byte ceiling exceeded")
	}
	defer os.Remove(spoolPath)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].CreatedAt != refs[j].CreatedAt {
			return refs[i].CreatedAt > refs[j].CreatedAt
		}
		return bytes.Compare(refs[i].ID[:], refs[j].ID[:]) < 0
	})
	pages, err := writeOwnerPages(spoolPath, inventoryDir, refs, entityCount, binding)
	if err != nil {
		return ownerFailureSummary(), err
	}
	authentication, err := readOwnerAuthentication(db, binding, restored.AuthSecret.Bytes > 0)
	if err != nil {
		return ownerFailureSummary(), err
	}
	authArtifact, err := writeOwnerJSON(filepath.Join(temporary, "authentication.json"), authentication)
	if err != nil {
		return ownerFailureSummary(), err
	}
	if authArtifact.Bytes > ownerMaxAuthBytes {
		return ownerFailureSummary(), errors.New("authentication inventory byte ceiling exceeded")
	}
	restoredSHA, err := ownerCanonicalSHA(restored)
	if err != nil {
		return ownerFailureSummary(), err
	}
	manifestBody := ownerManifestBody{
		SchemaVersion:           ownerManifestSchema,
		ObservedAt:              binding.ObservedAt,
		SnapshotSHA256:          binding.SnapshotMetadataSHA256,
		TargetFingerprint:       binding.TargetFingerprint,
		ImageDigest:             binding.ImageDigest,
		SourceCommit:            binding.SourceCommit,
		EngramCount:             len(refs),
		EntityCount:             entityCount,
		PageCount:               len(pages),
		AuthenticationKeyCount:  len(authentication.Keys),
		Pages:                   pages,
		Authentication:          authArtifact,
		BindingReceiptSHA256:    binding.ReceiptSHA256,
		CheckpointReceiptSHA256: checkpointSHA,
		RestoredStateSHA256:     restoredSHA,
	}
	manifestReceipt, err := ownerCanonicalSHA(manifestBody)
	if err != nil {
		return ownerFailureSummary(), err
	}
	manifest := ownerManifest{
		SchemaVersion:           manifestBody.SchemaVersion,
		ObservedAt:              manifestBody.ObservedAt,
		SnapshotSHA256:          manifestBody.SnapshotSHA256,
		TargetFingerprint:       manifestBody.TargetFingerprint,
		ImageDigest:             manifestBody.ImageDigest,
		SourceCommit:            manifestBody.SourceCommit,
		EngramCount:             manifestBody.EngramCount,
		EntityCount:             manifestBody.EntityCount,
		PageCount:               manifestBody.PageCount,
		AuthenticationKeyCount:  manifestBody.AuthenticationKeyCount,
		Pages:                   manifestBody.Pages,
		Authentication:          manifestBody.Authentication,
		BindingReceiptSHA256:    manifestBody.BindingReceiptSHA256,
		CheckpointReceiptSHA256: manifestBody.CheckpointReceiptSHA256,
		RestoredStateSHA256:     manifestBody.RestoredStateSHA256,
		ReceiptSHA256:           manifestReceipt,
	}
	manifestArtifact, err := writeOwnerJSON(filepath.Join(temporary, "manifest.json"), manifest)
	if err != nil {
		return ownerFailureSummary(), err
	}
	if err := syncOwnerDirectory(inventoryDir); err != nil {
		return ownerFailureSummary(), err
	}
	if err := syncOwnerDirectory(temporary); err != nil {
		return ownerFailureSummary(), err
	}
	if err := unix.Renameat2(
		unix.AT_FDCWD, temporary,
		unix.AT_FDCWD, config.OutputDir,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return ownerFailureSummary(), errors.New("private output directory could not be published")
	}
	if err := syncOwnerDirectory(parent); err != nil {
		_ = os.RemoveAll(config.OutputDir)
		_ = syncOwnerDirectory(parent)
		return ownerFailureSummary(), err
	}
	published = true
	return ownerPublicSummary{
		Valid:                  true,
		EngramCount:            len(refs),
		EntityCount:            entityCount,
		PageCount:              len(pages),
		AuthenticationKeyCount: len(authentication.Keys),
		ManifestSHA256:         manifestArtifact.SHA256,
		ReceiptSHA256:          manifestReceipt,
	}, nil
}

func validateOwnerConfig(config ownerEvidenceConfig) error {
	if config.DataRoot == "" || config.CheckpointReceiptPath == "" || config.BindingPath == "" || config.OutputDir == "" {
		return errors.New("all owner evidence paths are required")
	}
	if config.Now == nil {
		return errors.New("owner evidence clock is required")
	}
	if err := validateExistingDirectory(config.DataRoot); err != nil {
		return errors.New("restored data root is unsafe")
	}
	if err := validatePrivateInputFile(config.CheckpointReceiptPath); err != nil {
		return errors.New("checkpoint receipt is unsafe")
	}
	if err := validatePrivateInputFile(config.BindingPath); err != nil {
		return errors.New("owner binding is unsafe")
	}
	if err := requireAbsent(config.OutputDir, "owner evidence output path"); err != nil {
		return err
	}
	if err := validateOutputParent(config.OutputDir); err != nil {
		return err
	}
	data, err := filepath.Abs(config.DataRoot)
	if err != nil {
		return errors.New("restored data root could not be normalized")
	}
	output, err := filepath.Abs(config.OutputDir)
	if err != nil {
		return errors.New("owner evidence output path could not be normalized")
	}
	if data == output || pathInside(data, output) || pathInside(output, data) {
		return errors.New("owner evidence output path must be separate from restored data")
	}
	return nil
}

func validatePrivateInputFile(path string) error {
	if err := validateExistingRegularFile(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		return errors.New("private input must have mode 0600")
	}
	return nil
}

func readOwnerBinding(path string, now time.Time) (ownerBinding, error) {
	var binding ownerBinding
	data, err := os.ReadFile(path)
	if err != nil || len(data) > ownerMaxAuthBytes {
		return binding, errors.New("owner binding could not be read")
	}
	if err := ownerStrictJSON(data, &binding); err != nil || !ownerCanonicalMatches(data, binding) {
		return binding, errors.New("owner binding is malformed")
	}
	body := ownerBindingBody{
		SchemaVersion:               binding.SchemaVersion,
		ObservedAt:                  binding.ObservedAt,
		SourceAppSHA256:             binding.SourceAppSHA256,
		SourceMachineSHA256:         binding.SourceMachineSHA256,
		SourceVolumeSHA256:          binding.SourceVolumeSHA256,
		IntendedMachineConfigSHA256: binding.IntendedMachineConfigSHA256,
		ImageDigest:                 binding.ImageDigest,
		SourceCommit:                binding.SourceCommit,
		TargetFingerprint:           binding.TargetFingerprint,
		SnapshotMetadataSHA256:      binding.SnapshotMetadataSHA256,
		SnapshotSourceVolumeSHA256:  binding.SnapshotSourceVolumeSHA256,
		SnapshotCreatedAt:           binding.SnapshotCreatedAt,
		SnapshotRegion:              binding.SnapshotRegion,
		SnapshotSizeBytes:           binding.SnapshotSizeBytes,
		SnapshotStatus:              binding.SnapshotStatus,
		RestoreMachineSHA256:        binding.RestoreMachineSHA256,
		RestoreVolumeSHA256:         binding.RestoreVolumeSHA256,
		RestorePrivate:              binding.RestorePrivate,
		StaticTokenPresent:          binding.StaticTokenPresent,
		StaticTokenReceiptSHA256:    binding.StaticTokenReceiptSHA256,
		QuiescenceReceiptSHA256:     binding.QuiescenceReceiptSHA256,
		CheckpointReceiptSHA256:     binding.CheckpointReceiptSHA256,
		SnapshotReceiptSHA256:       binding.SnapshotReceiptSHA256,
	}
	expectedReceipt, err := ownerCanonicalSHA(body)
	if err != nil || expectedReceipt != binding.ReceiptSHA256 {
		return binding, errors.New("owner binding receipt mismatch")
	}
	observed, err := ownerStrictTime(binding.ObservedAt)
	if err != nil || observed.After(now) || now.Sub(observed) > ownerMaxAge {
		return binding, errors.New("owner binding is stale")
	}
	snapshotCreated, err := ownerStrictTime(binding.SnapshotCreatedAt)
	if err != nil || snapshotCreated.After(observed) || observed.Sub(snapshotCreated) > ownerMaxAge {
		return binding, errors.New("snapshot binding is stale")
	}
	for _, value := range []string{
		binding.SourceAppSHA256, binding.SourceMachineSHA256, binding.SourceVolumeSHA256,
		binding.IntendedMachineConfigSHA256, binding.SnapshotMetadataSHA256,
		binding.SnapshotSourceVolumeSHA256, binding.RestoreMachineSHA256,
		binding.RestoreVolumeSHA256, binding.StaticTokenReceiptSHA256,
		binding.QuiescenceReceiptSHA256, binding.CheckpointReceiptSHA256,
		binding.SnapshotReceiptSHA256, binding.ReceiptSHA256,
	} {
		if !isLowerHex(value, 64) {
			return binding, errors.New("owner binding digest is malformed")
		}
	}
	if binding.SchemaVersion != ownerBindingSchema ||
		binding.ImageDigest != baselineImageDigest ||
		binding.SourceCommit != baselineSourceCommit ||
		binding.TargetFingerprint != ownerExpectedTarget ||
		binding.SnapshotSourceVolumeSHA256 != binding.SourceVolumeSHA256 ||
		binding.SnapshotStatus != "completed" || binding.SnapshotRegion == "" ||
		binding.SnapshotSizeBytes <= 0 || !binding.RestorePrivate || !binding.StaticTokenPresent {
		return binding, errors.New("owner binding does not satisfy immutable requirements")
	}
	return binding, nil
}

func readCheckpointReceipt(path string) (proofReceipt, string, error) {
	var receipt proofReceipt
	data, err := os.ReadFile(path)
	if err != nil || len(data) > ownerMaxPageBytes {
		return receipt, "", errors.New("checkpoint receipt could not be read")
	}
	if err := ownerStrictJSON(data, &receipt); err != nil {
		return receipt, "", errors.New("checkpoint receipt is malformed")
	}
	if receipt.SchemaVersion != proofSchemaVersion || !receipt.Equality.All || !receipt.Equality.SourceStable ||
		!receipt.Equality.PebbleEqual || !receipt.Equality.WALEqual || !receipt.Equality.AuthSecretEqual ||
		receipt.Identity.BaselineImageDigest != baselineImageDigest ||
		receipt.Identity.BaselineSourceCommit != baselineSourceCommit ||
		!isLowerHex(receipt.Identity.BaselineBinarySHA256, 64) || !isLowerHex(receipt.Identity.HelperSourceCommit, 40) {
		return receipt, "", errors.New("checkpoint receipt is incomplete")
	}
	if !equalState(receipt.SourceBefore, receipt.Checkpoint) || !equalState(receipt.Checkpoint, receipt.SourceAfter) {
		return receipt, "", errors.New("checkpoint receipt equality is inconsistent")
	}
	sum := sha256.Sum256(data)
	return receipt, hex.EncodeToString(sum[:]), nil
}

func resolveOwnerVault(db *pebble.DB, vault string) ([8]byte, error) {
	computed := ownerVaultPrefix(vault)
	indexKey := append([]byte{0x0f}, computed[:]...)
	value, closer, err := db.Get(indexKey)
	if errors.Is(err, pebble.ErrNotFound) {
		return computed, nil
	}
	if err != nil {
		return [8]byte{}, errors.New("vault index could not be read")
	}
	defer closer.Close()
	if len(value) != 8 {
		return [8]byte{}, errors.New("vault index is malformed")
	}
	var result [8]byte
	copy(result[:], value)
	return result, nil
}

func ownerVaultPrefix(value string) [8]byte {
	hashValue := siphash.Hash(0x736f6d6570736575, 0x646f72616e646f6d, []byte(value))
	var result [8]byte
	binary.BigEndian.PutUint64(result[:], hashValue)
	return result
}

func ownerEntityIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(norm.NFKC.String(value)))
}

func ownerEntityHash(value string) [8]byte {
	hashValue := siphash.Hash(0x736f6d6570736575, 0x646f72616e646f6d, []byte(ownerEntityIdentity(value)))
	var result [8]byte
	binary.BigEndian.PutUint64(result[:], hashValue)
	return result
}

func countOwnerEntities(db *pebble.DB, vault [8]byte) (int, error) {
	prefix := append([]byte{0x20}, vault[:]...)
	iterator, err := db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: ownerPrefixEnd(prefix)})
	if err != nil {
		return 0, errors.New("entity link iterator could not be created")
	}
	defer iterator.Close()
	seen := make(map[string]struct{})
	count := 0
	for iterator.First(); iterator.Valid(); iterator.Next() {
		key := iterator.Key()
		value := iterator.Value()
		if len(key) != 33 || len(value) == 0 || !utf8.Valid(value) {
			return 0, errors.New("entity link is malformed")
		}
		name := string(value)
		identity := ownerEntityIdentity(name)
		if identity == "" {
			return 0, errors.New("entity identity is empty")
		}
		hashValue := ownerEntityHash(name)
		if !bytes.Equal(key[25:33], hashValue[:]) {
			return 0, errors.New("entity link hash mismatch")
		}
		if _, exists := seen[identity]; exists {
			continue
		}
		recordKey := append([]byte{0x1f}, hashValue[:]...)
		recordValue, closer, getErr := db.Get(recordKey)
		if errors.Is(getErr, pebble.ErrNotFound) {
			continue
		}
		if getErr != nil {
			return 0, errors.New("entity record could not be read")
		}
		var record ownerEntityRecord
		decodeErr := ownerStrictMsgpack(recordValue, &record)
		closer.Close()
		if decodeErr != nil || !validOwnerEntityRecord(record, identity) {
			return 0, errors.New("entity record is malformed")
		}
		seen[identity] = struct{}{}
		count++
	}
	if err := iterator.Error(); err != nil {
		return 0, errors.New("entity link scan failed")
	}
	return count, nil
}

func validOwnerEntityRecord(record ownerEntityRecord, identity string) bool {
	if !utf8.ValidString(record.Name) || ownerEntityIdentity(record.Name) != identity ||
		!utf8.ValidString(record.Type) || strings.TrimSpace(record.Type) == "" ||
		!utf8.ValidString(record.Source) || strings.TrimSpace(record.Source) == "" ||
		math.IsNaN(float64(record.Confidence)) || math.IsInf(float64(record.Confidence), 0) ||
		record.Confidence < 0 || record.Confidence > 1 || record.MentionCount < 0 ||
		record.UpdatedAt < 0 || record.FirstSeen < 0 || record.UpdatedAt < record.FirstSeen {
		return false
	}
	switch record.State {
	case "active", "deprecated", "resolved":
		return record.MergedInto == ""
	case "merged":
		return utf8.ValidString(record.MergedInto) && ownerEntityIdentity(record.MergedInto) != ""
	default:
		return false
	}
}

func spoolOwnerInventory(db *pebble.DB, vault [8]byte, directory string) ([]ownerRecordRef, string, uint64, error) {
	spool, err := os.CreateTemp(directory, ".inventory-records-*.tmp")
	if err != nil {
		return nil, "", 0, errors.New("inventory spool could not be created")
	}
	spoolPath := spool.Name()
	remove := true
	defer func() {
		_ = spool.Close()
		if remove {
			_ = os.Remove(spoolPath)
		}
	}()
	if err := spool.Chmod(0600); err != nil {
		return nil, "", 0, errors.New("inventory spool permissions could not be set")
	}
	prefix := append([]byte{0x01}, vault[:]...)
	iterator, err := db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: ownerPrefixEnd(prefix)})
	if err != nil {
		return nil, "", 0, errors.New("inventory iterator could not be created")
	}
	defer iterator.Close()
	refs := make([]ownerRecordRef, 0)
	seen := make(map[[16]byte]struct{})
	var aggregate uint64
	for iterator.First(); iterator.Valid(); iterator.Next() {
		key := iterator.Key()
		if len(key) != 25 || !bytes.Equal(key[1:9], vault[:]) {
			return nil, "", 0, errors.New("engram key is malformed")
		}
		var id [16]byte
		copy(id[:], key[9:25])
		if _, exists := seen[id]; exists {
			return nil, "", 0, errors.New("duplicate engram identifier")
		}
		seen[id] = struct{}{}
		if len(seen) > ownerMaxRecords {
			return nil, "", 0, errors.New("inventory record ceiling exceeded")
		}
		record, include, decodeErr := decodeOwnerERF(iterator.Value(), id)
		if decodeErr != nil {
			return nil, "", 0, decodeErr
		}
		if !include {
			continue
		}
		encoded, encodeErr := ownerCanonicalJSON(record)
		if encodeErr != nil || len(encoded) > ownerMaxRecordBytes {
			return nil, "", 0, errors.New("inventory record byte ceiling exceeded")
		}
		if ^uint64(0)-aggregate < uint64(len(encoded)) {
			return nil, "", 0, errors.New("inventory aggregate byte counter overflow")
		}
		aggregate += uint64(len(encoded))
		if aggregate > ownerMaxInventoryBytes {
			return nil, "", 0, errors.New("inventory aggregate byte ceiling exceeded")
		}
		offset, seekErr := spool.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return nil, "", 0, errors.New("inventory spool position could not be read")
		}
		if _, writeErr := spool.Write(encoded); writeErr != nil {
			return nil, "", 0, errors.New("inventory spool could not be written")
		}
		refs = append(refs, ownerRecordRef{CreatedAt: record.CreatedAt, ID: id, Offset: offset, Length: uint32(len(encoded))})
	}
	if err := iterator.Error(); err != nil {
		return nil, "", 0, errors.New("inventory scan failed")
	}
	if err := spool.Sync(); err != nil {
		return nil, "", 0, errors.New("inventory spool could not be synchronized")
	}
	if err := spool.Close(); err != nil {
		return nil, "", 0, errors.New("inventory spool could not be closed")
	}
	remove = false
	return refs, spoolPath, aggregate, nil
}

func decodeOwnerERF(data []byte, keyID [16]byte) (ownerInventoryRecord, bool, error) {
	if len(data) < ownerERFFixedOverhead || len(data) > ownerMaxRecordBytes {
		return ownerInventoryRecord{}, false, errors.New("engram record size is invalid")
	}
	if binary.BigEndian.Uint32(data[0:4]) != 0x4d554e4e || (data[4] != 0x01 && data[4] != 0x02) || !ownerVerifyCRC16(data[:8]) {
		return ownerInventoryRecord{}, false, errors.New("engram record header is invalid")
	}
	if !ownerVerifyCRC32(data) {
		return ownerInventoryRecord{}, false, errors.New("engram record checksum is invalid")
	}
	if !bytes.Equal(data[8:24], keyID[:]) {
		return ownerInventoryRecord{}, false, errors.New("engram key and record identifier mismatch")
	}
	state := data[64]
	if state > 0x06 && state != 0x7f {
		return ownerInventoryRecord{}, false, errors.New("engram lifecycle state is unsupported")
	}
	if state == 0x06 || state == 0x7f {
		return ownerInventoryRecord{}, false, nil
	}
	conceptOff := binary.BigEndian.Uint32(data[108:112])
	conceptLen := uint32(binary.BigEndian.Uint16(data[112:114]))
	createdByOff := binary.BigEndian.Uint32(data[114:118])
	createdByLen := uint32(binary.BigEndian.Uint16(data[118:120]))
	contentOff := binary.BigEndian.Uint32(data[120:124])
	contentLen := binary.BigEndian.Uint32(data[124:128])
	tagsOff := binary.BigEndian.Uint32(data[128:132])
	tagsLen := binary.BigEndian.Uint32(data[132:136])
	assocOff := binary.BigEndian.Uint32(data[136:140])
	assocLen := binary.BigEndian.Uint32(data[140:144])
	embedOff := binary.BigEndian.Uint32(data[144:148])
	embedLen := binary.BigEndian.Uint32(data[148:152])
	sections := [][2]uint32{{conceptOff, conceptLen}, {createdByOff, createdByLen}, {contentOff, contentLen}, {tagsOff, tagsLen}, {assocOff, assocLen}, {embedOff, embedLen}}
	trailer := uint64(len(data) - ownerERFTrailerSize)
	expectedOffset := uint64(ownerERFVariableStart)
	for _, section := range sections {
		if section[1] == 0 {
			if section[0] != 0 && uint64(section[0]) != expectedOffset {
				return ownerInventoryRecord{}, false, errors.New("engram empty variable section offset is invalid")
			}
			continue
		}
		if uint64(section[0]) != expectedOffset || uint64(section[0])+uint64(section[1]) > trailer {
			return ownerInventoryRecord{}, false, errors.New("engram variable sections are not contiguous")
		}
		expectedOffset += uint64(section[1])
	}
	if conceptLen == 0 || conceptLen > ownerERFMaxConcept || createdByLen > ownerERFMaxCreatedBy || assocLen%ownerERFAssociationSize != 0 ||
		int(binary.BigEndian.Uint16(data[65:67])) != int(assocLen)/ownerERFAssociationSize {
		return ownerInventoryRecord{}, false, errors.New("engram variable section length is invalid")
	}
	if err := validateOwnerTaggedFields(data[expectedOffset:trailer]); err != nil {
		return ownerInventoryRecord{}, false, err
	}
	conceptBytes := data[conceptOff : conceptOff+conceptLen]
	createdByBytes := data[createdByOff : createdByOff+createdByLen]
	contentBytes := data[contentOff : contentOff+contentLen]
	if !utf8.Valid(conceptBytes) || !utf8.Valid(createdByBytes) {
		return ownerInventoryRecord{}, false, errors.New("engram text is not valid UTF-8")
	}
	if data[5]&(1<<1) != 0 {
		decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(ownerERFMaxContent), zstd.WithDecoderMaxWindow(ownerERFMaxContent))
		if err != nil {
			return ownerInventoryRecord{}, false, errors.New("engram decompressor could not be created")
		}
		decompressed, err := decoder.DecodeAll(contentBytes, nil)
		decoder.Close()
		if err != nil {
			return ownerInventoryRecord{}, false, errors.New("engram content could not be decompressed")
		}
		contentBytes = decompressed
	}
	if len(contentBytes) > ownerERFMaxContent || !utf8.Valid(contentBytes) {
		return ownerInventoryRecord{}, false, errors.New("engram content is invalid")
	}
	var tags []string
	if tagsLen > 0 {
		if err := ownerStrictMsgpack(data[tagsOff:tagsOff+tagsLen], &tags); err != nil {
			return ownerInventoryRecord{}, false, errors.New("engram tags are malformed")
		}
	}
	seenTags := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if !utf8.ValidString(tag) {
			return ownerInventoryRecord{}, false, errors.New("engram tag is not valid UTF-8")
		}
		if _, exists := seenTags[tag]; exists {
			return ownerInventoryRecord{}, false, errors.New("engram tags contain a duplicate")
		}
		seenTags[tag] = struct{}{}
	}
	if data[4] == 0x02 && (assocLen != 0 || embedLen != 0) {
		return ownerInventoryRecord{}, false, errors.New("engram v2 contains inline association or embedding data")
	}
	flags := data[5]
	if flags&(1<<0) == 0 && embedLen != 0 || flags&(1<<0) != 0 && embedLen == 0 && data[4] == 0x01 {
		return ownerInventoryRecord{}, false, errors.New("engram embedding flags are inconsistent")
	}
	if embedLen > 0 {
		if flags&(1<<2) != 0 {
			if embedLen < 8 {
				return ownerInventoryRecord{}, false, errors.New("engram quantized embedding is malformed")
			}
		} else if embedLen%4 != 0 {
			return ownerInventoryRecord{}, false, errors.New("engram embedding is malformed")
		}
	}
	confidence := math.Float32frombits(binary.BigEndian.Uint32(data[48:52]))
	if math.IsNaN(float64(confidence)) || math.IsInf(float64(confidence), 0) || confidence < 0 || confidence > 1 {
		return ownerInventoryRecord{}, false, errors.New("engram confidence is invalid")
	}
	createdNanos := int64(binary.BigEndian.Uint64(data[24:32]))
	if createdNanos < 0 {
		return ownerInventoryRecord{}, false, errors.New("engram creation time is invalid")
	}
	identifier, err := ulid.ParseStrict(ulid.ULID(keyID).String())
	if err != nil || !bytes.Equal(identifier[:], keyID[:]) {
		return ownerInventoryRecord{}, false, errors.New("engram identifier is invalid")
	}
	sort.Strings(tags)
	return ownerInventoryRecord{
		ID: identifier.String(), Concept: string(conceptBytes), Content: string(contentBytes),
		Confidence: confidence, Tags: tags, Vault: ownerVault,
		CreatedAt: time.Unix(0, createdNanos).Unix(), EmbedDim: data[67],
	}, true, nil
}

func validateOwnerTaggedFields(data []byte) error {
	seen := make(map[byte]struct{})
	for len(data) > 0 {
		if len(data) < 3 {
			return errors.New("engram tagged extension is truncated")
		}
		tag := data[0]
		length := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < length || (tag != 0x19 && tag != 0x1a && tag != 0x1b) {
			return errors.New("engram tagged extension is malformed")
		}
		if _, exists := seen[tag]; exists {
			return errors.New("engram tagged extension is duplicated")
		}
		seen[tag] = struct{}{}
		value := data[:length]
		switch tag {
		case 0x19, 0x1a:
			if !utf8.Valid(value) {
				return errors.New("engram tagged text is not valid UTF-8")
			}
		case 0x1b:
			var points []string
			if err := ownerStrictMsgpack(value, &points); err != nil {
				return errors.New("engram key points are malformed")
			}
			for _, point := range points {
				if !utf8.ValidString(point) {
					return errors.New("engram key point is not valid UTF-8")
				}
			}
		}
		data = data[length:]
	}
	return nil
}

func ownerStrictMsgpack(data []byte, target any) error {
	decoder := msgpack.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing MessagePack data")
	}
	return nil
}

func ownerVerifyCRC16(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	crc := uint32(0xffff)
	for _, value := range data[:6] {
		crc ^= uint32(value) << 8
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x10000 != 0 {
				crc ^= 0x1021
			}
		}
	}
	return binary.BigEndian.Uint16(data[6:8]) == uint16(crc^0xffff)
}

func ownerVerifyCRC32(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	position := len(data) - 4
	return binary.BigEndian.Uint32(data[position:]) == crc32.Checksum(data[:position], ownerCRC32Table)
}

func writeOwnerPages(spoolPath, inventoryDir string, refs []ownerRecordRef, entityCount int, binding ownerBinding) ([]ownerArtifact, error) {
	spool, err := os.Open(spoolPath)
	if err != nil {
		return nil, errors.New("inventory spool could not be opened")
	}
	defer spool.Close()
	pages := make([]ownerArtifact, 0, (len(refs)+ownerPageSize-1)/ownerPageSize+1)
	for offset := 0; ; {
		end := offset + ownerPageSize
		if end > len(refs) {
			end = len(refs)
		}
		rows := make([]ownerInventoryRecord, 0, end-offset)
		var pageBytes uint64
		for _, ref := range refs[offset:end] {
			data := make([]byte, ref.Length)
			if _, err := spool.ReadAt(data, ref.Offset); err != nil {
				return nil, errors.New("inventory spool could not be read")
			}
			var row ownerInventoryRecord
			if err := ownerStrictJSON(data, &row); err != nil {
				return nil, errors.New("inventory spool record is malformed")
			}
			pageBytes += uint64(len(data))
			if pageBytes > ownerMaxPageBytes {
				return nil, errors.New("inventory page byte ceiling exceeded")
			}
			rows = append(rows, row)
		}
		page := ownerInventoryPage{Engrams: rows, Total: len(refs), Limit: ownerPageSize, Offset: offset, EntityCount: entityCount, ObservedAt: binding.ObservedAt, SnapshotSHA256: binding.SnapshotMetadataSHA256}
		name := fmt.Sprintf("page-%06d.json", len(pages))
		artifact, err := writeOwnerJSON(filepath.Join(inventoryDir, name), page)
		if err != nil {
			return nil, err
		}
		artifact.Path = filepath.ToSlash(filepath.Join("inventory", name))
		pages = append(pages, artifact)
		if len(pages) > ownerMaxPages {
			return nil, errors.New("inventory page ceiling exceeded")
		}
		if offset == len(refs) {
			break
		}
		offset = end
	}
	return pages, nil
}

func readOwnerAuthentication(db *pebble.DB, binding ownerBinding, authSecretPresent bool) (ownerAuthentication, error) {
	result := ownerAuthentication{
		SchemaVersion: ownerAuthenticationSchema, ObservedAt: binding.ObservedAt,
		Complete: true, Truncated: false, AuthenticationMode: "static-token+auth-secret+mk-keys",
		Vault: ownerVault, VaultPinned: true, StaticTokenPresent: binding.StaticTokenPresent,
		AuthSecretPresent: authSecretPresent, Keys: []ownerAuthenticationKey{},
	}
	type recordEntry struct {
		key         ownerAPIKey
		storageHash [16]byte
	}
	records := make(map[[16]byte]recordEntry)
	recordIterator, err := db.NewIter(&pebble.IterOptions{LowerBound: []byte{0x12}, UpperBound: []byte{0x13}})
	if err != nil {
		return result, errors.New("authentication record iterator could not be created")
	}
	for recordIterator.First(); recordIterator.Valid(); recordIterator.Next() {
		keyBytes := recordIterator.Key()
		if len(keyBytes) != 17 {
			recordIterator.Close()
			return result, errors.New("authentication record key is malformed")
		}
		var storageHash [16]byte
		copy(storageHash[:], keyBytes[1:])
		if _, exists := records[storageHash]; exists {
			recordIterator.Close()
			return result, errors.New("authentication storage hash is duplicated")
		}
		var key ownerAPIKey
		if err := ownerStrictJSON(recordIterator.Value(), &key); err != nil {
			recordIterator.Close()
			return result, errors.New("authentication record is malformed")
		}
		idBytes, err := base64.RawURLEncoding.DecodeString(key.ID)
		if err != nil || len(idBytes) != 8 || len(key.StorageHash) != 16 || !bytes.Equal(key.StorageHash, storageHash[:]) || !bytes.Equal(idBytes, storageHash[:8]) ||
			key.Vault != ownerVault || (key.Mode != "observe" && key.Mode != "write" && key.Mode != "full") || !utf8.ValidString(key.ID) || !utf8.ValidString(key.Vault) || !utf8.ValidString(key.Label) {
			recordIterator.Close()
			return result, errors.New("authentication record does not satisfy baseline layout")
		}
		records[storageHash] = recordEntry{key: key, storageHash: storageHash}
	}
	if err := recordIterator.Error(); err != nil {
		recordIterator.Close()
		return result, errors.New("authentication record scan failed")
	}
	recordIterator.Close()
	indexPrefix := append(append([]byte{0x13}, []byte(ownerVault)...), 0x00)
	indexIterator, err := db.NewIter(&pebble.IterOptions{LowerBound: indexPrefix, UpperBound: ownerPrefixEnd(indexPrefix)})
	if err != nil {
		return result, errors.New("authentication index iterator could not be created")
	}
	indexed := make(map[[16]byte]struct{})
	seenIDs := make(map[[8]byte]struct{})
	for indexIterator.First(); indexIterator.Valid(); indexIterator.Next() {
		keyBytes := indexIterator.Key()
		value := indexIterator.Value()
		if len(keyBytes) != len(indexPrefix)+8 || len(value) != 16 {
			indexIterator.Close()
			return result, errors.New("authentication index is malformed")
		}
		var id [8]byte
		copy(id[:], keyBytes[len(indexPrefix):])
		if _, exists := seenIDs[id]; exists {
			indexIterator.Close()
			return result, errors.New("authentication key identifier is duplicated")
		}
		seenIDs[id] = struct{}{}
		var storageHash [16]byte
		copy(storageHash[:], value)
		record, exists := records[storageHash]
		if !exists || !bytes.Equal(id[:], storageHash[:8]) {
			indexIterator.Close()
			return result, errors.New("authentication index does not resolve exactly")
		}
		if _, exists := indexed[storageHash]; exists {
			indexIterator.Close()
			return result, errors.New("authentication record is indexed more than once")
		}
		indexed[storageHash] = struct{}{}
		fingerprint := sha256.Sum256(storageHash[:])
		result.Keys = append(result.Keys, ownerAuthenticationKey{FingerprintSHA256: hex.EncodeToString(fingerprint[:]), Mode: record.key.Mode, VaultPinned: true})
		if len(result.Keys) > ownerMaxAuthKeys {
			indexIterator.Close()
			return result, errors.New("authentication key ceiling exceeded")
		}
	}
	if err := indexIterator.Error(); err != nil {
		indexIterator.Close()
		return result, errors.New("authentication index scan failed")
	}
	indexIterator.Close()
	if len(indexed) != len(records) || len(result.Keys) == 0 {
		return result, errors.New("authentication inventory is incomplete")
	}
	sort.Slice(result.Keys, func(i, j int) bool { return result.Keys[i].FingerprintSHA256 < result.Keys[j].FingerprintSHA256 })
	encoded, err := ownerCanonicalJSON(result.Keys)
	if err != nil || len(encoded) > ownerMaxAuthBytes {
		return result, errors.New("authentication inventory byte ceiling exceeded")
	}
	return result, nil
}

func ownerPrefixEnd(prefix []byte) []byte {
	end := append([]byte(nil), prefix...)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}

func ownerStrictJSON(data []byte, target any) error {
	if err := ownerRejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func ownerRejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is malformed")
				}
				if _, exists := keys[key]; exists {
					return errors.New("JSON object contains a duplicate key")
				}
				keys[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("JSON delimiter is malformed")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func ownerCanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func ownerCanonicalSHA(value any) (string, error) {
	data, err := ownerCanonicalJSON(value)
	if err != nil {
		return "", errors.New("canonical JSON could not be encoded")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ownerCanonicalMatches(data []byte, value any) bool {
	canonical, err := ownerCanonicalJSON(value)
	return err == nil && bytes.Equal(bytes.TrimSpace(data), canonical)
}

func ownerStrictTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("time is not canonical UTC RFC3339")
	}
	return parsed.UTC(), nil
}

func writeOwnerJSON(path string, value any) (ownerArtifact, error) {
	data, err := ownerCanonicalJSON(value)
	if err != nil {
		return ownerArtifact{}, errors.New("private evidence JSON could not be encoded")
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".owner-artifact-*.tmp")
	if err != nil {
		return ownerArtifact{}, errors.New("private evidence temporary file could not be created")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return ownerArtifact{}, errors.New("private evidence permissions could not be set")
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return ownerArtifact{}, errors.New("private evidence could not be written")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return ownerArtifact{}, errors.New("private evidence could not be synchronized")
	}
	if err := temporary.Close(); err != nil {
		return ownerArtifact{}, errors.New("private evidence could not be closed")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return ownerArtifact{}, errors.New("private evidence could not be published")
	}
	sum := sha256.Sum256(data)
	return ownerArtifact{Path: filepath.Base(path), Bytes: uint64(len(data)), SHA256: hex.EncodeToString(sum[:])}, nil
}

func syncOwnerDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("private evidence directory could not be opened")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("private evidence directory could not be synchronized")
	}
	return nil
}

func ownerFailureSummary() ownerPublicSummary {
	return ownerPublicSummary{Valid: false, Error: "owner_evidence_failed"}
}
