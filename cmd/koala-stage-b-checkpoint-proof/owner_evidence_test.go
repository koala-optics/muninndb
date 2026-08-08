package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/dchest/siphash"
	"github.com/klauspost/compress/zstd"
	"github.com/oklog/ulid/v2"
	"github.com/vmihailenco/msgpack/v5"
)

func TestOwnerEvidenceBuildsStablePrivateBundle(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 201)
	var output bytes.Buffer
	summary, err := executeOwnerEvidence(ownerEvidenceConfig{
		DataRoot: fixture.root, CheckpointReceiptPath: fixture.checkpointReceipt,
		BindingPath: fixture.binding, OutputDir: fixture.output,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("owner evidence failed: %v", err)
	}
	if err := json.NewEncoder(&output).Encode(summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Valid || summary.EngramCount != 201 || summary.EntityCount != 2 || summary.PageCount != 3 || summary.AuthenticationKeyCount != 2 {
		t.Fatalf("unexpected public summary: %+v", summary)
	}
	if len(summary.ManifestSHA256) != 64 || len(summary.ReceiptSHA256) != 64 {
		t.Fatalf("summary hashes are malformed: %+v", summary)
	}
	if got := mustMode(t, fixture.output); got != 0700 {
		t.Fatalf("output mode = %04o, want 0700", got)
	}
	for _, path := range []string{
		"manifest.json", "authentication.json", "inventory/page-000000.json",
		"inventory/page-000001.json", "inventory/page-000002.json",
	} {
		if got := mustMode(t, filepath.Join(fixture.output, path)); got != 0600 {
			t.Fatalf("%s mode = %04o, want 0600", path, got)
		}
	}
	var first ownerInventoryPage
	readJSON(t, filepath.Join(fixture.output, "inventory/page-000000.json"), &first)
	if first.Offset != 0 || first.Limit != ownerPageSize || first.Total != 201 || len(first.Engrams) != 200 || first.EntityCount != 2 {
		t.Fatalf("unexpected first page: %+v", first)
	}
	var last ownerInventoryPage
	readJSON(t, filepath.Join(fixture.output, "inventory/page-000002.json"), &last)
	if last.Offset != 201 || len(last.Engrams) != 0 {
		t.Fatalf("terminal page is not explicit: %+v", last)
	}
	if first.Engrams[0].CreatedAt <= first.Engrams[199].CreatedAt {
		t.Fatal("inventory is not sorted newest first")
	}
	for _, forbidden := range []string{fixture.root, fixture.binding, fixture.checkpointReceipt, "fixture-content-", "private-machine"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("public summary exposed %q: %s", forbidden, output.String())
		}
	}
}

func TestOwnerEvidenceEmptyInventoryHasTerminalPage(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 0)
	summary, err := executeOwnerEvidence(ownerEvidenceConfig{
		DataRoot: fixture.root, CheckpointReceiptPath: fixture.checkpointReceipt,
		BindingPath: fixture.binding, OutputDir: fixture.output,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Valid || summary.EngramCount != 0 || summary.PageCount != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	var page ownerInventoryPage
	readJSON(t, filepath.Join(fixture.output, "inventory/page-000000.json"), &page)
	if page.Offset != 0 || page.Total != 0 || len(page.Engrams) != 0 {
		t.Fatalf("unexpected terminal page: %+v", page)
	}
}

func TestOwnerEvidenceIsExplicitAndLegacyArgumentsRemainLegacy(t *testing.T) {
	var output bytes.Buffer
	if got := runCLI([]string{"--data-root", "/private"}, &output); got != 2 {
		t.Fatalf("legacy CLI accepted owner-only argument: exit=%d output=%s", got, output.String())
	}
	output.Reset()
	if got := runCLI([]string{ownerEvidenceMode, "--source-root", "/private"}, &output); got != 2 {
		t.Fatalf("owner CLI accepted legacy-only argument: exit=%d output=%s", got, output.String())
	}
}

func TestOwnerEvidenceRejectsUnsafeInputsAndOutput(t *testing.T) {
	t.Run("binding-mode", func(t *testing.T) {
		fixture := newOwnerEvidenceFixture(t, 1)
		if err := os.Chmod(fixture.binding, 0644); err != nil {
			t.Fatal(err)
		}
		assertOwnerEvidenceFails(t, fixture)
	})
	t.Run("existing-output", func(t *testing.T) {
		fixture := newOwnerEvidenceFixture(t, 1)
		if err := os.Mkdir(fixture.output, 0700); err != nil {
			t.Fatal(err)
		}
		assertOwnerEvidenceFailsKeepingOutput(t, fixture)
	})
	t.Run("symlink-binding", func(t *testing.T) {
		fixture := newOwnerEvidenceFixture(t, 1)
		target := fixture.binding
		link := filepath.Join(t.TempDir(), "binding.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		fixture.binding = link
		assertOwnerEvidenceFails(t, fixture)
	})
	t.Run("inside-data", func(t *testing.T) {
		fixture := newOwnerEvidenceFixture(t, 1)
		fixture.output = filepath.Join(fixture.root, "private-output")
		assertOwnerEvidenceFails(t, fixture)
	})
}

func TestOwnerEvidencePublicationNeverOverwritesRacedTarget(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 1)
	parent := filepath.Dir(fixture.output)
	sentinel := filepath.Join(fixture.output, "sentinel")
	created := false
	summary, err := executeOwnerEvidence(ownerEvidenceConfig{
		DataRoot: fixture.root, CheckpointReceiptPath: fixture.checkpointReceipt,
		BindingPath: fixture.binding, OutputDir: fixture.output,
		Now: func() time.Time {
			if !created {
				created = true
				if err := os.Mkdir(fixture.output, 0700); err != nil {
					t.Fatal(err)
				}
				writePrivateBytes(t, sentinel, []byte("preserve"))
			}
			return fixture.now
		},
	})
	if err == nil || summary.Valid {
		t.Fatalf("raced publication unexpectedly passed: summary=%+v err=%v", summary, err)
	}
	data, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(data) != "preserve" {
		t.Fatalf("raced target was overwritten: data=%q err=%v", data, readErr)
	}
	temporary, globErr := filepath.Glob(filepath.Join(parent, ".owner-evidence-*.tmp"))
	if globErr != nil || len(temporary) != 0 {
		t.Fatalf("failed publication left private temporary directories: paths=%v err=%v", temporary, globErr)
	}
}

func TestOwnerBindingFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ownerBinding, time.Time)
	}{
		{"receipt", func(value *ownerBinding, _ time.Time) { value.ReceiptSHA256 = strings.Repeat("0", 64) }},
		{"stale", func(value *ownerBinding, now time.Time) {
			value.ObservedAt = now.Add(-ownerMaxAge - time.Second).Format(time.RFC3339)
		}},
		{"future", func(value *ownerBinding, now time.Time) { value.ObservedAt = now.Add(time.Second).Format(time.RFC3339) }},
		{"target", func(value *ownerBinding, _ time.Time) { value.TargetFingerprint = strings.Repeat("1", 64) }},
		{"image", func(value *ownerBinding, _ time.Time) { value.ImageDigest = "sha256:" + strings.Repeat("1", 64) }},
		{"source", func(value *ownerBinding, _ time.Time) { value.SourceCommit = strings.Repeat("1", 40) }},
		{"volume", func(value *ownerBinding, _ time.Time) { value.SnapshotSourceVolumeSHA256 = strings.Repeat("1", 64) }},
		{"public-restore", func(value *ownerBinding, _ time.Time) { value.RestorePrivate = false }},
		{"missing-static-token", func(value *ownerBinding, _ time.Time) { value.StaticTokenPresent = false }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerEvidenceFixture(t, 1)
			var binding ownerBinding
			readJSON(t, fixture.binding, &binding)
			test.mutate(&binding, fixture.now)
			if test.name != "receipt" {
				binding.ReceiptSHA256 = bindingReceipt(t, binding)
			}
			writePrivateCanonicalJSON(t, fixture.binding, binding)
			assertOwnerEvidenceFails(t, fixture)
		})
	}
}

func TestOwnerStrictJSONRejectsDuplicateKeysAndCanonicalJSONSortsKeys(t *testing.T) {
	var target struct {
		Value int `json:"value"`
	}
	if err := ownerStrictJSON([]byte(`{"value":1,"value":2}`), &target); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	encoded, err := ownerCanonicalJSON(map[string]any{"z": 1, "a": map[string]any{"y": 2, "b": 3}})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"a":{"b":3,"y":2},"z":1}` {
		t.Fatalf("canonical JSON = %s", encoded)
	}
}

func TestOwnerBindingRequiresCanonicalBytes(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 1)
	var binding ownerBinding
	readJSON(t, fixture.binding, &binding)
	writePrivateJSON(t, fixture.binding, binding)
	assertOwnerEvidenceFails(t, fixture)
}

func TestOwnerEvidenceRequiresExactRestoredCheckpoint(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 2)
	db, err := pebble.Open(filepath.Join(fixture.root, "pebble"), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set([]byte("late"), []byte("mutation"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnerEvidenceFails(t, fixture)
}

func TestDecodeOwnerERFGoldenVectorsAndRejections(t *testing.T) {
	id := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	var raw [16]byte
	copy(raw[:], id[:])
	plain := buildOwnerERF(t, raw, "concept", "content", []string{"b", "a"}, 0x01, 1, false)
	record, include, err := decodeOwnerERF(plain, raw)
	if err != nil || !include || record.ID != id.String() || record.Content != "content" || strings.Join(record.Tags, ",") != "a,b" {
		t.Fatalf("plain vector: record=%+v include=%v err=%v", record, include, err)
	}
	compressed := buildOwnerERF(t, raw, "concept", strings.Repeat("content", 200), []string{"tag"}, 0x01, 1, true)
	record, include, err = decodeOwnerERF(compressed, raw)
	if err != nil || !include || record.Content != strings.Repeat("content", 200) {
		t.Fatalf("compressed vector: include=%v err=%v", include, err)
	}
	archived := buildOwnerERF(t, raw, "concept", "content", nil, 0x06, 1, false)
	if _, include, err := decodeOwnerERF(archived, raw); err != nil || include {
		t.Fatalf("archived record was included: include=%v err=%v", include, err)
	}
	softDeleted := buildOwnerERF(t, raw, "concept", "content", nil, 0x7f, 1, false)
	if _, include, err := decodeOwnerERF(softDeleted, raw); err != nil || include {
		t.Fatalf("soft-deleted record was included: include=%v err=%v", include, err)
	}

	mutations := []struct {
		name  string
		apply func([]byte)
	}{
		{"crc", func(data []byte) { data[len(data)-1] ^= 0xff }},
		{"state", func(data []byte) { data[64] = 0x70; repairOwnerCRC(data) }},
		{"bounds", func(data []byte) { binary.BigEndian.PutUint32(data[108:112], uint32(len(data))); repairOwnerCRC(data) }},
		{"overlap", func(data []byte) {
			binary.BigEndian.PutUint32(data[114:118], ownerERFVariableStart)
			repairOwnerCRC(data)
		}},
		{"association-count", func(data []byte) { binary.BigEndian.PutUint16(data[65:67], 1); repairOwnerCRC(data) }},
		{"utf8", func(data []byte) {
			offset := binary.BigEndian.Uint32(data[108:112])
			data[offset] = 0xff
			repairOwnerCRC(data)
		}},
		{"confidence", func(data []byte) {
			binary.BigEndian.PutUint32(data[48:52], math.Float32bits(float32(math.NaN())))
			repairOwnerCRC(data)
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			data := append([]byte(nil), plain...)
			mutation.apply(data)
			if _, _, err := decodeOwnerERF(data, raw); err == nil {
				t.Fatal("malformed vector was accepted")
			}
		})
	}
	t.Run("truncated-tag", func(t *testing.T) {
		position := len(plain) - ownerERFTrailerSize
		data := append([]byte(nil), plain[:position]...)
		data = append(data, 0x19, 0x00, 0x02, 'x', 0, 0, 0, 0)
		repairOwnerCRC(data)
		if _, _, err := decodeOwnerERF(data, raw); err == nil {
			t.Fatal("truncated tagged extension was accepted")
		}
	})
}

func TestOwnerEvidenceOrderingUsesULIDTieBreak(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 0)
	db, err := pebble.Open(filepath.Join(fixture.root, "pebble"), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	created := fixture.now.Add(-time.Minute)
	ids := []ulid.ULID{
		ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW"),
		ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
	}
	for _, id := range ids {
		writeOwnerEngram(t, db, id, created, "tie")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	refreshOwnerCheckpoint(t, fixture)
	summary, err := executeOwnerEvidence(ownerEvidenceConfig{DataRoot: fixture.root, CheckpointReceiptPath: fixture.checkpointReceipt, BindingPath: fixture.binding, OutputDir: fixture.output, Now: func() time.Time { return fixture.now }})
	if err != nil || !summary.Valid {
		t.Fatalf("executeOwnerEvidence: summary=%+v err=%v", summary, err)
	}
	var page ownerInventoryPage
	readJSON(t, filepath.Join(fixture.output, "inventory/page-000000.json"), &page)
	if page.Engrams[0].ID != ids[1].String() || page.Engrams[1].ID != ids[0].String() {
		t.Fatalf("tie order = %s, %s", page.Engrams[0].ID, page.Engrams[1].ID)
	}
}

func TestOwnerEntityCountNormalizesAndRejectsMalformedLinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "source")
	writeSourceFixture(t, root, 0)
	db, err := pebble.Open(filepath.Join(root, "pebble"), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	vault := ownerVaultPrefix(ownerVault)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV"), "PostgreSQL", true)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW"), " postgresql ", false)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAX"), "MissingRecord", false)
	count, err := countOwnerEntities(db, vault)
	if err != nil || count != 1 {
		t.Fatalf("entity count = %d, err=%v", count, err)
	}
	badID := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAY")
	key := ownerEntityLinkKey(vault, badID, "Bad")
	key[len(key)-1] ^= 0xff
	if err := db.Set(key, []byte("Bad"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if _, err := countOwnerEntities(db, vault); err == nil {
		t.Fatal("entity link hash mismatch was accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerEntityCountRejectsMalformedPresentRecord(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "source")
	writeSourceFixture(t, root, 0)
	db, err := pebble.Open(filepath.Join(root, "pebble"), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	vault := ownerVaultPrefix(ownerVault)
	id := ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	writeOwnerEntity(t, db, vault, id, "Malformed", true)
	hash := ownerEntityHash("Malformed")
	data, err := msgpack.Marshal(ownerEntityRecord{Name: "Malformed", Type: "database", Confidence: 2, Source: "fixture", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(append([]byte{0x1f}, hash[:]...), data, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if _, err := countOwnerEntities(db, vault); err == nil {
		t.Fatal("malformed present entity record was accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerEvidenceCeilingsFailClosed(t *testing.T) {
	t.Run("record-bytes", func(t *testing.T) {
		if _, _, err := decodeOwnerERF(make([]byte, ownerMaxRecordBytes+1), [16]byte{}); err == nil {
			t.Fatal("oversized inventory record was accepted")
		}
	})
	t.Run("page-bytes", func(t *testing.T) {
		directory := t.TempDir()
		spoolPath := filepath.Join(directory, "spool")
		inventoryDir := filepath.Join(directory, "inventory")
		if err := os.Mkdir(inventoryDir, 0700); err != nil {
			t.Fatal(err)
		}
		row := ownerInventoryRecord{ID: ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV").String(), Concept: "concept", Content: strings.Repeat("x", ownerMaxRecordBytes-1024), Confidence: 1, Tags: []string{}, Vault: ownerVault, CreatedAt: 1, EmbedDim: 0}
		encoded, err := ownerCanonicalJSON(row)
		if err != nil || len(encoded) > ownerMaxRecordBytes {
			t.Fatalf("page fixture record: bytes=%d err=%v", len(encoded), err)
		}
		if err := os.WriteFile(spoolPath, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		refs := make([]ownerRecordRef, ownerMaxPageBytes/len(encoded)+1)
		for index := range refs {
			refs[index] = ownerRecordRef{Length: uint32(len(encoded))}
		}
		if _, err := writeOwnerPages(spoolPath, inventoryDir, refs, 0, ownerBinding{}); err == nil {
			t.Fatal("oversized inventory page was accepted")
		}
	})
	t.Run("authentication-keys", func(t *testing.T) {
		db, err := pebble.Open(filepath.Join(t.TempDir(), "pebble"), &pebble.Options{})
		if err != nil {
			t.Fatal(err)
		}
		batch := db.NewBatch()
		prefix := append(append([]byte{0x13}, []byte(ownerVault)...), 0x00)
		for index := 0; index <= ownerMaxAuthKeys; index++ {
			storageHash := make([]byte, 16)
			binary.BigEndian.PutUint64(storageHash[:8], uint64(index+1))
			binary.BigEndian.PutUint64(storageHash[8:], uint64(index+1))
			key := ownerAPIKey{ID: base64.RawURLEncoding.EncodeToString(storageHash[:8]), Vault: ownerVault, Label: "fixture", Mode: "observe", CreatedAt: time.Unix(1_700_000_000, 0).UTC(), StorageHash: storageHash}
			data, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := batch.Set(append([]byte{0x12}, storageHash...), data, nil); err != nil {
				t.Fatal(err)
			}
			if err := batch.Set(append(append([]byte(nil), prefix...), storageHash[:8]...), storageHash, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := batch.Commit(pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := batch.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readOwnerAuthentication(db, ownerBinding{}, true); err == nil {
			t.Fatal("authentication key ceiling was not enforced")
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOwnerAuthenticationRequiresExactRecordIndexParity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *pebble.DB)
	}{
		{"missing-record", func(t *testing.T, db *pebble.DB) { mustDeletePrefix(t, db, 0x12, 1) }},
		{"unindexed-record", func(t *testing.T, db *pebble.DB) { writeOwnerAPIKey(t, db, bytes.Repeat([]byte{9}, 16), "full", false) }},
		{"wrong-mode", func(t *testing.T, db *pebble.DB) {
			rewriteFirstOwnerAPIKey(t, db, func(key *ownerAPIKey) { key.Mode = "admin" })
		}},
		{"wrong-vault", func(t *testing.T, db *pebble.DB) {
			rewriteFirstOwnerAPIKey(t, db, func(key *ownerAPIKey) { key.Vault = "other" })
		}},
		{"wrong-id", func(t *testing.T, db *pebble.DB) {
			rewriteFirstOwnerAPIKey(t, db, func(key *ownerAPIKey) { key.ID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 8)) })
		}},
		{"invalid-id-base64", func(t *testing.T, db *pebble.DB) {
			rewriteFirstOwnerAPIKey(t, db, func(key *ownerAPIKey) { key.ID = "not+base64" })
		}},
		{"storage-hash-mismatch", func(t *testing.T, db *pebble.DB) {
			rewriteFirstOwnerAPIKey(t, db, func(key *ownerAPIKey) { key.StorageHash = bytes.Repeat([]byte{7}, 16) })
		}},
		{"empty-inventory", func(t *testing.T, db *pebble.DB) {
			mustDeletePrefix(t, db, 0x12, 2)
			mustDeletePrefix(t, db, 0x13, 2)
		}},
		{"malformed-index", func(t *testing.T, db *pebble.DB) {
			prefix := append(append([]byte{0x13}, []byte(ownerVault)...), 0x00)
			_ = db.Set(append(prefix, 1), []byte{1}, pebble.Sync)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerEvidenceFixture(t, 1)
			db, err := pebble.Open(filepath.Join(fixture.root, "pebble"), &pebble.Options{})
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			refreshOwnerCheckpoint(t, fixture)
			assertOwnerEvidenceFails(t, fixture)
		})
	}
}

func TestOwnerFailureSummaryIsPayloadFree(t *testing.T) {
	fixture := newOwnerEvidenceFixture(t, 1)
	if err := os.WriteFile(fixture.binding, []byte(`{"private":"private-machine"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	exitCode := runCLI([]string{ownerEvidenceMode, "--data-root", fixture.root, "--checkpoint-receipt", fixture.checkpointReceipt, "--owner-binding", fixture.binding, "--output-dir", fixture.output}, &output)
	if exitCode != 1 || output.String() != "{\"valid\":false,\"error\":\"owner_evidence_failed\"}\n" {
		t.Fatalf("unexpected failure output: exit=%d output=%s", exitCode, output.String())
	}
	for _, forbidden := range []string{fixture.root, fixture.binding, fixture.checkpointReceipt, "private-machine"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("failure output leaked %q: %s", forbidden, output.String())
		}
	}
	if _, err := os.Stat(fixture.output); !os.IsNotExist(err) {
		t.Fatalf("failed run left output: %v", err)
	}
}

func TestWriteNonProductionOwnerWitnessFixture(t *testing.T) {
	root := os.Getenv("KOALA_OWNER_EVIDENCE_WITNESS_FIXTURE")
	if root == "" {
		t.Skip("set KOALA_OWNER_EVIDENCE_WITNESS_FIXTURE to write the workflow-only fixture")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("witness fixture path must not exist: %v", err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	fixture := newOwnerEvidenceFixtureAt(t, root, 502385)
	if fixture.root != filepath.Join(root, "source") {
		t.Fatalf("unexpected witness source: %s", fixture.root)
	}
}

type ownerEvidenceFixture struct {
	root              string
	checkpointReceipt string
	binding           string
	output            string
	now               time.Time
}

func newOwnerEvidenceFixture(t *testing.T, count int) ownerEvidenceFixture {
	return newOwnerEvidenceFixtureAt(t, t.TempDir(), count)
}

func newOwnerEvidenceFixtureAt(t *testing.T, base string, count int) ownerEvidenceFixture {
	t.Helper()
	witness := os.Getenv("KOALA_OWNER_EVIDENCE_WITNESS_FIXTURE") != "" &&
		filepath.Clean(base) == filepath.Clean(os.Getenv("KOALA_OWNER_EVIDENCE_WITNESS_FIXTURE"))
	now := time.Unix(1_800_000_000, 0).UTC()
	if witness {
		now = time.Now().UTC().Truncate(time.Second)
	}
	root := filepath.Join(base, "source")
	writeSourceFixture(t, root, 0)
	db, err := pebble.Open(filepath.Join(root, "pebble"), &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	vault := ownerVaultPrefix(ownerVault)
	vaultIndex := append([]byte{0x0f}, vault[:]...)
	if err := db.Set(vaultIndex, vault[:], pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if witness {
		batch := db.NewBatch()
		for index := 0; index < count; index++ {
			entropy := sha256.Sum256([]byte(formatFixtureNumber("engram", index)))
			created := now.Add(-time.Duration(index) * time.Second)
			id, err := ulid.New(uint64(created.UnixMilli()), bytes.NewReader(entropy[:]))
			if err != nil {
				t.Fatal(err)
			}
			var raw [16]byte
			copy(raw[:], id[:])
			value := buildOwnerERFAt(t, raw, created, "concept-"+id.String(), formatFixtureNumber("fixture-content", index), []string{"tag"}, 0x01, 1, false)
			key := append(append([]byte{0x01}, vault[:]...), raw[:]...)
			if err := batch.Set(key, value, nil); err != nil {
				t.Fatal(err)
			}
			if (index+1)%10_000 == 0 {
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
	} else {
		for index := 0; index < count; index++ {
			entropy := sha256.Sum256([]byte(formatFixtureNumber("engram", index)))
			id, err := ulid.New(uint64(now.Add(-time.Duration(index)*time.Second).UnixMilli()), bytes.NewReader(entropy[:]))
			if err != nil {
				t.Fatal(err)
			}
			writeOwnerEngram(t, db, id, now.Add(-time.Duration(index)*time.Second), formatFixtureNumber("fixture-content", index))
		}
	}
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAV"), "PostgreSQL", true)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAW"), " postgresql ", false)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAX"), "Redis", true)
	writeOwnerEntity(t, db, vault, ulid.MustParse("01ARZ3NDEKTSV4RRFFQ69G5FAY"), "Missing", false)
	writeOwnerAPIKey(t, db, bytes.Repeat([]byte{1}, 16), "observe", true)
	writeOwnerAPIKey(t, db, bytes.Repeat([]byte{2}, 16), "write", true)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fixture := ownerEvidenceFixture{root: root, checkpointReceipt: filepath.Join(base, "checkpoint.json"), binding: filepath.Join(base, "binding.json"), output: filepath.Join(base, "evidence"), now: now}
	refreshOwnerCheckpoint(t, fixture)
	return fixture
}

func refreshOwnerCheckpoint(t *testing.T, fixture ownerEvidenceFixture) {
	t.Helper()
	state, err := inspectDataRoot(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	receipt := proofReceipt{SchemaVersion: proofSchemaVersion, CreatedAt: fixture.now.Format(time.RFC3339), Identity: proofIdentity{BaselineImageDigest: baselineImageDigest, BaselineSourceCommit: baselineSourceCommit, BaselineBinarySHA256: strings.Repeat("a", 64), HelperSourceCommit: strings.Repeat("b", 40)}, Paths: privatePaths{SourceRoot: fixture.root, CheckpointRoot: fixture.root, ReceiptPath: fixture.checkpointReceipt, BaselineBinary: "/usr/local/bin/muninndb-server"}, Backup: backupExecution{ExitCode: 0, StdoutSHA256: strings.Repeat("c", 64), StderrSHA256: strings.Repeat("d", 64)}, SourceBefore: state, Checkpoint: state, SourceAfter: state, Equality: equalityProof{SourceStable: true, PebbleEqual: true, WALEqual: true, AuthSecretEqual: true, All: true}}
	writePrivateJSON(t, fixture.checkpointReceipt, receipt)
	checkpointData, err := os.ReadFile(fixture.checkpointReceipt)
	if err != nil {
		t.Fatal(err)
	}
	checkpointSHA := sha256.Sum256(checkpointData)
	binding := ownerBinding{SchemaVersion: ownerBindingSchema, ObservedAt: fixture.now.Format(time.RFC3339), SourceAppSHA256: strings.Repeat("1", 64), SourceMachineSHA256: strings.Repeat("2", 64), SourceVolumeSHA256: strings.Repeat("3", 64), IntendedMachineConfigSHA256: strings.Repeat("4", 64), ImageDigest: baselineImageDigest, SourceCommit: baselineSourceCommit, TargetFingerprint: ownerExpectedTarget, SnapshotMetadataSHA256: strings.Repeat("5", 64), SnapshotSourceVolumeSHA256: strings.Repeat("3", 64), SnapshotCreatedAt: fixture.now.Add(-time.Minute).Format(time.RFC3339), SnapshotRegion: "private-region", SnapshotSizeBytes: 1024, SnapshotStatus: "completed", RestoreMachineSHA256: strings.Repeat("6", 64), RestoreVolumeSHA256: strings.Repeat("7", 64), RestorePrivate: true, StaticTokenPresent: true, StaticTokenReceiptSHA256: strings.Repeat("8", 64), QuiescenceReceiptSHA256: strings.Repeat("9", 64), CheckpointReceiptSHA256: hex.EncodeToString(checkpointSHA[:]), SnapshotReceiptSHA256: strings.Repeat("a", 64)}
	binding.ReceiptSHA256 = bindingReceipt(t, binding)
	writePrivateCanonicalJSON(t, fixture.binding, binding)
}

func bindingReceipt(t *testing.T, binding ownerBinding) string {
	t.Helper()
	body := ownerBindingBody{SchemaVersion: binding.SchemaVersion, ObservedAt: binding.ObservedAt, SourceAppSHA256: binding.SourceAppSHA256, SourceMachineSHA256: binding.SourceMachineSHA256, SourceVolumeSHA256: binding.SourceVolumeSHA256, IntendedMachineConfigSHA256: binding.IntendedMachineConfigSHA256, ImageDigest: binding.ImageDigest, SourceCommit: binding.SourceCommit, TargetFingerprint: binding.TargetFingerprint, SnapshotMetadataSHA256: binding.SnapshotMetadataSHA256, SnapshotSourceVolumeSHA256: binding.SnapshotSourceVolumeSHA256, SnapshotCreatedAt: binding.SnapshotCreatedAt, SnapshotRegion: binding.SnapshotRegion, SnapshotSizeBytes: binding.SnapshotSizeBytes, SnapshotStatus: binding.SnapshotStatus, RestoreMachineSHA256: binding.RestoreMachineSHA256, RestoreVolumeSHA256: binding.RestoreVolumeSHA256, RestorePrivate: binding.RestorePrivate, StaticTokenPresent: binding.StaticTokenPresent, StaticTokenReceiptSHA256: binding.StaticTokenReceiptSHA256, QuiescenceReceiptSHA256: binding.QuiescenceReceiptSHA256, CheckpointReceiptSHA256: binding.CheckpointReceiptSHA256, SnapshotReceiptSHA256: binding.SnapshotReceiptSHA256}
	value, err := ownerCanonicalSHA(body)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func writeOwnerEngram(t *testing.T, db *pebble.DB, id ulid.ULID, created time.Time, content string) {
	t.Helper()
	var raw [16]byte
	copy(raw[:], id[:])
	value := buildOwnerERFAt(t, raw, created, "concept-"+id.String(), content, []string{"tag"}, 0x01, 1, len(content) > 512)
	vault := ownerVaultPrefix(ownerVault)
	key := append(append([]byte{0x01}, vault[:]...), raw[:]...)
	if err := db.Set(key, value, pebble.Sync); err != nil {
		t.Fatal(err)
	}
}

func buildOwnerERF(t *testing.T, id [16]byte, concept, content string, tags []string, state, version uint8, compressed bool) []byte {
	return buildOwnerERFAt(t, id, time.Unix(1_700_000_000, 0).UTC(), concept, content, tags, state, version, compressed)
}

func buildOwnerERFAt(t *testing.T, id [16]byte, created time.Time, concept, content string, tags []string, state, version uint8, compressed bool) []byte {
	t.Helper()
	conceptBytes := []byte(concept)
	createdBy := []byte("fixture")
	contentBytes := []byte(content)
	flags := uint8(0)
	if compressed {
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			t.Fatal(err)
		}
		contentBytes = encoder.EncodeAll(contentBytes, nil)
		encoder.Close()
		flags |= 1 << 1
	}
	tagsBytes, err := msgpack.Marshal(tags)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, ownerERFVariableStart)
	binary.BigEndian.PutUint32(data[0:4], 0x4d554e4e)
	data[4], data[5] = version, flags
	copy(data[8:24], id[:])
	binary.BigEndian.PutUint64(data[24:32], uint64(created.UnixNano()))
	binary.BigEndian.PutUint64(data[32:40], uint64(created.UnixNano()))
	binary.BigEndian.PutUint64(data[40:48], uint64(created.UnixNano()))
	binary.BigEndian.PutUint32(data[48:52], math.Float32bits(0.8))
	data[64], data[67] = state, 0
	offset := uint32(ownerERFVariableStart)
	binary.BigEndian.PutUint32(data[108:112], offset)
	binary.BigEndian.PutUint16(data[112:114], uint16(len(conceptBytes)))
	offset += uint32(len(conceptBytes))
	binary.BigEndian.PutUint32(data[114:118], offset)
	binary.BigEndian.PutUint16(data[118:120], uint16(len(createdBy)))
	offset += uint32(len(createdBy))
	binary.BigEndian.PutUint32(data[120:124], offset)
	binary.BigEndian.PutUint32(data[124:128], uint32(len(contentBytes)))
	offset += uint32(len(contentBytes))
	binary.BigEndian.PutUint32(data[128:132], offset)
	binary.BigEndian.PutUint32(data[132:136], uint32(len(tagsBytes)))
	data = append(data, conceptBytes...)
	data = append(data, createdBy...)
	data = append(data, contentBytes...)
	data = append(data, tagsBytes...)
	data = append(data, 0, 0, 0, 0)
	repairOwnerCRC(data)
	return data
}

func repairOwnerCRC(data []byte) {
	binary.BigEndian.PutUint16(data[6:8], ownerComputeCRC16(data[:6]))
	binary.BigEndian.PutUint32(data[len(data)-4:], crc32.Checksum(data[:len(data)-4], ownerCRC32Table))
}

func ownerComputeCRC16(data []byte) uint16 {
	crc := uint32(0xffff)
	for _, value := range data {
		crc ^= uint32(value) << 8
		for index := 0; index < 8; index++ {
			crc <<= 1
			if crc&0x10000 != 0 {
				crc ^= 0x1021
			}
		}
	}
	return uint16(crc ^ 0xffff)
}

func writeOwnerEntity(t *testing.T, db *pebble.DB, vault [8]byte, id ulid.ULID, name string, writeRecord bool) {
	t.Helper()
	if err := db.Set(ownerEntityLinkKey(vault, id, name), []byte(name), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if !writeRecord {
		return
	}
	record := ownerEntityRecord{Name: name, Type: "database", Confidence: 1, Source: "fixture", State: "active"}
	value, err := msgpack.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	hash := ownerEntityHash(name)
	if err := db.Set(append([]byte{0x1f}, hash[:]...), value, pebble.Sync); err != nil {
		t.Fatal(err)
	}
}

func ownerEntityLinkKey(vault [8]byte, id ulid.ULID, name string) []byte {
	hash := ownerEntityHash(name)
	key := append([]byte{0x20}, vault[:]...)
	key = append(key, id[:]...)
	return append(key, hash[:]...)
}

func writeOwnerAPIKey(t *testing.T, db *pebble.DB, storageHash []byte, mode string, index bool) {
	t.Helper()
	key := ownerAPIKey{ID: base64.RawURLEncoding.EncodeToString(storageHash[:8]), Vault: ownerVault, Label: "fixture", Mode: mode, CreatedAt: time.Unix(1_700_000_000, 0).UTC(), StorageHash: append([]byte(nil), storageHash...)}
	data, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(append([]byte{0x12}, storageHash...), data, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if index {
		indexKey := append(append(append([]byte{0x13}, []byte(ownerVault)...), 0x00), storageHash[:8]...)
		if err := db.Set(indexKey, storageHash, pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
}

func rewriteFirstOwnerAPIKey(t *testing.T, db *pebble.DB, mutate func(*ownerAPIKey)) {
	t.Helper()
	iterator, err := db.NewIter(&pebble.IterOptions{LowerBound: []byte{0x12}, UpperBound: []byte{0x13}})
	if err != nil {
		t.Fatal(err)
	}
	if !iterator.First() {
		iterator.Close()
		t.Fatal("missing authentication record")
	}
	keyBytes := append([]byte(nil), iterator.Key()...)
	var key ownerAPIKey
	if err := json.Unmarshal(iterator.Value(), &key); err != nil {
		iterator.Close()
		t.Fatal(err)
	}
	iterator.Close()
	mutate(&key)
	data, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(keyBytes, data, pebble.Sync); err != nil {
		t.Fatal(err)
	}
}

func mustDeletePrefix(t *testing.T, db *pebble.DB, prefix byte, count int) {
	t.Helper()
	iterator, err := db.NewIter(&pebble.IterOptions{LowerBound: []byte{prefix}, UpperBound: []byte{prefix + 1}})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([][]byte, 0, count)
	for iterator.First(); iterator.Valid() && len(keys) < count; iterator.Next() {
		keys = append(keys, append([]byte(nil), iterator.Key()...))
	}
	iterator.Close()
	for _, key := range keys {
		if err := db.Delete(key, pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
}

func writePrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePrivateBytes(t, path, append(data, '\n'))
}

func writePrivateCanonicalJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := ownerCanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	writePrivateBytes(t, path, append(data, '\n'))
}

func writePrivateBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func assertOwnerEvidenceFailsKeepingOutput(t *testing.T, fixture ownerEvidenceFixture) {
	t.Helper()
	var output bytes.Buffer
	exitCode := runCLI([]string{ownerEvidenceMode, "--data-root", fixture.root, "--checkpoint-receipt", fixture.checkpointReceipt, "--owner-binding", fixture.binding, "--output-dir", fixture.output}, &output)
	if exitCode == 0 || output.String() != "{\"valid\":false,\"error\":\"owner_evidence_failed\"}\n" {
		t.Fatalf("unexpected failure result: exit=%d output=%s", exitCode, output.String())
	}
	if info, err := os.Stat(fixture.output); err != nil || !info.IsDir() {
		t.Fatalf("pre-existing output was changed: info=%v err=%v", info, err)
	}
}

func assertOwnerEvidenceFails(t *testing.T, fixture ownerEvidenceFixture) {
	t.Helper()
	var output bytes.Buffer
	exitCode := runCLI([]string{ownerEvidenceMode, "--data-root", fixture.root, "--checkpoint-receipt", fixture.checkpointReceipt, "--owner-binding", fixture.binding, "--output-dir", fixture.output}, &output)
	if exitCode == 0 {
		t.Fatalf("owner evidence unexpectedly passed: %s", output.String())
	}
	if output.String() != "{\"valid\":false,\"error\":\"owner_evidence_failed\"}\n" {
		t.Fatalf("failure output is not fixed and payload-free: %s", output.String())
	}
	if _, err := os.Stat(fixture.output); !os.IsNotExist(err) {
		t.Fatalf("failed run left published output: %v", err)
	}
}

func TestOwnerVaultPrefixPinsBaselineSipHash(t *testing.T) {
	wantHash := siphash.Hash(0x736f6d6570736575, 0x646f72616e646f6d, []byte(ownerVault))
	var want [8]byte
	binary.BigEndian.PutUint64(want[:], wantHash)
	if got := ownerVaultPrefix(ownerVault); got != want {
		t.Fatalf("vault prefix = %x, want %x", got, want)
	}
}
