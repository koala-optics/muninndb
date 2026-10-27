package plugin

import (
	"context"
	"os"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

// openTestStore returns a PebbleStore backed by a temp directory.
// It registers t.Cleanup to close and remove the directory.
func openTestStore(t *testing.T) *storage.PebbleStore {
	t.Helper()
	dir, err := os.MkdirTemp("", "muninndb-plugin-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	db, err := storage.OpenPebble(dir, storage.DefaultOptions())
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("open pebble: %v", err)
	}
	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 100})
	t.Cleanup(func() {
		store.Close()
		os.RemoveAll(dir)
	})
	return store
}

func TestStoreAdapter_Methods(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}
	ctx := context.Background()

	// Write a real engram first so FindVaultPrefix works.
	ws := store.VaultPrefix("test-vault")
	id, err := store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "test concept",
		Content: "test content",
	})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	// UpsertEntity should store an entity record.
	if err := adapter.UpsertEntity(ctx, ExtractedEntity{Name: "PostgreSQL", Type: "database", Confidence: 0.9}); err != nil {
		t.Errorf("UpsertEntity should return nil, got %v", err)
	}

	// Verify the entity was stored.
	record, err := store.GetEntityRecord(ctx, "postgresql")
	if err != nil {
		t.Fatalf("GetEntityRecord: %v", err)
	}
	if record == nil {
		t.Fatal("entity record should not be nil after UpsertEntity")
	}
	if record.Name != "PostgreSQL" {
		t.Errorf("entity name = %q, want %q", record.Name, "PostgreSQL")
	}

	// LinkEngramToEntity should link a real engram.
	if err := adapter.LinkEngramToEntity(ctx, ULID(id), "PostgreSQL"); err != nil {
		t.Errorf("LinkEngramToEntity should return nil, got %v", err)
	}

	// UpsertRelationship should store a relationship record.
	if err := adapter.UpsertRelationship(ctx, ULID(id), ExtractedRelation{FromEntity: "payment-service", ToEntity: "PostgreSQL", RelType: "uses", Weight: 0.9}); err != nil {
		t.Errorf("UpsertRelationship should return nil, got %v", err)
	}

	// UpdateDigest should update engram fields.
	result := &EnrichmentResult{
		Summary:    "PostgreSQL is used for payments",
		KeyPoints:  []string{"database", "payments"},
		MemoryType: "task",
		TypeLabel:  "database_task",
	}
	if err := adapter.UpdateDigest(ctx, ULID(id), result); err != nil {
		t.Errorf("UpdateDigest should return nil, got %v", err)
	}

	// Verify digest was updated.
	eng, err := store.GetEngram(ctx, ws, id)
	if err != nil {
		t.Fatalf("GetEngram: %v", err)
	}
	if eng.Summary != "PostgreSQL is used for payments" {
		t.Errorf("engram Summary = %q, want %q", eng.Summary, "PostgreSQL is used for payments")
	}
	if eng.MemoryType != storage.TypeTask {
		t.Errorf("engram MemoryType = %v, want %v", eng.MemoryType, storage.TypeTask)
	}
	if eng.TypeLabel != "database_task" {
		t.Errorf("engram TypeLabel = %q, want %q", eng.TypeLabel, "database_task")
	}
	flags, err := store.GetDigestFlags(ctx, id)
	if err != nil {
		t.Fatalf("GetDigestFlags: %v", err)
	}
	if flags&DigestSummarized == 0 {
		t.Fatalf("expected DigestSummarized flag to be set, flags=%08b", flags)
	}
	if flags&DigestClassified == 0 {
		t.Fatalf("expected DigestClassified flag to be set, flags=%08b", flags)
	}
}

func TestStoreAdapter_LinkEngramToEntity_NotFound(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}
	ctx := context.Background()

	// Use a random ULID that doesn't exist in the store.
	var missingID ULID
	err := adapter.LinkEngramToEntity(ctx, missingID, "SomeEntity")
	if err == nil {
		t.Error("LinkEngramToEntity should return error for unknown engram ID")
	}
}

func TestStoreAdapter_UpsertRelationship_NotFound(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}
	ctx := context.Background()

	var missingID ULID
	err := adapter.UpsertRelationship(ctx, missingID, ExtractedRelation{FromEntity: "a", ToEntity: "b"})
	if err == nil {
		t.Error("UpsertRelationship should return error for unknown engram ID")
	}
}

func TestStoreAdapter_UpdateDigest_NilResult(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}

	if err := adapter.UpdateDigest(context.Background(), ULID{}, nil); err == nil {
		t.Fatal("expected error for nil enrichment result")
	}
}

func TestNewStoreAdapter(t *testing.T) {
	adapter := NewStoreAdapter(nil, nil)
	if adapter == nil {
		t.Fatal("NewStoreAdapter returned nil")
	}
}

func TestStoreAdapter_ScanWithoutFlagNilStore(t *testing.T) {
	// Verify the interface compliance.
	var _ PluginStore = &pluginStoreAdapter{}
}

func TestStoreAdapter_ScanRecordsVaultPrefix(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}
	ctx := context.Background()

	ws := store.VaultPrefix("scan-vault")
	id, err := store.WriteEngram(ctx, ws, &storage.Engram{Concept: "scan concept", Content: "scan content"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	iter := adapter.ScanWithoutFlag(ctx, DigestEmbed, 0)
	if !iter.Next() {
		t.Fatal("ScanWithoutFlag yielded no engram")
	}
	if got := iter.Engram().ID; got != id {
		t.Fatalf("scan yielded %v, want %v", got, id)
	}
	adapter.seenMu.Lock()
	recorded, ok := adapter.seenWS[id]
	adapter.seenMu.Unlock()
	if !ok || recorded != ws {
		t.Fatalf("recorded prefix = %v (ok=%v), want %v", recorded, ok, ws)
	}
	if got, ok := adapter.vaultPrefix(ctx, id); !ok || got != ws {
		t.Fatalf("vaultPrefix = %v (ok=%v), want %v", got, ok, ws)
	}

	if err := iter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	adapter.seenMu.Lock()
	left := len(adapter.seenWS)
	adapter.seenMu.Unlock()
	if left != 0 {
		t.Fatalf("Close left %d recorded prefixes", left)
	}
	// With nothing recorded the adapter still resolves through FindVaultPrefix.
	if got, ok := adapter.vaultPrefix(ctx, id); !ok || got != ws {
		t.Fatalf("fallback vaultPrefix = %v (ok=%v), want %v", got, ok, ws)
	}
}

func TestStoreAdapter_StaleRecordedPrefixFallsBack(t *testing.T) {
	store := openTestStore(t)
	adapter := &pluginStoreAdapter{store: store}
	ctx := context.Background()

	ws := store.VaultPrefix("home-vault")
	id, err := store.WriteEngram(ctx, ws, &storage.Engram{Concept: "stale concept", Content: "stale content"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	// A recorded prefix that no longer holds the engram must not be trusted.
	adapter.seenWS = map[ULID][8]byte{id: store.VaultPrefix("other-vault")}
	if got, ok := adapter.vaultPrefix(ctx, id); !ok || got != ws {
		t.Fatalf("vaultPrefix = %v (ok=%v), want %v", got, ok, ws)
	}
}
