package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

func TestCountEntities_ExactNormalizedVaultCount(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "entity-count"
	ws := eng.store.ResolveVaultPrefix(vault)
	first := storage.NewULID()
	second := storage.NewULID()

	for _, record := range []storage.EntityRecord{
		{Name: "PostgreSQL", Type: "database", Confidence: 1},
		{Name: "Redis", Type: "database", Confidence: 1},
	} {
		if err := eng.store.UpsertEntityRecord(ctx, record, "test"); err != nil {
			t.Fatalf("UpsertEntityRecord: %v", err)
		}
	}
	for _, link := range []struct {
		id   storage.ULID
		name string
	}{
		{first, "PostgreSQL"},
		{second, " postgresql "},
		{first, "Redis"},
		{second, "MissingRecord"},
	} {
		if err := eng.store.WriteEntityEngramLink(ctx, ws, link.id, link.name); err != nil {
			t.Fatalf("WriteEntityEngramLink: %v", err)
		}
	}

	count, err := eng.CountEntities(ctx, vault)
	if err != nil {
		t.Fatalf("CountEntities: %v", err)
	}
	if count != 2 {
		t.Fatalf("CountEntities = %d, want 2", count)
	}
}

func TestCountEntities_EmptyVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	count, err := eng.CountEntities(context.Background(), "empty-count")
	if err != nil {
		t.Fatalf("CountEntities: %v", err)
	}
	if count != 0 {
		t.Fatalf("CountEntities = %d, want 0", count)
	}
}

func TestCountEntities_PropagatesEntityReadFailure(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	vault := "cancelled-count"
	if err := eng.store.WriteEntityEngramLink(
		context.Background(),
		eng.store.ResolveVaultPrefix(vault),
		storage.NewULID(),
		"PostgreSQL",
	); err != nil {
		t.Fatalf("WriteEntityEngramLink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := eng.CountEntities(ctx, vault); err == nil {
		t.Fatal("CountEntities returned nil error for cancelled entity read")
	}
}
