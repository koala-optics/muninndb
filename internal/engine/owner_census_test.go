package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

func TestOwnerCensus_CountsActiveOnlyAndDigestIsOrderIndependent(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "owner-census"
	ws := eng.store.ResolveVaultPrefix(vault)

	idActive, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census active", Content: "kept", Tags: []string{"a", "b"},
	})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	_ = idActive
	if _, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census second", Content: "also kept",
	}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	idDeleted, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census deleted", Content: "dropped",
	})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	if err := eng.store.SoftDelete(ctx, ws, idDeleted); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	first, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus: %v", err)
	}
	if first.Total != 2 {
		t.Fatalf("Total = %d, want 2 (soft-deleted row must be excluded)", first.Total)
	}
	if len(first.IdentitySHA256) != 64 {
		t.Fatalf("IdentitySHA256 = %q, want 64 hex chars", first.IdentitySHA256)
	}

	second, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus second: %v", err)
	}
	if second.Total != first.Total || second.IdentitySHA256 != first.IdentitySHA256 {
		t.Fatalf("stable vault produced unequal censuses: %+v vs %+v", first, second)
	}

	if _, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census third", Content: "changes the set",
	}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	third, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus third: %v", err)
	}
	if third.Total != 3 || third.IdentitySHA256 == first.IdentitySHA256 {
		t.Fatalf("set change not reflected: %+v vs %+v", third, first)
	}
}

func TestOwnerCensus_EmptyVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	census, err := eng.OwnerCensus(context.Background(), "owner-census-empty")
	if err != nil {
		t.Fatalf("OwnerCensus: %v", err)
	}
	if census.Total != 0 || census.EntityCount != 0 {
		t.Fatalf("empty vault census = %+v, want zeros", census)
	}
	if len(census.IdentitySHA256) != 64 {
		t.Fatalf("IdentitySHA256 = %q, want 64 hex chars", census.IdentitySHA256)
	}
}
