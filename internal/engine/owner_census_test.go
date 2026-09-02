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

// TestOwnerCensus_IgnoresServerMutatedFields pins the fix for the census
// drift seen in production: the retroactive embedding processor
// (storage.UpdateEmbedding patches EmbedDim in place) and the cognitive
// confidence workers (storage.UpdateConfidence) rewrite live rows without
// changing the owner row set. Those mutations must not move the digest,
// while a genuine set change still must.
func TestOwnerCensus_IgnoresServerMutatedFields(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "owner-census-server-mutated"
	ws := eng.store.ResolveVaultPrefix(vault)

	id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census mutated", Content: "same owner row", Tags: []string{"x"},
	})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	before, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus before: %v", err)
	}

	vec := make([]float32, 384)
	vec[0] = 0.5
	if err := eng.store.UpdateEmbedding(ctx, ws, id, vec); err != nil {
		t.Fatalf("UpdateEmbedding: %v", err)
	}
	if err := eng.store.UpdateConfidence(ctx, ws, id, 0.42); err != nil {
		t.Fatalf("UpdateConfidence: %v", err)
	}
	mutated, err := eng.store.GetEngram(ctx, ws, id)
	if err != nil {
		t.Fatalf("GetEngram: %v", err)
	}
	if mutated.EmbedDim != storage.EmbedDimension(1) || mutated.Confidence != 0.42 {
		t.Fatalf("precondition: server mutations not applied: embed_dim=%d confidence=%v", mutated.EmbedDim, mutated.Confidence)
	}

	after, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus after: %v", err)
	}
	if after.Total != before.Total || after.IdentitySHA256 != before.IdentitySHA256 {
		t.Fatalf("server-mutated confidence/embed_dim moved the census: %+v vs %+v", before, after)
	}

	if _, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
		Concept: "census added", Content: "changes the set",
	}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	changed, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus changed: %v", err)
	}
	if changed.Total != before.Total+1 || changed.IdentitySHA256 == before.IdentitySHA256 {
		t.Fatalf("set change not reflected: %+v vs %+v", changed, before)
	}
}
