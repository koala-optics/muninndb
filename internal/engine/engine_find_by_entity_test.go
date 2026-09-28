package engine

import (
	"context"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/storage"
	"github.com/stretchr/testify/require"
)

// TestFindByEntity_ExcludesArchived verifies that archived engrams do not appear
// in FindByEntity results.
func TestFindByEntity_ExcludesArchived(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-archived"
	ws := eng.store.ResolveVaultPrefix(vault)

	// Write two engrams and link both to the same entity.
	engA := &storage.Engram{Concept: "active-engram", Content: "This one stays active"}
	idA, err := eng.store.WriteEngram(ctx, ws, engA)
	require.NoError(t, err)

	engB := &storage.Engram{Concept: "archived-engram", Content: "This one gets archived"}
	idB, err := eng.store.WriteEngram(ctx, ws, engB)
	require.NoError(t, err)

	err = eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name:   "SharedEntity",
		Type:   "concept",
		Source: "inline",
	}, "inline")
	require.NoError(t, err)
	err = eng.store.WriteEntityEngramLink(ctx, ws, idA, "SharedEntity")
	require.NoError(t, err)
	err = eng.store.WriteEntityEngramLink(ctx, ws, idB, "SharedEntity")
	require.NoError(t, err)

	// Archive engram B.
	err = eng.UpdateLifecycleState(ctx, vault, idB.String(), "archived")
	require.NoError(t, err)

	// FindByEntity must return only the active engram.
	res, err := eng.FindByEntity(ctx, vault, "SharedEntity", 50, 0)
	require.NoError(t, err)
	require.Equal(t, "SharedEntity", res.MatchedEntity)
	require.False(t, res.Fuzzy, "exact lookup must not be marked fuzzy")

	var foundActive, foundArchived bool
	for _, r := range res.Engrams {
		if r.ID == idA {
			foundActive = true
		}
		if r.ID == idB {
			foundArchived = true
		}
	}
	require.True(t, foundActive, "active engram A should appear in FindByEntity results")
	require.False(t, foundArchived, "archived engram B should NOT appear in FindByEntity results")
}

// TestFindByEntity_ExcludesSoftDeleted verifies that soft-deleted engrams do not
// appear in FindByEntity results.
func TestFindByEntity_NewestFirst(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-newest"
	const entity = "OrderedEntity"
	ws := eng.store.ResolveVaultPrefix(vault)
	require.NoError(t, eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name: entity, Type: "concept", Source: "inline",
	}, "inline"))

	ids := make([]storage.ULID, 5)
	for i := range ids {
		createdAt := time.Now().Add(time.Duration(i) * time.Minute)
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
			Concept: "ordered", Content: "observation", CreatedAt: createdAt,
		})
		require.NoError(t, err)
		require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, entity))
		ids[i] = id
	}

	res, err := eng.FindByEntity(ctx, vault, entity, 3, 0)
	require.NoError(t, err)
	require.Len(t, res.Engrams, 3)
	for i := range res.Engrams {
		require.Equal(t, ids[len(ids)-1-i], res.Engrams[i].ID)
	}
}

func TestFindByEntity_Pagination(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-pagination"
	const entity = "PagedEntity"
	ws := eng.store.ResolveVaultPrefix(vault)
	require.NoError(t, eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name: entity, Type: "concept", Source: "inline",
	}, "inline"))

	ids := make([]storage.ULID, 60)
	for i := range ids {
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
			Concept: "paged", Content: "observation",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
		require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, entity))
		ids[i] = id
	}

	pageOne, err := eng.FindByEntity(ctx, vault, entity, 50, 0)
	require.NoError(t, err)
	require.Len(t, pageOne.Engrams, 50)
	pageOneIDs := make([]storage.ULID, len(pageOne.Engrams))
	for i, engram := range pageOne.Engrams {
		want := ids[len(ids)-1-i]
		require.Equal(t, want, engram.ID, "page one must be newest-first")
		pageOneIDs[i] = engram.ID
	}

	pageTwo, err := eng.FindByEntity(ctx, vault, entity, 50, 50)
	require.NoError(t, err)
	require.Len(t, pageTwo.Engrams, 10)
	for i, engram := range pageTwo.Engrams {
		require.Equal(t, ids[9-i], engram.ID, "page two must continue newest-first")
		require.NotContains(t, pageOneIDs, engram.ID, "pages must not overlap")
	}

	all, err := eng.FindByEntity(ctx, vault, entity, 500, 0)
	require.NoError(t, err)
	require.Len(t, all.Engrams, 60)
	for i, engram := range all.Engrams {
		require.Equal(t, ids[len(ids)-1-i], engram.ID, "all results must be newest-first")
	}
}

func TestFindByEntity_OffsetSkipsOnlyLiveEngrams(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-live-offset"
	const entity = "LiveOffsetEntity"
	ws := eng.store.ResolveVaultPrefix(vault)
	require.NoError(t, eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name: entity, Type: "concept", Source: "inline",
	}, "inline"))

	ids := make([]storage.ULID, 5)
	for i := range ids {
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
			Concept: "live offset", Content: "observation",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
		require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, entity))
		ids[i] = id
	}
	require.NoError(t, eng.UpdateLifecycleState(ctx, vault, ids[3].String(), "archived"))
	require.NoError(t, eng.store.SoftDelete(ctx, ws, ids[4]))

	res, err := eng.FindByEntity(ctx, vault, entity, 2, 1)
	require.NoError(t, err)
	require.Len(t, res.Engrams, 2)
	require.Equal(t, ids[1], res.Engrams[0].ID)
	require.Equal(t, ids[0], res.Engrams[1].ID)
}

func TestFindByEntity_ExcludesSoftDeleted(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-softdeleted"
	ws := eng.store.ResolveVaultPrefix(vault)

	engA := &storage.Engram{Concept: "active-engram", Content: "This one stays active"}
	idA, err := eng.store.WriteEngram(ctx, ws, engA)
	require.NoError(t, err)

	engB := &storage.Engram{Concept: "deleted-engram", Content: "This one gets deleted"}
	idB, err := eng.store.WriteEngram(ctx, ws, engB)
	require.NoError(t, err)

	err = eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name:   "SharedEntity2",
		Type:   "concept",
		Source: "inline",
	}, "inline")
	require.NoError(t, err)
	err = eng.store.WriteEntityEngramLink(ctx, ws, idA, "SharedEntity2")
	require.NoError(t, err)
	err = eng.store.WriteEntityEngramLink(ctx, ws, idB, "SharedEntity2")
	require.NoError(t, err)

	err = eng.store.SoftDelete(ctx, ws, idB)
	require.NoError(t, err)

	res, err := eng.FindByEntity(ctx, vault, "SharedEntity2", 50, 0)
	require.NoError(t, err)

	var foundActive, foundDeleted bool
	for _, r := range res.Engrams {
		if r.ID == idA {
			foundActive = true
		}
		if r.ID == idB {
			foundDeleted = true
		}
	}
	require.True(t, foundActive, "active engram A should appear in FindByEntity results")
	require.False(t, foundDeleted, "soft-deleted engram B should NOT appear in FindByEntity results")
}
