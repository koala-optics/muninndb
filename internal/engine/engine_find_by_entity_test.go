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

// TestFindByEntity_MissDoesNotRescanLinkIndex covers the exact-name-miss path:
// a near-variant resolves to the same engrams as the exact name, a name that
// matches nothing returns nothing, the pager's end-of-data probe keeps the
// resolution, and none of the misses after the first walks the vault's link
// index again — including for an entity written after the first miss.
func TestFindByEntity_MissDoesNotRescanLinkIndex(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-miss"
	ws := eng.store.ResolveVaultPrefix(vault)

	link := func(entity string, n int) []storage.ULID {
		ids := make([]storage.ULID, 0, n)
		for i := 0; i < n; i++ {
			id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{Concept: entity, Content: "about " + entity})
			require.NoError(t, err)
			require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, entity))
			ids = append(ids, id)
		}
		return ids
	}
	idsOf := func(res *FindByEntityResult) []storage.ULID {
		ids := make([]storage.ULID, 0, len(res.Engrams))
		for _, e := range res.Engrams {
			ids = append(ids, e.ID)
		}
		return ids
	}

	link("cop:Tayyab Shahzad", 9)
	link("cop:Walmart", 3)

	exact, err := eng.FindByEntity(ctx, vault, "cop:Tayyab Shahzad", 500, 0)
	require.NoError(t, err)
	require.False(t, exact.Fuzzy)
	require.Len(t, exact.Engrams, 9)

	// First miss builds the vault's entity-name cache.
	fuzzy, err := eng.FindByEntity(ctx, vault, "cop:Tayyab", 500, 0)
	require.NoError(t, err)
	require.True(t, fuzzy.Fuzzy)
	require.Equal(t, "cop:Tayyab Shahzad", fuzzy.MatchedEntity)
	require.Equal(t, idsOf(exact), idsOf(fuzzy), "a fuzzy hit must return the exact name's rows in the same order")
	builds := eng.store.EntityNameCacheBuilds()

	// Pager end-of-data probe: empty page, resolution kept.
	probe, err := eng.FindByEntity(ctx, vault, "cop:Tayyab", 500, 9)
	require.NoError(t, err)
	require.Empty(t, probe.Engrams)
	require.Equal(t, "cop:Tayyab Shahzad", probe.MatchedEntity)

	// A name with no exact and no fuzzy entity.
	for i := 0; i < 3; i++ {
		none, err := eng.FindByEntity(ctx, vault, "cop:Zzqxv Nobody", 500, 0)
		require.NoError(t, err)
		require.Empty(t, none.Engrams)
		require.Empty(t, none.MatchedEntity)
		require.False(t, none.Fuzzy)
	}

	// An entity first written after the cache was built resolves fuzzily too.
	newIDs := link("cop:Fross Zelnick", 2)
	late, err := eng.FindByEntity(ctx, vault, "cop:Fross", 500, 0)
	require.NoError(t, err)
	require.True(t, late.Fuzzy)
	require.Equal(t, "cop:Fross Zelnick", late.MatchedEntity)
	require.ElementsMatch(t, newIDs, idsOf(late))

	require.Equal(t, builds, eng.store.EntityNameCacheBuilds(),
		"misses after the first must be served from the entity-name cache")
}
