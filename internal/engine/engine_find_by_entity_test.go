package engine

import (
	"context"
	"testing"

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
	results, err := eng.FindByEntity(ctx, vault, "SharedEntity", 50)
	require.NoError(t, err)

	var foundActive, foundArchived bool
	for _, r := range results {
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

	results, err := eng.FindByEntity(ctx, vault, "SharedEntity2", 50)
	require.NoError(t, err)

	var foundActive, foundDeleted bool
	for _, r := range results {
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

// TestFindByEntity_NewestFirstAndPaging is the regression test for the bug where
// FindByEntity walked the reverse index oldest-first and stopped at the cap, so
// for any entity with more than `limit` observations every recent write was
// invisible. It writes more engrams than a single page, then asserts:
//   (1) a capped read returns the NEWEST engrams, newest-first;
//   (2) offset paginates through older engrams without overlap;
//   (3) Total reflects the full set, not the page.
func TestFindByEntity_NewestFirstAndPaging(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vault = "find-by-entity-paging"
	const entity = "PagingEntity"
	const total = 60
	ws := eng.store.ResolveVaultPrefix(vault)

	require.NoError(t, eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{
		Name: entity, Type: "concept", Source: "inline",
	}, "inline"))

	// Write engrams in order; ULIDs are monotonic, so ids[i] for larger i is newer.
	ids := make([]storage.ULID, 0, total)
	for i := 0; i < total; i++ {
		e := &storage.Engram{Concept: "paging", Content: "obs"}
		id, err := eng.store.WriteEngram(ctx, ws, e)
		require.NoError(t, err)
		require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, entity))
		ids = append(ids, id)
	}

	// (1) Capped read returns the newest `limit`, newest-first.
	const pageSize = 10
	page0, err := eng.FindByEntityPaged(ctx, vault, entity, pageSize, 0)
	require.NoError(t, err)
	require.Len(t, page0.Engrams, pageSize)
	require.GreaterOrEqual(t, page0.Total, total, "Total should reflect the full set, not the page")

	// Newest-first: page0[0] must be the LAST written id; the page must equal the
	// final `pageSize` ids in reverse.
	for i := 0; i < pageSize; i++ {
		want := ids[total-1-i]
		require.Equal(t, want, page0.Engrams[i].ID,
			"page0[%d] should be the %d-th newest engram", i, i)
	}

	// (2) Next page (offset=pageSize) continues with the next-older block, no overlap.
	page1, err := eng.FindByEntityPaged(ctx, vault, entity, pageSize, pageSize)
	require.NoError(t, err)
	require.Len(t, page1.Engrams, pageSize)
	for i := 0; i < pageSize; i++ {
		want := ids[total-1-pageSize-i]
		require.Equal(t, want, page1.Engrams[i].ID,
			"page1[%d] should continue newest-first after the first page", i)
	}
	// No overlap between page0 and page1.
	seen := map[storage.ULID]bool{}
	for _, e := range page0.Engrams {
		seen[e.ID] = true
	}
	for _, e := range page1.Engrams {
		require.False(t, seen[e.ID], "page1 must not repeat any engram from page0")
	}

	// (3) Back-compat shim returns the same newest engram first.
	shim, err := eng.FindByEntity(ctx, vault, entity, pageSize)
	require.NoError(t, err)
	require.Len(t, shim, pageSize)
	require.Equal(t, ids[total-1], shim[0].ID, "FindByEntity shim must also be newest-first")
}
