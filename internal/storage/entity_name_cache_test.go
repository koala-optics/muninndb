package storage

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// scannedNames is the reference: what ScanVaultEntityNames reports, sorted.
func scannedNames(t *testing.T, store *PebbleStore, ws [8]byte) []string {
	t.Helper()
	var names []string
	require.NoError(t, store.ScanVaultEntityNames(context.Background(), ws, func(name string) error {
		names = append(names, name)
		return nil
	}))
	sort.Strings(names)
	return names
}

func cachedNames(t *testing.T, store *PebbleStore, ws [8]byte) []string {
	t.Helper()
	got, err := store.VaultEntityNames(context.Background(), ws)
	require.NoError(t, err)
	names := append([]string(nil), got...)
	sort.Strings(names)
	return names
}

// TestVaultEntityNames_MatchesScanUnderMutations drives every 0x20 mutator in
// random order and requires the cached set to equal a fresh scan after each
// step — same identities, same representative casing.
func TestVaultEntityNames_MatchesScanUnderMutations(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("entity-name-cache-mutations")
	other := store.VaultPrefix("entity-name-cache-other-vault")
	rng := rand.New(rand.NewSource(571))

	// Case/whitespace variants share an identity; the representative casing
	// must track the lowest engram ID exactly.
	variants := [][]string{
		{"Tayyab Shahzad", "tayyab shahzad", "TAYYAB SHAHZAD"},
		{"Fross Zelnick", "fross zelnick"},
		{"Walmart", "WALMART", " walmart "},
		{"Higley", "higley"},
		{"Calyptus"},
		{"Token Arcade", "token arcade"},
	}
	pick := func() string {
		v := variants[rng.Intn(len(variants))]
		return v[rng.Intn(len(v))]
	}

	type link struct {
		id   ULID
		name string
	}
	var links []link
	ids := make([]ULID, 40)
	for i := range ids {
		eng := &Engram{Concept: fmt.Sprintf("c-%d", i), Content: "x"}
		id, err := store.WriteEngram(ctx, ws, eng)
		require.NoError(t, err)
		ids[i] = id
	}

	require.Empty(t, cachedNames(t, store, ws)) // build on the empty vault

	for step := 0; step < 400; step++ {
		switch op := rng.Intn(10); {
		case op < 5 || len(links) == 0: // write (new link or overwrite casing)
			l := link{id: ids[rng.Intn(len(ids))], name: pick()}
			require.NoError(t, store.WriteEntityEngramLink(ctx, ws, l.id, l.name))
			links = append(links, l)
		case op < 7: // delete one link
			i := rng.Intn(len(links))
			require.NoError(t, store.DeleteEntityEngramLink(ctx, ws, links[i].id, links[i].name))
		case op < 9: // relink (merge path)
			i := rng.Intn(len(links))
			to := pick()
			require.NoError(t, store.RelinkEntityEngramLink(ctx, ws, links[i].id, links[i].name, to))
			links = append(links, link{id: links[i].id, name: to})
		default: // hard-delete an engram with all its links
			require.NoError(t, store.DeleteEngram(ctx, ws, ids[rng.Intn(len(ids))]))
		}
		// Another vault's writes must never leak in.
		require.NoError(t, store.WriteEntityEngramLink(ctx, other, NewULID(), "Other Vault Only"))

		require.Equal(t, scannedNames(t, store, ws), cachedNames(t, store, ws), "step %d", step)
	}

	_, err := store.ClearVault(ctx, ws)
	require.NoError(t, err)
	require.Empty(t, cachedNames(t, store, ws))
	require.Equal(t, []string{"Other Vault Only"}, cachedNames(t, store, other))
}

// TestVaultEntityNames_WritesDoNotRescan is the performance contract: once a
// vault's cache is built, reads and link writes never walk the link index
// again; only a delete of an identity's first link forces one rebuild.
func TestVaultEntityNames_WritesDoNotRescan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("entity-name-cache-no-rescan")

	first, second := NewULID(), NewULID()
	if bytes.Compare(first[:], second[:]) > 0 { // same-millisecond ULIDs are not ordered
		first, second = second, first
	}
	require.NoError(t, store.WriteEntityEngramLink(ctx, ws, first, "Alpha"))
	require.NoError(t, store.WriteEntityEngramLink(ctx, ws, second, "alpha"))

	require.Equal(t, []string{"Alpha"}, cachedNames(t, store, ws))
	builds := store.entityNameCacheBuilds.Load()

	for i := 0; i < 50; i++ {
		require.NoError(t, store.WriteEntityEngramLink(ctx, ws, NewULID(), fmt.Sprintf("Entity %d", i)))
		_ = cachedNames(t, store, ws)
	}
	// Deleting a later link of a known identity keeps the cache.
	require.NoError(t, store.DeleteEntityEngramLink(ctx, ws, second, "alpha"))
	require.Len(t, cachedNames(t, store, ws), 51)
	require.Equal(t, builds, store.entityNameCacheBuilds.Load(), "writes and non-first deletes must not rescan")

	// Deleting the identity's first link drops the cache; one rebuild follows.
	require.NoError(t, store.DeleteEntityEngramLink(ctx, ws, first, "Alpha"))
	require.Len(t, cachedNames(t, store, ws), 50)
	_ = cachedNames(t, store, ws)
	require.Equal(t, builds+1, store.entityNameCacheBuilds.Load())
}

// TestVaultEntityNames_Disabled verifies the kill switch serves straight from
// the scan.
func TestVaultEntityNames_Disabled(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("entity-name-cache-disabled")
	require.NoError(t, store.WriteEntityEngramLink(ctx, ws, NewULID(), "Alpha"))
	require.Equal(t, []string{"Alpha"}, cachedNames(t, store, ws))

	store.DisableEntityNameCache()
	builds := store.entityNameCacheBuilds.Load()
	require.NoError(t, store.WriteEntityEngramLink(ctx, ws, NewULID(), "Beta"))
	require.Equal(t, []string{"Alpha", "Beta"}, cachedNames(t, store, ws))
	require.Equal(t, builds, store.entityNameCacheBuilds.Load())
}

// TestVaultEntityNames_ConcurrentWritesDuringBuild races link writes and
// deletes against cache builds and reads (run with -race), then requires the
// settled cache to equal a fresh scan.
func TestVaultEntityNames_ConcurrentWritesDuringBuild(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("entity-name-cache-concurrent")

	for i := 0; i < 2000; i++ {
		require.NoError(t, store.WriteEntityEngramLink(ctx, ws, NewULID(), fmt.Sprintf("Seed %d", i%300)))
	}

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			for i := 0; i < 300; i++ {
				id := NewULID()
				name := fmt.Sprintf("Writer %d Entity %d", w, rng.Intn(60))
				if err := store.WriteEntityEngramLink(ctx, ws, id, name); err != nil {
					t.Error(err)
					return
				}
				if rng.Intn(4) == 0 {
					if err := store.DeleteEntityEngramLink(ctx, ws, id, name); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if _, err := store.VaultEntityNames(ctx, ws); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	require.Equal(t, scannedNames(t, store, ws), cachedNames(t, store, ws))
}
