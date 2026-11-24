package storage

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/prefix"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// Vault entity-name cache.
//
// ScanVaultEntityNames walks every 0x20 engram→entity link in a vault to
// produce its distinct entity identities. That is O(links), not O(entities):
// seconds on a vault with hundreds of thousands of engrams. The fuzzy entity
// resolver runs it on every find_by_entity call whose exact name misses, so a
// miss cost the same whether the name was a near-variant or nonsense.
//
// The cache holds, per vault, exactly the set ScanVaultEntityNames would
// return: one representative name per normalized identity, where the
// representative is the casing stored on the identity's lowest-keyed link
// (0x20 keys sort by ws|engramID|nameHash and the hash is of the normalized
// name, so "first seen" is the link with the smallest engram ID). It is built
// by one scan and then maintained from the link mutators:
//
//   - a written link upserts its identity and replaces the representative
//     when its engram ID is <= the current minimum (exact);
//   - a deleted link is a no-op when the identity's representative sits on a
//     smaller engram ID (the identity and its casing are unaffected); any
//     other delete drops the vault's cache, and the next read rescans;
//   - ClearVault drops the vault's cache.
//
// Replication appliers write 0x20 keys straight to Pebble, bypassing these
// hooks, so the cache must be disabled (DisableEntityNameCache) on any node
// that applies replicated or snapshot data.

type entityNameRep struct {
	name  string
	minID [16]byte
}

type entityLinkWrite struct {
	id   [16]byte
	name string
}

type vaultEntityNameCache struct {
	// buildMu serializes builds so concurrent missers share one scan.
	buildMu sync.Mutex

	mu    sync.Mutex
	ready bool
	reps  map[string]*entityNameRep // normalized identity → representative
	names []string                  // immutable snapshot of reps; nil when stale

	building   bool
	pending    []entityLinkWrite // writes observed while a build scan runs
	buildDirty bool              // a delete/clear raced the build: do not install
}

func (ps *PebbleStore) entityNameCacheFor(ws [8]byte) *vaultEntityNameCache {
	if v, ok := ps.entityNameCaches.Load(ws); ok {
		return v.(*vaultEntityNameCache)
	}
	v, _ := ps.entityNameCaches.LoadOrStore(ws, &vaultEntityNameCache{})
	return v.(*vaultEntityNameCache)
}

// DisableEntityNameCache permanently turns the vault entity-name cache off for
// this store and drops what it holds. Call it before wiring anything that
// writes entity links without going through the PebbleStore link mutators
// (replication applier, snapshot receiver).
func (ps *PebbleStore) DisableEntityNameCache() {
	ps.entityNameCacheOff.Store(true)
	ps.entityNameCaches.Range(func(k, v any) bool {
		c := v.(*vaultEntityNameCache)
		c.mu.Lock()
		c.dropLocked()
		c.mu.Unlock()
		return true
	})
}

// dropLocked discards the cached set. Caller holds c.mu.
func (c *vaultEntityNameCache) dropLocked() {
	c.ready = false
	c.reps = nil
	c.names = nil
	if c.building {
		c.buildDirty = true
	}
}

// applyWriteLocked folds one written link into reps. Caller holds c.mu.
func (c *vaultEntityNameCache) applyWriteLocked(id [16]byte, name string) {
	identity := keys.NormalizeEntityName(name)
	rep, ok := c.reps[identity]
	if !ok {
		c.reps[identity] = &entityNameRep{name: name, minID: id}
		c.names = nil
		return
	}
	if bytes.Compare(id[:], rep.minID[:]) <= 0 {
		if rep.name != name {
			rep.name = name
			c.names = nil
		}
		rep.minID = id
	}
}

// noteEntityLinkWritten records a committed 0x20 link write. Call after the
// batch commits.
func (ps *PebbleStore) noteEntityLinkWritten(ws [8]byte, id [16]byte, name string) {
	if name == "" || ps.entityNameCacheOff.Load() {
		return
	}
	v, ok := ps.entityNameCaches.Load(ws)
	if !ok {
		return
	}
	c := v.(*vaultEntityNameCache)
	c.mu.Lock()
	if c.building {
		c.pending = append(c.pending, entityLinkWrite{id: id, name: name})
	}
	if c.ready {
		c.applyWriteLocked(id, name)
	}
	c.mu.Unlock()
}

// noteEntityLinkDeleted records a committed 0x20 link delete. Call after the
// batch commits. The cached set survives only when the identity is known and
// its representative sits on a strictly smaller engram ID — then neither the
// identity's existence nor its casing can have changed. The <= side also
// covers a delete whose hook overtakes the hook of the write it removes.
func (ps *PebbleStore) noteEntityLinkDeleted(ws [8]byte, id [16]byte, name string) {
	if ps.entityNameCacheOff.Load() {
		return
	}
	v, ok := ps.entityNameCaches.Load(ws)
	if !ok {
		return
	}
	c := v.(*vaultEntityNameCache)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.building {
		c.buildDirty = true
	}
	if !c.ready {
		return
	}
	rep, known := c.reps[keys.NormalizeEntityName(name)]
	if known && bytes.Compare(id[:], rep.minID[:]) > 0 {
		return
	}
	c.dropLocked()
}

// invalidateEntityNameCache drops a vault's cached set (bulk mutations).
func (ps *PebbleStore) invalidateEntityNameCache(ws [8]byte) {
	v, ok := ps.entityNameCaches.Load(ws)
	if !ok {
		return
	}
	c := v.(*vaultEntityNameCache)
	c.mu.Lock()
	c.dropLocked()
	c.mu.Unlock()
}

// snapshotLocked returns the immutable name slice, rebuilding it from reps
// when stale. Caller holds c.mu.
func (c *vaultEntityNameCache) snapshotLocked() []string {
	if c.names == nil {
		names := make([]string, 0, len(c.reps))
		for _, rep := range c.reps {
			names = append(names, rep.name)
		}
		c.names = names
	}
	return c.names
}

// VaultEntityNames returns the vault's distinct entity names — the same set
// ScanVaultEntityNames reports (one representative per normalized identity,
// first-seen casing) — in unspecified order. The returned slice is shared and
// must not be modified. It is served from the entity-name cache when enabled;
// the first call per vault (and the first after an invalidating delete) pays
// one ScanVaultEntityNames-equivalent scan.
func (ps *PebbleStore) VaultEntityNames(ctx context.Context, ws [8]byte) ([]string, error) {
	if ps.entityNameCacheOff.Load() {
		var names []string
		err := ps.ScanVaultEntityNames(ctx, ws, func(name string) error {
			names = append(names, name)
			return nil
		})
		return names, err
	}

	c := ps.entityNameCacheFor(ws)
	c.mu.Lock()
	if c.ready {
		names := c.snapshotLocked()
		c.mu.Unlock()
		return names, nil
	}
	c.mu.Unlock()

	c.buildMu.Lock()
	defer c.buildMu.Unlock()

	c.mu.Lock()
	if c.ready { // another caller built it while we waited
		names := c.snapshotLocked()
		c.mu.Unlock()
		return names, nil
	}
	// Start buffering writes before the scan's iterator is opened: every
	// write committed after the iterator snapshot is then either in the scan
	// or in pending (possibly both — applying a write twice is idempotent).
	c.building = true
	c.pending = nil
	c.buildDirty = false
	c.mu.Unlock()

	ps.entityNameCacheBuilds.Add(1)
	reps, err := ps.scanVaultEntityReps(ctx, ws)

	c.mu.Lock()
	defer c.mu.Unlock()
	pending, dirty := c.pending, c.buildDirty
	c.building = false
	c.pending = nil
	c.buildDirty = false
	if err != nil {
		return nil, err
	}

	// The scan itself is a consistent point-in-time answer for this caller.
	names := make([]string, 0, len(reps))
	for _, rep := range reps {
		names = append(names, rep.name)
	}
	if dirty || ps.entityNameCacheOff.Load() {
		return names, nil // a delete raced the scan: answer, but do not cache
	}
	c.reps = reps
	c.names = names
	c.ready = true
	for _, w := range pending {
		c.applyWriteLocked(w.id, w.name)
	}
	return names, nil
}

// scanVaultEntityReps walks the vault's 0x20 forward index and returns one
// representative per normalized identity, taken from the first (lowest-keyed)
// link — the same rule as ScanVaultEntityNames.
func (ps *PebbleStore) scanVaultEntityReps(ctx context.Context, ws [8]byte) (map[string]*entityNameRep, error) {
	lower := make([]byte, 1+8)
	lower[0] = prefix.EntityEngramLink
	copy(lower[1:9], ws[:])
	upper := make([]byte, len(lower))
	copy(upper, lower)
	for i := len(upper) - 1; i >= 0; i-- {
		upper[i]++
		if upper[i] != 0 {
			break
		}
	}

	iter, err := ps.db.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, fmt.Errorf("vault entity names: iter: %w", err)
	}
	defer iter.Close()

	reps := make(map[string]*entityNameRep)
	n := 0
	for valid := iter.First(); valid; valid = iter.Next() {
		if n++; n&0xFFF == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		name := string(iter.Value())
		if name == "" {
			continue
		}
		identity := keys.NormalizeEntityName(name)
		if _, seen := reps[identity]; seen {
			continue
		}
		rep := &entityNameRep{name: name}
		if k := iter.Key(); len(k) >= 25 { // 0x20 | ws(8) | engramID(16) | nameHash(8)
			copy(rep.minID[:], k[9:25])
		}
		reps[identity] = rep
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("vault entity names: scan: %w", err)
	}
	return reps, nil
}

// EntityNameCacheBuilds reports how many full link-index scans have been run
// to build or rebuild a vault's entity-name cache (observability and tests).
func (ps *PebbleStore) EntityNameCacheBuilds() int64 {
	return ps.entityNameCacheBuilds.Load()
}
