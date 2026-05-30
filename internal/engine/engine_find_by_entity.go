package engine

import (
	"context"
	"fmt"

	"github.com/scrypster/muninndb/internal/storage"
)

// errStopScan is the sentinel used to halt a reverse index scan once the
// requested page has been collected. It is not a real error.
var errStopScan = fmt.Errorf("stop scan")

// FindByEntityResult carries a single page of entity engrams plus enough
// metadata for a client to paginate. Total is the number of index entries for
// the entity in this vault (pre lifecycle-filter), an upper bound on the count
// of live engrams; it lets a caller know whether more pages exist without
// hydrating every engram.
type FindByEntityResult struct {
	Engrams []*storage.Engram
	Total   int
	Offset  int
	Limit   int
}

// FindByEntity returns up to limit engrams in vault that mention entityName,
// newest-first. Back-compat shim over FindByEntityPaged with offset=0.
func (e *Engine) FindByEntity(ctx context.Context, vault, entityName string, limit int) ([]*storage.Engram, error) {
	res, err := e.FindByEntityPaged(ctx, vault, entityName, limit, 0)
	if err != nil {
		return nil, err
	}
	return res.Engrams, nil
}

// FindByEntityPaged returns a page of engrams in vault that mention entityName,
// in newest-first order, using the 0x23 reverse index.
//
// Ordering: the reverse index is keyed by ULID, which is lexicographically
// time-sortable, so walking it in descending order yields the most recent
// observations first. This is the fix for the prior behavior, which walked the
// index oldest-first and stopped at the cap. For any entity with more than
// `limit` lifetime observations that hid every recent write behind the oldest N.
//
// Paging: offset entries (after vault + lifecycle filtering) are skipped, then
// up to limit are collected. limit defaults to 20 and is capped at maxFindLimit.
// Total is the count of vault-scoped index entries for the entity (an upper
// bound on live engrams, computed without hydrating the skipped/over-limit ones).
func (e *Engine) FindByEntityPaged(ctx context.Context, vault, entityName string, limit, offset int) (*FindByEntityResult, error) {
	const maxFindLimit = 500
	if entityName == "" {
		return nil, fmt.Errorf("find_by_entity: entity_name is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > maxFindLimit {
		limit = maxFindLimit
	}
	if offset < 0 {
		offset = 0
	}
	ws := e.store.ResolveVaultPrefix(vault)

	results := make([]*storage.Engram, 0, limit)
	matched := 0 // vault-scoped index entries seen (the Total upper bound)
	skipped := 0 // live engrams skipped to honor offset

	err := e.store.ScanEntityEngramsReverse(ctx, entityName, func(gotWS [8]byte, id storage.ULID) error {
		if gotWS != ws {
			return nil // different vault - skip, do not count
		}
		matched++
		// Stop hydrating once we have a full page. We keep counting (cheap, no
		// GetEngram) so Total reflects the full vault-scoped index, but we never
		// hydrate beyond what's needed for this page.
		if len(results) >= limit {
			return nil // keep scanning only to finish the Total count
		}
		eng, gerr := e.store.GetEngram(ctx, ws, id)
		if gerr != nil || eng == nil {
			matched-- // missing/deleted index entry should not inflate Total
			return nil
		}
		if eng.State == storage.StateSoftDeleted || eng.State == storage.StateArchived {
			matched-- // not a live engram
			return nil
		}
		if skipped < offset {
			skipped++
			return nil
		}
		results = append(results, eng)
		return nil
	})
	if err != nil && err != errStopScan {
		return nil, fmt.Errorf("find_by_entity: scan: %w", err)
	}

	return &FindByEntityResult{
		Engrams: results,
		Total:   matched,
		Offset:  offset,
		Limit:   limit,
	}, nil
}
