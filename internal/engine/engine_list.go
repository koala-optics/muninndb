package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/scrypster/muninndb/internal/storage"
)

// ListEngramsParams holds all parameters for a passive engram list operation.
// No Hebbian side effects, no activity tracking, no scoring pipeline.
type ListEngramsParams struct {
	Vault   string
	Limit   int
	Offset  int
	Sort    string    // "created" (default) or "accessed"
	Tags    []string  // filter: engram must have ALL of these tags
	State   string    // filter: lifecycle state (e.g. "active", "planning"); empty = all non-deleted
	MinConf float32   // filter: minimum confidence (0–1); 0 = no min
	MaxConf float32   // filter: maximum confidence (0–1); 0 = no max
	Since   time.Time // filter: created after this time; zero = no bound
	Before  time.Time // filter: created before this time; zero = no bound
}

// ListEngramsResult holds the result of a passive engram list.
type ListEngramsResult struct {
	Engrams []*storage.Engram
	Total   int // total matching (before pagination)
}

// ListEngrams performs a passive, read-only scan of engrams in a vault.
// It applies tag/state/confidence/time filters, sorts by creation time or
// last-access time, and then paginates. No Hebbian weights are updated,
// no activity tracking occurs, and no scoring pipeline is invoked.
func (e *Engine) ListEngrams(ctx context.Context, params ListEngramsParams) (*ListEngramsResult, error) {
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Sort == "" {
		params.Sort = "created"
	}

	ws := e.store.ResolveVaultPrefix(params.Vault)

	// Parse optional state filter.
	var stateFilter *storage.LifecycleState
	if params.State != "" {
		s, err := storage.ParseLifecycleState(params.State)
		if err == nil {
			stateFilter = &s
		}
	}

	// Collect all matching engrams via passive scan.
	var matched []*storage.Engram

	scanErr := e.store.ScanEngrams(ctx, ws, func(eng *storage.Engram) error {
		// Always exclude soft-deleted unless explicitly requested.
		if eng.State == storage.StateSoftDeleted {
			if stateFilter == nil || *stateFilter != storage.StateSoftDeleted {
				return nil
			}
		}
		// Always exclude archived unless explicitly requested.
		if eng.State == storage.StateArchived {
			if stateFilter == nil || *stateFilter != storage.StateArchived {
				return nil
			}
		}

		// State filter.
		if stateFilter != nil && eng.State != *stateFilter {
			return nil
		}

		// Confidence range filters.
		if params.MinConf > 0 && eng.Confidence < params.MinConf {
			return nil
		}
		if params.MaxConf > 0 && eng.Confidence > params.MaxConf {
			return nil
		}

		// Time range filters (based on creation time / ULID timestamp).
		if !params.Since.IsZero() && eng.CreatedAt.Before(params.Since) {
			return nil
		}
		if !params.Before.IsZero() && !eng.CreatedAt.Before(params.Before) {
			return nil
		}

		// Tag filter: engram must have ALL requested tags.
		if len(params.Tags) > 0 {
			tagSet := make(map[string]struct{}, len(eng.Tags))
			for _, t := range eng.Tags {
				tagSet[t] = struct{}{}
			}
			for _, required := range params.Tags {
				if _, ok := tagSet[required]; !ok {
					return nil
				}
			}
		}

		matched = append(matched, eng)
		return nil
	})
	if scanErr != nil {
		return nil, scanErr
	}

	// Sort.
	switch params.Sort {
	case "accessed":
		sort.Slice(matched, func(i, j int) bool {
			return matched[i].LastAccess.After(matched[j].LastAccess)
		})
	default: // "created" — descending (newest first)
		sort.Slice(matched, func(i, j int) bool {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		})
	}

	total := len(matched)

	// Paginate.
	if params.Offset >= total {
		return &ListEngramsResult{Engrams: []*storage.Engram{}, Total: total}, nil
	}
	end := params.Offset + params.Limit
	if end > total {
		end = total
	}
	page := matched[params.Offset:end]

	return &ListEngramsResult{Engrams: page, Total: total}, nil
}

// maxKeysetScanRows bounds the rows one keyset page visits, so a long run of
// soft-deleted or archived rows returns a short page with a cursor instead of
// running into the request deadline.
// minimal: fixed budget (a var only so tests can shrink it); make it a
// parameter if callers need different latency.
var maxKeysetScanRows = 20_000

var errKeysetPageDone = errors.New("keyset page done")

// ListEngramsAfter is a passive keyset page over a vault in ascending ID (ULID
// key) order. It returns up to limit non-deleted, non-archived engrams whose ID
// is greater than after (nil = vault start), the same active set OwnerCensus
// counts. next is the cursor for the following page, or nil once the scan has
// reached the end of the vault. A page may hold fewer than limit rows while
// next is non-nil (the per-page scan budget ran out).
func (e *Engine) ListEngramsAfter(ctx context.Context, vault string, after *storage.ULID, limit int) (page []*storage.Engram, next *storage.ULID, err error) {
	if limit < 1 {
		return nil, nil, errors.New("list engrams after: limit must be at least 1")
	}
	ws := e.store.ResolveVaultPrefix(vault)
	page = []*storage.Engram{}
	visited := 0
	var last storage.ULID
	err = e.store.ScanEngramsFrom(ctx, ws, after, func(eng *storage.Engram) error {
		if after != nil {
			// The scan seeks by key; the cursor is the decoded ID. A record whose
			// ID sorts before the cursor would send the next page backwards, so
			// fail loudly instead of looping or skipping.
			if c := storage.CompareULIDs(eng.ID, *after); c == 0 {
				return nil
			} else if c < 0 {
				return fmt.Errorf("list engrams after: record %s sorts before cursor %s", eng.ID, *after)
			}
		}
		active := eng.State != storage.StateSoftDeleted && eng.State != storage.StateArchived
		// A full page stops only at the next active row, so a vault whose
		// remaining rows are all inactive reports nil next on this page.
		if visited == maxKeysetScanRows || (active && len(page) == limit) {
			return errKeysetPageDone
		}
		visited++
		last = eng.ID
		if active {
			page = append(page, eng)
		}
		return nil
	})
	if errors.Is(err, errKeysetPageDone) {
		return page, &last, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return page, nil, nil
}
