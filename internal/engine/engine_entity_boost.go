package engine

import (
	"context"
	"sort"

	"github.com/scrypster/muninndb/internal/engine/activation"
	"github.com/scrypster/muninndb/internal/storage"
)

const (
	// entityBoostFactor is the score added to engrams that share a named entity
	// with a top-N BFS result. Kept well below typical BFS association weights
	// (~0.3–0.9) so the boost surfaces related content without dominating.
	entityBoostFactor = float64(0.15)

	// entityBoostTopN is the number of top BFS results whose entity links are
	// used as seeds for the spread-activation pass.
	entityBoostTopN = 5
)

// applyEntityBoost performs a post-BFS spread-activation pass using named
// entities. It takes the top-N results from the BFS activation, collects
// every entity linked to those engrams via the 0x20 forward index, then
// finds all other engrams in the same vault that mention those entities via
// the 0x23 reverse index. Each such engram receives a score boost of
// entityBoostFactor (or is added to the result set with that score if it was
// not already returned by BFS). Results are re-sorted by score descending.
//
// Each engram is boosted at most once per query: without that, an engram
// sharing several entities with several seeds stacked up to
// entityBoostTopN x entities x entityBoostFactor and outranked strong direct
// matches. An engram added here must also satisfy the request's filters and
// threshold, exactly like one returned by Run.
func (e *Engine) applyEntityBoost(ctx context.Context, ws [8]byte, results []activation.ScoredEngram, filters []activation.Filter, threshold float64) []activation.ScoredEngram {
	if len(results) == 0 {
		return results
	}
	boosted := make(map[storage.ULID]bool, len(results))

	// Seed the boost from at most entityBoostTopN top results.
	seedCount := len(results)
	if seedCount > entityBoostTopN {
		seedCount = entityBoostTopN
	}
	seeds := results[:seedCount]

	// Build a reverse lookup: ULID → index in results slice.
	seenInResults := make(map[storage.ULID]int, len(results))
	for i, r := range results {
		seenInResults[r.Engram.ID] = i
	}

	// For each seed engram, iterate its entity links (0x20 forward index).
	for _, topEng := range seeds {
		_ = e.store.ScanEngramEntities(ctx, ws, topEng.Engram.ID, func(entityName string) error {
			// For each entity, scan all engrams that mention it (0x23 reverse index).
			return e.store.ScanEntityEngrams(ctx, entityName, func(entityWS [8]byte, engramID storage.ULID) error {
				if entityWS != ws {
					return nil // skip other vaults
				}
				// Skip the seed itself — it already has its BFS score.
				if engramID == topEng.Engram.ID {
					return nil
				}

				if boosted[engramID] {
					return nil
				}
				if idx, found := seenInResults[engramID]; found {
					// Boost existing result.
					results[idx].Score += entityBoostFactor
					boosted[engramID] = true
				} else {
					// A new result enters at entityBoostFactor, so it must clear the
					// caller's threshold (checked before the fetch) and filters.
					if entityBoostFactor < threshold {
						return nil
					}
					eng, err := e.store.GetEngram(ctx, ws, engramID)
					if err != nil || eng == nil {
						return nil
					}
					if eng.State == storage.StateSoftDeleted || eng.State == storage.StateArchived {
						return nil
					}
					if !activation.PassesMetaFilter(eng, filters) {
						return nil
					}
					results = append(results, activation.ScoredEngram{
						Engram: eng,
						Score:  entityBoostFactor,
					})
					seenInResults[engramID] = len(results) - 1
					boosted[engramID] = true
				}
				return nil
			})
		})
	}

	// Re-sort descending by score after boost adjustments.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}
