package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/engine/activation"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/stretchr/testify/require"
)

// TestEntityBoost_BoostsOnceAndHonorsThresholdAndFilters: result B shares two
// entities with two other seeds yet gains entityBoostFactor exactly once (it
// used to stack +0.15 per seed x entity); a new engram D linked to a seed's
// entity is added only when entityBoostFactor clears the threshold and D
// passes the request filters.
func TestEntityBoost_BoostsOnceAndHonorsThresholdAndFilters(t *testing.T) {
	t.Parallel()
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	ws := eng.store.ResolveVaultPrefix("boost-contract-test")

	write := func(concept string, tags []string, entities ...string) storage.ULID {
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{
			Concept: concept, Content: concept + " content", Confidence: 0.9, Tags: tags,
		})
		require.NoError(t, err)
		for _, name := range entities {
			require.NoError(t, eng.store.UpsertEntityRecord(ctx, storage.EntityRecord{Name: name, Type: "org", Source: "inline"}, "inline"))
			require.NoError(t, eng.store.WriteEntityEngramLink(ctx, ws, id, name))
		}
		return id
	}
	idS1 := write("seed-1", nil, "Acme", "Widget")
	idS2 := write("seed-2", nil, "Acme", "Widget")
	idB := write("result-b", nil, "Acme", "Widget")
	idD := write("new-d", []string{"other"}, "Acme")

	results := func() []activation.ScoredEngram {
		var out []activation.ScoredEngram
		for _, id := range []storage.ULID{idS1, idS2, idB} {
			full, err := eng.store.GetEngram(ctx, ws, id)
			require.NoError(t, err)
			out = append(out, activation.ScoredEngram{Engram: full, Score: 0.5})
		}
		return out
	}
	score := func(rs []activation.ScoredEngram, id storage.ULID) (float64, bool) {
		for _, r := range rs {
			if r.Engram.ID == id {
				return r.Score, true
			}
		}
		return 0, false
	}

	rs := eng.applyEntityBoost(ctx, ws, results(), nil, 0)
	bScore, ok := score(rs, idB)
	require.True(t, ok, "B stays in results")
	require.InDelta(t, 0.5+entityBoostFactor, bScore, 0.001, "B is boosted exactly once")
	_, dFound := score(rs, idD)
	require.True(t, dFound, "D is added with no threshold or filters")

	rs = eng.applyEntityBoost(ctx, ws, results(), nil, 0.3)
	_, dFound = score(rs, idD)
	require.False(t, dFound, "D (entityBoostFactor score) must not be added below the threshold")

	rs = eng.applyEntityBoost(ctx, ws, results(), []activation.Filter{{Field: "tags_all", Value: []string{"d2c"}}}, 0)
	_, dFound = score(rs, idD)
	require.False(t, dFound, "D must not be added when it fails the request filters")
}
