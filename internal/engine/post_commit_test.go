package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/engine/activation"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	"github.com/scrypster/muninndb/internal/index/fts"
	"github.com/scrypster/muninndb/internal/plugin"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/storage/keys"
	"github.com/scrypster/muninndb/internal/transport/mbp"
	"github.com/stretchr/testify/require"
)

// testEnvWithDB is like testEnv but also returns the raw *pebble.DB so tests
// can corrupt specific keys to force targeted secondary-persistence failures.
// The cleanup closes the DB through store.Close() only; do not close db directly.
func testEnvWithDB(t *testing.T) (*Engine, *pebble.DB, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "muninndb-engine-test-*")
	if err != nil {
		t.Fatal(err)
	}

	db, err := storage.OpenPebble(dir, storage.DefaultOptions())
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}

	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 1000})
	ftsIdx := fts.New(db)

	embedder := &noopEmbedder{}
	actEngine := activation.New(store, &ftsAdapter{ftsIdx}, nil, embedder)
	trigSystem := trigger.New(store, &ftsTrigAdapter{ftsIdx}, nil, embedder)
	eng := NewEngine(EngineConfig{Store: store, FTSIndex: ftsIdx, ActivationEngine: actEngine, TriggerSystem: trigSystem, Embedder: embedder})

	return eng, db, func() {
		eng.Stop()
		store.Close()
		os.RemoveAll(dir)
	}
}

func TestWriteRequiredPostCommitIgnoresCallerCancellation(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	eng.afterPrimaryCommit = cancel

	resp, err := eng.Write(ctx, &mbp.WriteRequest{
		Vault:   "post-commit-caller-cancel",
		Concept: "caller cancellation",
		Content: "required entity persistence survives request cancellation",
		Entities: []mbp.InlineEntity{
			{Name: "PostgreSQL", Type: "database"},
		},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Hint)
	require.ErrorIs(t, ctx.Err(), context.Canceled)

	record, err := eng.store.GetEntityRecord(context.Background(), "PostgreSQL")
	require.NoError(t, err)
	require.NotNil(t, record)
	require.Equal(t, int32(1), record.MentionCount)

	id, err := storage.ParseULID(resp.ID)
	require.NoError(t, err)
	flags, err := eng.store.GetDigestFlags(context.Background(), plugin.ULID(id))
	require.NoError(t, err)
	require.NotZero(t, flags&plugin.DigestEntities)

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(1), stats.Attempts)
	require.Equal(t, int64(1), stats.Completed)
	require.Zero(t, stats.Degraded)
}

func TestStopCancelsAndDrainsRequiredPostCommit(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx, done, ok := eng.beginRequiredPostCommit()
	require.True(t, ok)

	stopped := make(chan struct{})
	go func() {
		eng.Stop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("post-commit context was not canceled by Engine.Stop")
	}

	select {
	case <-stopped:
		t.Fatal("Engine.Stop returned before required post-commit work drained")
	default:
	}

	done()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Engine.Stop did not return after required post-commit work drained")
	}
}

func TestRequiredPostCommitRejectsWorkAfterStop(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	eng.Stop()

	outcomes := eng.runRequiredPostCommit([]requiredPostCommitItem{{
		id:                   storage.NewULID(),
		skipBackgroundEnrich: true,
	}})
	require.Len(t, outcomes, 1)
	require.True(t, outcomes[0].degraded)
	require.Equal(t, postCommitFailureShutdownRejection, outcomes[0].firstFailure)

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(1), stats.Attempts)
	require.Zero(t, stats.Completed)
	require.Equal(t, int64(1), stats.Degraded)
	require.Equal(t, int64(1), stats.ShutdownRejections)
}

func TestWriteCoOccurrenceFailureLeavesEntityDigestIncomplete(t *testing.T) {
	eng, db, cleanup := testEnvWithDB(t)
	defer cleanup()

	ws := eng.store.ResolveVaultPrefix("post-commit-co-occurrence")
	hashA := keys.EntityNameHash("PostgreSQL")
	hashB := keys.EntityNameHash("Redis")
	if bytes.Compare(hashA[:], hashB[:]) > 0 {
		hashA, hashB = hashB, hashA
	}
	require.NoError(t, db.Set(keys.CoOccurrenceKey(ws, hashA, hashB), []byte{0xc1}, pebble.NoSync))

	resp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "post-commit-co-occurrence",
		Concept: "entity graph",
		Content: "PostgreSQL and Redis participate in the entity graph",
		Entities: []mbp.InlineEntity{
			{Name: "PostgreSQL", Type: "database"},
			{Name: "Redis", Type: "database"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, postCommitHint, resp.Hint)

	count, err := eng.store.CountWithFlag(context.Background(), plugin.DigestEntities)
	require.NoError(t, err)
	require.Zero(t, count)

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(1), stats.Attempts)
	require.Equal(t, int64(1), stats.Degraded)
	require.Equal(t, int64(1), stats.CoOccurrenceFailures)
}

func TestWriteEntityRelationshipCancellationPreservesIndependentDigestFlags(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	eng.beforeEntityRelationships = eng.stopCancel
	resp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "post-commit-entity-relationship",
		Concept: "entity relationship persistence",
		Content: "Alice uses PostgreSQL",
		Entities: []mbp.InlineEntity{
			{Name: "Alice", Type: "person"},
			{Name: "PostgreSQL", Type: "database"},
		},
		EntityRelationships: []mbp.InlineEntityRelationship{
			{
				FromEntity: "Alice",
				ToEntity:   "PostgreSQL",
				RelType:    "uses",
				Weight:     0.9,
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, postCommitHint, resp.Hint)

	id, err := storage.ParseULID(resp.ID)
	require.NoError(t, err)
	flags, err := eng.store.GetDigestFlags(context.Background(), plugin.ULID(id))
	require.NoError(t, err)
	require.NotZero(t, flags&plugin.DigestEntities)
	require.Zero(t, flags&plugin.DigestRelationships)

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(1), stats.Attempts)
	require.Equal(t, int64(1), stats.Degraded)
	require.Equal(t, int64(1), stats.ShutdownCancellations)
}

func TestWriteEntityRelationshipSetsRelationshipDigest(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	resp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "post-commit-entity-relationship-success",
		Concept: "entity relationship completion",
		Content: "Alice uses PostgreSQL",
		EntityRelationships: []mbp.InlineEntityRelationship{
			{
				FromEntity: "Alice",
				ToEntity:   "PostgreSQL",
				RelType:    "uses",
				Weight:     0.9,
			},
		},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Hint)

	id, err := storage.ParseULID(resp.ID)
	require.NoError(t, err)
	flags, err := eng.store.GetDigestFlags(context.Background(), plugin.ULID(id))
	require.NoError(t, err)
	require.Zero(t, flags&plugin.DigestEntities)
	require.NotZero(t, flags&plugin.DigestRelationships)
}

func TestBackgroundOnlyPersistsCallerRelationshipWithoutCompletingStage(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "write"
		if batch {
			name = "write_batch"
		}
		t.Run(name, func(t *testing.T) {
			eng, cleanup := testEnvWithInlineMode(t, "background_only")
			defer cleanup()

			req := &mbp.WriteRequest{
				Vault:   "test-vault",
				Concept: "background relationship persistence",
				Content: "Alice uses PostgreSQL " + name,
				EntityRelationships: []mbp.InlineEntityRelationship{
					{
						FromEntity: "Alice",
						ToEntity:   "PostgreSQL",
						RelType:    "uses",
						Weight:     0.9,
					},
				},
			}

			var resp *mbp.WriteResponse
			var err error
			if batch {
				responses, errs := eng.WriteBatch(
					context.Background(),
					[]*mbp.WriteRequest{req},
				)
				require.NoError(t, errs[0])
				resp = responses[0]
			} else {
				resp, err = eng.Write(context.Background(), req)
				require.NoError(t, err)
			}
			require.Empty(t, resp.Hint)

			id, err := storage.ParseULID(resp.ID)
			require.NoError(t, err)
			flags, err := eng.store.GetDigestFlags(
				context.Background(),
				plugin.ULID(id),
			)
			if err != nil {
				require.ErrorIs(t, err, pebble.ErrNotFound)
			} else {
				require.Zero(t, flags&plugin.DigestRelationships)
			}

			read, err := eng.Read(context.Background(), &mbp.ReadRequest{
				Vault: "test-vault",
				ID:    resp.ID,
			})
			require.NoError(t, err)
			require.Len(t, read.EntityRelationships, 1)
			require.Equal(t, "uses", read.EntityRelationships[0].RelType)
		})
	}
}

func TestWriteWithoutHNSWLeavesEmbeddingDigestIncomplete(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	// NewEngine starts the optional semantic-neighbor worker even when its HNSW
	// dependency is nil. Disable that unrelated asynchronous path so this test
	// isolates required post-commit persistence.
	eng.neighborWorker.Stop()
	eng.neighborWorker = nil

	resp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:     "post-commit-embedding",
		Concept:   "embedding persistence",
		Content:   "embedding completion requires the vector index",
		Embedding: []float32{0.1, 0.2, 0.3},
	})
	require.NoError(t, err)
	require.Equal(t, postCommitHint, resp.Hint)

	count, err := eng.store.CountWithFlag(context.Background(), plugin.DigestEmbed)
	require.NoError(t, err)
	require.Zero(t, count)

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(1), stats.Attempts)
	require.Equal(t, int64(1), stats.Degraded)
	require.Equal(t, int64(1), stats.EmbeddingFailures)
}

func TestObservabilityPostCommitCountersUseFixedShape(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	eng.neighborWorker.Stop()
	eng.neighborWorker = nil

	_, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "post-commit-observability",
		Concept: "successful entity persistence",
		Content: "entity persistence succeeds",
		Entities: []mbp.InlineEntity{
			{Name: "Pebble", Type: "database"},
		},
	})
	require.NoError(t, err)

	_, err = eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:     "post-commit-observability",
		Concept:   "degraded embedding persistence",
		Content:   "embedding persistence degrades without HNSW",
		Embedding: []float32{0.4, 0.5, 0.6},
	})
	require.NoError(t, err)

	snapshot, err := eng.Observability(context.Background(), "test", 1)
	require.NoError(t, err)
	require.Equal(t, int64(2), snapshot.PostCommit.Attempts)
	require.Equal(t, int64(1), snapshot.PostCommit.Completed)
	require.Equal(t, int64(1), snapshot.PostCommit.Degraded)
	require.Equal(t, int64(1), snapshot.PostCommit.EmbeddingFailures)

	raw, err := json.Marshal(snapshot.PostCommit)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.ElementsMatch(t, []string{
		"attempts",
		"completed",
		"degraded",
		"entity_record_failures",
		"entity_link_failures",
		"co_occurrence_failures",
		"association_failures",
		"entity_relationship_failures",
		"digest_flag_failures",
		"embedding_failures",
		"timeouts",
		"shutdown_cancellations",
		"shutdown_rejections",
	}, mapKeys(fields))
}

func TestWriteBatchRunsRequiredPostCommitOncePerCommittedNonduplicateItem(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	_, err := eng.Write(ctx, &mbp.WriteRequest{
		Vault:   "post-commit-batch",
		Concept: "existing memory",
		Content: "duplicate batch content",
	})
	require.NoError(t, err)

	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{
		{
			Vault:   "post-commit-batch",
			Concept: "first committed item",
			Content: "first unique batch content",
			Entities: []mbp.InlineEntity{
				{Name: "Batch Alice", Type: "person"},
			},
		},
		{
			Vault:   "post-commit-batch",
			Concept: "duplicate item",
			Content: "duplicate batch content",
			Entities: []mbp.InlineEntity{
				{Name: "Duplicate Entity", Type: "other"},
			},
		},
		{
			Vault:   "post-commit-batch",
			Concept: "invalid item",
			Content: "invalid association target",
			Entities: []mbp.InlineEntity{
				{Name: "Failed Entity", Type: "other"},
			},
			Associations: []mbp.Association{{TargetID: "not-a-ulid"}},
		},
		{
			Vault:   "post-commit-batch",
			Concept: "second committed item",
			Content: "second unique batch content",
			Entities: []mbp.InlineEntity{
				{Name: "Batch Bob", Type: "person"},
			},
		},
	})

	require.Len(t, responses, 4)
	require.Len(t, errs, 4)
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.Error(t, errs[2])
	require.NoError(t, errs[3])
	require.Equal(t, "duplicate_content", responses[1].Hint)
	require.Nil(t, responses[2])

	for _, name := range []string{"Batch Alice", "Batch Bob"} {
		record, recordErr := eng.store.GetEntityRecord(ctx, name)
		require.NoError(t, recordErr)
		require.NotNil(t, record)
		require.Equal(t, int32(1), record.MentionCount)
	}
	for _, name := range []string{"Duplicate Entity", "Failed Entity"} {
		record, recordErr := eng.store.GetEntityRecord(ctx, name)
		require.NoError(t, recordErr)
		require.Nil(t, record)
	}

	stats := eng.postCommitCounters.snapshot()
	require.Equal(t, int64(2), stats.Attempts)
	require.Equal(t, int64(2), stats.Completed)
	require.Zero(t, stats.Degraded)
}

func mapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
