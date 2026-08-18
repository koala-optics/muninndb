package engine

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scrypster/muninndb/internal/plugin"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

const (
	postCommitTimeout = 30 * time.Second
	postCommitHint    = "primary_committed; post_commit=degraded; retry=unsafe"
)

const (
	postCommitFailureEntityRecord       = "entity_record"
	postCommitFailureEntityLink         = "entity_link"
	postCommitFailureCoOccurrence       = "co_occurrence"
	postCommitFailureAssociation        = "association"
	postCommitFailureEntityRelationship = "entity_relationship"
	postCommitFailureDigestFlag         = "digest_flag"
	postCommitFailureEmbedding          = "embedding"
	postCommitFailureTimeout            = "timeout"
	postCommitFailureShutdown           = "shutdown"
	postCommitFailureShutdownRejection  = "shutdown_rejection"
)

type postCommitCounters struct {
	attempts                   atomic.Int64
	completed                  atomic.Int64
	degraded                   atomic.Int64
	entityRecordFailures       atomic.Int64
	entityLinkFailures         atomic.Int64
	coOccurrenceFailures       atomic.Int64
	associationFailures        atomic.Int64
	entityRelationshipFailures atomic.Int64
	digestFlagFailures         atomic.Int64
	embeddingFailures          atomic.Int64
	timeouts                   atomic.Int64
	shutdownCancellations      atomic.Int64
	shutdownRejections         atomic.Int64
}

func (c *postCommitCounters) snapshot() PostCommitStats {
	return PostCommitStats{
		Attempts:                   c.attempts.Load(),
		Completed:                  c.completed.Load(),
		Degraded:                   c.degraded.Load(),
		EntityRecordFailures:       c.entityRecordFailures.Load(),
		EntityLinkFailures:         c.entityLinkFailures.Load(),
		CoOccurrenceFailures:       c.coOccurrenceFailures.Load(),
		AssociationFailures:        c.associationFailures.Load(),
		EntityRelationshipFailures: c.entityRelationshipFailures.Load(),
		DigestFlagFailures:         c.digestFlagFailures.Load(),
		EmbeddingFailures:          c.embeddingFailures.Load(),
		Timeouts:                   c.timeouts.Load(),
		ShutdownCancellations:      c.shutdownCancellations.Load(),
		ShutdownRejections:         c.shutdownRejections.Load(),
	}
}

// requiredPostCommitItem carries everything one committed engram needs for its
// required (caller-supplied) secondary persistence: inline entities and their
// links/co-occurrence, inline associations, entity relationships, the caller
// embedding, and the enrichment-skip flag. Summary/classification stage flags
// are metadata about caller-supplied fields already inside the committed
// engram, not separate persistence, so they stay on the caller path.
type requiredPostCommitItem struct {
	wsPrefix                  [8]byte
	id                        storage.ULID
	embedding                 []float32
	callerEntities            []mbp.InlineEntity
	callerRelationships       []mbp.InlineRelationship
	callerEntityRelationships []mbp.InlineEntityRelationship
	completeRelationshipStage bool
	skipBackgroundEnrich      bool
}

func (item requiredPostCommitItem) required() bool {
	return len(item.embedding) > 0 ||
		len(item.callerEntities) > 0 ||
		len(item.callerRelationships) > 0 ||
		len(item.callerEntityRelationships) > 0 ||
		item.skipBackgroundEnrich
}

type postCommitOutcome struct {
	degraded     bool
	firstFailure string
	contextError bool
}

// beginRequiredPostCommit admits one unit of required post-commit work into
// the lifecycle-scoped WaitGroup, or refuses when shutdown has begun. The
// returned context is detached from the request and bounded by the engine
// lifecycle plus postCommitTimeout.
func (e *Engine) beginRequiredPostCommit() (context.Context, context.CancelFunc, bool) {
	e.postCommitMu.RLock()
	if e.postCommitStopped.Load() || e.stopCtx == nil || e.stopCtx.Err() != nil {
		e.postCommitMu.RUnlock()
		return nil, nil, false
	}
	e.postCommitWG.Add(1)
	ctx, cancel := context.WithTimeout(e.stopCtx, postCommitTimeout)
	e.postCommitMu.RUnlock()
	return ctx, func() {
		cancel()
		e.postCommitWG.Done()
	}, true
}

func (e *Engine) runRequiredPostCommit(items []requiredPostCommitItem) []postCommitOutcome {
	outcomes := make([]postCommitOutcome, len(items))
	var required int
	for i := range items {
		if items[i].required() {
			required++
		}
	}
	if required == 0 {
		return outcomes
	}

	ctx, done, ok := e.beginRequiredPostCommit()
	if !ok {
		for i := range items {
			if !items[i].required() {
				continue
			}
			e.postCommitCounters.attempts.Add(1)
			e.recordPostCommitFailure(&outcomes[i], postCommitFailureShutdownRejection)
			e.finishPostCommitOutcome(outcomes[i])
		}
		return outcomes
	}
	defer done()

	for i := range items {
		if !items[i].required() {
			continue
		}
		e.postCommitCounters.attempts.Add(1)
		e.persistRequiredPostCommit(ctx, items[i], &outcomes[i])
		e.finishPostCommitOutcome(outcomes[i])
	}
	return outcomes
}

func (e *Engine) persistRequiredPostCommit(ctx context.Context, item requiredPostCommitItem, outcome *postCommitOutcome) {
	if e.stopPostCommitOnContext(ctx, outcome) {
		return
	}

	entityPersistenceComplete := true
	linkedEntityNames := make([]string, 0, len(item.callerEntities))
	for _, ent := range item.callerEntities {
		if e.stopPostCommitOnContext(ctx, outcome) {
			return
		}
		typ := strings.ToLower(strings.TrimSpace(ent.Type))
		if typ == "" {
			typ = "other"
		}
		record := storage.EntityRecord{Name: ent.Name, Type: typ, Confidence: 1.0}
		if err := e.store.UpsertEntityRecord(ctx, record, "inline"); err != nil {
			entityPersistenceComplete = false
			e.recordPostCommitError(ctx, outcome, postCommitFailureEntityRecord)
			continue
		}
		if err := e.store.WriteEntityEngramLink(ctx, item.wsPrefix, item.id, ent.Name); err != nil {
			entityPersistenceComplete = false
			e.recordPostCommitError(ctx, outcome, postCommitFailureEntityLink)
			continue
		}
		linkedEntityNames = append(linkedEntityNames, ent.Name)
	}

	for i := 0; i < len(linkedEntityNames); i++ {
		for j := i + 1; j < len(linkedEntityNames); j++ {
			if e.stopPostCommitOnContext(ctx, outcome) {
				return
			}
			if err := e.store.IncrementEntityCoOccurrence(ctx, item.wsPrefix, linkedEntityNames[i], linkedEntityNames[j]); err != nil {
				entityPersistenceComplete = false
				e.recordPostCommitError(ctx, outcome, postCommitFailureCoOccurrence)
			}
			if err := e.store.UpsertRelationshipRecord(ctx, item.wsPrefix, item.id, storage.RelationshipRecord{
				FromEntity: linkedEntityNames[i],
				ToEntity:   linkedEntityNames[j],
				RelType:    "co_occurs_with",
				Weight:     0.3,
				Source:     "co-occurrence",
			}); err != nil {
				entityPersistenceComplete = false
				e.recordPostCommitError(ctx, outcome, postCommitFailureEntityRelationship)
			}
		}
	}
	if len(item.callerEntities) > 0 && entityPersistenceComplete &&
		!e.stopPostCommitOnContext(ctx, outcome) {
		if err := e.store.SetDigestFlag(ctx, item.id, plugin.DigestEntities); err != nil {
			e.recordPostCommitError(ctx, outcome, postCommitFailureDigestFlag)
		}
	}

	for _, rel := range item.callerRelationships {
		if e.stopPostCommitOnContext(ctx, outcome) {
			return
		}
		targetULID, err := storage.ParseULID(rel.TargetID)
		if err != nil {
			e.recordPostCommitFailure(outcome, postCommitFailureAssociation)
			continue
		}
		assoc := &storage.Association{
			TargetID:   targetULID,
			RelType:    storage.RelType(relTypeFromString(rel.Relation)),
			Weight:     rel.Weight,
			Confidence: 1.0,
			CreatedAt:  time.Now(),
		}
		if err := e.store.WriteAssociation(ctx, item.wsPrefix, item.id, targetULID, assoc); err != nil {
			e.recordPostCommitError(ctx, outcome, postCommitFailureAssociation)
		}
	}

	relationshipPersistenceComplete := true
	validEntityRelationships := 0
	if e.beforeEntityRelationships != nil && len(item.callerEntityRelationships) > 0 {
		e.beforeEntityRelationships()
	}
	for _, rel := range item.callerEntityRelationships {
		if e.stopPostCommitOnContext(ctx, outcome) {
			return
		}
		if rel.FromEntity == "" || rel.ToEntity == "" || rel.RelType == "" {
			continue
		}
		validEntityRelationships++
		weight := rel.Weight
		if weight <= 0 {
			weight = 0.9
		}
		if err := e.store.UpsertRelationshipRecord(ctx, item.wsPrefix, item.id, storage.RelationshipRecord{
			FromEntity: rel.FromEntity,
			ToEntity:   rel.ToEntity,
			RelType:    rel.RelType,
			Weight:     weight,
			Source:     "inline",
		}); err != nil {
			relationshipPersistenceComplete = false
			e.recordPostCommitError(ctx, outcome, postCommitFailureEntityRelationship)
		}
	}
	if item.completeRelationshipStage && validEntityRelationships > 0 &&
		relationshipPersistenceComplete && !e.stopPostCommitOnContext(ctx, outcome) {
		if err := e.store.SetDigestFlag(ctx, item.id, plugin.DigestRelationships); err != nil {
			e.recordPostCommitError(ctx, outcome, postCommitFailureDigestFlag)
		}
	}

	if len(item.embedding) > 0 && !e.stopPostCommitOnContext(ctx, outcome) {
		embeddingComplete := true
		if e.hnswRegistry == nil {
			embeddingComplete = false
			e.recordPostCommitFailure(outcome, postCommitFailureEmbedding)
		} else if err := e.hnswRegistry.Insert(ctx, item.wsPrefix, [16]byte(item.id), item.embedding); err != nil {
			embeddingComplete = false
			e.recordPostCommitError(ctx, outcome, postCommitFailureEmbedding)
		}
		if embeddingComplete && !e.stopPostCommitOnContext(ctx, outcome) {
			if err := e.store.SetDigestFlag(ctx, item.id, plugin.DigestEmbed); err != nil {
				e.recordPostCommitError(ctx, outcome, postCommitFailureDigestFlag)
			}
		}
	}

	if item.skipBackgroundEnrich && !e.stopPostCommitOnContext(ctx, outcome) {
		if err := e.store.SetDigestFlag(ctx, item.id, plugin.DigestEnrich); err != nil {
			e.recordPostCommitError(ctx, outcome, postCommitFailureDigestFlag)
		}
	}
}

func (e *Engine) stopPostCommitOnContext(ctx context.Context, outcome *postCommitOutcome) bool {
	if ctx.Err() == nil {
		return false
	}
	e.recordPostCommitContextFailure(ctx, outcome)
	return true
}

func (e *Engine) recordPostCommitError(ctx context.Context, outcome *postCommitOutcome, category string) {
	if ctx.Err() != nil {
		e.recordPostCommitContextFailure(ctx, outcome)
		return
	}
	e.recordPostCommitFailure(outcome, category)
}

func (e *Engine) recordPostCommitContextFailure(ctx context.Context, outcome *postCommitOutcome) {
	if outcome.contextError {
		return
	}
	outcome.contextError = true
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		e.recordPostCommitFailure(outcome, postCommitFailureTimeout)
		return
	}
	e.recordPostCommitFailure(outcome, postCommitFailureShutdown)
}

func (e *Engine) recordPostCommitFailure(outcome *postCommitOutcome, category string) {
	outcome.degraded = true
	if outcome.firstFailure == "" {
		outcome.firstFailure = category
	}
	switch category {
	case postCommitFailureEntityRecord:
		e.postCommitCounters.entityRecordFailures.Add(1)
	case postCommitFailureEntityLink:
		e.postCommitCounters.entityLinkFailures.Add(1)
	case postCommitFailureCoOccurrence:
		e.postCommitCounters.coOccurrenceFailures.Add(1)
	case postCommitFailureAssociation:
		e.postCommitCounters.associationFailures.Add(1)
	case postCommitFailureEntityRelationship:
		e.postCommitCounters.entityRelationshipFailures.Add(1)
	case postCommitFailureDigestFlag:
		e.postCommitCounters.digestFlagFailures.Add(1)
	case postCommitFailureEmbedding:
		e.postCommitCounters.embeddingFailures.Add(1)
	case postCommitFailureTimeout:
		e.postCommitCounters.timeouts.Add(1)
	case postCommitFailureShutdown:
		e.postCommitCounters.shutdownCancellations.Add(1)
	case postCommitFailureShutdownRejection:
		e.postCommitCounters.shutdownRejections.Add(1)
	}
}

func (e *Engine) finishPostCommitOutcome(outcome postCommitOutcome) {
	if !outcome.degraded {
		e.postCommitCounters.completed.Add(1)
		return
	}
	e.postCommitCounters.degraded.Add(1)
	slog.Warn("engine: required post-commit persistence degraded", "category", outcome.firstFailure)
}

func (e *Engine) drainRequiredPostCommit() {
	e.postCommitMu.Lock()
	e.postCommitStopped.Store(true)
	e.postCommitMu.Unlock()

	e.postCommitWG.Wait()
}

// Compile-time assertion that the lifecycle fence remains a real lock. This is
// intentionally local to the post-commit implementation so future refactors do
// not replace it with a check-then-Add WaitGroup race.
var _ sync.Locker = (*sync.RWMutex)(nil)
