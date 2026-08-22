package engine

import (
	"context"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestGetEntityTimeline_ChronologicalOrder(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()

	// Write 3 engrams at different times, all mentioning the same entity.
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-1 * time.Hour),
		now,
	}

	entityName := "TestEntity"
	for i, tm := range times {
		req := &mbp.WriteRequest{
			Vault:   "default",
			Concept: "Concept " + string(rune(i)),
			Content: "Content " + string(rune(i)),
		}
		req.CreatedAt = &tm
		req.Entities = []mbp.InlineEntity{
			{Name: entityName, Type: "test"},
		}
		_, err := eng.Write(ctx, req)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	// Retrieve timeline
	timeline, err := eng.GetEntityTimeline(ctx, "default", entityName, 10)
	if err != nil {
		t.Fatalf("GetEntityTimeline failed: %v", err)
	}

	// Verify results
	if timeline.Entity != entityName {
		t.Errorf("Expected entity %q, got %q", entityName, timeline.Entity)
	}
	if timeline.Count != 3 {
		t.Errorf("Expected 3 entries, got %d", timeline.Count)
	}
	if timeline.MentionCount != 3 {
		t.Errorf("Expected mention count 3, got %d", timeline.MentionCount)
	}

	// Verify chronological order (oldest first)
	for i := 0; i < len(timeline.Entries)-1; i++ {
		if !timeline.Entries[i].CreatedAt.Before(timeline.Entries[i+1].CreatedAt) {
			t.Errorf("Entries not in chronological order at index %d and %d", i, i+1)
		}
	}
}

func TestGetEntityTimeline_LimitCaps(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()

	// Write 5 engrams mentioning the same entity.
	entityName := "LimitTest"
	now := time.Now()
	for i := 0; i < 5; i++ {
		req := &mbp.WriteRequest{
			Vault:   "default",
			Concept: "Concept " + string(rune(i)),
			Content: "Content " + string(rune(i)),
		}
		tm := now.Add(time.Duration(-i) * time.Hour)
		req.CreatedAt = &tm
		req.Entities = []mbp.InlineEntity{
			{Name: entityName, Type: "test"},
		}
		_, err := eng.Write(ctx, req)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	// Retrieve timeline with limit=3
	timeline, err := eng.GetEntityTimeline(ctx, "default", entityName, 3)
	if err != nil {
		t.Fatalf("GetEntityTimeline failed: %v", err)
	}

	if timeline.Count != 3 {
		t.Errorf("Expected 3 entries (capped by limit), got %d", timeline.Count)
	}
	if timeline.MentionCount != 5 {
		t.Errorf("Expected mention count 5 (total), got %d", timeline.MentionCount)
	}

	// REGRESSION GUARD: a capped timeline must keep the most RECENT `limit`
	// mentions, not the oldest. i=0 is newest (now), i=4 is oldest (now-4h).
	// The old oldest-first scan returned the 3 OLDEST and silently hid recent
	// history; this asserts the 3 NEWEST are present. Entries are sorted
	// ascending for display, so the newest of the kept set is the last entry.
	if len(timeline.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(timeline.Entries))
	}
	newest := timeline.Entries[len(timeline.Entries)-1].CreatedAt
	oldestKept := timeline.Entries[0].CreatedAt
	// newest kept must be within ~1s of `now` (i=0), not now-4h.
	if now.Sub(newest) > time.Second {
		t.Errorf("capped timeline missing the most recent mention: newest kept=%v, expected ~%v (oldest-first truncation regression)", newest, now)
	}
	// oldest kept must be now-2h (i=2), i.e. the 3rd-newest, NOT now-4h.
	expectedOldestKept := now.Add(-2 * time.Hour)
	if oldestKept.Sub(expectedOldestKept).Abs() > time.Second {
		t.Errorf("capped timeline kept wrong window: oldest kept=%v, expected ~%v (the 3 newest are now, now-1h, now-2h)", oldestKept, expectedOldestKept)
	}
}

func TestGetEntityTimeline_EntityNotFound(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()

	// Try to get timeline for non-existent entity
	timeline, err := eng.GetEntityTimeline(ctx, "default", "NonExistentEntity", 10)
	if err == nil {
		t.Errorf("Expected error for non-existent entity, got nil")
	}
	if timeline != nil {
		t.Errorf("Expected nil timeline for non-existent entity, got %v", timeline)
	}
}

func TestGetEntityTimeline_DefaultLimit(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()

	// Write 15 engrams
	entityName := "DefaultLimitTest"
	now := time.Now()
	for i := 0; i < 15; i++ {
		req := &mbp.WriteRequest{
			Vault:   "default",
			Concept: "Concept " + string(rune(i)),
			Content: "Content " + string(rune(i)),
		}
		tm := now.Add(time.Duration(-i) * time.Hour)
		req.CreatedAt = &tm
		req.Entities = []mbp.InlineEntity{
			{Name: entityName, Type: "test"},
		}
		_, err := eng.Write(ctx, req)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	// Default limit should be 10
	timeline, err := eng.GetEntityTimeline(ctx, "default", entityName, 0)
	if err != nil {
		t.Fatalf("GetEntityTimeline failed: %v", err)
	}

	if timeline.Count != 10 {
		t.Errorf("Expected 10 entries (default limit), got %d", timeline.Count)
	}
}

func TestGetEntityTimeline_SkipsSoftDeleted(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()

	entityName := "SoftDeleteTest"
	now := time.Now()

	// Write 2 engrams
	var engramIDs []string
	for i := 0; i < 2; i++ {
		req := &mbp.WriteRequest{
			Vault:   "default",
			Concept: "Concept " + string(rune(i)),
			Content: "Content " + string(rune(i)),
		}
		tm := now.Add(time.Duration(-i) * time.Hour)
		req.CreatedAt = &tm
		req.Entities = []mbp.InlineEntity{
			{Name: entityName, Type: "test"},
		}
		resp, err := eng.Write(ctx, req)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		engramIDs = append(engramIDs, resp.ID)
	}

	// Soft-delete the first engram
	_, err := eng.Forget(ctx, &mbp.ForgetRequest{
		Vault: "default",
		ID:    engramIDs[0],
	})
	if err != nil {
		t.Fatalf("Forget failed: %v", err)
	}

	// Timeline should only include the non-deleted engram
	timeline, err := eng.GetEntityTimeline(ctx, "default", entityName, 10)
	if err != nil {
		t.Fatalf("GetEntityTimeline failed: %v", err)
	}

	if timeline.Count != 1 {
		t.Errorf("Expected 1 non-deleted entry, got %d", timeline.Count)
	}
}
