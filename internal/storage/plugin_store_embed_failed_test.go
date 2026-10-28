package storage

import (
	"context"
	"testing"
)

// TestCountEmbedFailed_AndClearEmbedFailed: only an embed-failed digest record
// without an embedding is counted and re-queued; embedded+enrich-failed (0x82)
// and unflagged records are untouched, and a second clear is a no-op.
func TestCountEmbedFailed_AndClearEmbedFailed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("embed-failed-vault")

	var ids []ULID
	for i := 0; i < 3; i++ {
		id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "concept", Content: "content"})
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		ids = append(ids, id)
	}
	if err := store.SetDigestFlag(ctx, ids[0], digestEmbedFailed); err != nil {
		t.Fatalf("SetDigestFlag[0]: %v", err)
	}
	if err := store.SetDigestFlag(ctx, ids[1], digestEmbedded|digestEmbedFailed); err != nil {
		t.Fatalf("SetDigestFlag[1]: %v", err)
	}

	if got, err := store.CountEmbedFailed(ctx); err != nil || got != 1 {
		t.Fatalf("CountEmbedFailed before clear = %d, %v; want 1, nil", got, err)
	}
	if n, err := store.ClearEmbedFailed(ctx); err != nil || n != 1 {
		t.Fatalf("ClearEmbedFailed = %d, %v; want 1, nil", n, err)
	}
	if got, err := store.CountEmbedFailed(ctx); err != nil || got != 0 {
		t.Fatalf("CountEmbedFailed after clear = %d, %v; want 0, nil", got, err)
	}
	if raw, _ := store.GetDigestFlags(ctx, ids[0]); raw&digestEmbedFailed != 0 {
		t.Errorf("ids[0] flags = %#x; embed-failed bit should be cleared", raw)
	}
	if raw, _ := store.GetDigestFlags(ctx, ids[1]); raw != digestEmbedded|digestEmbedFailed {
		t.Errorf("ids[1] flags = %#x; want %#x untouched", raw, digestEmbedded|digestEmbedFailed)
	}
	if n, err := store.ClearEmbedFailed(ctx); err != nil || n != 0 {
		t.Fatalf("second ClearEmbedFailed = %d, %v; want 0, nil", n, err)
	}
}

// TestCountWithoutFlag_SkipsFlaggedFailedAndDeleted pins CountWithoutFlag's
// semantics after the flags-before-decode reorder: processed, skip-flagged and
// soft-deleted engrams are excluded; only the pending one is counted.
func TestCountWithoutFlag_SkipsFlaggedFailedAndDeleted(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("count-without-flag-skips-vault")

	var ids []ULID
	for i := 0; i < 4; i++ {
		id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "concept", Content: "content"})
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		ids = append(ids, id)
	}
	if err := store.SetDigestFlag(ctx, ids[0], digestEmbedded); err != nil {
		t.Fatalf("SetDigestFlag[0]: %v", err)
	}
	if err := store.SetDigestFlag(ctx, ids[1], digestEmbedFailed); err != nil {
		t.Fatalf("SetDigestFlag[1]: %v", err)
	}
	if err := store.SoftDelete(ctx, ws, ids[2]); err != nil {
		t.Fatalf("SoftDelete[2]: %v", err)
	}

	count, err := store.CountWithoutFlag(ctx, digestEmbedded, digestEmbedFailed)
	if err != nil {
		t.Fatalf("CountWithoutFlag: %v", err)
	}
	if count != 1 {
		t.Errorf("CountWithoutFlag = %d, want 1 (only ids[3] is pending)", count)
	}
}
