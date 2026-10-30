package storage

import (
	"context"
	"math"
	"testing"
)

// TestScanEngramsFrom_StartsAtCursorAndJoinsEmbeddings verifies that a scan
// started mid-vault visits exactly the rows from start onward in key order and
// attaches each row's own embedding (the 0x18 iterator is bounded at start too).
func TestScanEngramsFrom_StartsAtCursorAndJoinsEmbeddings(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("scan-from")
	other := store.VaultPrefix("scan-from-other")

	for i := 0; i < 6; i++ {
		eng := &Engram{Concept: "c", Content: "row"}
		if i%3 != 1 { // rows without an embedding exercise the join's skip path
			eng.Embedding = []float32{float32(i) / 10, 0.5, -0.5}
		}
		if _, err := store.WriteEngram(ctx, ws, eng); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}
	if _, err := store.WriteEngram(ctx, other, &Engram{Concept: "c", Content: "other vault"}); err != nil {
		t.Fatalf("WriteEngram other: %v", err)
	}

	var all []*Engram
	if err := store.ScanEngrams(ctx, ws, func(e *Engram) error {
		all = append(all, e)
		return nil
	}); err != nil {
		t.Fatalf("ScanEngrams: %v", err)
	}
	if len(all) != 6 {
		t.Fatalf("ScanEngrams visited %d rows, want 6", len(all))
	}

	start := all[3].ID
	var from []*Engram
	if err := store.ScanEngramsFrom(ctx, ws, &start, func(e *Engram) error {
		from = append(from, e)
		return nil
	}); err != nil {
		t.Fatalf("ScanEngramsFrom: %v", err)
	}
	if len(from) != 3 {
		t.Fatalf("ScanEngramsFrom visited %d rows, want 3", len(from))
	}
	for i, e := range from {
		want := all[3+i]
		if e.ID != want.ID {
			t.Fatalf("row %d id = %s, want %s", i, e.ID, want.ID)
		}
		if len(e.Embedding) != len(want.Embedding) {
			t.Fatalf("row %d embedding len = %d, want %d", i, len(e.Embedding), len(want.Embedding))
		}
		for j := range want.Embedding {
			if math.Abs(float64(e.Embedding[j]-want.Embedding[j])) > 0.02 {
				t.Fatalf("row %d embedding[%d] = %v, want %v", i, j, e.Embedding[j], want.Embedding[j])
			}
		}
	}
}
