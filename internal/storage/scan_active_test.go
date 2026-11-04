package storage

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/storage/erf"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// TestScanActiveEngrams_MatchesFilteredScanEngrams pins ScanActiveEngrams to
// ScanEngrams with the census state filter applied: the same rows in the same
// order with the same owner fields, soft-deleted and archived rows excluded,
// and no embedding joined.
func TestScanActiveEngrams_MatchesFilteredScanEngrams(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("scan-active")
	other := store.VaultPrefix("scan-active-other")

	long := make([]byte, 2048) // above the zstd threshold, so content is compressed
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	var deleted []ULID
	for i := 0; i < 9; i++ {
		eng := &Engram{Concept: "c", Content: "row", Tags: []string{"t"}, Embedding: []float32{0.1, 0.2, float32(i)}}
		if i%4 == 0 {
			eng.Content = string(long)
		}
		if i == 7 {
			eng.State = StateArchived
		}
		id, err := store.WriteEngram(ctx, ws, eng)
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		if i%3 == 2 {
			deleted = append(deleted, id)
		}
	}
	for _, id := range deleted {
		if err := store.SoftDelete(ctx, ws, id); err != nil {
			t.Fatalf("SoftDelete: %v", err)
		}
	}
	if _, err := store.WriteEngram(ctx, other, &Engram{Concept: "c", Content: "other vault"}); err != nil {
		t.Fatalf("WriteEngram other: %v", err)
	}

	var want []*Engram
	archived := 0
	if err := store.ScanEngrams(ctx, ws, func(e *Engram) error {
		if e.State == StateArchived {
			archived++
		}
		if e.State != StateSoftDeleted && e.State != StateArchived {
			want = append(want, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("ScanEngrams: %v", err)
	}
	if archived != 1 || len(want) != 5 {
		t.Fatalf("precondition: archived=%d active=%d, want 1 and 5", archived, len(want))
	}

	var got []*Engram
	if err := store.ScanActiveEngrams(ctx, ws, func(e *Engram) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("ScanActiveEngrams: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ScanActiveEngrams visited %d rows, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.Concept != w.Concept || g.Content != w.Content ||
			!g.CreatedAt.Equal(w.CreatedAt) || g.State != w.State || !slices.Equal(g.Tags, w.Tags) {
			t.Fatalf("row %d differs: got %+v, want %+v", i, g, w)
		}
		if g.Embedding != nil {
			t.Fatalf("row %d carries an embedding; ScanActiveEngrams joins none", i)
		}
	}
}

// TestScanActiveEngrams_SkipsUndecodableActiveRecord verifies an active record
// that fails decode is skipped (not counted, not fatal), as ScanEngrams does.
func TestScanActiveEngrams_SkipsUndecodableActiveRecord(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("scan-active-corrupt")

	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "c", Content: "corrupt me"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	if _, err := store.WriteEngram(ctx, ws, &Engram{Concept: "c", Content: "kept"}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	key := keys.EngramKey(ws, [16]byte(id))
	raw, err := Get(store.db, key)
	if err != nil || raw == nil {
		t.Fatalf("read raw record: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF // break the CRC32 trailer; the state byte still says active
	if err := store.db.Set(key, raw, nil); err != nil {
		t.Fatalf("overwrite record: %v", err)
	}

	countScan := 0
	if err := store.ScanEngrams(ctx, ws, func(*Engram) error { countScan++; return nil }); err != nil {
		t.Fatalf("ScanEngrams: %v", err)
	}
	countActive := 0
	if err := store.ScanActiveEngrams(ctx, ws, func(*Engram) error { countActive++; return nil }); err != nil {
		t.Fatalf("ScanActiveEngrams: %v", err)
	}
	if countScan != 1 || countActive != 1 {
		t.Fatalf("rows yielded: ScanEngrams=%d ScanActiveEngrams=%d, want 1 and 1", countScan, countActive)
	}
}

// TestScanActiveEngrams_ContextCancelledMidScan verifies the per-row context
// check: a cancel during the scan stops it before the next row, including
// across a run of skipped soft-deleted rows.
func TestScanActiveEngrams_ContextCancelledMidScan(t *testing.T) {
	store := newTestStore(t)
	ws := store.VaultPrefix("scan-active-cancel")
	for i := 0; i < 4; i++ {
		id, err := store.WriteEngram(context.Background(), ws, &Engram{Concept: "c", Content: "row"})
		if err != nil {
			t.Fatalf("WriteEngram: %v", err)
		}
		if i == 1 {
			if err := store.SoftDelete(context.Background(), ws, id); err != nil {
				t.Fatalf("SoftDelete: %v", err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := store.ScanActiveEngrams(ctx, ws, func(*Engram) error {
		calls++
		cancel()
		return nil
	})
	if err != context.Canceled || calls != 1 {
		t.Fatalf("ScanActiveEngrams err = %v after %d rows, want context.Canceled after 1", err, calls)
	}
}

// TestScanActiveEngrams_CorruptInactiveRecordIsLogged verifies a record whose
// state byte reads soft-deleted but whose CRC32 fails is skipped, as
// ScanEngrams skips it, and still gets the undecodable-record warning.
func TestScanActiveEngrams_CorruptInactiveRecordIsLogged(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("scan-active-corrupt-inactive")
	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "c", Content: "flipped"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	key := keys.EngramKey(ws, [16]byte(id))
	raw, err := Get(store.db, key)
	if err != nil || raw == nil {
		t.Fatalf("read raw record: %v", err)
	}
	raw[erf.OffsetState] = uint8(StateSoftDeleted) // flip the unprotected byte; CRC32 now fails
	if err := store.db.Set(key, raw, nil); err != nil {
		t.Fatalf("overwrite record: %v", err)
	}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	rows := 0
	if err := store.ScanActiveEngrams(ctx, ws, func(*Engram) error { rows++; return nil }); err != nil {
		t.Fatalf("ScanActiveEngrams: %v", err)
	}
	if rows != 0 {
		t.Fatalf("ScanActiveEngrams yielded %d rows, want 0", rows)
	}
	if !strings.Contains(logs.String(), "skipped undecodable record") || !strings.Contains(logs.String(), id.String()) {
		t.Fatalf("no undecodable-record warning for %s; log: %q", id, logs.String())
	}
}
