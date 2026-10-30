package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

func walkListEngramsAfter(t *testing.T, eng *Engine, vault string, limit int) (ids []storage.ULID, pages int) {
	t.Helper()
	var after *storage.ULID
	for pages < 1000 {
		page, next, err := eng.ListEngramsAfter(context.Background(), vault, after, limit)
		if err != nil {
			t.Fatalf("ListEngramsAfter: %v", err)
		}
		pages++
		if len(page) > limit {
			t.Fatalf("page holds %d rows, limit %d", len(page), limit)
		}
		for _, e := range page {
			ids = append(ids, e.ID)
		}
		if next == nil {
			return ids, pages
		}
		after = next
	}
	t.Fatal("keyset walk did not terminate")
	return nil, pages
}

func TestListEngramsAfter_WalksActiveSetOnceInIDOrder(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "keyset"
	ws := eng.store.ResolveVaultPrefix(vault)

	for i := 0; i < 7; i++ {
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{Concept: "keyset", Content: "row"})
		if err != nil {
			t.Fatalf("WriteEngram: %v", err)
		}
		if i == 2 || i == 5 {
			if err := eng.store.SoftDelete(ctx, ws, id); err != nil {
				t.Fatalf("SoftDelete: %v", err)
			}
		}
	}
	otherWS := eng.store.ResolveVaultPrefix("keyset-other")
	if _, err := eng.store.WriteEngram(ctx, otherWS, &storage.Engram{Concept: "other", Content: "row"}); err != nil {
		t.Fatalf("WriteEngram other: %v", err)
	}

	census, err := eng.OwnerCensus(ctx, vault)
	if err != nil {
		t.Fatalf("OwnerCensus: %v", err)
	}
	for _, limit := range []int{1, 2, 5, 200} {
		ids, pages := walkListEngramsAfter(t, eng, vault, limit)
		if len(ids) != census.Total {
			t.Fatalf("limit %d: walked %d rows, census %d", limit, len(ids), census.Total)
		}
		for i := 1; i < len(ids); i++ {
			if storage.CompareULIDs(ids[i-1], ids[i]) >= 0 {
				t.Fatalf("limit %d: ids not strictly ascending at %d", limit, i)
			}
		}
		// 5 active rows: the last page reports nil next even when it is full
		// or soft-deleted rows sort after it, so no trailing empty page.
		if wantPages := (census.Total + limit - 1) / limit; pages != wantPages {
			t.Fatalf("limit %d: %d pages, want %d", limit, pages, wantPages)
		}
	}
}

func TestListEngramsAfter_ScanBudgetReturnsShortPageWithCursor(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "keyset-budget"
	ws := eng.store.ResolveVaultPrefix(vault)
	saved := maxKeysetScanRows
	maxKeysetScanRows = 2
	defer func() { maxKeysetScanRows = saved }()

	for i := 0; i < 6; i++ {
		id, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{Concept: "budget", Content: "row"})
		if err != nil {
			t.Fatalf("WriteEngram: %v", err)
		}
		if i < 4 {
			if err := eng.store.SoftDelete(ctx, ws, id); err != nil {
				t.Fatalf("SoftDelete: %v", err)
			}
		}
	}

	ids, _ := walkListEngramsAfter(t, eng, vault, 200)
	if len(ids) != 2 {
		t.Fatalf("walked %d active rows, want 2", len(ids))
	}
	first, next, err := eng.ListEngramsAfter(ctx, vault, nil, 200)
	if err != nil {
		t.Fatalf("ListEngramsAfter: %v", err)
	}
	if next == nil {
		t.Fatal("budget-limited page must return a cursor")
	}
	if len(first) > 2 {
		t.Fatalf("budget-limited page holds %d rows, budget 2", len(first))
	}
}

func TestListEngramsAfter_CursorRowDeletedBetweenPages(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vault := "keyset-delete"
	ws := eng.store.ResolveVaultPrefix(vault)
	for i := 0; i < 4; i++ {
		if _, err := eng.store.WriteEngram(ctx, ws, &storage.Engram{Concept: "delete", Content: "row"}); err != nil {
			t.Fatalf("WriteEngram: %v", err)
		}
	}

	page, next, err := eng.ListEngramsAfter(ctx, vault, nil, 2)
	if err != nil || next == nil || len(page) != 2 {
		t.Fatalf("first page = %d rows, next %v, err %v", len(page), next, err)
	}
	if err := eng.store.SoftDelete(ctx, ws, *next); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	rest, done, err := eng.ListEngramsAfter(ctx, vault, next, 2)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if done != nil || len(rest) != 2 {
		t.Fatalf("second page = %d rows, next %v; want the 2 rows after the cursor", len(rest), done)
	}
	for _, e := range rest {
		if e.ID == page[0].ID || e.ID == page[1].ID {
			t.Fatalf("row %s returned twice", e.ID)
		}
	}
}
