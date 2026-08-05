package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// TestPurgeExpiredIdempotency verifies that the shared 0x19 sweep expires
// validated payload receipts without deleting fresh or unrecognized records.
func TestPurgeExpiredIdempotency_PurgesPayloadReceiptsSafely(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("payload-retention")

	freshID, err := store.WriteEngram(ctx, ws, &Engram{Concept: "fresh", Content: "fresh"})
	if err != nil {
		t.Fatalf("WriteEngram fresh: %v", err)
	}
	if err := store.WritePayloadReceipt(ctx, ws, "stage-b:fresh", freshID.String(), payloadDigestA); err != nil {
		t.Fatalf("WritePayloadReceipt fresh: %v", err)
	}

	expired := PayloadReceipt{
		EngramID:      freshID.String(),
		OpID:          "stage-b:expired",
		PayloadSHA256: payloadDigestA,
		CreatedAt:     time.Now().Add(-2 * time.Hour).UnixNano(),
	}
	expiredValue, err := json.Marshal(expired)
	if err != nil {
		t.Fatalf("marshal expired payload receipt: %v", err)
	}
	if err := store.db.Set(keys.PayloadReceiptKey(ws, expired.OpID), expiredValue, pebble.Sync); err != nil {
		t.Fatalf("write expired payload receipt: %v", err)
	}
	unknownKey := keys.PayloadReceiptKey(ws, "stage-b:unknown")
	unknown := PayloadReceipt{
		EngramID:      freshID.String(),
		OpID:          "stage-b:unknown",
		PayloadSHA256: payloadDigestA,
		CreatedAt:     time.Now().Add(-2 * time.Hour).UnixNano(),
	}
	unknownValue, err := json.Marshal(unknown)
	if err != nil {
		t.Fatalf("marshal unknown shared-prefix record: %v", err)
	}
	unknownValue = append(unknownValue[:len(unknownValue)-1], []byte(`,"seq":1}`)...)
	if err := store.db.Set(unknownKey, unknownValue, pebble.Sync); err != nil {
		t.Fatalf("write unknown shared-prefix record: %v", err)
	}
	// A replication entry has the same 9-byte key shape as a legacy receipt.
	// Even JSON-shaped replication data must survive unless it is exactly a
	// canonical IdempotencyReceipt object.
	replicationLikeKey := []byte{0x19, 0, 0, 0, 0, 0, 0, 0, 1}
	if err := store.db.Set(replicationLikeKey, []byte(`{"engram_id":"replication","created_at":1,"seq":1}`), pebble.Sync); err != nil {
		t.Fatalf("write replication-like record: %v", err)
	}

	deleted, err := store.PurgeExpiredIdempotency(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PurgeExpiredIdempotency: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("sweep deleted %d receipts, want one expired payload receipt", deleted)
	}
	if receipt, err := store.CheckPayloadReceipt(ctx, ws, expired.OpID); err != nil {
		t.Fatalf("CheckPayloadReceipt expired: %v", err)
	} else if receipt != nil {
		t.Fatalf("expired payload receipt survived: %+v", receipt)
	}
	if receipt, err := store.CheckPayloadReceipt(ctx, ws, "stage-b:fresh"); err != nil {
		t.Fatalf("CheckPayloadReceipt fresh: %v", err)
	} else if receipt == nil || receipt.EngramID != freshID.String() {
		t.Fatalf("fresh payload receipt changed: %+v", receipt)
	}
	if value, closer, err := store.db.Get(unknownKey); err != nil {
		t.Fatalf("unknown shared-prefix record was deleted: %v", err)
	} else {
		if len(value) == 0 {
			t.Fatal("unknown shared-prefix record was emptied")
		}
		closer.Close()
	}
	if value, closer, err := store.db.Get(replicationLikeKey); err != nil {
		t.Fatalf("JSON-shaped replication record was deleted: %v", err)
	} else {
		if len(value) == 0 {
			t.Fatal("JSON-shaped replication record was emptied")
		}
		closer.Close()
	}
}

// TestPurgeExpiredIdempotency verifies that PurgeExpiredIdempotency deletes
// stale receipts and leaves fresh ones intact, returning the correct count.
func TestPurgeExpiredIdempotency(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	maxAge := time.Hour

	// Stale: created more than maxAge ago.
	staleTime := time.Now().Add(-2 * maxAge).UnixNano()
	staleIDs := []string{"stale-op-1", "stale-op-2", "stale-op-3"}
	// Write receipts directly to control CreatedAt; WriteIdempotency always uses time.Now().
	for _, opID := range staleIDs {
		receipt := IdempotencyReceipt{
			EngramID:  "engram-" + opID,
			CreatedAt: staleTime,
		}
		val, err := json.Marshal(receipt)
		if err != nil {
			t.Fatalf("marshal stale receipt: %v", err)
		}
		key := keys.IdempotencyKey(opID)
		if err := store.db.Set(key, val, pebble.NoSync); err != nil {
			t.Fatalf("write stale receipt %q: %v", opID, err)
		}
	}

	// Fresh: created just now (well within maxAge).
	freshTime := time.Now().UnixNano()
	freshIDs := []string{"fresh-op-1", "fresh-op-2"}
	for _, opID := range freshIDs {
		receipt := IdempotencyReceipt{
			EngramID:  "engram-" + opID,
			CreatedAt: freshTime,
		}
		val, err := json.Marshal(receipt)
		if err != nil {
			t.Fatalf("marshal fresh receipt: %v", err)
		}
		key := keys.IdempotencyKey(opID)
		if err := store.db.Set(key, val, pebble.NoSync); err != nil {
			t.Fatalf("write fresh receipt %q: %v", opID, err)
		}
	}

	deleted, err := store.PurgeExpiredIdempotency(ctx, maxAge)
	if err != nil {
		t.Fatalf("PurgeExpiredIdempotency: %v", err)
	}
	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	// Stale receipts must be gone.
	for _, opID := range staleIDs {
		r, err := store.CheckIdempotency(ctx, opID)
		if err != nil {
			t.Fatalf("CheckIdempotency(%q): %v", opID, err)
		}
		if r != nil {
			t.Errorf("stale receipt %q still present after purge", opID)
		}
	}

	// Fresh receipts must survive.
	for _, opID := range freshIDs {
		r, err := store.CheckIdempotency(ctx, opID)
		if err != nil {
			t.Fatalf("CheckIdempotency(%q): %v", opID, err)
		}
		if r == nil {
			t.Errorf("fresh receipt %q was incorrectly purged", opID)
		}
	}
}
