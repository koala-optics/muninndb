package storage

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

const (
	payloadDigestA = "e43d052c4b592d72e3fb62886f71b354c90c4e7661ada41477cd57b721bc5e46"
	payloadDigestB = "33dd57234331d00de85122a0e1c114ae9027e124b7db273bf9e42abd8a128efd"
)

func TestWriteEngramWithPayloadReceipt_CommitsBoth(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("payload-atomic")
	eng := &Engram{Concept: "payload", Content: "atomic memory"}

	id, err := store.WriteEngramWithPayloadReceipt(ctx, ws, eng, "stage-b:atomic", payloadDigestA)
	if err != nil {
		t.Fatalf("WriteEngramWithPayloadReceipt: %v", err)
	}
	if id == (ULID{}) {
		t.Fatal("expected assigned engram ID")
	}
	if got, err := store.GetEngram(ctx, ws, id); err != nil || got == nil {
		t.Fatalf("engram not committed with receipt: got=%v err=%v", got, err)
	}
	receipt, err := store.CheckPayloadReceipt(ctx, ws, "stage-b:atomic")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt: %v", err)
	}
	if receipt == nil {
		t.Fatal("payload receipt not committed with engram")
	}
	if receipt.EngramID != id.String() || receipt.PayloadSHA256 != payloadDigestA {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
}

func TestWriteEngramWithPayloadReceipt_FirstWriteCountsOnce(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("payload-count")

	if _, err := store.WriteEngramWithPayloadReceipt(ctx, ws, &Engram{Concept: "payload", Content: "counted once"}, "stage-b:count", payloadDigestA); err != nil {
		t.Fatalf("WriteEngramWithPayloadReceipt: %v", err)
	}
	if got := store.GetVaultCount(ctx, ws); got != 1 {
		t.Fatalf("payload first write vault count = %d, want 1", got)
	}
}

func TestWriteEngramWithPayloadReceipt_WritesConceptIndex(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("payload-concept")
	eng := &Engram{Concept: "payload.indexed", Content: "indexed memory"}

	id, err := store.WriteEngramWithPayloadReceipt(ctx, ws, eng, "stage-b:concept-index", payloadDigestA)
	if err != nil {
		t.Fatalf("WriteEngramWithPayloadReceipt: %v", err)
	}
	var indexed []ULID
	if err := store.ScanConceptIndex(ctx, ws, keys.Hash(eng.Concept), func(got ULID) error {
		indexed = append(indexed, got)
		return nil
	}); err != nil {
		t.Fatalf("ScanConceptIndex: %v", err)
	}
	if len(indexed) != 1 || indexed[0] != id {
		t.Fatalf("concept index = %v, want [%s]", indexed, id.String())
	}
}

func TestWritePayloadReceipt_ReplicatesStandaloneReceipt(t *testing.T) {
	ctx := context.Background()
	db, err := pebble.Open(t.TempDir(), &pebble.Options{})
	if err != nil {
		t.Fatalf("open source db: %v", err)
	}
	var calls atomic.Int32
	var captured []byte
	store := NewPebbleStore(db, PebbleStoreConfig{RepLogAppend: func(op uint8, key, value []byte) error {
		if op == 3 {
			calls.Add(1)
			captured = append([]byte(nil), value...)
		}
		return nil
	}})
	t.Cleanup(func() { _ = store.Close() })
	ws := store.VaultPrefix("payload-standalone-replicated")

	if err := store.WritePayloadReceipt(ctx, ws, "stage-b:standalone-replicated", "memory-existing", payloadDigestA); err != nil {
		t.Fatalf("WritePayloadReceipt: %v", err)
	}
	if calls.Load() != 1 || len(captured) == 0 {
		t.Fatalf("replication callback calls=%d repr=%d bytes, want one non-empty batch", calls.Load(), len(captured))
	}

	replicaDB, err := pebble.Open(t.TempDir(), &pebble.Options{})
	if err != nil {
		t.Fatalf("open replica db: %v", err)
	}
	defer replicaDB.Close()
	replicaBatch := replicaDB.NewBatch()
	if err := replicaBatch.SetRepr(captured); err != nil {
		t.Fatalf("SetRepr: %v", err)
	}
	if err := replicaBatch.Commit(pebble.NoSync); err != nil {
		t.Fatalf("replica commit: %v", err)
	}
	_ = replicaBatch.Close()

	value, closer, err := replicaDB.Get(keys.PayloadReceiptKey(ws, "stage-b:standalone-replicated"))
	if err != nil {
		t.Fatalf("replica missing standalone payload receipt: %v", err)
	}
	defer closer.Close()
	var receipt PayloadReceipt
	if err := json.Unmarshal(value, &receipt); err != nil {
		t.Fatalf("decode replica receipt: %v", err)
	}
	if receipt.EngramID != "memory-existing" || receipt.PayloadSHA256 != payloadDigestA {
		t.Fatalf("replica receipt mismatch: %+v", receipt)
	}
}

func TestWriteEngramWithPayloadReceipt_ReplicatesReceiptWithEngram(t *testing.T) {
	ctx := context.Background()
	db, err := pebble.Open(t.TempDir(), &pebble.Options{})
	if err != nil {
		t.Fatalf("open source db: %v", err)
	}
	var calls atomic.Int32
	var captured []byte
	store := NewPebbleStore(db, PebbleStoreConfig{RepLogAppend: func(op uint8, key, value []byte) error {
		if op == 3 {
			calls.Add(1)
			captured = append([]byte(nil), value...)
		}
		return nil
	}})
	t.Cleanup(func() { _ = store.Close() })
	ws := store.VaultPrefix("payload-replicated")

	id, err := store.WriteEngramWithPayloadReceipt(ctx, ws, &Engram{Concept: "payload", Content: "replicated"}, "stage-b:replicated", payloadDigestA)
	if err != nil {
		t.Fatalf("WriteEngramWithPayloadReceipt: %v", err)
	}
	if calls.Load() != 1 || len(captured) == 0 {
		t.Fatalf("replication callback calls=%d repr=%d bytes, want one non-empty batch", calls.Load(), len(captured))
	}

	replicaDB, err := pebble.Open(t.TempDir(), &pebble.Options{})
	if err != nil {
		t.Fatalf("open replica db: %v", err)
	}
	defer replicaDB.Close()
	replicaBatch := replicaDB.NewBatch()
	if err := replicaBatch.SetRepr(captured); err != nil {
		t.Fatalf("SetRepr: %v", err)
	}
	if err := replicaBatch.Commit(pebble.NoSync); err != nil {
		t.Fatalf("replica commit: %v", err)
	}
	_ = replicaBatch.Close()

	if value, closer, err := replicaDB.Get(keys.EngramKey(ws, [16]byte(id))); err != nil {
		t.Fatalf("replica missing engram: %v", err)
	} else {
		_ = value
		closer.Close()
	}
	value, closer, err := replicaDB.Get(keys.PayloadReceiptKey(ws, "stage-b:replicated"))
	if err != nil {
		t.Fatalf("replica missing payload receipt: %v", err)
	}
	defer closer.Close()
	var receipt PayloadReceipt
	if err := json.Unmarshal(value, &receipt); err != nil {
		t.Fatalf("decode replica receipt: %v", err)
	}
	if receipt.EngramID != id.String() || receipt.PayloadSHA256 != payloadDigestA {
		t.Fatalf("replica receipt mismatch: %+v", receipt)
	}
}

func TestWriteEngramWithPayloadReceipt_InvalidDigestWritesNothing(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("payload-invalid")
	eng := &Engram{Concept: "payload", Content: "must not persist"}

	if _, err := store.WriteEngramWithPayloadReceipt(ctx, ws, eng, "stage-b:invalid", "not-a-sha256"); err == nil {
		t.Fatal("expected invalid digest to fail")
	}
	count, err := store.CountEngrams(ctx)
	if err != nil {
		t.Fatalf("CountEngrams: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid receipt produced %d engrams", count)
	}
	receipt, err := store.CheckPayloadReceipt(ctx, ws, "stage-b:invalid")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt: %v", err)
	}
	if receipt != nil {
		t.Fatalf("invalid digest produced receipt: %+v", receipt)
	}
}

func TestPayloadReceipt_IsVaultScoped(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	wsA := store.VaultPrefix("vault-a")
	wsB := store.VaultPrefix("vault-b")

	if err := store.WritePayloadReceipt(ctx, wsA, "shared-op", "memory-a", payloadDigestA); err != nil {
		t.Fatalf("WritePayloadReceipt vault-a: %v", err)
	}
	if err := store.WritePayloadReceipt(ctx, wsB, "shared-op", "memory-b", payloadDigestB); err != nil {
		t.Fatalf("WritePayloadReceipt vault-b: %v", err)
	}

	receiptA, err := store.CheckPayloadReceipt(ctx, wsA, "shared-op")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt vault-a: %v", err)
	}
	receiptB, err := store.CheckPayloadReceipt(ctx, wsB, "shared-op")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt vault-b: %v", err)
	}
	if receiptA == nil || receiptA.EngramID != "memory-a" || receiptA.PayloadSHA256 != payloadDigestA {
		t.Fatalf("vault-a receipt mismatch: %+v", receiptA)
	}
	if receiptB == nil || receiptB.EngramID != "memory-b" || receiptB.PayloadSHA256 != payloadDigestB {
		t.Fatalf("vault-b receipt mismatch: %+v", receiptB)
	}
}

func TestDeletePayloadReceipt_RefusesUnrecognizedSharedPrefixRecord(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("payload-delete-safety")
	const opID = "stage-b:delete-safety"
	key := keys.PayloadReceiptKey(ws, opID)
	want := []byte(`{"not":"a-payload-receipt"}`)
	if err := store.db.Set(key, want, pebble.Sync); err != nil {
		t.Fatalf("set unrecognized record: %v", err)
	}

	if err := store.DeletePayloadReceipt(ctx, ws, opID, "memory-delete-safety", payloadDigestA); err == nil {
		t.Fatal("expected unrecognized 0x19 record deletion to fail closed")
	}
	value, closer, err := store.db.Get(key)
	if err != nil {
		t.Fatalf("unrecognized 0x19 record was deleted: %v", err)
	}
	defer closer.Close()
	if string(value) != string(want) {
		t.Fatalf("unrecognized 0x19 record changed: got %q want %q", value, want)
	}
}

func TestPayloadReceipt_DoesNotPromoteLegacyReceipt(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ws := store.VaultPrefix("default")
	if err := store.WriteIdempotency(ctx, "legacy-op", "legacy-memory"); err != nil {
		t.Fatalf("WriteIdempotency: %v", err)
	}

	receipt, err := store.CheckPayloadReceipt(ctx, ws, "legacy-op")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt: %v", err)
	}
	if receipt != nil {
		t.Fatalf("legacy receipt was promoted to payload proof: %+v", receipt)
	}
}
