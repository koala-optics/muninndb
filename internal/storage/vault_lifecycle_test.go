package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func TestClearVault_AllPrefixesGone(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("test-clear")

	// Write vault name
	if err := store.WriteVaultName(ws, "test-clear"); err != nil {
		t.Fatalf("WriteVaultName: %v", err)
	}

	// Write an engram
	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "test", Content: "content", Confidence: 1.0, Stability: 30})
	if err != nil {
		t.Fatal(err)
	}
	_ = id

	// Clear
	n, err := store.ClearVault(ctx, ws)
	if err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	if n < 1 {
		t.Errorf("expected vault count >= 1, got %d", n)
	}

	// All 20 vault-scoped prefixes must be empty
	vaultPrefixes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	for _, p := range vaultPrefixes {
		lo := make([]byte, 9)
		lo[0] = p
		copy(lo[1:], ws[:])
		wsPlus, err := incrementWS(ws)
		if err != nil {
			t.Fatalf("incrementWS: %v", err)
		}
		hi := make([]byte, 9)
		hi[0] = p
		copy(hi[1:], wsPlus[:])
		iter, err := store.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
		if err != nil {
			t.Fatalf("NewIter for prefix 0x%02X: %v", p, err)
		}
		if iter.First() {
			t.Errorf("prefix 0x%02X still has keys after ClearVault", p)
		}
		iter.Close()
	}

	// 0x0E vault meta must still exist (Clear preserves name)
	names, _ := store.ListVaultNames()
	found := false
	for _, nm := range names {
		if nm == "test-clear" {
			found = true
		}
	}
	if !found {
		t.Error("ClearVault should preserve vault name registration")
	}
}

func TestClearVault_ClearsOnlyScopedPayloadReceipts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	wsA := store.VaultPrefix("receipt-vault-a")
	wsB := store.VaultPrefix("receipt-vault-b")

	if err := store.WritePayloadReceipt(ctx, wsA, "shared-op", "memory-a", payloadDigestA); err != nil {
		t.Fatalf("WritePayloadReceipt vault-a: %v", err)
	}
	if err := store.WritePayloadReceipt(ctx, wsB, "shared-op", "memory-b", payloadDigestB); err != nil {
		t.Fatalf("WritePayloadReceipt vault-b: %v", err)
	}
	// Exercise the final byte range: an exclusive upper bound of prefix|0xff
	// misses valid longer keys whose SipHash suffix starts with 0xff.
	var highSuffixOp string
	for i := 0; i < 10_000; i++ {
		candidate := fmt.Sprintf("high-suffix-%d", i)
		if keys.PayloadReceiptKey(wsA, candidate)[9] == 0xff {
			highSuffixOp = candidate
			break
		}
	}
	if highSuffixOp == "" {
		t.Fatal("could not find deterministic payload key with 0xff-leading suffix")
	}
	if err := store.WritePayloadReceipt(ctx, wsA, highSuffixOp, "memory-high", payloadDigestA); err != nil {
		t.Fatalf("WritePayloadReceipt high suffix: %v", err)
	}
	// The 0x19 namespace is shared with global idempotency and replication data.
	// ClearVault must remove only validated 17-byte payload receipts, not every
	// key whose first eight payload bytes happen to match the vault prefix.
	overloadedShort := append([]byte{0x19}, wsA[:]...)
	if err := store.db.Set(overloadedShort, []byte("replication-like"), pebble.Sync); err != nil {
		t.Fatalf("set overloaded short key: %v", err)
	}
	overloadedLong := append(append([]byte(nil), overloadedShort...), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	if err := store.db.Set(overloadedLong, []byte("not-a-payload-receipt"), pebble.Sync); err != nil {
		t.Fatalf("set overloaded long key: %v", err)
	}

	if _, err := store.ClearVault(ctx, wsA); err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	if receipt, err := store.CheckPayloadReceipt(ctx, wsA, "shared-op"); err != nil {
		t.Fatalf("CheckPayloadReceipt vault-a: %v", err)
	} else if receipt != nil {
		t.Fatalf("cleared vault retained payload receipt: %+v", receipt)
	}
	if receipt, err := store.CheckPayloadReceipt(ctx, wsA, highSuffixOp); err != nil {
		t.Fatalf("CheckPayloadReceipt high suffix: %v", err)
	} else if receipt != nil {
		t.Fatalf("cleared vault retained high-suffix payload receipt: %+v", receipt)
	}
	if receipt, err := store.CheckPayloadReceipt(ctx, wsB, "shared-op"); err != nil {
		t.Fatalf("CheckPayloadReceipt vault-b: %v", err)
	} else if receipt == nil || receipt.EngramID != "memory-b" {
		t.Fatalf("other vault payload receipt changed: %+v", receipt)
	}
	for _, key := range [][]byte{overloadedShort, overloadedLong} {
		value, closer, err := store.db.Get(key)
		if err != nil {
			t.Fatalf("overloaded 0x19 key was deleted: %x: %v", key, err)
		}
		if len(value) == 0 {
			t.Fatalf("overloaded 0x19 key was emptied: %x", key)
		}
		closer.Close()
	}
}

func TestClearVault_SerializesPayloadReceiptWrites(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("receipt-clear-race")

	mu := payloadReceiptVaultLocks.For(ws[:])
	mu.Lock()
	clearDone := make(chan error, 1)
	go func() {
		_, err := store.ClearVault(ctx, ws)
		clearDone <- err
	}()
	select {
	case err := <-clearDone:
		mu.Unlock()
		t.Fatalf("ClearVault bypassed payload receipt lifecycle lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	mu.Unlock()
	select {
	case err := <-clearDone:
		if err != nil {
			t.Fatalf("ClearVault: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClearVault did not resume after payload receipt lifecycle lock release")
	}

	mu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- store.WritePayloadReceipt(ctx, ws, "stage-b:after-clear", "memory-after-clear", payloadDigestA)
	}()
	select {
	case err := <-writeDone:
		mu.Unlock()
		t.Fatalf("payload receipt write bypassed lifecycle lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	mu.Unlock()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("WritePayloadReceipt: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("payload receipt write did not resume after lifecycle lock release")
	}
}

func TestClearVault_CrossVaultSafety(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	wsA := store.VaultPrefix("vault-a")
	wsB := store.VaultPrefix("vault-b")

	engA, _ := store.WriteEngram(ctx, wsA, &Engram{Concept: "A", Content: "a", Confidence: 1.0, Stability: 30})
	engB, _ := store.WriteEngram(ctx, wsB, &Engram{Concept: "B", Content: "b", Confidence: 1.0, Stability: 30})

	if _, err := store.ClearVault(ctx, wsA); err != nil {
		t.Fatal(err)
	}

	// vault-A engram must be gone
	if _, err := store.GetEngram(ctx, wsA, engA); err == nil {
		t.Error("expected vault-A engram to be gone after ClearVault")
	}

	// vault-B engram must still exist
	got, err := store.GetEngram(ctx, wsB, engB)
	if err != nil {
		t.Fatalf("vault-B engram should still exist: %v", err)
	}
	if got.Concept != "B" {
		t.Errorf("unexpected concept: %q", got.Concept)
	}
}

func TestClearVault_L1CacheEvicted(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("cache-test")

	id, _ := store.WriteEngram(ctx, ws, &Engram{Concept: "cached", Content: "c", Confidence: 1.0, Stability: 30})
	store.GetEngram(ctx, ws, id) // populate L1 cache
	if _, ok := store.cache.Get(ws, id); !ok {
		t.Skip("cache did not populate — test not meaningful")
	}

	store.ClearVault(ctx, ws)

	if _, ok := store.cache.Get(ws, id); ok {
		t.Error("expected L1 cache miss after ClearVault")
	}
}

func TestClearVault_VaultCounterEvicted(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("counter-test")

	store.WriteEngram(ctx, ws, &Engram{Concept: "x", Content: "y", Confidence: 1.0, Stability: 30})
	store.GetVaultCount(ctx, ws) // seed in-memory counter

	store.ClearVault(ctx, ws)

	if _, ok := store.vaultCounters.Load(ws); ok {
		t.Error("vaultCounters entry should be evicted after ClearVault")
	}
}

func TestDeleteVaultNameOnly_RemovesNameRegistration(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("to-delete")
	store.WriteVaultName(ws, "to-delete")
	store.WriteEngram(ctx, ws, &Engram{Concept: "x", Content: "y", Confidence: 1.0, Stability: 30})

	// First clear data
	store.ClearVault(ctx, ws)

	// Then delete name registration
	if err := store.DeleteVaultNameOnly(ctx, "to-delete", ws); err != nil {
		t.Fatal(err)
	}

	names, _ := store.ListVaultNames()
	for _, nm := range names {
		if nm == "to-delete" {
			t.Error("vault name still registered after DeleteVaultNameOnly")
		}
	}
}

func TestDeleteVault_0x11OrphansNotDeleted(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("orphan-test")

	id, _ := store.WriteEngram(ctx, ws, &Engram{Concept: "x", Content: "y", Confidence: 1.0, Stability: 30})
	store.SetDigestFlag(ctx, id, 0x01)
	store.ClearVault(ctx, ws)
	store.DeleteVaultNameOnly(ctx, "orphan-test", ws)

	// 0x11 DigestFlag for this ULID must still exist (global, not vault-scoped)
	flags, err := store.GetDigestFlags(ctx, id)
	if err != nil {
		t.Fatalf("expected digest flag to survive vault deletion: %v", err)
	}
	if flags&0x01 == 0 {
		t.Error("digest flag should survive vault deletion")
	}
}
