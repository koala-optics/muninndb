package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

const (
	enginePayloadDigestA = "e43d052c4b592d72e3fb62886f71b354c90c4e7661ada41477cd57b721bc5e46"
	enginePayloadDigestB = "33dd57234331d00de85122a0e1c114ae9027e124b7db273bf9e42abd8a128efd"
)

func TestWriteWithPayloadReceipt_IdenticalPayloadReturnsOriginal(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "default", Concept: "payload", Content: "same"}

	first, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:same", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("first WriteWithPayloadReceipt: %v", err)
	}
	second, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:same", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("second WriteWithPayloadReceipt: %v", err)
	}
	if first.ID != second.ID || second.Hint != "idempotent" {
		t.Fatalf("expected idempotent original ID, got first=%+v second=%+v", first, second)
	}
}

func TestWriteWithPayloadReceipt_DifferentPayloadRefuses(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	first, err := eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "first"}, "stage-b:drift", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("first WriteWithPayloadReceipt: %v", err)
	}
	second, err := eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "second"}, "stage-b:drift", enginePayloadDigestB)
	if !errors.Is(err, ErrPayloadReceiptConflict) {
		t.Fatalf("expected ErrPayloadReceiptConflict, got response=%+v err=%v", second, err)
	}
	if second != nil {
		t.Fatalf("payload drift returned success: %+v", second)
	}
	receipt, err := eng.ReadPayloadReceipt(ctx, "default", "stage-b:drift")
	if err != nil {
		t.Fatalf("ReadPayloadReceipt: %v", err)
	}
	if receipt.EngramID != first.ID || receipt.PayloadSHA256 != enginePayloadDigestA {
		t.Fatalf("original receipt changed after conflict: %+v", receipt)
	}
}

func TestWriteWithPayloadReceipt_LegacyReceiptFailsClosed(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	if err := store.WriteIdempotency(ctx, "stage-b:legacy", "legacy-memory"); err != nil {
		t.Fatalf("WriteIdempotency: %v", err)
	}

	resp, err := eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "new"}, "stage-b:legacy", enginePayloadDigestA)
	if !errors.Is(err, ErrLegacyPayloadReceipt) {
		t.Fatalf("expected ErrLegacyPayloadReceipt, got response=%+v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatalf("legacy receipt produced false success: %+v", resp)
	}
}

func TestWriteWithPayloadReceipt_ConcurrentIdenticalCreatesOne(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	responses := make([]*mbp.WriteResponse, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range responses {
		i := i
		go func() {
			defer wg.Done()
			responses[i], errs[i] = eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "concurrent"}, "stage-b:concurrent-same", enginePayloadDigestA)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if responses[0].ID != responses[1].ID {
		t.Fatalf("concurrent identical payloads returned different IDs: %+v", responses)
	}
	count, err := store.CountEngrams(ctx)
	if err != nil {
		t.Fatalf("CountEngrams: %v", err)
	}
	if count != 1 {
		t.Fatalf("concurrent identical payloads created %d engrams", count)
	}
}

func TestWriteWithPayloadReceipt_ConcurrentDifferentCannotBothSucceed(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	digests := []string{enginePayloadDigestA, enginePayloadDigestB}
	contents := []string{"first contender", "second contender"}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range errs {
		i := i
		go func() {
			defer wg.Done()
			_, errs[i] = eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: contents[i]}, "stage-b:concurrent-drift", digests[i])
		}()
	}
	wg.Wait()
	successes := 0
	conflicts := 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPayloadReceiptConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("expected one success and one conflict, got successes=%d conflicts=%d errors=%v", successes, conflicts, errs)
	}
	count, err := store.CountEngrams(ctx)
	if err != nil {
		t.Fatalf("CountEngrams: %v", err)
	}
	if count != 1 {
		t.Fatalf("concurrent payload drift created %d engrams", count)
	}
}

func TestWriteWithPayloadReceipt_RetryAfterHardDeleteDoesNotReturnDanglingID(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "default", Content: "delete and retry"}

	first, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:deleted-retry", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("first WriteWithPayloadReceipt: %v", err)
	}
	id, err := storage.ParseULID(first.ID)
	if err != nil {
		t.Fatalf("ParseULID: %v", err)
	}
	if err := store.DeleteEngram(ctx, store.VaultPrefix("default"), id); err != nil {
		t.Fatalf("DeleteEngram: %v", err)
	}

	second, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:deleted-retry", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("retry WriteWithPayloadReceipt: %v", err)
	}
	if second.ID == first.ID || second.Hint == "idempotent" {
		t.Fatalf("retry returned dangling receipt: first=%+v retry=%+v", first, second)
	}
	secondID, err := storage.ParseULID(second.ID)
	if err != nil {
		t.Fatalf("ParseULID retry: %v", err)
	}
	if _, err := store.GetEngram(ctx, store.VaultPrefix("default"), secondID); err != nil {
		t.Fatalf("retry response references missing engram: %v", err)
	}
}

func TestWriteWithPayloadReceipt_RetryAfterSoftDeleteDoesNotReturnDeletedID(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "default", Content: "soft delete and retry"}

	first, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:soft-deleted-retry", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("first WriteWithPayloadReceipt: %v", err)
	}
	id, err := storage.ParseULID(first.ID)
	if err != nil {
		t.Fatalf("ParseULID: %v", err)
	}
	if err := store.SoftDelete(ctx, store.VaultPrefix("default"), id); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	second, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:soft-deleted-retry", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("retry WriteWithPayloadReceipt: %v", err)
	}
	if second.ID == first.ID || second.Hint == "idempotent" {
		t.Fatalf("retry returned soft-deleted receipt: first=%+v retry=%+v", first, second)
	}
	secondID, err := storage.ParseULID(second.ID)
	if err != nil {
		t.Fatalf("ParseULID retry: %v", err)
	}
	got, err := store.GetEngram(ctx, store.VaultPrefix("default"), secondID)
	if err != nil {
		t.Fatalf("retry response references missing engram: %v", err)
	}
	if got.State == storage.StateSoftDeleted {
		t.Fatalf("retry response references soft-deleted engram: %+v", got)
	}
}

func TestWriteWithPayloadReceipt_SharesLegacyOperationLock(t *testing.T) {
	eng, _, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	const opID = "stage-b:mixed-lock"

	mu := eng.getIdempotencyLock(opID)
	mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "payload"}, opID, enginePayloadDigestA)
	}()
	select {
	case <-done:
		mu.Unlock()
		t.Fatal("payload write bypassed the legacy operation-ID lock")
	case <-time.After(100 * time.Millisecond):
	}
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("payload write did not resume after legacy operation-ID lock release")
	}
}

func TestWriteWithPayloadReceipt_InvalidDigestCannotReportSuccess(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()

	resp, err := eng.WriteWithPayloadReceipt(ctx, &mbp.WriteRequest{Vault: "default", Content: "must not persist"}, "stage-b:invalid", "not-a-sha256")
	if err == nil || resp != nil {
		t.Fatalf("invalid receipt reported success: response=%+v err=%v", resp, err)
	}
	count, countErr := store.CountEngrams(ctx)
	if countErr != nil {
		t.Fatalf("CountEngrams: %v", countErr)
	}
	if count != 0 {
		t.Fatalf("invalid receipt wrote %d engrams", count)
	}
}

func TestWriteWithPayloadReceipt_InvalidDigestCannotReuseReceipt(t *testing.T) {
	eng, _, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "default", Content: "same receipt"}

	first, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:invalid-retry", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("first WriteWithPayloadReceipt: %v", err)
	}
	resp, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:invalid-retry", "not-a-sha256")
	if err == nil || resp != nil {
		t.Fatalf("invalid digest reused receipt: first=%+v response=%+v err=%v", first, resp, err)
	}
}

func TestWriteWithPayloadReceipt_DuplicateContentPersistsReceipt(t *testing.T) {
	eng, store, cleanup := testEnvWithStore(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "default", Content: "already stored"}

	original, err := eng.Write(ctx, req)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	duplicate, err := eng.WriteWithPayloadReceipt(ctx, req, "stage-b:duplicate-content", enginePayloadDigestA)
	if err != nil {
		t.Fatalf("WriteWithPayloadReceipt: %v", err)
	}
	if duplicate.ID != original.ID || duplicate.Hint != "duplicate_content" {
		t.Fatalf("expected duplicate original ID, got original=%+v duplicate=%+v", original, duplicate)
	}
	receipt, err := store.CheckPayloadReceipt(ctx, store.VaultPrefix("default"), "stage-b:duplicate-content")
	if err != nil {
		t.Fatalf("CheckPayloadReceipt: %v", err)
	}
	if receipt == nil || receipt.EngramID != original.ID || receipt.PayloadSHA256 != enginePayloadDigestA {
		t.Fatalf("duplicate success lacked durable payload receipt: %+v", receipt)
	}
}
