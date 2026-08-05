package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

const idempotencyPurgeBatchSize = 1000

// IdempotencyReceipt is the value stored at an idempotency key.
type IdempotencyReceipt struct {
	EngramID  string `json:"engram_id"`
	CreatedAt int64  `json:"created_at"` // unix nanos
}

// CheckIdempotency looks up an op_id receipt. Returns nil, nil if not found.
func (ps *PebbleStore) CheckIdempotency(ctx context.Context, opID string) (*IdempotencyReceipt, error) {
	key := keys.IdempotencyKey(opID)
	val, err := Get(ps.db, key)
	if err != nil {
		return nil, fmt.Errorf("check idempotency: %w", err)
	}
	if val == nil {
		return nil, nil
	}
	var receipt IdempotencyReceipt
	if err := json.Unmarshal(val, &receipt); err != nil {
		return nil, fmt.Errorf("decode idempotency receipt: %w", err)
	}
	return &receipt, nil
}

// WriteIdempotency writes an idempotency receipt for op_id → engramID.
func (ps *PebbleStore) WriteIdempotency(ctx context.Context, opID, engramID string) error {
	receipt := IdempotencyReceipt{
		EngramID:  engramID,
		CreatedAt: time.Now().UnixNano(),
	}
	val, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("marshal idempotency receipt: %w", err)
	}
	key := keys.IdempotencyKey(opID)
	return ps.db.Set(key, val, pebble.NoSync)
}

// PurgeExpiredIdempotency deletes idempotency receipts older than maxAge.
// It scans the 0x19 key prefix, deletes entries whose CreatedAt is before
// (now - maxAge), and batches deletes in groups of 1000. The ctx is checked
// between batches so the caller can cancel a long-running sweep.
// Returns the number of entries deleted.
func decodeIdempotencyReceipt(value []byte) (*IdempotencyReceipt, error) {
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.DisallowUnknownFields()
	var receipt IdempotencyReceipt
	if err := dec.Decode(&receipt); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("idempotency receipt has trailing JSON")
	}
	if receipt.EngramID == "" || receipt.CreatedAt <= 0 {
		return nil, fmt.Errorf("idempotency receipt is incomplete")
	}
	return &receipt, nil
}

func (ps *PebbleStore) PurgeExpiredIdempotency(ctx context.Context, maxAge time.Duration) (int, error) {
	unlock := lockAllPayloadReceiptVaults()
	defer unlock()
	cutoff := time.Now().Add(-maxAge).UnixNano()

	lower := []byte{0x19}
	upper := keys.PrefixUpperBound(lower)

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: lower,
		UpperBound: upper,
	})
	if err != nil {
		return 0, fmt.Errorf("purge idempotency: new iter: %w", err)
	}
	defer iter.Close()

	var toDelete [][]byte
	for iter.SeekGE(lower); iter.Valid(); iter.Next() {
		k := iter.Key()
		if len(k) == 0 || k[0] != 0x19 {
			break
		}
		val := iter.Value()
		switch len(k) {
		case 9:
			// Legacy receipts and replication records share this shape. Require the
			// exact receipt schema so JSON-shaped replication data cannot be expired.
			receipt, err := decodeIdempotencyReceipt(val)
			if err != nil {
				continue
			}
			if receipt.CreatedAt < cutoff {
				keyCopy := append([]byte(nil), k...)
				toDelete = append(toDelete, keyCopy)
			}
		case 17:
			// A 17-byte 0x19 key is deletable only when the value is an exact,
			// complete PayloadReceipt and its stored op_id reproduces this key.
			receipt, err := decodePayloadReceipt(val)
			if err != nil || !bytes.Equal(k, keys.PayloadReceiptKey([8]byte(k[1:9]), receipt.OpID)) {
				slog.Warn("idempotency sweep: preserved unrecognized 17-byte 0x19 record", "key", fmt.Sprintf("%x", k))
				continue
			}
			if receipt.CreatedAt < cutoff {
				keyCopy := append([]byte(nil), k...)
				toDelete = append(toDelete, keyCopy)
			}
		}
	}
	if err := iter.Error(); err != nil {
		return 0, fmt.Errorf("purge idempotency: iter scan: %w", err)
	}

	deleted := 0
	for i := 0; i < len(toDelete); i += idempotencyPurgeBatchSize {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		end := i + idempotencyPurgeBatchSize
		if end > len(toDelete) {
			end = len(toDelete)
		}
		batch := ps.db.NewBatch()
		for _, k := range toDelete[i:end] {
			if err := batch.Delete(k, nil); err != nil {
				batch.Close()
				return deleted, fmt.Errorf("purge idempotency: batch delete: %w", err)
			}
		}
		if err := batch.Commit(pebble.NoSync); err != nil {
			batch.Close()
			return deleted, fmt.Errorf("purge idempotency: batch commit: %w", err)
		}
		batch.Close()
		deleted += end - i
	}
	return deleted, nil
}
