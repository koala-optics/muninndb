package storage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

const payloadSHA256Bytes = 32

// PayloadReceipt is server-owned proof that one vault-scoped operation ID was
// bound to the complete canonical request payload when its engram was created.
type PayloadReceipt struct {
	EngramID      string `json:"engram_id"`
	OpID          string `json:"op_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	CreatedAt     int64  `json:"created_at"`
}

// ValidatePayloadIdentity checks the client-independent fields required for
// vault-scoped payload identity before any success path can reuse a receipt.
func ValidatePayloadIdentity(opID, payloadSHA256 string) error {
	if opID == "" {
		return fmt.Errorf("payload receipt op_id is required")
	}
	digest, err := hex.DecodeString(payloadSHA256)
	if err != nil || len(digest) != payloadSHA256Bytes {
		return fmt.Errorf("payload receipt digest must be a 64-character SHA-256 hex string")
	}
	return nil
}

func validatePayloadReceipt(opID, engramID, payloadSHA256 string) error {
	if err := ValidatePayloadIdentity(opID, payloadSHA256); err != nil {
		return err
	}
	if engramID == "" {
		return fmt.Errorf("payload receipt engram_id is required")
	}
	return nil
}

func newPayloadReceipt(opID, engramID, payloadSHA256 string) (*PayloadReceipt, []byte, error) {
	if err := validatePayloadReceipt(opID, engramID, payloadSHA256); err != nil {
		return nil, nil, err
	}
	receipt := &PayloadReceipt{
		EngramID:      engramID,
		OpID:          opID,
		PayloadSHA256: payloadSHA256,
		CreatedAt:     time.Now().UnixNano(),
	}
	value, err := json.Marshal(receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal payload receipt: %w", err)
	}
	return receipt, value, nil
}

// CheckPayloadReceipt returns a vault-scoped payload receipt, or nil if none
// exists. The stored op_id is compared in full so a SipHash collision fails
// closed instead of returning another operation's receipt.
func (ps *PebbleStore) CheckPayloadReceipt(ctx context.Context, ws [8]byte, opID string) (*PayloadReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opID == "" {
		return nil, fmt.Errorf("payload receipt op_id is required")
	}
	value, err := Get(ps.db, keys.PayloadReceiptKey(ws, opID))
	if err != nil {
		return nil, fmt.Errorf("check payload receipt: %w", err)
	}
	if value == nil {
		return nil, nil
	}
	var receipt PayloadReceipt
	if err := json.Unmarshal(value, &receipt); err != nil {
		return nil, fmt.Errorf("decode payload receipt: %w", err)
	}
	if err := validatePayloadReceipt(receipt.OpID, receipt.EngramID, receipt.PayloadSHA256); err != nil {
		return nil, fmt.Errorf("invalid stored payload receipt: %w", err)
	}
	if receipt.OpID != opID {
		return nil, fmt.Errorf("payload receipt op_id collision")
	}
	return &receipt, nil
}

// WritePayloadReceipt writes a vault-scoped payload receipt without creating an
// engram. Production payload-bound writes use WriteEngramWithPayloadReceipt so
// the engram and receipt share one atomic batch.
func (ps *PebbleStore) WritePayloadReceipt(ctx context.Context, ws [8]byte, opID, engramID, payloadSHA256 string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, value, err := newPayloadReceipt(opID, engramID, payloadSHA256)
	if err != nil {
		return err
	}
	batch := ps.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(keys.PayloadReceiptKey(ws, opID), value, nil); err != nil {
		return fmt.Errorf("queue payload receipt: %w", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("commit payload receipt: %w", err)
	}
	ps.replicateBatch(batch)
	return nil
}

// WriteEngramWithPayloadReceipt atomically persists an engram and its
// vault-scoped payload receipt in one Pebble batch.
func (ps *PebbleStore) WriteEngramWithPayloadReceipt(ctx context.Context, ws [8]byte, eng *Engram, opID, payloadSHA256 string) (ULID, error) {
	if eng == nil {
		return ULID{}, fmt.Errorf("engram is required")
	}
	// Assign the ID before receipt validation so the exact ID stored in the
	// receipt is also the one queued by pebbleStoreBatch.WriteEngram.
	if eng.ID == (ULID{}) {
		if !eng.CreatedAt.IsZero() {
			eng.ID = NewULIDWithTime(eng.CreatedAt)
		} else {
			eng.ID = NewULID()
		}
	}
	_, receiptValue, err := newPayloadReceipt(opID, eng.ID.String(), payloadSHA256)
	if err != nil {
		return ULID{}, err
	}

	// Initialize before commit so a cold counter scan cannot include this write
	// and then count it again in pebbleStoreBatch.Commit's post-commit increment.
	ps.getOrInitCounter(ctx, ws)

	batch := ps.NewBatch().(*pebbleStoreBatch)
	if err := batch.WriteEngram(ctx, ws, eng); err != nil {
		batch.Discard()
		return ULID{}, err
	}
	if err := batch.batch.Set(keys.PayloadReceiptKey(ws, opID), receiptValue, nil); err != nil {
		batch.Discard()
		return ULID{}, fmt.Errorf("queue payload receipt: %w", err)
	}
	if err := batch.Commit(); err != nil {
		batch.Discard()
		return ULID{}, err
	}
	ps.replicateBatch(batch.batch)
	batch.Discard()
	return eng.ID, nil
}
