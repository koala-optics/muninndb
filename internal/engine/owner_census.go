package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/scrypster/muninndb/internal/storage"
)

// OwnerCensusResult is one whole-vault active census: the exact count of
// non-deleted, non-archived engrams plus an order-independent digest of
// their owner-facing identities. One engine call costs one vault scan -
// the same price a single owner-inventory page already pays - so a caller
// can prove set stability with two cheap calls instead of a paged
// enumeration of the entire vault.
type OwnerCensusResult struct {
	Total          int
	EntityCount    int
	IdentitySHA256 string
}

// ownerCensusRowHash hashes the same owner-facing identity fields the
// muninn_owner_inventory page exposes (id, concept, content, confidence,
// tags, created_at, embed_dim), length-prefixed so field boundaries are
// unambiguous. Rows hash identically iff their owner projections match.
func ownerCensusRowHash(engram *storage.Engram) [32]byte {
	hasher := sha256.New()
	writeField := func(field []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		hasher.Write(length[:])
		hasher.Write(field)
	}
	id := engram.ID.String()
	writeField([]byte(id))
	writeField([]byte(engram.Concept))
	writeField([]byte(engram.Content))
	var confidence [4]byte
	binary.BigEndian.PutUint32(confidence[:], uint32(engram.Confidence*1e6))
	writeField(confidence[:])
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(engram.Tags)))
	writeField(count[:])
	for _, tag := range engram.Tags {
		writeField([]byte(tag))
	}
	var created [8]byte
	binary.BigEndian.PutUint64(created[:], uint64(engram.CreatedAt.Unix()))
	writeField(created[:])
	writeField([]byte{uint8(engram.EmbedDim)})
	var digest [32]byte
	hasher.Sum(digest[:0])
	return digest
}

// OwnerCensus scans a vault once and returns the active engram count, the
// exact entity count, and a deterministic identity digest. The digest is
// the SHA-256 of the lexicographically sorted per-row hashes, so it is
// independent of scan order and equal iff the active identity sets are
// equal. Soft-deleted and archived engrams are excluded - the same active
// filter ListEngrams applies by default.
func (e *Engine) OwnerCensus(ctx context.Context, vault string) (*OwnerCensusResult, error) {
	ws := e.store.ResolveVaultPrefix(vault)
	rowHashes := make([][32]byte, 0, 1024)
	err := e.store.ScanEngrams(ctx, ws, func(engram *storage.Engram) error {
		if engram.State == storage.StateSoftDeleted || engram.State == storage.StateArchived {
			return nil
		}
		rowHashes = append(rowHashes, ownerCensusRowHash(engram))
		return nil
	})
	if err != nil {
		return nil, err
	}
	entityCount, err := e.CountEntities(ctx, vault)
	if err != nil {
		return nil, err
	}
	sort.Slice(rowHashes, func(i, j int) bool {
		return bytes.Compare(rowHashes[i][:], rowHashes[j][:]) < 0
	})
	setHasher := sha256.New()
	for _, rowHash := range rowHashes {
		setHasher.Write(rowHash[:])
	}
	return &OwnerCensusResult{
		Total:          len(rowHashes),
		EntityCount:    entityCount,
		IdentitySHA256: hex.EncodeToString(setHasher.Sum(nil)),
	}, nil
}
