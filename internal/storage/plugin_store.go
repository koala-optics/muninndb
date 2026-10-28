package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/prefix"
	"github.com/scrypster/muninndb/internal/storage/erf"
	"github.com/scrypster/muninndb/internal/storage/keys"
	"github.com/scrypster/muninndb/internal/types"
)

// CountWithoutFlag returns the number of engrams across all vaults that are
// missing the given digest flag bit. Engrams that have any skipFlags bit set
// are excluded from the count (e.g. permanently-failed engrams).
func (ps *PebbleStore) CountWithoutFlag(ctx context.Context, flag, skipFlags uint8) (int64, error) {
	lowerBound := []byte{prefix.Engram}
	upperBound := []byte{prefix.Meta}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	var count int64
	for valid := iter.First(); valid; valid = iter.Next() {
		k := iter.Key()
		if len(k) < 25 {
			continue
		}
		var id [16]byte
		copy(id[:], k[9:25])

		// Digest flags first: a one-byte point read rules out nearly every engram
		// (already processed or permanently failed) without decoding its record.
		raw, err := ps.getDigestFlagsRaw(id)
		if !((err != nil || raw&flag == 0) && (skipFlags == 0 || raw&skipFlags == 0)) {
			continue
		}

		// Skip soft-deleted and archived engrams - mirrors ScanWithoutFlag so
		// CountWithoutFlag and the scan agree on what is actually pending.
		val := make([]byte, len(iter.Value()))
		copy(val, iter.Value())
		if erfEng, decErr := erf.Decode(val); decErr == nil {
			eng := fromERFEngram(erfEng)
			if eng.State == StateSoftDeleted || eng.State == StateArchived {
				continue
			}
		}
		count++
	}
	return count, nil
}

// digestEmbedded and digestEmbedFailed mirror plugin.DigestEmbed and
// plugin.DigestEmbedFailed (storage cannot import plugin).
const (
	digestEmbedded    uint8 = 0x02
	digestEmbedFailed uint8 = 0x80
)

// CountEmbedFailed returns the number of 0x11 digest records flagged
// DigestEmbedFailed (0x80) that have no embedding (0x02 unset). The embed
// processor skips these forever, so they are missing from semantic recall until
// ClearEmbedFailed re-queues them. Where 0x02 is set the shared 0x80 bit can only
// mean DigestEnrichFailed, so those records are not counted.
func (ps *PebbleStore) CountEmbedFailed(ctx context.Context) (int64, error) {
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefix.DigestFlags},
		UpperBound: []byte{prefix.Coherence},
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	var count int64
	for valid := iter.First(); valid; valid = iter.Next() {
		val := iter.Value()
		if len(val) > 0 && val[0]&digestEmbedFailed != 0 && val[0]&digestEmbedded == 0 {
			count++
		}
	}
	return count, iter.Error()
}

// ClearEmbedFailed clears DigestEmbedFailed on every digest record that has no
// embedding, returning the embed-failed engrams to the embed queue (an engram
// that genuinely fails again is re-flagged on its next attempt). Same rule as
// migration v6 ClearStrandedEmbedFailed, available at runtime.
// minimal: duplicates v6's loop because a migrate test imports storage; share a
// helper package if a third caller appears.
func (ps *PebbleStore) ClearEmbedFailed(ctx context.Context) (int, error) {
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefix.DigestFlags},
		UpperBound: []byte{prefix.Coherence},
	})
	if err != nil {
		return 0, fmt.Errorf("clear embed-failed: iter: %w", err)
	}
	batch := ps.db.NewBatch()
	defer func() { _ = batch.Close() }()

	cleared := 0
	for valid := iter.First(); valid; valid = iter.Next() {
		val := iter.Value()
		if len(val) == 0 || val[0]&digestEmbedFailed == 0 || val[0]&digestEmbedded != 0 {
			continue
		}
		next := append([]byte(nil), val...)
		next[0] &^= digestEmbedFailed
		if err := batch.Set(iter.Key(), next, nil); err != nil {
			_ = iter.Close()
			return 0, fmt.Errorf("clear embed-failed: batch set: %w", err)
		}
		cleared++
	}
	if err := iter.Error(); err != nil {
		_ = iter.Close()
		return 0, fmt.Errorf("clear embed-failed: scan: %w", err)
	}
	if err := iter.Close(); err != nil {
		return 0, fmt.Errorf("clear embed-failed: close iter: %w", err)
	}
	if cleared == 0 {
		return 0, nil
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return 0, fmt.Errorf("clear embed-failed: commit: %w", err)
	}
	ps.replicateBatch(batch)
	return cleared, nil
}

// CountWithFlag returns the number of engrams across all vaults that have the
// given digest flag bit set. It scans the 0x11 DigestFlags key space directly
// (a global key space — no vault scope needed).
func (ps *PebbleStore) CountWithFlag(ctx context.Context, flag uint8) (int64, error) {
	lowerBound := []byte{prefix.DigestFlags}
	upperBound := []byte{prefix.Coherence}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	var count int64
	for valid := iter.First(); valid; valid = iter.Next() {
		val := iter.Value()
		if len(val) > 0 && val[0]&flag != 0 {
			count++
		}
	}
	return count, iter.Error()
}

// ScanWithoutFlag returns a forward-only iterator over all engrams that are
// missing the given digest flag bit. Engrams that have any skipFlags bit set
// are skipped during iteration.
func (ps *PebbleStore) ScanWithoutFlag(ctx context.Context, flag, skipFlags uint8) *PluginEngramIterator {
	lowerBound := []byte{prefix.Engram}
	upperBound := []byte{prefix.Meta}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		return &PluginEngramIterator{
			iterErr: err,
			wsCache: make(map[ULID][8]byte),
		}
	}

	return &PluginEngramIterator{
		ps:        ps,
		iter:      iter,
		flag:      flag,
		skipFlags: skipFlags,
		started:   false,
		current:   nil,
		wsCache:   make(map[ULID][8]byte),
	}
}

// SetDigestFlag sets a digest flag bit on an engram's digest flags record.
func (ps *PebbleStore) SetDigestFlag(ctx context.Context, id ULID, flag uint8) error {
	raw, err := ps.getDigestFlagsRaw([16]byte(id))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return fmt.Errorf("SetDigestFlag: read current flags: %w", err)
		}
		raw = 0
	}
	raw |= flag
	key := keys.DigestFlagsKey([16]byte(id))
	return ps.db.Set(key, []byte{raw}, pebble.NoSync)
}

// GetDigestFlags returns the current digest flags byte for an engram.
func (ps *PebbleStore) GetDigestFlags(ctx context.Context, id ULID) (uint8, error) {
	return ps.getDigestFlagsRaw([16]byte(id))
}

func (ps *PebbleStore) getDigestFlagsRaw(id [16]byte) (uint8, error) {
	key := keys.DigestFlagsKey(id)
	val, closer, err := ps.db.Get(key)
	if err != nil {
		return 0, err
	}
	defer closer.Close()
	if len(val) == 0 {
		return 0, nil
	}
	return val[0], nil
}

// UpdateEmbedding stores an embedding vector for an engram.
// The wsPrefix is looked up from the engram's key scan.
// For ERF v2, only the 0x18 embedding key is written; the full engram is not re-encoded.
// It also patches EmbedDim in the ERF record so the UI reflects embedding status.
func (ps *PebbleStore) UpdateEmbedding(ctx context.Context, wsPrefix [8]byte, id ULID, vec []float32) error {
	params, quantized := erf.Quantize(vec)
	paramsBuf := erf.EncodeQuantizeParams(params)
	embedBytes := make([]byte, 8+len(quantized))
	copy(embedBytes[:8], paramsBuf[:])
	for i, v := range quantized {
		embedBytes[8+i] = byte(v)
	}

	batch := ps.db.NewBatch()
	defer batch.Close()

	// Write the quantized embedding vector.
	batch.Set(keys.EmbeddingKey(wsPrefix, [16]byte(id)), embedBytes, nil)

	// Patch EmbedDim in the ERF record so the UI reflects embedding status.
	// EmbedDim lives at byte offset erf.OffsetEmbedDim (67) from the record start.
	// PatchEmbedDim also recomputes the CRC32 trailer so the record stays valid.
	dim := DimFromLen(len(vec))
	if dim != types.EmbedNone {
		erfKey := keys.EngramKey(wsPrefix, [16]byte(id))
		val, closer, err := ps.db.Get(erfKey)
		if err == nil {
			buf := make([]byte, len(val))
			copy(buf, val)
			closer.Close()

			if patchErr := erf.PatchEmbedDim(buf, uint8(dim)); patchErr != nil {
				slog.Warn("UpdateEmbedding: failed to patch EmbedDim in ERF record",
					"id", id,
					"err", patchErr,
				)
			} else {
				batch.Set(erfKey, buf, nil)
				// Also update the 0x02 meta key so GetMetadata sees the new EmbedDim.
				metaKey := keys.MetaKey(wsPrefix, [16]byte(id))
				batch.Set(metaKey, erf.MetaKeySlice(buf), nil)
				// Invalidate both caches so the next read re-fetches from Pebble.
				ps.cache.Delete(wsPrefix, id)
				ps.metaCache.Remove([16]byte(id))
			}
		}
		// If the ERF record doesn't exist (race), skip — WriteEngram will set it.
	}

	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("update embedding: commit: %w", err)
	}
	ps.replicateBatch(batch)
	return nil
}

// FindVaultPrefix scans the 0x01 key space to find the vault prefix for an engram ID.
// Returns the first matching vault prefix, or zero if not found.
func (ps *PebbleStore) FindVaultPrefix(id ULID) ([8]byte, bool) {
	// Build a scan: look for any key 0x01 | * | id(16)
	// We scan the full 0x01 range and look for the id suffix.
	lowerBound := []byte{prefix.Engram}
	upperBound := []byte{prefix.Meta}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		return [8]byte{}, false
	}
	defer iter.Close()

	for valid := iter.First(); valid; valid = iter.Next() {
		k := iter.Key()
		if len(k) < 25 {
			continue
		}
		var keyID [16]byte
		copy(keyID[:], k[9:25])
		if keyID == [16]byte(id) {
			var ws [8]byte
			copy(ws[:], k[1:9])
			return ws, true
		}
	}
	return [8]byte{}, false
}

// PluginEngramIterator is a forward-only iterator over engrams missing a digest flag.
// It implements plugin.EngramIterator.
type PluginEngramIterator struct {
	ps        *PebbleStore
	iter      *pebble.Iterator
	iterErr   error // set when NewIter failed; Next() immediately returns false
	flag      uint8
	skipFlags uint8 // skip engrams that have any of these bits set (e.g. DigestEmbedFailed)
	started   bool
	current   *Engram
	// wsCache maps ULID -> vault prefix so callers can retrieve it.
	wsCache   map[ULID][8]byte
	currentWS [8]byte
}

// Next advances to the next unprocessed engram. Returns false when exhausted.
func (it *PluginEngramIterator) Next() bool {
	if it.iter == nil {
		return false
	}
	for {
		var valid bool
		if !it.started {
			valid = it.iter.First()
			it.started = true
		} else {
			valid = it.iter.Next()
		}

		if !valid {
			it.current = nil
			return false
		}

		k := it.iter.Key()
		if len(k) < 25 {
			continue
		}

		var ws [8]byte
		copy(ws[:], k[1:9])
		var id [16]byte
		copy(id[:], k[9:25])

		// Check digest flag
		raw, err := it.ps.getDigestFlagsRaw(id)
		if err == nil && (raw&it.flag) != 0 {
			// Already has this flag, skip
			continue
		}
		// Skip engrams that have a permanent failure flag set (e.g. DigestEmbedFailed).
		if it.skipFlags != 0 && err == nil && raw&it.skipFlags != 0 {
			continue
		}

		// Decode engram
		val := make([]byte, len(it.iter.Value()))
		copy(val, it.iter.Value())
		erfEng, err := erf.Decode(val)
		if err != nil {
			continue
		}

		eng := fromERFEngram(erfEng)

		// Skip soft-deleted and archived engrams — they are not candidates for processing.
		if eng.State == StateSoftDeleted || eng.State == StateArchived {
			continue
		}

		it.current = eng
		it.currentWS = ws
		it.wsCache[ULID(id)] = ws
		return true
	}
}

// Engram returns the current engram. Only valid after Next() returns true.
func (it *PluginEngramIterator) Engram() *Engram {
	return it.current
}

// CurrentWS returns the vault workspace prefix of the current engram.
func (it *PluginEngramIterator) CurrentWS() [8]byte {
	return it.currentWS
}

// WS returns the vault workspace prefix for the given engram ID, if it was seen.
func (it *PluginEngramIterator) WS(id ULID) ([8]byte, bool) {
	ws, ok := it.wsCache[id]
	return ws, ok
}

// Close releases the underlying Pebble iterator.
func (it *PluginEngramIterator) Close() error {
	if it.iter == nil {
		return it.iterErr
	}
	return it.iter.Close()
}
