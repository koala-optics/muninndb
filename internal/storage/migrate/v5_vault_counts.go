package migrate

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/prefix"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// RebuildVaultCounts reconstructs every persisted 0x15 count from canonical
// 0x01 engram keys. Existing count keys are included so stale empty vaults are
// reset to zero. Rewriting the same exact values makes the migration idempotent.
func RebuildVaultCounts(db *pebble.DB) error {
	counts := make(map[[8]byte]uint64)
	engrams, err := db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefix.Engram},
		UpperBound: []byte{prefix.Meta},
	})
	if err != nil {
		return fmt.Errorf("rebuild vault counts: engram iter: %w", err)
	}
	for valid := engrams.First(); valid; valid = engrams.Next() {
		key := engrams.Key()
		if len(key) != 25 { // prefix(1) + vault(8) + ULID(16)
			_ = engrams.Close()
			return fmt.Errorf("rebuild vault counts: malformed engram key length %d at %x", len(key), key)
		}
		var vault [8]byte
		copy(vault[:], key[1:9])
		counts[vault]++
	}
	if err := engrams.Error(); err != nil {
		_ = engrams.Close()
		return fmt.Errorf("rebuild vault counts: engram scan: %w", err)
	}
	if err := engrams.Close(); err != nil {
		return fmt.Errorf("rebuild vault counts: close engram iter: %w", err)
	}

	persisted, err := db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefix.VaultCount},
		UpperBound: []byte{prefix.VaultCount + 1},
	})
	if err != nil {
		return fmt.Errorf("rebuild vault counts: count iter: %w", err)
	}
	for valid := persisted.First(); valid; valid = persisted.Next() {
		key := persisted.Key()
		if len(key) != 9 { // prefix(1) + vault(8)
			_ = persisted.Close()
			return fmt.Errorf("rebuild vault counts: malformed count key length %d at %x", len(key), key)
		}
		var vault [8]byte
		copy(vault[:], key[1:9])
		if _, ok := counts[vault]; !ok {
			counts[vault] = 0
		}
	}
	if err := persisted.Error(); err != nil {
		_ = persisted.Close()
		return fmt.Errorf("rebuild vault counts: count scan: %w", err)
	}
	if err := persisted.Close(); err != nil {
		return fmt.Errorf("rebuild vault counts: close count iter: %w", err)
	}

	batch := db.NewBatch()
	defer func() { _ = batch.Close() }()
	for vault, count := range counts {
		var value [8]byte
		binary.BigEndian.PutUint64(value[:], count)
		if err := batch.Set(keys.VaultCountKey(vault), value[:], nil); err != nil {
			return fmt.Errorf("rebuild vault counts: set count: %w", err)
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("rebuild vault counts: commit: %w", err)
	}

	slog.Info("rebuild vault counts complete", "vaults", len(counts))
	return nil
}
