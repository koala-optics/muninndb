package migrate

import (
	"fmt"
	"log/slog"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/prefix"
)

// ClearStrandedEmbedFailed clears DigestEmbedFailed (0x80) on every 0x11 digest
// record that lacks DigestEmbed (0x02). Before the retroactive processor left
// cancelled batches pending, each graceful stop flagged the in-flight embed
// micro-batch as permanently failed; every later scan skipped those engrams, so
// they never reached the vector index. Clearing the bit returns them to the
// embed queue, and an engram that genuinely fails again is re-flagged on its
// next attempt. Records that already carry DigestEmbed are untouched (there the
// shared bit can only mean DigestEnrichFailed). Idempotent: a re-run finds
// nothing to clear.
func ClearStrandedEmbedFailed(db *pebble.DB) error {
	const digestEmbed, digestEmbedFailed uint8 = 0x02, 0x80

	iter, err := db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{prefix.DigestFlags},
		UpperBound: []byte{prefix.DigestFlags + 1},
	})
	if err != nil {
		return fmt.Errorf("clear stranded embed-failed: iter: %w", err)
	}
	batch := db.NewBatch()
	defer func() { _ = batch.Close() }()

	cleared := 0
	for valid := iter.First(); valid; valid = iter.Next() {
		val := iter.Value()
		if len(val) == 0 || val[0]&digestEmbedFailed == 0 || val[0]&digestEmbed != 0 {
			continue
		}
		next := append([]byte(nil), val...)
		next[0] &^= digestEmbedFailed
		if err := batch.Set(iter.Key(), next, nil); err != nil {
			_ = iter.Close()
			return fmt.Errorf("clear stranded embed-failed: batch set: %w", err)
		}
		cleared++
	}
	if err := iter.Error(); err != nil {
		_ = iter.Close()
		return fmt.Errorf("clear stranded embed-failed: scan: %w", err)
	}
	if err := iter.Close(); err != nil {
		return fmt.Errorf("clear stranded embed-failed: close iter: %w", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("clear stranded embed-failed: commit: %w", err)
	}

	slog.Info("cleared stranded embed-failed flags", "engrams", cleared)
	return nil
}
