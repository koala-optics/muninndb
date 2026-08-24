package engine

import "context"

// CountEntities returns the exact number of resolvable entity identities linked
// from engrams in vault. The baseline ScanVaultEntityNames yields RAW stored
// name strings (rc.3's normalizes them), so normalized duplicates of one
// identity (" postgresql " vs "PostgreSQL") can each be yielded; dedupe on the
// resolved record's canonical Name, which GetEntityRecord reaches through the
// same normalized EntityNameHash either way.
func (e *Engine) CountEntities(ctx context.Context, vault string) (int, error) {
	ws := e.store.ResolveVaultPrefix(vault)
	count := 0
	seen := make(map[string]struct{})
	err := e.store.ScanVaultEntityNames(ctx, ws, func(name string) error {
		record, err := e.store.GetEntityRecord(ctx, name)
		if err != nil {
			return err
		}
		if record == nil {
			return nil
		}
		if _, already := seen[record.Name]; already {
			return nil
		}
		seen[record.Name] = struct{}{}
		count++
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
