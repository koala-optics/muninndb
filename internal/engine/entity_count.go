package engine

import "context"

// CountEntities returns the exact number of resolvable entity identities linked
// from engrams in vault. ScanVaultEntityNames normalizes duplicate identities.
func (e *Engine) CountEntities(ctx context.Context, vault string) (int, error) {
	ws := e.store.ResolveVaultPrefix(vault)
	count := 0
	err := e.store.ScanVaultEntityNames(ctx, ws, func(name string) error {
		record, err := e.store.GetEntityRecord(ctx, name)
		if err != nil {
			return err
		}
		if record == nil {
			return nil
		}
		count++
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
