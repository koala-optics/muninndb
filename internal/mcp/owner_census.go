package mcp

import (
	"context"
	"encoding/json"
	"net/http"
)

type ownerCensusEngine interface {
	OwnerCensus(ctx context.Context, vault string) (*OwnerCensusResult, error)
}

// OwnerCensusResult is the wire shape of one whole-vault active census.
type OwnerCensusResult struct {
	Total          int    `json:"total"`
	EntityCount    int    `json:"entity_count"`
	IdentitySHA256 string `json:"identity_sha256"`
}

// OwnerCensus runs one single-scan active census over the vault.
func (a *mcpEngineAdapter) OwnerCensus(ctx context.Context, vault string) (*OwnerCensusResult, error) {
	census, err := a.eng.OwnerCensus(ctx, vault)
	if err != nil {
		return nil, err
	}
	return &OwnerCensusResult{
		Total:          census.Total,
		EntityCount:    census.EntityCount,
		IdentitySHA256: census.IdentitySHA256,
	}, nil
}

func (s *MCPServer) handleOwnerCensus(
	ctx context.Context,
	w http.ResponseWriter,
	id json.RawMessage,
	vault string,
	args map[string]any,
) {
	reader, ok := s.engine.(ownerCensusEngine)
	if !ok {
		sendError(w, id, -32000, "tool error: owner census is unavailable")
		return
	}
	result, err := reader.OwnerCensus(ctx, vault)
	if err != nil {
		sendError(w, id, -32000, "tool error: owner census read failed")
		return
	}
	sendResult(w, id, textContent(mustJSON(result)))
}
