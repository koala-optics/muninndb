package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/scrypster/muninndb/internal/engine"
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

// ownerCensusErrorClass names why a census failed with a fixed label only.
// rc.5 production (heartbeat 36249093341) returned one opaque message for
// every cause, so a 30s SSE-path cut could not be told apart from a storage
// error without a second session reproducing it.
func ownerCensusErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, engine.ErrOwnerCensusEntityCount):
		return "entity count"
	default:
		return "storage"
	}
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
	started := time.Now()
	result, err := reader.OwnerCensus(ctx, vault)
	if err != nil {
		class := ownerCensusErrorClass(err)
		slog.Warn("mcp: owner census failed", "vault", vault, "class", class,
			"elapsed", time.Since(started), "err", err)
		sendError(w, id, -32000, "tool error: owner census read failed ("+class+")")
		return
	}
	sendResult(w, id, textContent(mustJSON(result)))
}
