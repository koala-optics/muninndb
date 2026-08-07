package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"

	"github.com/scrypster/muninndb/internal/engine"
)

const (
	defaultOwnerInventoryLimit = 100
	maxOwnerInventoryLimit     = 200
	maxOwnerInventoryOffset    = 1_000_000_000
)

type ownerInventoryEngine interface {
	OwnerInventory(ctx context.Context, vault string, limit, offset int) (*OwnerInventoryResult, error)
}

// OwnerInventoryEngram is the passive owner projection used for exact scans.
type OwnerInventoryEngram struct {
	ID         string   `json:"id"`
	Concept    string   `json:"concept"`
	Content    string   `json:"content"`
	Confidence float32  `json:"confidence"`
	Tags       []string `json:"tags"`
	Vault      string   `json:"vault"`
	CreatedAt  int64    `json:"created_at"`
	EmbedDim   uint8    `json:"embed_dim"`
}

// OwnerInventoryResult combines one passive engram page with an exact entity count.
type OwnerInventoryResult struct {
	Engrams     []OwnerInventoryEngram `json:"engrams"`
	Total       int                    `json:"total"`
	Limit       int                    `json:"limit"`
	Offset      int                    `json:"offset"`
	EntityCount int                    `json:"entity_count"`
}

// OwnerInventory reads one passive page and separately counts entity identities.
func (a *mcpEngineAdapter) OwnerInventory(ctx context.Context, vault string, limit, offset int) (*OwnerInventoryResult, error) {
	page, err := a.eng.ListEngrams(ctx, engine.ListEngramsParams{
		Vault:  vault,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}
	entityCount, err := a.eng.CountEntities(ctx, vault)
	if err != nil {
		return nil, err
	}

	engrams := make([]OwnerInventoryEngram, len(page.Engrams))
	for i, engram := range page.Engrams {
		tags := engram.Tags
		if tags == nil {
			tags = []string{}
		}
		engrams[i] = OwnerInventoryEngram{
			ID:         engram.ID.String(),
			Concept:    engram.Concept,
			Content:    engram.Content,
			Confidence: engram.Confidence,
			Tags:       tags,
			Vault:      vault,
			CreatedAt:  engram.CreatedAt.Unix(),
			EmbedDim:   uint8(engram.EmbedDim),
		}
	}
	return &OwnerInventoryResult{
		Engrams:     engrams,
		Total:       page.Total,
		Limit:       limit,
		Offset:      offset,
		EntityCount: entityCount,
	}, nil
}

func ownerInventoryInteger(args map[string]any, key string, defaultValue, minimum, maximum int) (int, error) {
	value, present := args[key]
	if !present {
		return defaultValue, nil
	}
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if number < float64(minimum) || number > float64(maximum) {
		return 0, fmt.Errorf("%s is outside the allowed range", key)
	}
	return int(number), nil
}

func (s *MCPServer) handleOwnerInventory(
	ctx context.Context,
	w http.ResponseWriter,
	id json.RawMessage,
	vault string,
	args map[string]any,
) {
	limit, err := ownerInventoryInteger(args, "limit", defaultOwnerInventoryLimit, 1, maxOwnerInventoryLimit)
	if err != nil {
		sendError(w, id, -32602, err.Error())
		return
	}
	offset, err := ownerInventoryInteger(args, "offset", 0, 0, maxOwnerInventoryOffset)
	if err != nil {
		sendError(w, id, -32602, err.Error())
		return
	}
	reader, ok := s.engine.(ownerInventoryEngine)
	if !ok {
		sendError(w, id, -32000, "tool error: owner inventory is unavailable")
		return
	}
	result, err := reader.OwnerInventory(ctx, vault, limit, offset)
	if err != nil {
		sendError(w, id, -32000, "tool error: owner inventory read failed")
		return
	}
	sendResult(w, id, textContent(mustJSON(result)))
}
