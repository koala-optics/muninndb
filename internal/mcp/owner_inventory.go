package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/scrypster/muninndb/internal/engine"
	"github.com/scrypster/muninndb/internal/storage"
)

const (
	defaultOwnerInventoryLimit = 100
	maxOwnerInventoryLimit     = 200
	maxOwnerInventoryOffset    = 1_000_000_000
)

type ownerInventoryEngine interface {
	OwnerInventory(ctx context.Context, vault string, limit, offset int) (*OwnerInventoryResult, error)
}

type ownerInventoryCursorEngine interface {
	OwnerInventoryAfter(ctx context.Context, vault string, after *storage.ULID, limit int) (*OwnerInventoryCursorResult, error)
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

// OwnerInventoryCursorResult is one keyset page in ascending ID order. An empty
// NextAfterID means the scan reached the end of the vault.
type OwnerInventoryCursorResult struct {
	Engrams     []OwnerInventoryEngram `json:"engrams"`
	Limit       int                    `json:"limit"`
	AfterID     string                 `json:"after_id"`
	NextAfterID string                 `json:"next_after_id"`
}

func ownerInventoryProjection(vault string, page []*storage.Engram) []OwnerInventoryEngram {
	engrams := make([]OwnerInventoryEngram, len(page))
	for i, engram := range page {
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
	return engrams
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
	return &OwnerInventoryResult{
		Engrams:     ownerInventoryProjection(vault, page.Engrams),
		Total:       page.Total,
		Limit:       limit,
		Offset:      offset,
		EntityCount: entityCount,
	}, nil
}

// OwnerInventoryAfter reads one keyset page after the cursor. It runs no
// whole-vault scan and no entity count, so its cost does not grow with depth.
func (a *mcpEngineAdapter) OwnerInventoryAfter(ctx context.Context, vault string, after *storage.ULID, limit int) (*OwnerInventoryCursorResult, error) {
	page, next, err := a.eng.ListEngramsAfter(ctx, vault, after, limit)
	if err != nil {
		return nil, err
	}
	result := &OwnerInventoryCursorResult{
		Engrams: ownerInventoryProjection(vault, page),
		Limit:   limit,
	}
	if after != nil {
		result.AfterID = after.String()
	}
	if next != nil {
		result.NextAfterID = next.String()
	}
	return result, nil
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

// ownerInventoryCursor parses after_id: "" starts a keyset pass (nil cursor).
func ownerInventoryCursor(value any) (*storage.ULID, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("after_id must be a string")
	}
	if text == "" {
		return nil, nil
	}
	id, err := storage.ParseULID(text)
	if err != nil {
		return nil, fmt.Errorf("after_id must be a ULID or empty")
	}
	return &id, nil
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
	if rawAfter, keyset := args["after_id"]; keyset {
		if _, hasOffset := args["offset"]; hasOffset {
			sendError(w, id, -32602, "after_id and offset cannot be combined")
			return
		}
		after, err := ownerInventoryCursor(rawAfter)
		if err != nil {
			sendError(w, id, -32602, err.Error())
			return
		}
		reader, ok := s.engine.(ownerInventoryCursorEngine)
		if !ok {
			sendError(w, id, -32000, "tool error: owner inventory is unavailable")
			return
		}
		started := time.Now()
		result, err := reader.OwnerInventoryAfter(ctx, vault, after, limit)
		if err != nil {
			sendOwnerInventoryError(w, id, vault, started, err)
			return
		}
		sendResult(w, id, textContent(mustJSON(result)))
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
	started := time.Now()
	result, err := reader.OwnerInventory(ctx, vault, limit, offset)
	if err != nil {
		sendOwnerInventoryError(w, id, vault, started, err)
		return
	}
	sendResult(w, id, textContent(mustJSON(result)))
}

// sendOwnerInventoryError names the failure class (deadline, canceled, storage)
// without leaking the underlying error text.
func sendOwnerInventoryError(w http.ResponseWriter, id json.RawMessage, vault string, started time.Time, err error) {
	class := ownerCensusErrorClass(err)
	slog.Warn("mcp: owner inventory failed", "vault", vault, "class", class,
		"elapsed", time.Since(started), "err", err)
	sendError(w, id, -32000, "tool error: owner inventory read failed ("+class+")")
}
