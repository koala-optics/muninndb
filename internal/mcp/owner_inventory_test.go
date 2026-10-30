package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

type ownerInventoryTestEngine struct {
	fakeEngine
	result *OwnerInventoryResult
	err    error
	calls  int
	vault  string
	limit  int
	offset int
}

func (e *ownerInventoryTestEngine) OwnerInventory(_ context.Context, vault string, limit, offset int) (*OwnerInventoryResult, error) {
	e.calls++
	e.vault, e.limit, e.offset = vault, limit, offset
	return e.result, e.err
}

type ownerInventoryCursorTestEngine struct {
	fakeEngine
	result *OwnerInventoryCursorResult
	err    error
	calls  int
	vault  string
	after  *storage.ULID
	limit  int
}

func (e *ownerInventoryCursorTestEngine) OwnerInventoryAfter(_ context.Context, vault string, after *storage.ULID, limit int) (*OwnerInventoryCursorResult, error) {
	e.calls++
	e.vault, e.after, e.limit = vault, after, limit
	return e.result, e.err
}

func TestHandleOwnerInventory_KeysetPage(t *testing.T) {
	cursor := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	eng := &ownerInventoryCursorTestEngine{result: &OwnerInventoryCursorResult{
		Engrams: []OwnerInventoryEngram{{ID: "01NEXT", Tags: []string{}, Vault: "inventory"}},
		Limit:   2, AfterID: cursor, NextAfterID: "01NEXT",
	}}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{"vault":"inventory","limit":2,"after_id":"`+cursor+`"}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	if content["next_after_id"] != "01NEXT" || content["after_id"] != cursor || content["limit"] != float64(2) {
		t.Fatalf("keyset echo = %#v", content)
	}
	if _, hasTotal := content["total"]; hasTotal {
		t.Fatalf("keyset page must not claim a total: %#v", content)
	}
	if eng.calls != 1 || eng.vault != "inventory" || eng.limit != 2 || eng.after == nil || eng.after.String() != cursor {
		t.Fatalf("engine call = %#v", eng)
	}
}

func TestHandleOwnerInventory_KeysetEmptyCursorStartsAtVaultStart(t *testing.T) {
	eng := &ownerInventoryCursorTestEngine{result: &OwnerInventoryCursorResult{Engrams: []OwnerInventoryEngram{}, Limit: 100}}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{"after_id":""}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if eng.calls != 1 || eng.after != nil || eng.limit != defaultOwnerInventoryLimit {
		t.Fatalf("engine call = %#v", eng)
	}
	if content := extractInnerJSON(t, resp); content["next_after_id"] != "" {
		t.Fatalf("terminal keyset page = %#v", content)
	}
}

func TestHandleOwnerInventory_KeysetInvalidArgumentsDoNotCallEngine(t *testing.T) {
	cases := []string{
		`{"after_id":7}`,
		`{"after_id":"not-a-ulid"}`,
		`{"after_id":"","offset":0}`,
		`{"after_id":"","limit":201}`,
	}
	for _, args := range cases {
		t.Run(args, func(t *testing.T) {
			eng := &ownerInventoryCursorTestEngine{}
			srv := New(":0", eng, "", nil, nil, nil)
			w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":`+args+`}}`)
			resp := decodeResp(t, w.Body.String())
			if resp.Error == nil || resp.Error.Code != -32602 {
				t.Fatalf("error = %#v, want invalid params", resp.Error)
			}
			if eng.calls != 0 {
				t.Fatalf("engine called %d times", eng.calls)
			}
		})
	}
}

func TestHandleOwnerInventory_KeysetErrorNamesClassWithoutLeaking(t *testing.T) {
	eng := &ownerInventoryCursorTestEngine{err: fmt.Errorf("secret owner detail: %w", context.DeadlineExceeded)}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{"after_id":""}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "read failed (deadline exceeded)") {
		t.Fatalf("error = %#v", resp.Error)
	}
	if strings.Contains(resp.Error.Message, "secret owner detail") {
		t.Fatalf("owner error leaked: %s", resp.Error.Message)
	}
}

func TestHandleOwnerInventory_HappyPath(t *testing.T) {
	eng := &ownerInventoryTestEngine{result: &OwnerInventoryResult{
		Engrams: []OwnerInventoryEngram{{
			ID: "01OWNER", Concept: "owner", Content: "content", Confidence: 0.75,
			Tags: []string{}, Vault: "inventory", CreatedAt: 123, EmbedDim: 4,
		}},
		Total: 9, Limit: 2, Offset: 4, EntityCount: 17,
	}}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{"vault":"inventory","limit":2,"offset":4}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	if content["total"] != float64(9) || content["limit"] != float64(2) || content["offset"] != float64(4) {
		t.Fatalf("pagination echo = %#v", content)
	}
	if content["entity_count"] != float64(17) {
		t.Fatalf("entity_count = %v, want 17", content["entity_count"])
	}
	rows := content["engrams"].([]any)
	row := rows[0].(map[string]any)
	if row["vault"] != "inventory" || row["embed_dim"] != float64(4) {
		t.Fatalf("projection = %#v", row)
	}
	if tags, ok := row["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatalf("tags = %#v, want []", row["tags"])
	}
	if eng.calls != 1 || eng.vault != "inventory" || eng.limit != 2 || eng.offset != 4 {
		t.Fatalf("engine call = %#v", eng)
	}
}

func TestHandleOwnerInventory_ExplicitEmptyTerminalPage(t *testing.T) {
	eng := &ownerInventoryTestEngine{result: &OwnerInventoryResult{
		Engrams: []OwnerInventoryEngram{}, Total: 3, Limit: 2, Offset: 3, EntityCount: 8,
	}}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{"limit":2,"offset":3}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	if rows := content["engrams"].([]any); len(rows) != 0 {
		t.Fatalf("engrams = %#v, want []", rows)
	}
	if content["total"] != float64(3) || content["offset"] != float64(3) {
		t.Fatalf("terminal page = %#v", content)
	}
}

func TestHandleOwnerInventory_InvalidArgumentsDoNotCallEngine(t *testing.T) {
	cases := []string{
		`{"limit":0}`,
		`{"limit":201}`,
		`{"limit":1.5}`,
		`{"limit":true}`,
		`{"offset":-1}`,
		`{"offset":1.5}`,
		`{"offset":1000000001}`,
	}
	for _, args := range cases {
		t.Run(args, func(t *testing.T) {
			eng := &ownerInventoryTestEngine{}
			srv := New(":0", eng, "", nil, nil, nil)
			w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":`+args+`}}`)
			resp := decodeResp(t, w.Body.String())
			if resp.Error == nil || resp.Error.Code != -32602 {
				t.Fatalf("error = %#v, want invalid params", resp.Error)
			}
			if eng.calls != 0 {
				t.Fatalf("engine called %d times", eng.calls)
			}
		})
	}
}

func TestHandleOwnerInventory_UnavailableAndErrorsAreSanitized(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		srv := newTestServer()
		w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{}}}`)
		resp := decodeResp(t, w.Body.String())
		if resp.Error == nil || !strings.Contains(resp.Error.Message, "unavailable") {
			t.Fatalf("error = %#v", resp.Error)
		}
	})

	t.Run("owner error", func(t *testing.T) {
		eng := &ownerInventoryTestEngine{err: errors.New("secret owner detail")}
		srv := New(":0", eng, "", nil, nil, nil)
		w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_inventory","arguments":{}}}`)
		resp := decodeResp(t, w.Body.String())
		if resp.Error == nil || !strings.Contains(resp.Error.Message, "read failed") {
			t.Fatalf("error = %#v", resp.Error)
		}
		if strings.Contains(resp.Error.Message, "secret owner detail") {
			t.Fatalf("owner error leaked: %s", resp.Error.Message)
		}
	})
}
