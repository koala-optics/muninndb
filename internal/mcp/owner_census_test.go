package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type ownerCensusTestEngine struct {
	fakeEngine
	result *OwnerCensusResult
	err    error
	calls  int
	vault  string
}

func (e *ownerCensusTestEngine) OwnerCensus(_ context.Context, vault string) (*OwnerCensusResult, error) {
	e.calls++
	e.vault = vault
	return e.result, e.err
}

func TestHandleOwnerCensus_HappyPath(t *testing.T) {
	eng := &ownerCensusTestEngine{result: &OwnerCensusResult{
		Total:          9,
		EntityCount:    17,
		IdentitySHA256: strings.Repeat("ab", 32),
	}}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{"vault":"census"}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	if content["total"] != float64(9) || content["entity_count"] != float64(17) {
		t.Fatalf("census counts = %#v", content)
	}
	if content["identity_sha256"] != strings.Repeat("ab", 32) {
		t.Fatalf("identity digest = %v", content["identity_sha256"])
	}
	if len(content) != 3 {
		t.Fatalf("census exposed unexpected fields: %#v", content)
	}
	if eng.calls != 1 || eng.vault != "census" {
		t.Fatalf("engine call = %#v", eng)
	}
}

func TestHandleOwnerCensus_EngineErrorIsOpaque(t *testing.T) {
	eng := &ownerCensusTestEngine{err: errors.New("pebble: internal detail")}
	srv := New(":0", eng, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error == nil {
		t.Fatal("expected an error response")
	}
	if strings.Contains(resp.Error.Message, "pebble") {
		t.Fatalf("engine detail leaked: %q", resp.Error.Message)
	}
}

func TestHandleOwnerCensus_UnavailableWithoutEngineSupport(t *testing.T) {
	srv := New(":0", &fakeEngine{}, "", nil, nil, nil)
	w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{}}}`)
	resp := decodeResp(t, w.Body.String())
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "unavailable") {
		t.Fatalf("expected unavailable error, got %v", resp.Error)
	}
}
