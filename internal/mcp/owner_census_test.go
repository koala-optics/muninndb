package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/engine"
)

type ownerCensusTestEngine struct {
	fakeEngine
	result *OwnerCensusResult
	err    error
	calls  int
	vault  string
	budget time.Duration
}

func (e *ownerCensusTestEngine) OwnerCensus(ctx context.Context, vault string) (*OwnerCensusResult, error) {
	e.calls++
	e.vault = vault
	if deadline, ok := ctx.Deadline(); ok {
		e.budget = time.Until(deadline)
	}
	return e.result, e.err
}

func TestHandleOwnerCensus_GetsLongerDeadline(t *testing.T) {
	eng := &ownerCensusTestEngine{result: &OwnerCensusResult{IdentitySHA256: strings.Repeat("ab", 32)}}
	srv := New(":0", eng, "", nil, nil, nil)
	postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{}}}`)
	if eng.budget <= requestDeadline || eng.budget > ownerCensusDeadline {
		t.Fatalf("census deadline budget = %v, want in (%v, %v]", eng.budget, requestDeadline, ownerCensusDeadline)
	}
}

// A streamable POST whose token also holds an open SSE stream is dispatched by
// processAndPushSSE, not handleRPC; the census must get the same deadline there
// (rc.5 production: census cut off at 30.1s on this path).
func TestStreamablePost_OwnerCensusWithOpenSSE_GetsLongerDeadline(t *testing.T) {
	eng := &ownerCensusTestEngine{result: &OwnerCensusResult{IdentitySHA256: strings.Repeat("ab", 32)}}
	srv := New(":0", eng, "mdb_census", nil, nil, nil)
	srv.sseSessionsMu.Lock()
	srv.sseSessions["census-sse"] = &sseSession{
		ch:   make(chan []byte, 4),
		auth: AuthContext{Token: "mdb_census", Authorized: true},
	}
	srv.sseSessionsMu.Unlock()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{}}}`
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer mdb_census")
	srv.handleStreamablePost(httptest.NewRecorder(), r)

	if eng.calls != 1 {
		t.Fatalf("census calls = %d, want 1", eng.calls)
	}
	if eng.budget <= requestDeadline || eng.budget > ownerCensusDeadline {
		t.Fatalf("census deadline budget via SSE = %v, want in (%v, %v]", eng.budget, requestDeadline, ownerCensusDeadline)
	}
}

func TestDeadlineFor_OtherCallsKeepSharedDeadline(t *testing.T) {
	for _, req := range []JSONRPCRequest{
		{Method: "tools/call", Params: &JSONRPCParams{Name: "muninn_owner_inventory"}},
		{Method: "tools/call"},
		{Method: "tools/list"},
	} {
		if got := deadlineFor(&req); got != requestDeadline {
			t.Fatalf("deadlineFor(%+v) = %v, want %v", req, got, requestDeadline)
		}
	}
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

// The -32000 message names the failure class with a fixed label, so a
// client-side log shows why a census failed without server log retention.
func TestHandleOwnerCensus_ErrorNamesClass(t *testing.T) {
	detail := errors.New("pebble: internal detail")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("scan: %w", context.DeadlineExceeded), "tool error: owner census read failed (deadline exceeded)"},
		{context.Canceled, "tool error: owner census read failed (canceled)"},
		{fmt.Errorf("%w: %w", engine.ErrOwnerCensusEntityCount, detail), "tool error: owner census read failed (entity count)"},
		{detail, "tool error: owner census read failed (storage)"},
	} {
		eng := &ownerCensusTestEngine{err: tc.err}
		srv := New(":0", eng, "", nil, nil, nil)
		w := postRPC(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"muninn_owner_census","arguments":{}}}`)
		resp := decodeResp(t, w.Body.String())
		if resp.Error == nil || resp.Error.Code != -32000 || resp.Error.Message != tc.want {
			t.Fatalf("err %v: got %+v, want -32000 %q", tc.err, resp.Error, tc.want)
		}
		if strings.Contains(resp.Error.Message, "pebble") {
			t.Fatalf("engine detail leaked: %q", resp.Error.Message)
		}
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
