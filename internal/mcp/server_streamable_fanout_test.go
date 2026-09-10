package mcp

// server_streamable_fanout_test.go - POST /mcp answers in the POST body only.
//
// Background: handleStreamablePost used to look up every SSE session whose
// AuthContext.Token equalled the caller's bearer token and push the response to
// all of them. With a shared static token every session of a deployment
// matched, so each tools/call result was broadcast to N unrelated sessions;
// each logged "Received a response for an unknown message ID" and dropped its
// stream (one deployment: 162 GB of client logs in four weeks). These tests pin
// the fix: streamable POST responses never reach any SSE channel, while the
// legacy GET /mcp + POST /mcp/message?sessionId= pair still pushes to its own
// stream and only its own stream.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newStaticTokenServerWithSSE(t *testing.T, token string, sessionIDs ...string) (*MCPServer, map[string]chan []byte) {
	t.Helper()
	srv := New(":0", &fakeEngine{}, token, nil, nil, nil)
	a := AuthContext{Token: token, Authorized: true}
	chans := make(map[string]chan []byte, len(sessionIDs))
	srv.sseSessionsMu.Lock()
	for _, id := range sessionIDs {
		ch := make(chan []byte, 8)
		chans[id] = ch
		srv.sseSessions[id] = &sseSession{ch: ch, auth: a}
	}
	srv.sseSessionsMu.Unlock()
	return srv, chans
}

func postStreamable(srv *MCPServer, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleStreamablePost(w, r)
	return w
}

func TestStreamablePost_ResponseInBodyOnly_NoSSEFanout(t *testing.T) {
	srv, chans := newStaticTokenServerWithSSE(t, "mdb_shared", "session-a", "session-b", "session-c")

	body := mkToolCallBody("muninn_status", map[string]any{"vault": "default"})
	w := postStreamable(srv, "mdb_shared", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with the response in the POST body, got %d: %s", w.Code, w.Body.String())
	}
	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("POST body is not a JSON-RPC response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error in POST body: %+v", resp.Error)
	}
	if string(resp.ID) != "1" {
		t.Errorf("expected response id 1 in POST body, got %s", resp.ID)
	}
	for id, ch := range chans {
		if n := len(ch); n != 0 {
			t.Errorf("SSE session %s received %d pushed event(s); streamable POST must not fan out", id, n)
		}
	}
}

func TestStreamablePost_InitializeNotFannedOut(t *testing.T) {
	srv, chans := newStaticTokenServerWithSSE(t, "mdb_shared", "session-a", "session-b")

	body := []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)
	w := postStreamable(srv, "mdb_shared", body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"protocolVersion"`)) {
		t.Errorf("initialize result missing from POST body: %s", w.Body.String())
	}
	for id, ch := range chans {
		if n := len(ch); n != 0 {
			t.Errorf("SSE session %s received %d pushed initialize response(s)", id, n)
		}
	}
}

func TestSSEMessage_StillPushesToItsOwnStreamOnly(t *testing.T) {
	srv, chans := newStaticTokenServerWithSSE(t, "mdb_shared", "mine", "other")

	body := mkToolCallBody("muninn_status", map[string]any{"vault": "default"})
	r := httptest.NewRequest(http.MethodPost, "/mcp/message?sessionId=mine", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer mdb_shared")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleSSEMessage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if n := len(chans["mine"]); n != 1 {
		t.Errorf("own SSE stream should receive exactly 1 pushed response, got %d", n)
	}
	if n := len(chans["other"]); n != 0 {
		t.Errorf("another session's SSE stream received %d pushed response(s)", n)
	}
}
