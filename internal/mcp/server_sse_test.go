package mcp

// server_sse_test.go — SSE session locking (#174) and reply pairing.
//
// #174: sseSessionsMu was sync.Mutex, so read-only session lookups serialized
// concurrent POSTs. Fix: sync.RWMutex; read paths use RLock/RUnlock.
// Run with -race to verify correctness under concurrent read/write access.
//
// Reply pairing: a POST /mcp reply used to be pushed to every SSE stream opened
// with the same bearer token. Clients sharing a token (every Claude Code
// session) then received each other's replies, and a colliding JSON-RPC id
// resolved the wrong request.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSSESessions_ConcurrentReadWrite is a race-detector test: SSE streams
// connect and disconnect while concurrent /mcp/message POSTs look sessions up.
// Run with: go test -race ./internal/mcp/...
func TestSSESessions_ConcurrentReadWrite(t *testing.T) {
	srv := newTestServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Writer: continuously add and remove sessions, simulating SSE stream
	// connect/disconnect events.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ctx.Err() == nil; i++ {
			id := fmt.Sprintf("sess%d", i%10)
			ch := make(chan []byte, 64)

			srv.sseSessionsMu.Lock()
			srv.sseSessions[id] = &sseSession{ch: ch, auth: AuthContext{Token: "tok"}}
			srv.sseSessionsMu.Unlock()

			runtime.Gosched()

			srv.sseSessionsMu.Lock()
			delete(srv.sseSessions, id)
			srv.sseSessionsMu.Unlock()
		}
	}()

	// Readers: concurrent /mcp/message POSTs, each looking up its session.
	for r := 0; r < 10; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req := httptest.NewRequest(http.MethodPost, "/mcp/message?sessionId=sess1",
					strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
				srv.handleSSEMessage(httptest.NewRecorder(), req)
				runtime.Gosched()
			}
		}()
	}

	wg.Wait()
	// If this completes without -race warnings, lock discipline is correct.
}

// TestStreamablePost_ReplyOnlyInPostBody: two clients share a token and each
// holds an open SSE stream. Replies to POST /mcp, a valid call and an invalid
// one, both with an id the other client also uses, go only in the POST body.
func TestStreamablePost_ReplyOnlyInPostBody(t *testing.T) {
	srv := New(":0", &fakeEngine{}, "mdb_shared", nil, nil, nil)
	streams := []chan []byte{make(chan []byte, 8), make(chan []byte, 8)}
	srv.sseSessionsMu.Lock()
	for i, ch := range streams {
		srv.sseSessions[fmt.Sprintf("client%d", i)] = &sseSession{
			ch:   ch,
			auth: AuthContext{Token: "mdb_shared", Authorized: true},
		}
	}
	srv.sseSessionsMu.Unlock()

	for _, tc := range []struct{ body, want string }{
		{`{"jsonrpc":"2.0","id":7,"method":"ping"}`, `"result":{}`},
		{`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"muninn_no_such_tool","arguments":{}}}`,
			`unknown tool: muninn_no_such_tool`},
	} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer mdb_shared")
		w := httptest.NewRecorder()
		srv.handleStreamablePost(w, r)
		if got := w.Body.String(); !strings.Contains(got, `"id":7`) || !strings.Contains(got, tc.want) {
			t.Fatalf("POST body = %q, want id 7 and %q", got, tc.want)
		}
	}
	for i, ch := range streams {
		if n := len(ch); n != 0 {
			t.Fatalf("SSE stream %d received %d replies to POST /mcp, want 0: %q", i, n, <-ch)
		}
	}
}
