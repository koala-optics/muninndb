package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/transport/mbp"
)

const degradedPostCommitHint = "primary_committed; post_commit=degraded; retry=unsafe"

type degradedBatchEngine struct{ fakeEngine }

func (e *degradedBatchEngine) WriteBatch(_ context.Context, reqs []*mbp.WriteRequest) ([]*mbp.WriteResponse, []error) {
	responses := make([]*mbp.WriteResponse, len(reqs))
	for i := range reqs {
		responses[i] = &mbp.WriteResponse{
			ID:   "degraded-batch-id",
			Hint: degradedPostCommitHint,
		}
	}
	return responses, make([]error, len(reqs))
}

func TestRememberBatchAppendsMalformedWarningToDegradedPostCommitHint(t *testing.T) {
	srv := newTestServerWith(&degradedBatchEngine{})
	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_remember_batch","arguments":{"vault":"default","memories":[{"content":"first memory","entities":["PostgreSQL"]}]}}}`
	w := postRPC(t, srv, body)
	resp := decodeResp(t, w.Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected RPC error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	results, ok := content["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected one result, got %#v", content["results"])
	}
	item, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %#v", results[0])
	}
	hint, _ := item["hint"].(string)
	if !strings.HasPrefix(hint, degradedPostCommitHint+"; ") {
		t.Fatalf("degraded hint was not preserved before malformed warning: %q", hint)
	}
	if !strings.Contains(hint, "malformed") {
		t.Fatalf("hint does not include malformed warning: %q", hint)
	}
}
