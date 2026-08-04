package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

const (
	mcpPayloadDigestA = "e43d052c4b592d72e3fb62886f71b354c90c4e7661ada41477cd57b721bc5e46"
	mcpPayloadDigestB = "33dd57234331d00de85122a0e1c114ae9027e124b7db273bf9e42abd8a128efd"
)

func TestCanonicalArgumentsSHA256_PythonGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "basic",
			raw:  `{"content":"hello world","op_id":"my-unique-op","vault":"default"}`,
			want: "e43d052c4b592d72e3fb62886f71b354c90c4e7661ada41477cd57b721bc5e46",
		},
		{
			name: "unicode and floats",
			raw:  `{"confidence":1.0,"content":"<safe>& café line","embedding":[-0.0,1e-09,0.0001,1e+20],"op_id":"stage-b:α","tags":["b","a"]}`,
			want: "2d08d7b07f35d8a267b2f8adf6b97681eb88300fcb421dda3decf5265a96e09f",
		},
		{
			name: "nested",
			raw:  `{"content":"nested","entities":[{"name":"MuninnDB","type":"service"}],"entity_relationships":[{"from_entity":"MuninnDB","rel_type":"writes","to_entity":"Queue","weight":0.9}],"op_id":"stage-b:nested"}`,
			want: "33dd57234331d00de85122a0e1c114ae9027e124b7db273bf9e42abd8a128efd",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalArgumentsSHA256([]byte(tc.raw))
			if err != nil {
				t.Fatalf("canonicalArgumentsSHA256: %v", err)
			}
			if got != tc.want {
				t.Fatalf("digest mismatch: got %s want %s", got, tc.want)
			}
		})
	}
}

func TestPythonJSONNumber_FormattingThresholds(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{raw: "1.2e6", want: "1200000.0"},
		{raw: "1e15", want: "1000000000000000.0"},
		{raw: "1e16", want: "1e+16"},
		{raw: "1234567890123456.0", want: "1234567890123456.0"},
		{raw: "1e-4", want: "0.0001"},
		{raw: "1e-5", want: "1e-05"},
		{raw: "-0.0", want: "-0.0"},
		{raw: "-0", want: "0"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := pythonJSONNumber(tc.raw)
			if err != nil {
				t.Fatalf("pythonJSONNumber(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("pythonJSONNumber(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCanonicalArgumentsSHA256_BindsCompleteArguments(t *testing.T) {
	base := `{"content":"same","op_id":"stage-b:complete","tags":["a","b"]}`
	changedOrder := `{"content":"same","op_id":"stage-b:complete","tags":["b","a"]}`
	extraField := `{"content":"same","op_id":"stage-b:complete","tags":["a","b"],"summary":"extra"}`
	baseHash, err := canonicalArgumentsSHA256([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	orderHash, err := canonicalArgumentsSHA256([]byte(changedOrder))
	if err != nil {
		t.Fatal(err)
	}
	extraHash, err := canonicalArgumentsSHA256([]byte(extraField))
	if err != nil {
		t.Fatal(err)
	}
	if baseHash == orderHash || baseHash == extraHash || orderHash == extraHash {
		t.Fatalf("complete argument changes did not change digest: %s %s %s", baseHash, orderHash, extraHash)
	}
}

type payloadReceiptFakeEngine struct {
	fakeEngine
	mu       sync.Mutex
	receipts map[string]*storage.PayloadReceipt
	writes   int
}

func (e *payloadReceiptFakeEngine) WriteWithPayloadReceipt(_ context.Context, req *mbp.WriteRequest, opID, payloadSHA256 string) (*mbp.WriteResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := req.Vault + "\x00" + opID
	if receipt := e.receipts[key]; receipt != nil {
		if receipt.PayloadSHA256 != payloadSHA256 {
			return nil, errors.New("payload receipt conflict")
		}
		return &mbp.WriteResponse{ID: receipt.EngramID, Hint: "idempotent"}, nil
	}
	if e.receipts == nil {
		e.receipts = make(map[string]*storage.PayloadReceipt)
	}
	e.writes++
	id := fmt.Sprintf("payload-id-%d", e.writes)
	e.receipts[key] = &storage.PayloadReceipt{EngramID: id, OpID: opID, PayloadSHA256: payloadSHA256}
	return &mbp.WriteResponse{ID: id}, nil
}

func (e *payloadReceiptFakeEngine) ReadPayloadReceipt(_ context.Context, vault, opID string) (*storage.PayloadReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if receipt := e.receipts[vault+"\x00"+opID]; receipt != nil {
		copy := *receipt
		return &copy, nil
	}
	return nil, nil
}

func TestJSONRPCParams_UnmarshalRejectsNonObjectArguments(t *testing.T) {
	for _, arguments := range []string{`[]`, `"text"`, `1`, `true`} {
		var request JSONRPCRequest
		err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_remember","arguments":`+arguments+`}}`), &request)
		if err == nil {
			t.Fatalf("non-object arguments %s were accepted as %#v", arguments, request.Params.Arguments)
		}
	}
}

func TestHandleRemember_SuppliedMalformedOpIDRefuses(t *testing.T) {
	for _, opID := range []string{`""`, `"   "`, `123`, `true`, `null`} {
		t.Run(opID, func(t *testing.T) {
			eng := &noOpIDEngine{}
			srv := newTestServerWith(eng)
			body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_remember","arguments":{"vault":"default","content":"must not write","op_id":` + opID + `}}}`
			resp := decodeResp(t, postRPC(t, srv, body).Body.String())
			if resp.Error == nil || resp.Error.Code != -32602 {
				t.Fatalf("malformed op_id %s returned error %#v", opID, resp.Error)
			}
			if eng.writeCalls != 0 {
				t.Fatalf("malformed op_id %s produced %d ordinary writes", opID, eng.writeCalls)
			}
		})
	}
}

func TestHandleRemember_PayloadReceiptBindsRawCompleteArguments(t *testing.T) {
	eng := &payloadReceiptFakeEngine{}
	srv := newTestServerWith(eng)
	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_remember","arguments":{"vault":"default","content":"hello world","op_id":"my-unique-op"}}}`
	resp := decodeResp(t, postRPC(t, srv, body).Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	receipt := eng.receipts["default\x00my-unique-op"]
	if receipt == nil || receipt.PayloadSHA256 != mcpPayloadDigestA {
		t.Fatalf("server did not bind Python-canonical complete arguments: %+v", receipt)
	}
}

func TestHandleRemember_PayloadDriftRefuses(t *testing.T) {
	eng := &payloadReceiptFakeEngine{}
	srv := newTestServerWith(eng)
	first := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_remember","arguments":{"vault":"default","content":"first","op_id":"stage-b:drift"}}}`
	second := `{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"muninn_remember","arguments":{"vault":"default","content":"second","op_id":"stage-b:drift"}}}`
	if resp := decodeResp(t, postRPC(t, srv, first).Body.String()); resp.Error != nil {
		t.Fatalf("first write: %v", resp.Error)
	}
	resp := decodeResp(t, postRPC(t, srv, second).Body.String())
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "payload receipt conflict") {
		t.Fatalf("payload drift did not fail closed: %+v", resp)
	}
	if eng.writes != 1 {
		t.Fatalf("payload drift produced %d writes", eng.writes)
	}
}

func TestPayloadReceiptRead_ReturnsOnlyIDAndDigest(t *testing.T) {
	eng := &payloadReceiptFakeEngine{receipts: map[string]*storage.PayloadReceipt{
		"default\x00stage-b:read": {EngramID: "memory-123", OpID: "stage-b:read", PayloadSHA256: mcpPayloadDigestB, CreatedAt: 123},
	}}
	srv := newTestServerWith(eng)
	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_payload_receipt","arguments":{"vault":"default","op_id":"stage-b:read"}}}`
	resp := decodeResp(t, postRPC(t, srv, body).Body.String())
	if resp.Error != nil {
		t.Fatalf("unexpected read error: %v", resp.Error)
	}
	content := extractInnerJSON(t, resp)
	if len(content) != 2 || content["memory_id"] != "memory-123" || content["observed_payload_sha256"] != mcpPayloadDigestB {
		t.Fatalf("receipt read exposed wrong fields: %#v", content)
	}
	for _, forbidden := range []string{"content", "arguments", "op_id", "vault", "created_at"} {
		if _, ok := content[forbidden]; ok {
			t.Fatalf("receipt read exposed forbidden field %q: %#v", forbidden, content)
		}
	}
}

func TestPayloadReceiptRead_RequiresConfiguredAuthentication(t *testing.T) {
	eng := &payloadReceiptFakeEngine{}
	srv := New(":0", eng, "mdb_required", nil, nil, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_payload_receipt","arguments":{"vault":"default","op_id":"stage-b:auth"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.srv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated receipt read returned HTTP %d", w.Code)
	}
}

func TestPayloadReceiptRead_PinnedVaultCannotReadAnotherVault(t *testing.T) {
	eng := &payloadReceiptFakeEngine{receipts: map[string]*storage.PayloadReceipt{
		"vault-b\x00stage-b:scope": {EngramID: "vault-b-memory", OpID: "stage-b:scope", PayloadSHA256: mcpPayloadDigestB},
	}}
	keys := newMockKeyStore(auth.APIKey{ID: "obs-payload", Vault: "vault-a", Mode: auth.ModeObserve})
	srv := New(":0", eng, "", keys, nil, nil)
	body := mkToolCallBody("muninn_payload_receipt", map[string]any{"op_id": "stage-b:scope"})
	w := doAuthenticatedPost(srv, "mk_obs-payload", body)
	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("vault-a credential read vault-b receipt")
	}
	if strings.Contains(w.Body.String(), "vault-b-memory") || strings.Contains(w.Body.String(), mcpPayloadDigestB) {
		t.Fatalf("cross-vault receipt leaked data: %s", w.Body.String())
	}
}

func TestPayloadReceiptTool_RegisteredReadOnly(t *testing.T) {
	found := false
	for _, name := range registeredToolNames() {
		if name == "muninn_payload_receipt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("muninn_payload_receipt is not registered")
	}
	if !isReadOnlyTool("muninn_payload_receipt") || isMutatingTool("muninn_payload_receipt") {
		t.Fatal("muninn_payload_receipt must be classified only as read-only")
	}
	defined := false
	for _, tool := range allToolDefinitions() {
		if tool.Name == "muninn_payload_receipt" {
			defined = true
			break
		}
	}
	if !defined {
		t.Fatal("muninn_payload_receipt is not exposed by tools/list")
	}
}
