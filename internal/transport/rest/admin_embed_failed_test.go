package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockEngineWithFailedEmbeds adds the optional embed-failure extensions.
type mockEngineWithFailedEmbeds struct {
	mockEngineWithStats
	failed  int64
	retried int
}

func (m *mockEngineWithFailedEmbeds) CountEmbedFailed(ctx context.Context) int64 { return m.failed }

func (m *mockEngineWithFailedEmbeds) RetryFailedEmbeds(ctx context.Context) (int, error) {
	m.retried++
	return int(m.failed), nil
}

func newEmbedTestServer(eng EngineAPI) *Server {
	return NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{Provider: "ollama", Model: "nomic"}, EnrichInfo{}, nil, "", nil)
}

func TestHandleEmbedStatus_FailedCount(t *testing.T) {
	cases := []struct {
		name string
		eng  EngineAPI
		want int64
	}{
		{"supported", &mockEngineWithFailedEmbeds{mockEngineWithStats: mockEngineWithStats{embeddedCount: 90, totalCount: 100}, failed: 7}, 7},
		{"unsupported", &mockEngineWithStats{embeddedCount: 90, totalCount: 100}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newEmbedTestServer(tc.eng).mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/embed/status", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			var resp EmbedStatusResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.FailedCount != tc.want {
				t.Errorf("failed_count = %d, want %d", resp.FailedCount, tc.want)
			}
		})
	}
}

func TestHandleRetryFailedEmbeds(t *testing.T) {
	eng := &mockEngineWithFailedEmbeds{failed: 7}
	w := httptest.NewRecorder()
	newEmbedTestServer(eng).mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/embed/retry-failed", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]int
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["requeued"] != 7 || eng.retried != 1 {
		t.Errorf("requeued = %d (retried %d times), want 7 (once)", resp["requeued"], eng.retried)
	}

	w = httptest.NewRecorder()
	newEmbedTestServer(&mockEngineWithStats{}).mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/embed/retry-failed", nil))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("unsupported engine: expected 501, got %d", w.Code)
	}
}
