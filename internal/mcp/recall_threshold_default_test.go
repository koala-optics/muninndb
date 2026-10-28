package mcp

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/transport/mbp"
)

// thresholdCapturingEngine records the Threshold from the last ActivateRequest.
type thresholdCapturingEngine struct {
	fakeEngine
	lastThreshold float32
}

func (e *thresholdCapturingEngine) Activate(_ context.Context, req *mbp.ActivateRequest) (*mbp.ActivateResponse, error) {
	e.lastThreshold = req.Threshold
	return &mbp.ActivateResponse{}, nil
}

// TestHandleRecall_Threshold_EngineDefault verifies that a recall without a
// threshold arg leaves Threshold at 0 so the engine applies the vault
// recall-mode preset or its 0.1 default, while explicit args and mode presets
// still win.
func TestHandleRecall_Threshold_EngineDefault(t *testing.T) {
	cases := []struct {
		name string
		args string
		want float32
	}{
		{"no threshold, no mode", `"context":["d2c"]`, 0},
		{"balanced mode, no threshold", `"context":["d2c"],"mode":"balanced"`, 0},
		{"explicit threshold", `"context":["d2c"],"threshold":0.3`, 0.3},
		{"semantic preset", `"context":["d2c"],"mode":"semantic"`, 0.3},
		{"explicit threshold beats preset", `"context":["d2c"],"mode":"semantic","threshold":0.7`, 0.7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := &thresholdCapturingEngine{lastThreshold: -1}
			srv := newTestServerWith(eng)
			body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"muninn_recall","arguments":{"vault":"default",` + tc.args + `}}}`
			w := postRPC(t, srv, body)
			if resp := decodeResp(t, w.Body.String()); resp.Error != nil {
				t.Fatalf("unexpected error: %v", resp.Error)
			}
			if eng.lastThreshold != tc.want {
				t.Errorf("Threshold = %v, want %v", eng.lastThreshold, tc.want)
			}
		})
	}
}
