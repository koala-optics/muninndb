package plugin

import (
	"context"
	"errors"
	"testing"
)

// cancellingEmbedPlugin simulates a shutdown arriving mid-inference: Embed
// cancels the processor's context and fails with the context error, as a
// provider does when its request is aborted.
type cancellingEmbedPlugin struct {
	mockPlugin
	cancel context.CancelFunc
}

func (p *cancellingEmbedPlugin) Embed(ctx context.Context, _ []string) ([]float32, error) {
	p.cancel()
	return nil, ctx.Err()
}
func (p *cancellingEmbedPlugin) Dimension() int    { return 384 }
func (p *cancellingEmbedPlugin) MaxBatchSize() int { return 1 }

// failingEmbedPlugin fails inference with a provider error while the context is live.
type failingEmbedPlugin struct {
	mockPlugin
}

func (p *failingEmbedPlugin) Embed(context.Context, []string) ([]float32, error) {
	return nil, errors.New("provider rejected input")
}
func (p *failingEmbedPlugin) Dimension() int    { return 384 }
func (p *failingEmbedPlugin) MaxBatchSize() int { return 1 }

// TestRetroactiveProcessor_CancelledEmbedLeavesBatchPending pins that a batch
// whose inference is aborted by shutdown is left pending, not flagged
// DigestEmbedFailed (which would exclude it from every later scan).
func TestRetroactiveProcessor_CancelledEmbedLeavesBatchPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &mockPluginStore{
		countResult: 1,
		scanResult:  &mockIterator{engrams: []*Engram{{Concept: "c", Content: "d"}}},
	}
	p := &cancellingEmbedPlugin{mockPlugin: mockPlugin{name: "embed-cancel", tier: TierEmbed}, cancel: cancel}
	rp := NewRetroactiveProcessor(store, p, DigestEmbed)

	if ok := rp.processBatch(ctx); !ok {
		t.Error("processBatch should return true")
	}
	if len(store.setFlags) != 0 {
		t.Errorf("cancelled batch must stay pending (no digest flags), flags set: %v", store.setFlags)
	}
	if store.updateEmbedCalls != 0 {
		t.Errorf("expected no embedding writes for a cancelled batch, got %d", store.updateEmbedCalls)
	}
}

// TestRetroactiveProcessor_EmbedProviderErrorFlagsFailed pins that a genuine
// provider failure (context still live) is still flagged DigestEmbedFailed.
func TestRetroactiveProcessor_EmbedProviderErrorFlagsFailed(t *testing.T) {
	store := &mockPluginStore{
		countResult: 1,
		scanResult:  &mockIterator{engrams: []*Engram{{Concept: "c", Content: "d"}}},
	}
	p := &failingEmbedPlugin{mockPlugin: mockPlugin{name: "embed-fail", tier: TierEmbed}}
	rp := NewRetroactiveProcessor(store, p, DigestEmbed)

	if ok := rp.processBatch(context.Background()); !ok {
		t.Error("processBatch should return true")
	}
	if len(store.setFlags) != 1 || store.setFlags[0] != DigestEmbedFailed {
		t.Errorf("expected exactly DigestEmbedFailed, got %v", store.setFlags)
	}
}
