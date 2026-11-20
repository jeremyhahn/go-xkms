package continuous

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// Ruling 1003 (2): go-xkms does not reach devices or own a device registry.
// The composing product (go-trusted-platform, through the go-quicbaas SDK)
// supplies the evidence fetcher (EvidenceSource) and the device lister
// (Inventory). The types below stand in for that product.

// callerInventory is a caller-owned device registry.
type callerInventory map[string][]string

func (c callerInventory) Tenants(context.Context) ([]string, error) {
	out := make([]string, 0, len(c))
	for tenant := range c {
		out = append(out, tenant)
	}
	return out, nil
}

func (c callerInventory) Devices(_ context.Context, tenant string) ([]string, error) {
	return append([]string(nil), c[tenant]...), nil
}

// callerFetcher is a caller-owned evidence fetcher; it records each fetch.
type callerFetcher struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *callerFetcher) Collect(_ context.Context, tenant, deviceID string, nonce []byte) (*appraisal.AppraiseQuoteRequest, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("fetcher got no verifier nonce")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[tenant+"/"+deviceID]++
	return &appraisal.AppraiseQuoteRequest{}, nil
}

func (f *callerFetcher) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

// acceptingAppraiser verifies any evidence that carries the issued nonce.
type acceptingAppraiser struct{}

func (acceptingAppraiser) AppraiseQuote(_ context.Context, _ string, req *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	if len(req.Nonce) != NonceSize {
		return nil, errors.New("no issued nonce")
	}
	return &appraisal.AttestationResult{Verified: true}, nil
}

// chanPublisher forwards verdicts to a channel, dropping them once it is
// full so a pass never blocks after the test stops reading.
type chanPublisher chan Verdict

func (c chanPublisher) Publish(_ context.Context, v Verdict) {
	select {
	case c <- v:
	default:
	}
}

func TestEngine_RunsThroughCallerSuppliedFetcherAndLister(t *testing.T) {
	inventory := callerInventory{
		"tenant-a": {"dev-1", "dev-2"},
		"tenant-b": {"dev-3"},
	}
	fetcher := &callerFetcher{calls: map[string]int{}}
	published := make(chanPublisher, 256)
	store := newTestStore(t)
	engine, err := NewEngine(Config{
		Source:     fetcher,
		Appraiser:  acceptingAppraiser{},
		Store:      store,
		Publishers: []Publisher{published},
		Inventory:  inventory,
		Interval:   5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()

	want := map[string]bool{"tenant-a/dev-1": true, "tenant-a/dev-2": true, "tenant-b/dev-3": true}
	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for len(seen) < len(want) {
		select {
		case v := <-published:
			key := v.Tenant + "/" + v.DeviceID
			if !want[key] {
				t.Fatalf("verdict for unlisted device %q", key)
			}
			if !v.Verified || v.Cause != "" {
				t.Fatalf("scheduled verdict = %+v, want verified", v)
			}
			seen[key] = true
		case err := <-done:
			t.Fatalf("Run returned early: %v", err)
		case <-deadline:
			t.Fatalf("scheduled verdicts seen = %v, want %v", seen, want)
		}
	}

	before := fetcher.count("tenant-b/dev-3")
	onDemand, err := engine.Reattest(ctx, "tenant-b", "dev-3")
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if !onDemand.Verified || onDemand.Tenant != "tenant-b" || onDemand.DeviceID != "dev-3" {
		t.Fatalf("on-demand verdict = %+v, want verified for tenant-b/dev-3", onDemand)
	}
	if after := fetcher.count("tenant-b/dev-3"); after <= before {
		t.Fatalf("on-demand re-attestation fetched %d times, want more than %d", after, before)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop when ctx was cancelled")
	}

	for key := range want {
		if fetcher.count(key) == 0 {
			t.Fatalf("fetcher never called for %s", key)
		}
	}
	for tenant, devices := range inventory {
		for _, deviceID := range devices {
			v, err := store.LatestVerdict(context.Background(), tenant, deviceID)
			if err != nil {
				t.Fatalf("LatestVerdict(%s/%s): %v", tenant, deviceID, err)
			}
			if !v.Verified {
				t.Fatalf("stored verdict for %s/%s = %+v, want verified", tenant, deviceID, v)
			}
		}
	}
}
