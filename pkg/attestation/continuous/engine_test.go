package continuous

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// recordingPublisher hands each verdict to a channel and keeps a copy.
type recordingPublisher struct {
	mu       sync.Mutex
	verdicts []Verdict
	ch       chan Verdict
}

func newRecordingPublisher(buffer int) *recordingPublisher {
	return &recordingPublisher{ch: make(chan Verdict, buffer)}
}

func (p *recordingPublisher) Publish(_ context.Context, v Verdict) {
	p.mu.Lock()
	p.verdicts = append(p.verdicts, v)
	p.mu.Unlock()
	p.ch <- v
}

func (p *recordingPublisher) all() []Verdict {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Verdict(nil), p.verdicts...)
}

// fakeTicker is a Ticker the test drives by hand.
type fakeTicker struct {
	ch      chan time.Time
	stopped bool
	mu      sync.Mutex
}

func (f *fakeTicker) C() <-chan time.Time { return f.ch }

func (f *fakeTicker) Stop() {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
}

// staticInventory lists fixed tenants and devices.
type staticInventory map[string][]string

func (s staticInventory) Tenants(context.Context) ([]string, error) {
	tenants := make([]string, 0, len(s))
	for tenant := range s {
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

func (s staticInventory) Devices(_ context.Context, tenant string) ([]string, error) {
	return s[tenant], nil
}

// failingInventory fails on the step named by failOn.
type failingInventory struct{ failOn string }

func (f failingInventory) Tenants(context.Context) ([]string, error) {
	if f.failOn == "tenants" {
		return nil, errors.New("inventory down")
	}
	return []string{"acme"}, nil
}

func (f failingInventory) Devices(context.Context, string) ([]string, error) {
	return nil, errors.New("devices down")
}

// errSource fails every collection.
type errSource struct{}

func (errSource) Collect(context.Context, string, string, []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return nil, errors.New("device unreachable")
}

// errAppraiser fails every appraisal call.
type errAppraiser struct{}

func (errAppraiser) AppraiseQuote(context.Context, string, *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return nil, errors.New("store unreachable")
}

func fixedClock() func() time.Time {
	var mu sync.Mutex
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		at = at.Add(time.Second)
		return at
	}
}

func newEngine(t *testing.T, w *world, cfg Config) *Engine {
	t.Helper()
	if cfg.Source == nil {
		cfg.Source = w.source
	}
	if cfg.Appraiser == nil {
		cfg.Appraiser = w.app
	}
	if cfg.Store == nil {
		cfg.Store = newTestStore(t)
	}
	if cfg.Now == nil {
		cfg.Now = fixedClock()
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestEngine_ReattestOnDemandPassAndFail(t *testing.T) {
	w := newWorld(t)
	pub := newRecordingPublisher(4)
	store := newTestStore(t)
	engine := newEngine(t, w, Config{Store: store, Publishers: []Publisher{pub}})
	ctx := context.Background()

	pass, err := engine.Reattest(ctx, w.tenant, "dev-good")
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if !pass.Verified || pass.Result == nil || !pass.Result.Verified || pass.Cause != "" {
		t.Fatalf("genuine evidence verdict = %+v, want verified", pass)
	}

	w.source.tamper("dev-bad")
	fail, err := engine.Reattest(ctx, w.tenant, "dev-bad")
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if fail.Verified || fail.Result == nil || fail.Result.Verified || fail.Cause == "" {
		t.Fatalf("tampered evidence verdict = %+v, want unverified with a cause", fail)
	}
	if fail.Tenant != w.tenant || fail.DeviceID != "dev-bad" || fail.At.IsZero() {
		t.Fatalf("verdict identity = %+v", fail)
	}

	latest, err := store.LatestVerdict(ctx, w.tenant, "dev-good")
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if !latest.Verified || !latest.At.Equal(pass.At) {
		t.Fatalf("stored verdict = %+v, want %+v", latest, pass)
	}
	if got := pub.all(); len(got) != 2 || got[0].DeviceID != "dev-good" || got[1].DeviceID != "dev-bad" {
		t.Fatalf("published = %+v, want both verdicts in order", got)
	}
}

func TestEngine_FreshNoncePerRun(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := engine.Reattest(ctx, w.tenant, "dev-1"); err != nil {
			t.Fatalf("Reattest %d: %v", i, err)
		}
	}
	nonces := w.source.noncesFor("dev-1")
	if len(nonces) != 2 {
		t.Fatalf("nonces = %d, want 2", len(nonces))
	}
	if len(nonces[0]) != NonceSize || bytes.Equal(nonces[0], nonces[1]) {
		t.Fatalf("nonces %x and %x are not two fresh %d-byte nonces", nonces[0], nonces[1], NonceSize)
	}
}

func TestEngine_CollectErrorIsAnUnverifiedVerdict(t *testing.T) {
	w := newWorld(t)
	pub := newRecordingPublisher(1)
	store := newTestStore(t)
	engine := newEngine(t, w, Config{Source: errSource{}, Store: store, Publishers: []Publisher{pub}})
	ctx := context.Background()

	v, err := engine.Reattest(ctx, w.tenant, "dev-1")
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if v.Verified || v.Result != nil || v.Cause == "" {
		t.Fatalf("verdict = %+v, want unverified with a collect cause", v)
	}
	stored, err := store.LatestVerdict(ctx, w.tenant, "dev-1")
	if err != nil || stored.Verified || stored.Cause != v.Cause {
		t.Fatalf("stored = %+v, %v; want the unverified verdict", stored, err)
	}
	if len(pub.all()) != 1 {
		t.Fatal("the unverified verdict was not published")
	}
}

func TestEngine_AppraisalErrorIsAnUnverifiedVerdict(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{Appraiser: errAppraiser{}})
	v, err := engine.Reattest(context.Background(), w.tenant, "dev-1")
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if v.Verified || v.Cause == "" {
		t.Fatalf("verdict = %+v, want unverified with an appraisal cause", v)
	}
}

func TestEngine_ReattestRefusesBadInput(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{})
	ctx := context.Background()
	if _, err := engine.Reattest(ctx, "", "dev-1"); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if _, err := engine.Reattest(ctx, w.tenant, ""); err == nil {
		t.Fatal("empty device accepted")
	}
}

func TestEngine_ReattestFailsWhenNoNonce(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{Rand: bytes.NewReader(nil)})
	if _, err := engine.Reattest(context.Background(), w.tenant, "dev-1"); err == nil {
		t.Fatal("Reattest without randomness succeeded")
	}
}

func TestEngine_RunVisitsEachDeviceOncePerTick(t *testing.T) {
	w := newWorld(t)
	inventory := staticInventory{"acme": {"dev-1", "dev-2"}, "globex": {"dev-3"}}
	pub := newRecordingPublisher(16)
	ticker := &fakeTicker{ch: make(chan time.Time)}
	var interval time.Duration
	engine := newEngine(t, w, Config{
		Inventory:  inventory,
		Publishers: []Publisher{pub},
		Interval:   time.Minute,
		NewTicker: func(d time.Duration) Ticker {
			interval = d
			return ticker
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()

	for pass := 1; pass <= 2; pass++ {
		ticker.ch <- time.Now()
		seen := map[string]int{}
		for i := 0; i < 3; i++ {
			v := <-pub.ch
			seen[v.Tenant+"/"+v.DeviceID]++
		}
		for _, key := range []string{"acme/dev-1", "acme/dev-2", "globex/dev-3"} {
			if seen[key] != 1 {
				t.Fatalf("pass %d visited %s %d times (%v)", pass, key, seen[key], seen)
			}
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if interval != time.Minute {
		t.Fatalf("ticker interval = %v, want 1m", interval)
	}
	ticker.mu.Lock()
	stopped := ticker.stopped
	ticker.mu.Unlock()
	if !stopped {
		t.Fatal("Run did not stop its ticker")
	}
	if n := len(w.source.noncesFor("dev-1")); n != 2 {
		t.Fatalf("dev-1 collected %d times over two passes, want 2", n)
	}
}

func TestEngine_PassReportsInventoryFailures(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for _, failOn := range []string{"tenants", "devices"} {
		engine := newEngine(t, w, Config{Inventory: failingInventory{failOn: failOn}, Interval: time.Minute})
		if err := engine.Pass(ctx); err == nil {
			t.Fatalf("Pass with %s failing succeeded", failOn)
		}
	}
}

func TestEngine_PassStopsOnCancel(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{Inventory: staticInventory{"acme": {"dev-1"}}, Interval: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Pass(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Pass = %v, want context.Canceled", err)
	}
}

func TestEngine_RunNeedsInventoryAndInterval(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{})
	if err := engine.Run(context.Background()); err == nil {
		t.Fatal("Run without an inventory and interval succeeded")
	}
}

func TestEngine_RunDefaultTicker(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{Inventory: staticInventory{}, Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
}

func TestNewEngine_RefusesIncompleteConfig(t *testing.T) {
	w := newWorld(t)
	store := newTestStore(t)
	for name, cfg := range map[string]Config{
		"source":    {Appraiser: w.app, Store: store},
		"appraiser": {Source: w.source, Store: store},
		"store":     {Source: w.source, Appraiser: w.app},
		"interval":  {Source: w.source, Appraiser: w.app, Store: store, Interval: -time.Second},
	} {
		if _, err := NewEngine(cfg); err == nil {
			t.Fatalf("NewEngine without a valid %s succeeded", name)
		} else {
			var ce *ConfigError
			if !errors.As(err, &ce) || ce.Error() == "" {
				t.Fatalf("NewEngine(%s) = %v, want a *ConfigError", name, err)
			}
		}
	}
}

// nilSource returns no evidence and no error.
type nilSource struct{}

func (nilSource) Collect(context.Context, string, string, []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return nil, nil
}

// absentAppraiser reports evidence absent, not forged.
type absentAppraiser struct{}

func (absentAppraiser) AppraiseQuote(context.Context, string, *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return &appraisal.AttestationResult{}, nil
}

func TestEngine_NoEvidenceAndAbsentEvidenceAreUnverified(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for name, cfg := range map[string]Config{
		"no evidence":     {Source: nilSource{}},
		"absent evidence": {Appraiser: absentAppraiser{}},
	} {
		v, err := newEngine(t, w, cfg).Reattest(ctx, w.tenant, "dev-1")
		if err != nil {
			t.Fatalf("%s: Reattest: %v", name, err)
		}
		if v.Verified || v.Cause == "" {
			t.Fatalf("%s: verdict = %+v, want unverified with a cause", name, v)
		}
	}
}

func TestEngine_RunReturnsAPassError(t *testing.T) {
	w := newWorld(t)
	ticker := &fakeTicker{ch: make(chan time.Time, 1)}
	engine := newEngine(t, w, Config{
		Inventory: failingInventory{failOn: "tenants"},
		Interval:  time.Minute,
		NewTicker: func(time.Duration) Ticker { return ticker },
	})
	ticker.ch <- time.Now()
	if err := engine.Run(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want the inventory failure", err)
	}
}

func TestEngine_PassStopsOnAReattestError(t *testing.T) {
	w := newWorld(t)
	engine := newEngine(t, w, Config{Inventory: staticInventory{"acme": {"bad device"}}, Interval: time.Minute})
	var ie *InputError
	if err := engine.Pass(context.Background()); !errors.As(err, &ie) {
		t.Fatalf("Pass = %v, want the device ID *InputError", err)
	}
}

func TestEngine_RunOnTheDefaultTicker(t *testing.T) {
	w := newWorld(t)
	pub := newRecordingPublisher(64)
	engine := newEngine(t, w, Config{
		Inventory:  staticInventory{"acme": {"dev-1"}},
		Interval:   time.Millisecond,
		Publishers: []Publisher{pub},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	if v := <-pub.ch; v.DeviceID != "dev-1" || !v.Verified {
		t.Fatalf("verdict = %+v, want dev-1 verified", v)
	}
	cancel()
	go func() {
		for range pub.ch {
		}
	}()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
}
