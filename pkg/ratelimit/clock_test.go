// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ratelimit

// The cases in this file moved here from test/integration/ratelimit (#1607):
// they drive the Limiter through an injected clock instead of sleeping, so
// token refill and idle cleanup are exact and instant.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock, safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newClocked returns a Limiter for config whose clock is a fresh fakeClock.
// CleanupInterval defaults to an hour so the cleanup worker never ticks
// during a test; tests call cleanup directly.
func newClocked(t *testing.T, config *Config) (*Limiter, *fakeClock) {
	t.Helper()
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Hour
	}
	clk := newFakeClock()
	l := New(config)
	l.now = clk.Now
	t.Cleanup(l.Stop)
	return l, clk
}

func TestClock_BurstThenRefill(t *testing.T) {
	limiter, clk := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 5})

	for i := 0; i < 5; i++ {
		if !limiter.Allow("test-client") {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	if limiter.Allow("test-client") {
		t.Fatal("request 6 allowed past the burst")
	}

	clk.Advance(1100 * time.Millisecond)
	if !limiter.Allow("test-client") {
		t.Fatal("request refused after one token refilled")
	}
}

func TestClock_HalfSecondRefill(t *testing.T) {
	limiter, clk := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 120, Burst: 1})

	if !limiter.Allow("wait-client") {
		t.Fatal("first request refused")
	}
	if limiter.Allow("wait-client") {
		t.Fatal("second request allowed with no token")
	}
	clk.Advance(400 * time.Millisecond)
	if limiter.Allow("wait-client") {
		t.Fatal("request allowed before the 500 ms refill")
	}
	clk.Advance(200 * time.Millisecond)
	if !limiter.Allow("wait-client") {
		t.Fatal("request refused after the 500 ms refill")
	}
}

func TestClock_TimeBasedRefill(t *testing.T) {
	limiter, clk := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 1})

	if !limiter.Allow("time-test-client") {
		t.Fatal("initial token refused")
	}
	if limiter.Allow("time-test-client") {
		t.Fatal("allowed with an empty bucket")
	}
	clk.Advance(1100 * time.Millisecond)
	if !limiter.Allow("time-test-client") {
		t.Fatal("refilled token refused")
	}
	if limiter.Allow("time-test-client") {
		t.Fatal("allowed again before the next refill")
	}
}

func TestClock_IdleClientCleanup(t *testing.T) {
	limiter, clk := newClocked(t, &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		MaxIdle:           200 * time.Millisecond,
	})

	limiter.Allow("transient-client")
	if got := limiter.Stats()["active_clients"]; got != 1 {
		t.Fatalf("active_clients = %v, want 1", got)
	}

	clk.Advance(200 * time.Millisecond)
	limiter.cleanup()
	if got := limiter.Stats()["active_clients"]; got != 1 {
		t.Fatalf("client removed at exactly MaxIdle: active_clients = %v", got)
	}

	clk.Advance(time.Millisecond)
	limiter.cleanup()
	if got := limiter.Stats()["active_clients"]; got != 0 {
		t.Fatalf("idle client kept: active_clients = %v, want 0", got)
	}
}

func TestClock_CleanupKeepsActiveClient(t *testing.T) {
	limiter, clk := newClocked(t, &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		MaxIdle:           200 * time.Millisecond,
	})

	limiter.Allow("idle")
	clk.Advance(150 * time.Millisecond)
	limiter.Allow("active")
	clk.Advance(100 * time.Millisecond)
	limiter.cleanup()

	limiter.mu.RLock()
	defer limiter.mu.RUnlock()
	if _, ok := limiter.limiters["idle"]; ok {
		t.Error("idle client kept")
	}
	if _, ok := limiter.limiters["active"]; !ok {
		t.Error("active client removed")
	}
}

func TestClock_DisabledAllowsAll(t *testing.T) {
	limiter := New(&Config{Enabled: false, RequestsPerMinute: 60})
	defer limiter.Stop()

	for i := 0; i < 100; i++ {
		if !limiter.Allow("test-client") {
			t.Fatal("disabled limiter refused a request")
		}
	}
}

func TestClock_IndependentClients(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 2})

	for _, c := range []string{"client-1", "client-2"} {
		if !limiter.Allow(c) || !limiter.Allow(c) {
			t.Fatalf("%s refused inside its burst", c)
		}
		if limiter.Allow(c) {
			t.Fatalf("%s allowed past its burst", c)
		}
	}
}

func TestClock_StatsAcrossClients(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 5})

	for i := 0; i < 10; i++ {
		limiter.Allow(fmt.Sprintf("client-%d", i))
	}

	stats := limiter.Stats()
	if stats["enabled"] != true {
		t.Error("enabled = false")
	}
	if stats["active_clients"] != 10 {
		t.Errorf("active_clients = %v, want 10", stats["active_clients"])
	}
	if stats["rate_per_min"] != 60.0 {
		t.Errorf("rate_per_min = %v, want 60", stats["rate_per_min"])
	}
	if stats["burst"] != 5 {
		t.Errorf("burst = %v, want 5", stats["burst"])
	}
}

func TestClock_MiddlewareBurstThen429(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 120, Burst: 2})
	handler := Middleware(limiter, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "success")
	}))

	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("request %d: status %d, want %d", i+1, w.Code, want)
		}
	}
}

// serveStatus sends one GET through handler and returns the status code.
func serveStatus(handler http.Handler, remoteAddr string, header map[string]string) int {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

func TestClock_TrustedProxyForwardingHeaders(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	proxies, err := ParseTrustedProxies([]string{"192.168.1.1"})
	if err != nil {
		t.Fatal(err)
	}

	for _, header := range []map[string]string{
		{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"},
		{"X-Real-IP": "10.0.0.5"},
	} {
		limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 1})
		handler := Middleware(limiter, proxies)(ok)
		if got := serveStatus(handler, "192.168.1.1:12345", header); got != http.StatusOK {
			t.Errorf("%v: first request status %d, want 200", header, got)
		}
		if got := serveStatus(handler, "192.168.1.1:12345", header); got != http.StatusTooManyRequests {
			t.Errorf("%v: second request status %d, want 429", header, got)
		}
	}
}

// TestClock_UntrustedForwardedFor proves a peer that is not a trusted proxy
// cannot escape its bucket by rotating X-Forwarded-For or by opening a new
// connection (a new source port).
func TestClock_UntrustedForwardedFor(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: 1})
	handler := Middleware(limiter, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i, tc := range []struct {
		remoteAddr, xff string
		want            int
	}{
		{"192.168.1.1:12345", "10.0.0.1", http.StatusOK},
		{"192.168.1.1:12345", "10.0.0.2", http.StatusTooManyRequests},
		{"192.168.1.1:23456", "", http.StatusTooManyRequests},
	} {
		header := map[string]string{}
		if tc.xff != "" {
			header["X-Forwarded-For"] = tc.xff
		}
		if got := serveStatus(handler, tc.remoteAddr, header); got != tc.want {
			t.Errorf("request %d: status %d, want %d", i, got, tc.want)
		}
	}
}

func TestClock_ConcurrentClients(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 600, Burst: 5})

	const clients, perClient = 10, 10
	var allowed, denied atomic.Int32
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(cid string) {
			defer wg.Done()
			for j := 0; j < perClient; j++ {
				if limiter.Allow(cid) {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}(fmt.Sprintf("client-%d", i))
	}
	wg.Wait()

	// The clock stands still, so each client gets exactly its burst.
	if got := allowed.Load(); got != clients*5 {
		t.Errorf("allowed = %d, want %d", got, clients*5)
	}
	if got := denied.Load(); got != clients*(perClient-5) {
		t.Errorf("denied = %d, want %d", got, clients*(perClient-5))
	}
}

func TestClock_HighLoad(t *testing.T) {
	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 6000, Burst: 100})

	const clients, perClient = 100, 50
	var allowed atomic.Int32
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(cid string) {
			defer wg.Done()
			for j := 0; j < perClient; j++ {
				if limiter.Allow(cid) {
					allowed.Add(1)
				}
			}
		}(fmt.Sprintf("high-load-client-%d", i))
	}
	wg.Wait()

	if got := allowed.Load(); got != clients*perClient {
		t.Errorf("allowed = %d, want %d (every request inside the burst)", got, clients*perClient)
	}
}

func TestClock_BurstSizes(t *testing.T) {
	for _, burst := range []int{1, 10, 100} {
		t.Run(fmt.Sprintf("burst=%d", burst), func(t *testing.T) {
			limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 60, Burst: burst})
			for i := 0; i < burst; i++ {
				if !limiter.Allow("burst-test-client") {
					t.Fatalf("request %d refused inside the burst", i+1)
				}
			}
			if limiter.Allow("burst-test-client") {
				t.Fatal("request allowed past the burst")
			}
		})
	}
}

func TestClock_Defaults(t *testing.T) {
	for name, config := range map[string]*Config{"nil": nil, "empty": {}} {
		limiter := New(config)
		if limiter.Stats()["enabled"] != false {
			t.Errorf("%s config: limiter enabled", name)
		}
		limiter.Stop()
	}

	limiter, _ := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 120})
	if got := limiter.Stats()["burst"]; got != 120 {
		t.Errorf("burst = %v, want RequestsPerMinute (120)", got)
	}
}

// TestClock_HTTPServerClients drives three clients through a real HTTP
// server, each sending a request every 100 ms of clock time: the burst of 5
// is spent, then the 2/s refill admits one request in five.
func TestClock_HTTPServerClients(t *testing.T) {
	limiter, clk := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 120, Burst: 5})
	// The test clients reach the server over loopback, standing in for a
	// trusted reverse proxy that names each client in X-Forwarded-For.
	proxies, err := ParseTrustedProxies([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Middleware(limiter, proxies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})))
	defer server.Close()

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	success := map[string]int{}
	limited := map[string]int{}
	client := &http.Client{Timeout: 5 * time.Second}
	for j := 0; j < 10; j++ {
		for _, ip := range ips {
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-For", ip)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				success[ip]++
			case http.StatusTooManyRequests:
				limited[ip]++
			default:
				t.Fatalf("%s: status %d", ip, resp.StatusCode)
			}
		}
		clk.Advance(100 * time.Millisecond)
	}

	for _, ip := range ips {
		// 5 burst tokens plus 0.2 per step over 9 steps (6.8): 6 admitted,
		// or 5 if float rounding leaves the sixth token just short of 1.
		if success[ip] < 5 || success[ip] > 6 || success[ip]+limited[ip] != 10 {
			t.Errorf("%s: %d allowed, %d limited; want 5-6 of 10 allowed", ip, success[ip], limited[ip])
		}
	}
}

func TestClock_StopThenStats(t *testing.T) {
	limiter := New(&Config{Enabled: true, RequestsPerMinute: 60, CleanupInterval: 100 * time.Millisecond})
	limiter.Allow("client-1")
	limiter.Allow("client-2")
	limiter.Stop()

	if got := limiter.Stats()["active_clients"]; got != 2 {
		t.Errorf("active_clients after Stop = %v, want 2", got)
	}
}

func TestClock_ZeroRate(t *testing.T) {
	limiter, clk := newClocked(t, &Config{Enabled: true, RequestsPerMinute: 0, Burst: 0})

	for i := 0; i < 10; i++ {
		if limiter.Allow("client") {
			t.Fatal("zero-rate limiter allowed a request")
		}
		clk.Advance(time.Hour)
	}
}
