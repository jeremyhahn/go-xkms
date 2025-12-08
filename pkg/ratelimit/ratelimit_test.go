// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ratelimit

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestNew(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             10,
	}

	limiter := New(config)
	if limiter == nil {
		t.Fatal("Expected limiter to be created")
		return
	}

	if !limiter.enabled {
		t.Error("Expected limiter to be enabled")
	}

	stats := limiter.Stats()
	if stats["enabled"] != true {
		t.Error("Expected enabled to be true in stats")
	}

	limiter.Stop()
}

func TestAllow(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60, // 1 per second
		Burst:             5,
	}

	limiter := New(config)
	defer limiter.Stop()

	clientID := "test-client"

	// First 5 requests should succeed (burst)
	for i := 0; i < 5; i++ {
		if !limiter.Allow(clientID) {
			t.Errorf("Request %d should be allowed (burst)", i+1)
		}
	}

	// Next request should be denied (burst exhausted)
	if limiter.Allow(clientID) {
		t.Error("Request should be denied after burst exhausted")
	}

	// Wait for 1 second, 1 token should be available
	time.Sleep(1 * time.Second)
	if !limiter.Allow(clientID) {
		t.Error("Request should be allowed after waiting")
	}
}

func TestDisabledLimiter(t *testing.T) {
	config := &Config{
		Enabled:           false,
		RequestsPerMinute: 1,
	}

	limiter := New(config)

	clientID := "test-client"

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		if !limiter.Allow(clientID) {
			t.Error("Disabled limiter should allow all requests")
		}
	}
}

func TestPerClientLimiting(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             1,
	}

	limiter := New(config)
	defer limiter.Stop()

	client1 := "client-1"
	client2 := "client-2"

	// Exhaust client1's burst
	if !limiter.Allow(client1) {
		t.Error("First request for client1 should be allowed")
	}
	if limiter.Allow(client1) {
		t.Error("Second request for client1 should be denied")
	}

	// Client2 should still have budget
	if !limiter.Allow(client2) {
		t.Error("First request for client2 should be allowed")
	}
}

func TestCleanup(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		CleanupInterval:   100 * time.Millisecond,
		MaxIdle:           200 * time.Millisecond,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Create a limiter entry
	limiter.Allow("test-client")

	// Check it exists
	limiter.mu.RLock()
	if len(limiter.limiters) != 1 {
		t.Errorf("Expected 1 limiter, got %d", len(limiter.limiters))
	}
	limiter.mu.RUnlock()

	// Wait for cleanup
	time.Sleep(400 * time.Millisecond)

	// Check it was cleaned up
	limiter.mu.RLock()
	if len(limiter.limiters) != 0 {
		t.Errorf("Expected 0 limiters after cleanup, got %d", len(limiter.limiters))
	}
	limiter.mu.RUnlock()
}

func TestMiddleware(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := New(config)
	defer limiter.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(limiter)
	wrappedHandler := middleware(handler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", rr.Code)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "203.0.113.1"},
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.1",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestStats(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 120,
		Burst:             10,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Add some clients
	limiter.Allow("client-1")
	limiter.Allow("client-2")

	stats := limiter.Stats()

	if stats["enabled"] != true {
		t.Error("Expected enabled to be true")
	}

	if stats["active_clients"] != 2 {
		t.Errorf("Expected 2 active clients, got %v", stats["active_clients"])
	}

	if stats["rate_per_min"] != 120.0 {
		t.Errorf("Expected rate_per_min 120, got %v", stats["rate_per_min"])
	}

	if stats["burst"] != 10 {
		t.Errorf("Expected burst 10, got %v", stats["burst"])
	}
}

func TestWait(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             1,
	}

	limiter := New(config)
	defer limiter.Stop()

	clientID := "test-client"

	// First wait should succeed immediately
	if err := limiter.Wait(clientID); err != nil {
		t.Errorf("First wait should succeed: %v", err)
	}
}

func TestWait_Disabled(t *testing.T) {
	config := &Config{
		Enabled:           false,
		RequestsPerMinute: 1,
	}

	limiter := New(config)

	// Should return nil when disabled
	if err := limiter.Wait("test-client"); err != nil {
		t.Errorf("Wait should return nil when disabled: %v", err)
	}
}

func TestIsEnabled(t *testing.T) {
	// Test enabled
	enabledLimiter := New(&Config{Enabled: true, RequestsPerMinute: 60})
	defer enabledLimiter.Stop()
	if !enabledLimiter.IsEnabled() {
		t.Error("Expected IsEnabled to return true")
	}

	// Test disabled
	disabledLimiter := New(&Config{Enabled: false})
	if disabledLimiter.IsEnabled() {
		t.Error("Expected IsEnabled to return false")
	}
}

func TestNewWithNilConfig(t *testing.T) {
	limiter := New(nil)
	if limiter == nil {
		t.Fatal("Expected limiter to be created with nil config")
	}
	if limiter.IsEnabled() {
		t.Error("Expected limiter to be disabled with nil config")
	}
}

func TestAllowConn(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Create a mock connection using a pipe
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// First two requests should be allowed (burst)
	if !limiter.AllowConn(client) {
		t.Error("First request should be allowed")
	}
	if !limiter.AllowConn(client) {
		t.Error("Second request should be allowed")
	}

	// Third request should be denied (burst exhausted)
	if limiter.AllowConn(client) {
		t.Error("Third request should be denied")
	}
}

func TestAllowConn_Disabled(t *testing.T) {
	config := &Config{
		Enabled:           false,
		RequestsPerMinute: 1,
	}

	limiter := New(config)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		if !limiter.AllowConn(client) {
			t.Error("AllowConn should always return true when disabled")
		}
	}
}

func TestAllowConn_NilConn(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             5,
	}

	limiter := New(config)
	defer limiter.Stop()

	// Should handle nil connection gracefully
	if !limiter.AllowConn(nil) {
		t.Error("AllowConn with nil conn should still work (uses 'unknown' as client ID)")
	}
}

func TestGetClientIPFromConn(t *testing.T) {
	// Test nil connection
	ip := getClientIPFromConn(nil)
	if ip != "unknown" {
		t.Errorf("Expected 'unknown' for nil conn, got %s", ip)
	}

	// Test valid connection
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	ip = getClientIPFromConn(client)
	if ip == "" {
		t.Error("Expected non-empty IP from valid connection")
	}
}

func TestGetClientIPFromContext(t *testing.T) {
	// Test context without peer info
	ctx := context.Background()
	ip := getClientIPFromContext(ctx)
	if ip != "unknown" {
		t.Errorf("Expected 'unknown' for context without peer, got %s", ip)
	}

	// Test context with peer info
	addr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:1234")
	peerInfo := &peer.Peer{Addr: addr}
	ctxWithPeer := peer.NewContext(context.Background(), peerInfo)

	ip = getClientIPFromContext(ctxWithPeer)
	if ip != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got %s", ip)
	}
}

func TestGetClientIPFromContext_NilAddr(t *testing.T) {
	peerInfo := &peer.Peer{Addr: nil}
	ctxWithPeer := peer.NewContext(context.Background(), peerInfo)

	ip := getClientIPFromContext(ctxWithPeer)
	if ip != "unknown" {
		t.Errorf("Expected 'unknown' for nil addr, got %s", ip)
	}
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestUnaryServerInterceptor(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := New(config)
	defer limiter.Stop()

	interceptor := UnaryServerInterceptor(limiter)

	// Create a context with peer info
	addr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:1234")
	peerInfo := &peer.Peer{Addr: addr}
	ctx := peer.NewContext(context.Background(), peerInfo)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	// First two requests should succeed (burst)
	for i := 0; i < 2; i++ {
		resp, err := interceptor(ctx, nil, nil, handler)
		if err != nil {
			t.Errorf("Request %d should succeed: %v", i+1, err)
		}
		if resp != "response" {
			t.Errorf("Expected 'response', got %v", resp)
		}
	}

	// Third request should be rate limited
	_, err := interceptor(ctx, nil, nil, handler)
	if err == nil {
		t.Error("Expected rate limit error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("Expected ResourceExhausted, got %v", st.Code())
	}
}

func TestStreamServerInterceptor(t *testing.T) {
	config := &Config{
		Enabled:           true,
		RequestsPerMinute: 60,
		Burst:             2,
	}

	limiter := New(config)
	defer limiter.Stop()

	interceptor := StreamServerInterceptor(limiter)

	// Create a context with peer info
	addr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:1234")
	peerInfo := &peer.Peer{Addr: addr}
	ctx := peer.NewContext(context.Background(), peerInfo)

	mockStream := &mockServerStream{ctx: ctx}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	// First two requests should succeed (burst)
	for i := 0; i < 2; i++ {
		err := interceptor(nil, mockStream, nil, handler)
		if err != nil {
			t.Errorf("Request %d should succeed: %v", i+1, err)
		}
	}

	// Third request should be rate limited
	err := interceptor(nil, mockStream, nil, handler)
	if err == nil {
		t.Error("Expected rate limit error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("Expected ResourceExhausted, got %v", st.Code())
	}
}

func TestGetClientIP_SingleXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.RemoteAddr = "192.168.1.1:1234"

	ip := getClientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("Expected '203.0.113.1', got '%s'", ip)
	}
}
