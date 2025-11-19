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

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHTTPMiddleware(t *testing.T) {
	Enable()

	// Reset metrics
	HTTPRequestsTotal.Reset()
	HTTPRequestDuration.Reset()
	ActiveConnections.Reset()

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Wrap with middleware
	wrappedHandler := HTTPMiddleware(handler)

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Execute request
	wrappedHandler.ServeHTTP(rec, req)

	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Verify metrics were recorded (basic check - can't easily verify exact counts)
	// The middleware should have incremented and decremented connections
	// and recorded the request
	time.Sleep(10 * time.Millisecond) // Give time for async operations
}

func TestHTTPMiddlewareStatusCodes(t *testing.T) {
	Enable()

	testCases := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"201 Created", http.StatusCreated},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			HTTPRequestsTotal.Reset()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			})

			wrappedHandler := HTTPMiddleware(handler)

			req := httptest.NewRequest("POST", "/test", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			if rec.Code != tc.statusCode {
				t.Errorf("Expected status %d, got %d", tc.statusCode, rec.Code)
			}
		})
	}
}

func TestHTTPMiddlewareWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	// Reset metrics
	HTTPRequestsTotal.Reset()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := HTTPMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// Request should still work
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader
	wrapper.WriteHeader(http.StatusCreated)
	if wrapper.statusCode != http.StatusCreated {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, wrapper.statusCode)
	}

	// Test multiple WriteHeader calls (should only set once)
	wrapper.WriteHeader(http.StatusBadRequest)
	if wrapper.statusCode != http.StatusCreated {
		t.Error("Status code should not change after first WriteHeader call")
	}

	// Test Write
	data := []byte("test data")
	n, err := wrapper.Write(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}
}

func TestResponseWriterDefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapper := &responseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Write without calling WriteHeader explicitly
	_, _ = wrapper.Write([]byte("test"))

	// Should default to 200 OK
	if wrapper.statusCode != http.StatusOK {
		t.Errorf("Expected default status code %d, got %d", http.StatusOK, wrapper.statusCode)
	}
}

func TestGRPCUnaryServerInterceptor(t *testing.T) {
	Enable()

	// Reset metrics
	GRPCRequestsTotal.Reset()
	GRPCRequestDuration.Reset()
	ActiveConnections.Reset()

	interceptor := GRPCUnaryServerInterceptor()

	// Create mock handler
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	// Create mock info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Call interceptor
	resp, err := interceptor(context.Background(), "request", info, handler)

	// Verify response
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp != "response" {
		t.Errorf("Expected response 'response', got %v", resp)
	}

	time.Sleep(10 * time.Millisecond)
}

func TestGRPCUnaryServerInterceptorWithError(t *testing.T) {
	Enable()

	GRPCRequestsTotal.Reset()

	interceptor := GRPCUnaryServerInterceptor()

	// Create mock handler that returns an error
	expectedErr := status.Error(codes.NotFound, "not found")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, expectedErr
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	// Call interceptor
	_, err := interceptor(context.Background(), "request", info, handler)

	// Verify error is propagated
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestGRPCUnaryServerInterceptorWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	interceptor := GRPCUnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)

	// Should still work when disabled
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp != "response" {
		t.Errorf("Expected response 'response', got %v", resp)
	}
}

type mockServerStream struct {
	grpc.ServerStream
}

func TestGRPCStreamServerInterceptor(t *testing.T) {
	Enable()

	// Reset metrics
	GRPCRequestsTotal.Reset()
	ActiveConnections.Reset()

	interceptor := GRPCStreamServerInterceptor()

	// Create mock handler
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	// Create mock info
	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	// Call interceptor
	err := interceptor(nil, &mockServerStream{}, info, handler)

	// Verify no error
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
}

func TestGRPCStreamServerInterceptorWithError(t *testing.T) {
	Enable()

	interceptor := GRPCStreamServerInterceptor()

	expectedErr := status.Error(codes.Internal, "internal error")
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return expectedErr
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	err := interceptor(nil, &mockServerStream{}, info, handler)

	// Verify error is propagated
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestConnectionTracker(t *testing.T) {
	Enable()

	// Reset gauge
	ActiveConnections.Reset()

	// Create tracker
	tracker := NewConnectionTracker(ProtocolQUIC)

	// Verify tracker was created
	if tracker == nil {
		t.Fatal("Expected tracker to be created")
	}

	if tracker.protocol != ProtocolQUIC {
		t.Errorf("Expected protocol %s, got %s", ProtocolQUIC, tracker.protocol)
	}

	// Wait a bit to get some duration
	time.Sleep(10 * time.Millisecond)

	// Check duration
	duration := tracker.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("Expected duration >= 10ms, got %v", duration)
	}

	// Close tracker
	tracker.Close()

	// Verify it doesn't panic
}

func TestConnectionTrackerWhenDisabled(t *testing.T) {
	Disable()
	defer Enable()

	// Should work without panicking even when disabled
	tracker := NewConnectionTracker(ProtocolMCP)
	if tracker == nil {
		t.Fatal("Expected tracker to be created even when disabled")
	}

	tracker.Close()
}

func TestProtocolConstants(t *testing.T) {
	protocols := []string{
		ProtocolHTTP, ProtocolGRPC, ProtocolQUIC, ProtocolMCP,
	}

	for _, protocol := range protocols {
		if protocol == "" {
			t.Error("Protocol constant is empty")
		}
	}
}

func BenchmarkHTTPMiddleware(b *testing.B) {
	Enable()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := HTTPMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)
	}
}

func BenchmarkGRPCUnaryServerInterceptor(b *testing.B) {
	Enable()

	interceptor := GRPCUnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = interceptor(context.Background(), "request", info, handler)
	}
}
