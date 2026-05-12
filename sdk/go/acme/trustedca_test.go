// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package trustedca

import (
	"crypto/tls"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// =============================================================================
// NewClient Tests
// =============================================================================

func TestNewClient_EmptyAddressNonEmbedded(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("expected error for empty address with non-embedded transport")
	}
	if !errors.IsInvalidInput(err) {
		t.Fatalf("expected invalid input error, got: %v", err)
	}
}

func TestNewClient_WithEmbedded_NilService(t *testing.T) {
	_, err := NewClient("", WithEmbedded(nil))
	if err == nil {
		t.Fatal("expected error for nil embedded service")
	}
	if !errors.IsInvalidInput(err) {
		t.Fatalf("expected invalid input error, got: %v", err)
	}
}

func TestNewClient_AutoDetectUnixSocket(t *testing.T) {
	// This should auto-detect unix socket from the leading /
	// Note: actual connection will fail since socket doesn't exist
	// but we're testing address parsing
	parsed := parseAddressForTest("/var/run/trusted-ca.sock")
	if parsed != "unix" {
		t.Fatalf("expected unix type for /var/run/trusted-ca.sock, got: %s", parsed)
	}
}

func TestNewClient_AutoDetectHTTPS(t *testing.T) {
	// Should auto-detect REST transport from https:// prefix
	opts := defaultOptions()
	applyHTTPDetection("https://ca.example.com:8443", opts)
	if opts.transportType != TransportREST {
		t.Fatalf("expected REST transport for https URL, got: %v", opts.transportType)
	}
}

func TestNewClient_AutoDetectHTTP(t *testing.T) {
	opts := defaultOptions()
	applyHTTPDetection("http://localhost:8080", opts)
	if opts.transportType != TransportREST {
		t.Fatalf("expected REST transport for http URL, got: %v", opts.transportType)
	}
}

func TestNewClient_TCPAddress(t *testing.T) {
	parsed := parseAddressForTest("localhost:9443")
	if parsed != "tcp" {
		t.Fatalf("expected tcp type for localhost:9443, got: %s", parsed)
	}
}

// =============================================================================
// Option Tests
// =============================================================================

func TestWithTimeout_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithTimeout(5 * time.Second)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.timeout != 5*time.Second {
		t.Fatalf("expected timeout 5s, got: %v", opts.timeout)
	}
}

func TestWithTimeout_Invalid(t *testing.T) {
	opts := defaultOptions()
	err := WithTimeout(0)(opts)
	if err == nil {
		t.Fatal("expected error for zero timeout")
	}
	if !errors.IsInvalidInput(err) {
		t.Fatalf("expected invalid input error, got: %v", err)
	}
}

func TestWithTimeout_Negative(t *testing.T) {
	opts := defaultOptions()
	err := WithTimeout(-1 * time.Second)(opts)
	if err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestWithKeepalive_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithKeepalive(15*time.Second, 10*time.Second)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.keepaliveTime != 15*time.Second {
		t.Fatalf("expected keepalive time 15s, got: %v", opts.keepaliveTime)
	}
	if opts.keepaliveTimeout != 10*time.Second {
		t.Fatalf("expected keepalive timeout 10s, got: %v", opts.keepaliveTimeout)
	}
}

func TestWithKeepalive_InvalidTime(t *testing.T) {
	opts := defaultOptions()
	err := WithKeepalive(0, 10*time.Second)(opts)
	if err == nil {
		t.Fatal("expected error for zero keepalive time")
	}
}

func TestWithKeepalive_InvalidTimeout(t *testing.T) {
	opts := defaultOptions()
	err := WithKeepalive(10*time.Second, 0)(opts)
	if err == nil {
		t.Fatal("expected error for zero keepalive timeout")
	}
}

func TestWithRetry_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithRetry(5, 200*time.Millisecond)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.maxRetries != 5 {
		t.Fatalf("expected maxRetries 5, got: %d", opts.maxRetries)
	}
	if opts.retryBackoff != 200*time.Millisecond {
		t.Fatalf("expected retryBackoff 200ms, got: %v", opts.retryBackoff)
	}
}

func TestWithRetry_InvalidMaxRetries(t *testing.T) {
	opts := defaultOptions()
	err := WithRetry(-1, 100*time.Millisecond)(opts)
	if err == nil {
		t.Fatal("expected error for negative maxRetries")
	}
}

func TestWithRetry_InvalidBackoff(t *testing.T) {
	opts := defaultOptions()
	err := WithRetry(3, -1*time.Millisecond)(opts)
	if err == nil {
		t.Fatal("expected error for negative backoff")
	}
}

func TestWithMaxRetryBackoff_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithMaxRetryBackoff(10 * time.Second)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.maxRetryBackoff != 10*time.Second {
		t.Fatalf("expected maxRetryBackoff 10s, got: %v", opts.maxRetryBackoff)
	}
}

func TestWithMaxRetryBackoff_Invalid(t *testing.T) {
	opts := defaultOptions()
	err := WithMaxRetryBackoff(0)(opts)
	if err == nil {
		t.Fatal("expected error for zero max retry backoff")
	}
}

func TestWithTLSConfig_Valid(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	opts := defaultOptions()
	err := WithTLSConfig(cfg)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.tlsConfig != cfg {
		t.Fatal("expected tlsConfig to be set")
	}
	if !opts.tlsEnabled {
		t.Fatal("expected tlsEnabled to be true")
	}
	if opts.insecure {
		t.Fatal("expected insecure to be false")
	}
}

func TestWithTLSConfig_Nil(t *testing.T) {
	opts := defaultOptions()
	err := WithTLSConfig(nil)(opts)
	if err == nil {
		t.Fatal("expected error for nil TLS config")
	}
}

func TestWithInsecure(t *testing.T) {
	opts := defaultOptions()
	opts.tlsEnabled = true
	opts.tlsConfig = &tls.Config{}
	err := WithInsecure()(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.tlsEnabled {
		t.Fatal("expected tlsEnabled to be false")
	}
	if opts.tlsConfig != nil {
		t.Fatal("expected tlsConfig to be nil")
	}
	if !opts.insecure {
		t.Fatal("expected insecure to be true")
	}
}

func TestWithConnectionPool_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithConnectionPool(5, 50)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.poolEnabled {
		t.Fatal("expected poolEnabled to be true")
	}
	if opts.poolMinSize != 5 {
		t.Fatalf("expected poolMinSize 5, got: %d", opts.poolMinSize)
	}
	if opts.poolMaxSize != 50 {
		t.Fatalf("expected poolMaxSize 50, got: %d", opts.poolMaxSize)
	}
}

func TestWithConnectionPool_InvalidMinSize(t *testing.T) {
	opts := defaultOptions()
	err := WithConnectionPool(0, 50)(opts)
	if err == nil {
		t.Fatal("expected error for zero minSize")
	}
}

func TestWithConnectionPool_InvalidMaxSize(t *testing.T) {
	opts := defaultOptions()
	err := WithConnectionPool(10, 5)(opts)
	if err == nil {
		t.Fatal("expected error for maxSize < minSize")
	}
}

func TestWithPoolMaxAge_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithPoolMaxAge(2 * time.Hour)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.poolMaxAge != 2*time.Hour {
		t.Fatalf("expected poolMaxAge 2h, got: %v", opts.poolMaxAge)
	}
}

func TestWithPoolMaxAge_Invalid(t *testing.T) {
	opts := defaultOptions()
	err := WithPoolMaxAge(0)(opts)
	if err == nil {
		t.Fatal("expected error for zero pool max age")
	}
}

func TestWithPoolHealthInterval_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithPoolHealthInterval(60 * time.Second)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.poolHealthInterval != 60*time.Second {
		t.Fatalf("expected poolHealthInterval 60s, got: %v", opts.poolHealthInterval)
	}
}

func TestWithPoolHealthInterval_Invalid(t *testing.T) {
	opts := defaultOptions()
	err := WithPoolHealthInterval(0)(opts)
	if err == nil {
		t.Fatal("expected error for zero pool health interval")
	}
}

func TestWithREST(t *testing.T) {
	opts := defaultOptions()
	err := WithREST()(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.transportType != TransportREST {
		t.Fatalf("expected TransportREST, got: %v", opts.transportType)
	}
}

func TestWithQUIC(t *testing.T) {
	opts := defaultOptions()
	err := WithQUIC()(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.transportType != TransportQUIC {
		t.Fatalf("expected TransportQUIC, got: %v", opts.transportType)
	}
}

func TestWithUnix_Valid(t *testing.T) {
	opts := defaultOptions()
	err := WithUnix("/var/run/ca.sock")(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.transportType != TransportUnix {
		t.Fatalf("expected TransportUnix, got: %v", opts.transportType)
	}
	if opts.unixSocketPath != "/var/run/ca.sock" {
		t.Fatalf("expected socket path /var/run/ca.sock, got: %s", opts.unixSocketPath)
	}
}

func TestWithUnix_Empty(t *testing.T) {
	opts := defaultOptions()
	err := WithUnix("")(opts)
	if err == nil {
		t.Fatal("expected error for empty socket path")
	}
}

func TestWithEmbedded_Valid(t *testing.T) {
	mockSvc := &mockService{}
	opts := defaultOptions()
	err := WithEmbedded(mockSvc)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.transportType != TransportEmbedded {
		t.Fatalf("expected TransportEmbedded, got: %v", opts.transportType)
	}
	if opts.embeddedService != mockSvc {
		t.Fatal("expected embeddedService to be set")
	}
}

func TestWithEmbedded_Nil(t *testing.T) {
	opts := defaultOptions()
	err := WithEmbedded(nil)(opts)
	if err == nil {
		t.Fatal("expected error for nil embedded service")
	}
}

func TestWithMCP(t *testing.T) {
	opts := defaultOptions()
	err := WithMCP()(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.transportType != TransportMCP {
		t.Fatalf("expected TransportMCP, got: %v", opts.transportType)
	}
}

func TestWithLogger_Valid(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	opts := defaultOptions()
	err := WithLogger(logger)(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.logger != logger {
		t.Fatal("expected logger to be set")
	}
}

func TestWithLogger_Nil(t *testing.T) {
	opts := defaultOptions()
	err := WithLogger(nil)(opts)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
}

// =============================================================================
// TransportType Tests
// =============================================================================

func TestTransportType_String(t *testing.T) {
	tests := []struct {
		tt   TransportType
		want string
	}{
		{TransportGRPC, "grpc"},
		{TransportREST, "rest"},
		{TransportQUIC, "quic"},
		{TransportUnix, "unix"},
		{TransportEmbedded, "embedded"},
		{TransportMCP, "mcp"},
		{TransportType(99), "unknown"},
	}

	for _, test := range tests {
		got := test.tt.String()
		if got != test.want {
			t.Errorf("TransportType(%d).String() = %q, want %q", test.tt, got, test.want)
		}
	}
}

// =============================================================================
// Default Options Tests
// =============================================================================

func TestDefaultOptions(t *testing.T) {
	opts := defaultOptions()

	if opts.transportType != TransportGRPC {
		t.Errorf("expected default transportType TransportGRPC, got: %v", opts.transportType)
	}
	if opts.timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got: %v", opts.timeout)
	}
	if opts.keepaliveTime != 10*time.Second {
		t.Errorf("expected default keepaliveTime 10s, got: %v", opts.keepaliveTime)
	}
	if opts.keepaliveTimeout != 5*time.Second {
		t.Errorf("expected default keepaliveTimeout 5s, got: %v", opts.keepaliveTimeout)
	}
	if opts.maxRetries != 3 {
		t.Errorf("expected default maxRetries 3, got: %d", opts.maxRetries)
	}
	if opts.retryBackoff != 100*time.Millisecond {
		t.Errorf("expected default retryBackoff 100ms, got: %v", opts.retryBackoff)
	}
	if opts.maxRetryBackoff != 5*time.Second {
		t.Errorf("expected default maxRetryBackoff 5s, got: %v", opts.maxRetryBackoff)
	}
	if opts.tlsEnabled {
		t.Error("expected default tlsEnabled false")
	}
	if opts.insecure {
		t.Error("expected default insecure false")
	}
	if opts.poolEnabled {
		t.Error("expected default poolEnabled false")
	}
	if opts.poolMinSize != 5 {
		t.Errorf("expected default poolMinSize 5, got: %d", opts.poolMinSize)
	}
	if opts.poolMaxSize != 50 {
		t.Errorf("expected default poolMaxSize 50, got: %d", opts.poolMaxSize)
	}
	if opts.poolMaxAge != time.Hour {
		t.Errorf("expected default poolMaxAge 1h, got: %v", opts.poolMaxAge)
	}
	if opts.poolHealthInterval != 30*time.Second {
		t.Errorf("expected default poolHealthInterval 30s, got: %v", opts.poolHealthInterval)
	}
}

// =============================================================================
// TLS Config Loading Tests
// =============================================================================

func TestLoadTLSConfig_EmptyConfig(t *testing.T) {
	cfg := TLSConfig{}
	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got: %d", tlsCfg.MinVersion)
	}
}

func TestLoadTLSConfig_WithServerName(t *testing.T) {
	cfg := TLSConfig{ServerName: "ca.example.com"}
	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ServerName != "ca.example.com" {
		t.Errorf("expected ServerName ca.example.com, got: %s", tlsCfg.ServerName)
	}
}

func TestLoadTLSConfig_EnforcesTLS13(t *testing.T) {
	cfg := TLSConfig{}
	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 enforcement, got MinVersion=%v", tlsCfg.MinVersion)
	}
}

func TestLoadTLSConfig_InvalidCertFile(t *testing.T) {
	cfg := TLSConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}
	_, err := loadTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

func TestLoadTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := TLSConfig{
		CAFile: "/nonexistent/ca.pem",
	}
	_, err := loadTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// mockService is a mock service for testing embedded transport
type mockService struct{}

// parseAddressForTest is a helper to test address parsing
func parseAddressForTest(address string) string {
	if len(address) > 0 && address[0] == '/' {
		return "unix"
	}
	if len(address) > 7 && address[:7] == "unix://" {
		return "unix"
	}
	if len(address) > 16 && address[:16] == "unix-abstract://" {
		return "unix-abstract"
	}
	return "tcp"
}

// applyHTTPDetection simulates HTTP URL detection
func applyHTTPDetection(address string, opts *clientOptions) {
	if len(address) >= 7 && address[:7] == "http://" {
		if opts.transportType == TransportGRPC {
			opts.transportType = TransportREST
		}
	}
	if len(address) >= 8 && address[:8] == "https://" {
		if opts.transportType == TransportGRPC {
			opts.transportType = TransportREST
		}
	}
}
