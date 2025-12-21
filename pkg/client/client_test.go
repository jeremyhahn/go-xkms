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

package client

import (
	"testing"
)

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     string
	}{
		{"unix", ProtocolUnix, "unix"},
		{"unix-grpc", ProtocolUnixGRPC, "unix-grpc"},
		{"rest", ProtocolREST, "rest"},
		{"grpc", ProtocolGRPC, "grpc"},
		{"quic", ProtocolQUIC, "quic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.protocol); got != tt.want {
				t.Errorf("Protocol = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	// Test with nil config - should use defaults (unix-grpc)
	client, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(nil) returned nil client")
	}

	// Should be a Unix gRPC client by default
	_, ok := client.(*unixGRPCClient)
	if !ok {
		t.Errorf("Expected unixGRPCClient, got %T", client)
	}
}

func TestNew_EmptyProtocol(t *testing.T) {
	// Test with empty protocol - should default to Unix gRPC
	cfg := &Config{
		Protocol: "",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(empty protocol) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(empty protocol) returned nil client")
	}

	// Should be a Unix gRPC client
	_, ok := client.(*unixGRPCClient)
	if !ok {
		t.Errorf("Expected unixGRPCClient, got %T", client)
	}
}

func TestNew_UnixProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolUnix,
		Address:  "/tmp/test.sock",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(Unix) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(Unix) returned nil client")
	}

	uc, ok := client.(*unixClient)
	if !ok {
		t.Errorf("Expected unixClient, got %T", client)
	}
	if uc.config.Address != "/tmp/test.sock" {
		t.Errorf("Address = %v, want /tmp/test.sock", uc.config.Address)
	}
}

func TestNew_UnixGRPCProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolUnixGRPC,
		Address:  "/tmp/test.sock",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(UnixGRPC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(UnixGRPC) returned nil client")
	}

	ugc, ok := client.(*unixGRPCClient)
	if !ok {
		t.Errorf("Expected unixGRPCClient, got %T", client)
	}
	if ugc.config.Address != "/tmp/test.sock" {
		t.Errorf("Address = %v, want /tmp/test.sock", ugc.config.Address)
	}
}

func TestNew_RESTProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(REST) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(REST) returned nil client")
	}

	rc, ok := client.(*restClient)
	if !ok {
		t.Errorf("Expected restClient, got %T", client)
	}
	if rc.baseURL != "http://localhost:8443" {
		t.Errorf("baseURL = %v, want http://localhost:8443", rc.baseURL)
	}
}

func TestNew_GRPCProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolGRPC,
		Address:  "localhost:9443",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(gRPC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(gRPC) returned nil client")
	}

	gc, ok := client.(*grpcClient)
	if !ok {
		t.Errorf("Expected grpcClient, got %T", client)
	}
	if gc.config.Address != "localhost:9443" {
		t.Errorf("Address = %v, want localhost:9443", gc.config.Address)
	}
}

func TestNew_QUICProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolQUIC,
		Address:  "localhost:8444",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New(QUIC) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("New(QUIC) returned nil client")
	}

	qc, ok := client.(*quicClient)
	if !ok {
		t.Errorf("Expected quicClient, got %T", client)
	}
	if qc.config.Address != "localhost:8444" {
		t.Errorf("Address = %v, want localhost:8444", qc.config.Address)
	}
}

func TestNew_UnsupportedProtocol(t *testing.T) {
	cfg := &Config{
		Protocol: Protocol("invalid"),
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("Expected error for unsupported protocol")
	}
}

func TestNew_DefaultAddresses(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     string
	}{
		{"unix default", ProtocolUnix, DefaultUnixSocketPath},
		{"unix-grpc default", ProtocolUnixGRPC, DefaultUnixSocketPath},
		{"rest default", ProtocolREST, "http://localhost:8443"},
		{"grpc default", ProtocolGRPC, "localhost:9443"},
		{"quic default", ProtocolQUIC, "localhost:8444"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Protocol: tt.protocol,
				Address:  "", // Empty to use default
			}
			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New() returned error: %v", err)
			}

			var addr string
			switch c := client.(type) {
			case *unixClient:
				addr = c.config.Address
			case *unixGRPCClient:
				addr = c.config.Address
			case *restClient:
				addr = c.baseURL
			case *grpcClient:
				addr = c.config.Address
			case *quicClient:
				// QUIC adds https:// prefix
				if c.baseURL == "https://"+tt.want {
					return // OK
				}
				addr = c.config.Address
			}

			if addr != tt.want {
				t.Errorf("Address = %v, want %v", addr, tt.want)
			}
		})
	}
}

func TestNewFromURL_Empty(t *testing.T) {
	// Empty URL should default to Unix socket with gRPC
	client, err := NewFromURL("")
	if err != nil {
		t.Fatalf("NewFromURL('') returned error: %v", err)
	}
	if client == nil {
		t.Fatal("NewFromURL('') returned nil client")
	}

	_, ok := client.(*unixGRPCClient)
	if !ok {
		t.Errorf("Expected unixGRPCClient, got %T", client)
	}
}

func TestNewFromURL_UnixScheme(t *testing.T) {
	client, err := NewFromURL("unix:///var/run/test.sock")
	if err != nil {
		t.Fatalf("NewFromURL(unix://) returned error: %v", err)
	}

	ugc, ok := client.(*unixGRPCClient)
	if !ok {
		t.Fatalf("Expected unixGRPCClient, got %T", client)
	}
	if ugc.config.Address != "/var/run/test.sock" {
		t.Errorf("Address = %v, want /var/run/test.sock", ugc.config.Address)
	}
}

func TestNewFromURL_UnixHTTPScheme(t *testing.T) {
	client, err := NewFromURL("unix+http:///var/run/test.sock")
	if err != nil {
		t.Fatalf("NewFromURL(unix+http://) returned error: %v", err)
	}

	uc, ok := client.(*unixClient)
	if !ok {
		t.Fatalf("Expected unixClient, got %T", client)
	}
	if uc.config.Address != "/var/run/test.sock" {
		t.Errorf("Address = %v, want /var/run/test.sock", uc.config.Address)
	}
}

func TestNewFromURL_HTTPScheme(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantTLS   bool
		wantProto Protocol
	}{
		{"http", "http://localhost:8080", false, ProtocolREST},
		{"https", "https://localhost:8443", true, ProtocolREST},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL(%s) returned error: %v", tt.url, err)
			}

			rc, ok := client.(*restClient)
			if !ok {
				t.Fatalf("Expected restClient, got %T", client)
			}
			if rc.config.TLSEnabled != tt.wantTLS {
				t.Errorf("TLSEnabled = %v, want %v", rc.config.TLSEnabled, tt.wantTLS)
			}
		})
	}
}

func TestNewFromURL_GRPCScheme(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantTLS  bool
		wantAddr string
	}{
		{"grpc", "grpc://localhost:9443", false, "localhost:9443"},
		{"grpcs", "grpcs://localhost:9443", true, "localhost:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFromURL(tt.url)
			if err != nil {
				t.Fatalf("NewFromURL(%s) returned error: %v", tt.url, err)
			}

			gc, ok := client.(*grpcClient)
			if !ok {
				t.Fatalf("Expected grpcClient, got %T", client)
			}
			if gc.config.TLSEnabled != tt.wantTLS {
				t.Errorf("TLSEnabled = %v, want %v", gc.config.TLSEnabled, tt.wantTLS)
			}
			if gc.config.Address != tt.wantAddr {
				t.Errorf("Address = %v, want %v", gc.config.Address, tt.wantAddr)
			}
		})
	}
}

func TestNewFromURL_QUICScheme(t *testing.T) {
	client, err := NewFromURL("quic://localhost:8444")
	if err != nil {
		t.Fatalf("NewFromURL(quic://) returned error: %v", err)
	}

	qc, ok := client.(*quicClient)
	if !ok {
		t.Fatalf("Expected quicClient, got %T", client)
	}
	// QUIC always uses TLS
	if !qc.config.TLSEnabled {
		t.Error("Expected TLSEnabled = true for QUIC")
	}
}

func TestNewFromURL_HostPort(t *testing.T) {
	// Plain host:port should default to REST
	client, err := NewFromURL("myhost:8080")
	if err != nil {
		t.Fatalf("NewFromURL(host:port) returned error: %v", err)
	}

	_, ok := client.(*restClient)
	if !ok {
		t.Errorf("Expected restClient for host:port, got %T", client)
	}
}

func TestConfig_TLSSettings(t *testing.T) {
	cfg := &Config{
		Protocol:              ProtocolREST,
		Address:               "https://localhost:8443",
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
		TLSCertFile:           "/path/to/cert.pem",
		TLSKeyFile:            "/path/to/key.pem",
		TLSCAFile:             "/path/to/ca.pem",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	rc, ok := client.(*restClient)
	if !ok {
		t.Fatalf("Expected restClient, got %T", client)
	}

	if !rc.config.TLSEnabled {
		t.Error("Expected TLSEnabled = true")
	}
	if !rc.config.TLSInsecureSkipVerify {
		t.Error("Expected TLSInsecureSkipVerify = true")
	}
	if rc.config.TLSCertFile != "/path/to/cert.pem" {
		t.Errorf("TLSCertFile = %v, want /path/to/cert.pem", rc.config.TLSCertFile)
	}
}

func TestConfig_JWTToken(t *testing.T) {
	cfg := &Config{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
		JWTToken: "test-jwt-token",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	rc, ok := client.(*restClient)
	if !ok {
		t.Fatalf("Expected restClient, got %T", client)
	}

	if rc.config.JWTToken != "test-jwt-token" {
		t.Errorf("JWTToken = %v, want test-jwt-token", rc.config.JWTToken)
	}
}

func TestConfig_CustomHeaders(t *testing.T) {
	headers := map[string]string{
		"X-Custom-Header": "custom-value",
		"Authorization":   "Bearer token",
	}

	cfg := &Config{
		Protocol: ProtocolREST,
		Address:  "http://localhost:8443",
		Headers:  headers,
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	rc, ok := client.(*restClient)
	if !ok {
		t.Fatalf("Expected restClient, got %T", client)
	}

	if len(rc.config.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(rc.config.Headers))
	}
	if rc.config.Headers["X-Custom-Header"] != "custom-value" {
		t.Errorf("X-Custom-Header = %v, want custom-value", rc.config.Headers["X-Custom-Header"])
	}
}

func TestErrors(t *testing.T) {
	// Test that error variables are defined
	if ErrUnsupportedProtocol == nil {
		t.Error("ErrUnsupportedProtocol is nil")
	}
	if ErrConnectionFailed == nil {
		t.Error("ErrConnectionFailed is nil")
	}
	if ErrNotConnected == nil {
		t.Error("ErrNotConnected is nil")
	}
}

func TestDefaultUnixSocketPath(t *testing.T) {
	if DefaultUnixSocketPath != "keychain-data/keychain.sock" {
		t.Errorf("DefaultUnixSocketPath = %v, want keychain-data/keychain.sock",
			DefaultUnixSocketPath)
	}
}
