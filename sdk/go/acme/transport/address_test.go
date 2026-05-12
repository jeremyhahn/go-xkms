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

package transport

import "testing"

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType AddressType
		expectedAddr string
		expectedPath string
	}{
		{
			name:         "TCP address",
			input:        "localhost:50051",
			expectedType: AddressTypeTCP,
			expectedAddr: "localhost:50051",
		},
		{
			name:         "TCP with IP",
			input:        "192.168.1.1:8080",
			expectedType: AddressTypeTCP,
			expectedAddr: "192.168.1.1:8080",
		},
		{
			name:         "Unix socket auto-detected",
			input:        "/var/run/trusted-ca.sock",
			expectedType: AddressTypeUnix,
			expectedAddr: "/var/run/trusted-ca.sock",
		},
		{
			name:         "Unix socket explicit",
			input:        "unix:///var/run/trusted-ca.sock",
			expectedType: AddressTypeUnix,
			expectedAddr: "/var/run/trusted-ca.sock",
		},
		{
			name:         "Unix abstract socket",
			input:        "unix-abstract://trusted-ca",
			expectedType: AddressTypeUnixAbstract,
			expectedAddr: "trusted-ca",
		},
		{
			name:         "HTTP URL with port and path",
			input:        "http://test-node1:8888/acme",
			expectedType: AddressTypeHTTP,
			expectedAddr: "test-node1:8888",
			expectedPath: "/acme",
		},
		{
			name:         "HTTP URL without path",
			input:        "http://localhost:8080",
			expectedType: AddressTypeHTTP,
			expectedAddr: "localhost:8080",
		},
		{
			name:         "HTTP URL without port",
			input:        "http://example.com/api",
			expectedType: AddressTypeHTTP,
			expectedAddr: "example.com:80",
			expectedPath: "/api",
		},
		{
			name:         "HTTPS URL with port and path",
			input:        "https://secure.example.com:8443/api/v1",
			expectedType: AddressTypeHTTPS,
			expectedAddr: "secure.example.com:8443",
			expectedPath: "/api/v1",
		},
		{
			name:         "HTTPS URL without port",
			input:        "https://secure.example.com/api",
			expectedType: AddressTypeHTTPS,
			expectedAddr: "secure.example.com:443",
			expectedPath: "/api",
		},
		{
			name:         "Embedded transport",
			input:        "embedded://local",
			expectedType: AddressTypeEmbedded,
			expectedAddr: "local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseAddress(tt.input)

			if parsed.Type != tt.expectedType {
				t.Errorf("expected type %v, got %v", tt.expectedType, parsed.Type)
			}
			if parsed.Address != tt.expectedAddr {
				t.Errorf("expected address %q, got %q", tt.expectedAddr, parsed.Address)
			}
			if parsed.Original != tt.input {
				t.Errorf("expected original %q, got %q", tt.input, parsed.Original)
			}
			if tt.expectedPath != "" && parsed.Path != tt.expectedPath {
				t.Errorf("expected path %q, got %q", tt.expectedPath, parsed.Path)
			}
		})
	}
}

func TestParseAddress_InvalidInputs(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType AddressType
	}{
		{
			name:         "empty string defaults to TCP",
			input:        "",
			expectedType: AddressTypeTCP,
		},
		{
			name:         "plain hostname defaults to TCP",
			input:        "localhost",
			expectedType: AddressTypeTCP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if parsed.Type != tt.expectedType {
				t.Errorf("expected type %v, got %v", tt.expectedType, parsed.Type)
			}
		})
	}
}

func TestParsedAddress_IsUnix(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"localhost:50051", false},
		{"/var/run/trusted-ca.sock", true},
		{"unix:///tmp/test.sock", true},
		{"unix-abstract://test", true},
		{"http://localhost:8080", false},
		{"https://localhost:8443", false},
		{"embedded://local", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.IsUnix(); got != tt.expected {
				t.Errorf("IsUnix() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_IsTCP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"localhost:50051", true},
		{"/var/run/trusted-ca.sock", false},
		{"unix:///tmp/test.sock", false},
		{"http://localhost:8080", false},
		{"https://localhost:8443", false},
		{"embedded://local", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.IsTCP(); got != tt.expected {
				t.Errorf("IsTCP() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_IsHTTP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"localhost:50051", false},
		{"/var/run/trusted-ca.sock", false},
		{"unix:///tmp/test.sock", false},
		{"http://localhost:8080", true},
		{"https://localhost:8443", true},
		{"http://test-node1:8888/acme", true},
		{"embedded://local", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.IsHTTP(); got != tt.expected {
				t.Errorf("IsHTTP() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_IsEmbedded(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"localhost:50051", false},
		{"/var/run/trusted-ca.sock", false},
		{"http://localhost:8080", false},
		{"embedded://local", true},
		{"embedded://server1", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.IsEmbedded(); got != tt.expected {
				t.Errorf("IsEmbedded() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_Network(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:50051", "tcp"},
		{"/var/run/trusted-ca.sock", "unix"},
		{"unix-abstract://test", "unix"},
		{"http://localhost:8080", "tcp"},
		{"https://localhost:8443", "tcp"},
		{"embedded://local", "embedded"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.Network(); got != tt.expected {
				t.Errorf("Network() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_NormalizeForGRPC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:50051", "localhost:50051"},
		{"/var/run/trusted-ca.sock", "unix:/var/run/trusted-ca.sock"},
		{"unix-abstract://test", "unix:@test"},
		{"http://test-node1:8888/acme", "test-node1:8888"},
		{"https://secure.example.com:8443/api", "secure.example.com:8443"},
		{"embedded://local", "passthrough:///local"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.NormalizeForGRPC(); got != tt.expected {
				t.Errorf("NormalizeForGRPC() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_NormalizeForREST(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:8080", "localhost:8080"},
		{"/var/run/trusted-ca.sock", ""},
		{"unix-abstract://test", ""},
		{"http://test-node1:8888/acme", "test-node1:8888"},
		{"embedded://local", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.NormalizeForREST(); got != tt.expected {
				t.Errorf("NormalizeForREST() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestParsedAddress_FullURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:8080", "localhost:8080"},
		{"/var/run/trusted-ca.sock", "/var/run/trusted-ca.sock"},
		{"http://test-node1:8888/acme", "http://test-node1:8888/acme"},
		{"https://secure.example.com:8443/api/v1", "https://secure.example.com:8443/api/v1"},
		{"http://example.com/api", "http://example.com:80/api"},
		{"embedded://local", "embedded://local"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if got := parsed.FullURL(); got != tt.expected {
				t.Errorf("FullURL() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestAddressType_String(t *testing.T) {
	tests := []struct {
		addrType AddressType
		expected string
	}{
		{AddressTypeTCP, "tcp"},
		{AddressTypeUnix, "unix"},
		{AddressTypeUnixAbstract, "unix-abstract"},
		{AddressTypeHTTP, "http"},
		{AddressTypeHTTPS, "https"},
		{AddressTypeEmbedded, "embedded"},
		{AddressType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.addrType.String(); got != tt.expected {
				t.Errorf("String() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestParseAddress_Scheme(t *testing.T) {
	tests := []struct {
		input          string
		expectedScheme string
	}{
		{"localhost:50051", "tcp"},
		{"/var/run/trusted-ca.sock", "unix"},
		{"unix:///tmp/test.sock", "unix"},
		{"unix-abstract://test", "unix-abstract"},
		{"http://localhost:8080", "http"},
		{"https://localhost:8443", "https"},
		{"embedded://local", "embedded"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed := ParseAddress(tt.input)
			if parsed.Scheme != tt.expectedScheme {
				t.Errorf("expected scheme %q, got %q", tt.expectedScheme, parsed.Scheme)
			}
		})
	}
}

func TestParseAddress_ACMEAddress(t *testing.T) {
	// Test the ACME directory endpoint format
	address := "http://acme-server:8888/directory"
	parsed := ParseAddress(address)

	if parsed.Type != AddressTypeHTTP {
		t.Errorf("expected type AddressTypeHTTP, got %v", parsed.Type)
	}

	if parsed.Address != "acme-server:8888" {
		t.Errorf("expected address 'acme-server:8888', got %q", parsed.Address)
	}

	if parsed.DialAddress != "acme-server:8888" {
		t.Errorf("expected dialAddress 'acme-server:8888', got %q", parsed.DialAddress)
	}

	if parsed.Path != "/directory" {
		t.Errorf("expected path '/directory', got %q", parsed.Path)
	}

	grpcAddr := parsed.NormalizeForGRPC()
	if grpcAddr != "acme-server:8888" {
		t.Errorf("NormalizeForGRPC() should return 'acme-server:8888', got %q", grpcAddr)
	}

	fullURL := parsed.FullURL()
	if fullURL != "http://acme-server:8888/directory" {
		t.Errorf("FullURL() should return original URL, got %q", fullURL)
	}
}
