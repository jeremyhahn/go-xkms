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

package common

import "testing"

// =============================================================================
// ParseDynamicChallenge Tests
// =============================================================================

func TestParseDynamicChallenge(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		wantName      string
		wantPort      string
		wantErr       error
	}{
		// Valid dynamic challenges
		{
			name:          "dynamic http challenge",
			challengeType: "http-8080",
			wantName:      "http",
			wantPort:      "8080",
			wantErr:       nil,
		},
		{
			name:          "dynamic enroll challenge",
			challengeType: "enroll-8443",
			wantName:      "enroll",
			wantPort:      "8443",
			wantErr:       nil,
		},
		{
			name:          "dynamic endorse challenge",
			challengeType: "endorse-9000",
			wantName:      "endorse",
			wantPort:      "9000",
			wantErr:       nil,
		},
		{
			name:          "dynamic dns challenge",
			challengeType: "dns-5353",
			wantName:      "dns",
			wantPort:      "5353",
			wantErr:       nil,
		},
		{
			name:          "dynamic port 443",
			challengeType: "http-443",
			wantName:      "http",
			wantPort:      "443",
			wantErr:       nil,
		},
		{
			name:          "dynamic port 1",
			challengeType: "http-1",
			wantName:      "http",
			wantPort:      "1",
			wantErr:       nil,
		},
		{
			name:          "dynamic port 65535",
			challengeType: "http-65535",
			wantName:      "http",
			wantPort:      "65535",
			wantErr:       nil,
		},

		// Valid standard challenges
		{
			name:          "standard http-01 challenge",
			challengeType: "http-01",
			wantName:      "http-01",
			wantPort:      "",
			wantErr:       nil,
		},
		{
			name:          "standard dns-01 challenge",
			challengeType: "dns-01",
			wantName:      "dns-01",
			wantPort:      "",
			wantErr:       nil,
		},
		{
			name:          "standard enroll-01 challenge",
			challengeType: "enroll-01",
			wantName:      "enroll-01",
			wantPort:      "",
			wantErr:       nil,
		},
		{
			name:          "standard endorse-01 challenge",
			challengeType: "endorse-01",
			wantName:      "endorse-01",
			wantPort:      "",
			wantErr:       nil,
		},

		// Invalid formats
		{
			name:          "empty string",
			challengeType: "",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "no hyphen",
			challengeType: "http",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "only hyphen",
			challengeType: "-",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port too large",
			challengeType: "http-65536",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port zero",
			challengeType: "http-0",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port 99999 too large",
			challengeType: "http-99999",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "negative port",
			challengeType: "http--80",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "non-numeric port",
			challengeType: "http-abc",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "uppercase",
			challengeType: "HTTP-8080",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "mixed case",
			challengeType: "Http-8080",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "unsupported challenge type",
			challengeType: "unknown-8080",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrUnsupportedChallenge,
		},
		{
			name:          "extra hyphens",
			challengeType: "http-80-80",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port with leading zeros",
			challengeType: "http-0080",
			wantName:      "http",
			wantPort:      "0080",
			wantErr:       nil,
		},
		{
			name:          "port too many digits",
			challengeType: "http-123456",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotPort, err := ParseDynamicChallenge(tt.challengeType)

			if err != tt.wantErr {
				t.Errorf("ParseDynamicChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotName != tt.wantName {
				t.Errorf("ParseDynamicChallenge() gotName = %v, want %v", gotName, tt.wantName)
			}

			if gotPort != tt.wantPort {
				t.Errorf("ParseDynamicChallenge() gotPort = %v, want %v", gotPort, tt.wantPort)
			}
		})
	}
}

// =============================================================================
// IsDynamicChallenge Tests
// =============================================================================

func TestIsDynamicChallenge(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          bool
	}{
		// Dynamic challenges
		{
			name:          "dynamic http",
			challengeType: "http-8080",
			want:          true,
		},
		{
			name:          "dynamic enroll",
			challengeType: "enroll-8443",
			want:          true,
		},
		{
			name:          "dynamic dns",
			challengeType: "dns-5353",
			want:          true,
		},
		{
			name:          "dynamic endorse",
			challengeType: "endorse-9000",
			want:          true,
		},
		{
			name:          "dynamic port 1",
			challengeType: "http-1",
			want:          true,
		},
		{
			name:          "dynamic port 65535",
			challengeType: "http-65535",
			want:          true,
		},

		// Standard challenges
		{
			name:          "standard http-01",
			challengeType: "http-01",
			want:          false,
		},
		{
			name:          "standard dns-01",
			challengeType: "dns-01",
			want:          false,
		},
		{
			name:          "standard enroll-01",
			challengeType: "enroll-01",
			want:          false,
		},
		{
			name:          "standard endorse-01",
			challengeType: "endorse-01",
			want:          false,
		},

		// Invalid formats
		{
			name:          "empty string",
			challengeType: "",
			want:          false,
		},
		{
			name:          "invalid format",
			challengeType: "invalid",
			want:          false,
		},
		{
			name:          "port too large",
			challengeType: "http-65536",
			want:          false,
		},
		{
			name:          "unsupported type",
			challengeType: "unknown-8080",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDynamicChallenge(tt.challengeType)
			if got != tt.want {
				t.Errorf("IsDynamicChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// GetChallengePort Tests
// =============================================================================

func TestGetChallengePort(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		// Dynamic challenges - return specified port
		{
			name:          "dynamic http",
			challengeType: "http-8080",
			want:          "8080",
		},
		{
			name:          "dynamic enroll",
			challengeType: "enroll-8443",
			want:          "8443",
		},
		{
			name:          "dynamic dns",
			challengeType: "dns-5353",
			want:          "5353",
		},
		{
			name:          "dynamic endorse",
			challengeType: "endorse-9000",
			want:          "9000",
		},

		// Standard challenges - return default ports
		{
			name:          "standard http-01",
			challengeType: "http-01",
			want:          "80",
		},
		{
			name:          "standard https-01",
			challengeType: "https-01",
			want:          "443",
		},
		{
			name:          "standard enroll-01",
			challengeType: "enroll-01",
			want:          "8443",
		},
		{
			name:          "standard endorse-01",
			challengeType: "endorse-01",
			want:          "8443",
		},
		{
			name:          "standard dns-01",
			challengeType: "dns-01",
			want:          "",
		},
		{
			name:          "standard unknown-01",
			challengeType: "unknown-01",
			want:          "",
		},

		// Invalid challenges - return empty string
		{
			name:          "empty string",
			challengeType: "",
			want:          "",
		},
		{
			name:          "invalid format",
			challengeType: "invalid",
			want:          "",
		},
		{
			name:          "unsupported type",
			challengeType: "unknown-8080",
			want:          "",
		},
		{
			name:          "port too large",
			challengeType: "http-65536",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetChallengePort(tt.challengeType)
			if got != tt.want {
				t.Errorf("GetChallengePort() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// NormalizeChallengeType Tests
// =============================================================================

func TestNormalizeChallengeType(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		// Dynamic challenges - normalize to standard form
		{
			name:          "dynamic http",
			challengeType: "http-8080",
			want:          "http-01",
		},
		{
			name:          "dynamic enroll",
			challengeType: "enroll-8443",
			want:          "enroll-01",
		},
		{
			name:          "dynamic dns",
			challengeType: "dns-5353",
			want:          "dns-01",
		},
		{
			name:          "dynamic endorse",
			challengeType: "endorse-9000",
			want:          "endorse-01",
		},
		{
			name:          "dynamic port 1",
			challengeType: "http-1",
			want:          "http-01",
		},
		{
			name:          "dynamic port 65535",
			challengeType: "http-65535",
			want:          "http-01",
		},

		// Standard challenges - return unchanged
		{
			name:          "standard http-01",
			challengeType: "http-01",
			want:          "http-01",
		},
		{
			name:          "standard dns-01",
			challengeType: "dns-01",
			want:          "dns-01",
		},
		{
			name:          "standard enroll-01",
			challengeType: "enroll-01",
			want:          "enroll-01",
		},
		{
			name:          "standard endorse-01",
			challengeType: "endorse-01",
			want:          "endorse-01",
		},

		// Invalid challenges - return empty string
		{
			name:          "empty string",
			challengeType: "",
			want:          "",
		},
		{
			name:          "invalid format",
			challengeType: "invalid",
			want:          "",
		},
		{
			name:          "unsupported type",
			challengeType: "unknown-8080",
			want:          "",
		},
		{
			name:          "port too large",
			challengeType: "http-65536",
			want:          "",
		},
		{
			name:          "port zero",
			challengeType: "dns-0",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeChallengeType(tt.challengeType)
			if got != tt.want {
				t.Errorf("NormalizeChallengeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeChallengeType_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		// Test cases that exercise different code paths
		{
			name:          "standard unknown challenge type with 2-digit suffix",
			challengeType: "unknown-01",
			want:          "unknown-01", // Returns as-is since it matches standard pattern
		},
		{
			name:          "another standard 2-digit suffix",
			challengeType: "test-99",
			want:          "test-99", // Returns as-is since it matches standard pattern
		},
		{
			name:          "tls-alpn standard format",
			challengeType: "tls-alpn-01",
			want:          "", // Doesn't match any pattern (has two hyphens)
		},
		{
			name:          "device-attest standard format",
			challengeType: "device-attest-01",
			want:          "", // Doesn't match any pattern (has two hyphens)
		},
		{
			name:          "special chars in type",
			challengeType: "http_test-01",
			want:          "", // Doesn't match regex (underscore not allowed)
		},
		{
			name:          "numeric prefix",
			challengeType: "123-8080",
			want:          "", // Doesn't match regex (numbers not allowed in name)
		},
		{
			name:          "trailing hyphen",
			challengeType: "http-8080-",
			want:          "", // Doesn't match any pattern
		},
		{
			name:          "leading hyphen",
			challengeType: "-http-8080",
			want:          "", // Doesn't match any pattern
		},
		{
			name:          "space in type",
			challengeType: "http 8080",
			want:          "", // Doesn't match any pattern
		},
		{
			name:          "tab in type",
			challengeType: "http\t8080",
			want:          "", // Doesn't match any pattern
		},
		{
			name:          "newline in type",
			challengeType: "http\n8080",
			want:          "", // Doesn't match any pattern
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeChallengeType(tt.challengeType)
			if got != tt.want {
				t.Errorf("NormalizeChallengeType(%q) = %q, want %q", tt.challengeType, got, tt.want)
			}
		})
	}
}

// =============================================================================
// FormatDynamicChallenge Tests
// =============================================================================

func TestFormatDynamicChallenge(t *testing.T) {
	tests := []struct {
		name     string
		baseType string
		port     string
		want     string
	}{
		{
			name:     "valid http challenge",
			baseType: "http",
			port:     "8080",
			want:     "http-8080",
		},
		{
			name:     "valid enroll challenge",
			baseType: "enroll",
			port:     "8443",
			want:     "enroll-8443",
		},
		{
			name:     "valid dns challenge",
			baseType: "dns",
			port:     "5353",
			want:     "dns-5353",
		},
		{
			name:     "empty base type",
			baseType: "",
			port:     "8080",
			want:     "",
		},
		{
			name:     "empty port",
			baseType: "http",
			port:     "",
			want:     "",
		},
		{
			name:     "both empty",
			baseType: "",
			port:     "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDynamicChallenge(tt.baseType, tt.port)
			if got != tt.want {
				t.Errorf("FormatDynamicChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Round Trip Tests
// =============================================================================

func TestDynamicChallengeRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
	}{
		{"http-8080", "http-8080"},
		{"enroll-8443", "enroll-8443"},
		{"dns-5353", "dns-5353"},
		{"endorse-9000", "endorse-9000"},
		{"http-1", "http-1"},
		{"http-65535", "http-65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the challenge
			name, port, err := ParseDynamicChallenge(tt.challengeType)
			if err != nil {
				t.Fatalf("ParseDynamicChallenge() error = %v", err)
			}

			// Format it back
			result := FormatDynamicChallenge(name, port)

			// Should match original
			if result != tt.challengeType {
				t.Errorf("Round trip failed: got %v, want %v", result, tt.challengeType)
			}
		})
	}
}

// =============================================================================
// DynamicChallengePatterns Tests
// =============================================================================

func TestDynamicChallengePatterns(t *testing.T) {
	expectedPatterns := map[string]string{
		"http":    "http-01",
		"dns":     "dns-01",
		"enroll":  "enroll-01",
		"endorse": "endorse-01",
	}

	for key, want := range expectedPatterns {
		got, exists := DynamicChallengePatterns[key]
		if !exists {
			t.Errorf("DynamicChallengePatterns missing key: %v", key)
			continue
		}
		if got != want {
			t.Errorf("DynamicChallengePatterns[%v] = %v, want %v", key, got, want)
		}
	}

	// Verify no extra keys
	if len(DynamicChallengePatterns) != len(expectedPatterns) {
		t.Errorf("DynamicChallengePatterns has %v entries, want %v",
			len(DynamicChallengePatterns), len(expectedPatterns))
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkParseDynamicChallenge(b *testing.B) {
	tests := []string{
		"http-8080",
		"http-01",
		"enroll-8443",
		"dns-01",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseDynamicChallenge(tests[i%len(tests)])
	}
}

func BenchmarkIsDynamicChallenge(b *testing.B) {
	tests := []string{
		"http-8080",
		"http-01",
		"enroll-8443",
		"dns-01",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsDynamicChallenge(tests[i%len(tests)])
	}
}

func BenchmarkNormalizeChallengeType(b *testing.B) {
	tests := []string{
		"http-8080",
		"http-01",
		"enroll-8443",
		"dns-01",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NormalizeChallengeType(tests[i%len(tests)])
	}
}

func BenchmarkGetChallengePort(b *testing.B) {
	tests := []string{
		"http-8080",
		"http-01",
		"enroll-8443",
		"dns-01",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetChallengePort(tests[i%len(tests)])
	}
}
