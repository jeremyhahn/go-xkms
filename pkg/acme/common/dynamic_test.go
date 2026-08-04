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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestParseDynamicChallenge_PortValidation_OutOfRange(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		wantErr       error
	}{
		{
			name:          "port_zero_invalid",
			challengeType: "http-0",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port_65536_invalid",
			challengeType: "http-65536",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port_99999_invalid",
			challengeType: "http-99999",
			wantErr:       ErrInvalidChallengeFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseDynamicChallenge(tt.challengeType)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestParseDynamicChallenge_UnknownBaseTypeDynamic(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		wantErr       error
	}{
		{
			name:          "unknown_base_type_dynamic",
			challengeType: "unknown-8080",
			wantErr:       ErrUnsupportedChallenge,
		},
		{
			name:          "invalid_base_type_dynamic",
			challengeType: "foobar-9000",
			wantErr:       ErrUnsupportedChallenge,
		},
		{
			name:          "typo_in_http_dynamic",
			challengeType: "htp-8080",
			wantErr:       ErrUnsupportedChallenge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseDynamicChallenge(tt.challengeType)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestParseDynamicChallenge_AllKnownTypes(t *testing.T) {
	for baseType, standard := range DynamicChallengePatterns {
		t.Run("dynamic_"+baseType, func(t *testing.T) {
			// Test dynamic format
			name, port, err := ParseDynamicChallenge(baseType + "-8080")
			require.NoError(t, err)
			assert.Equal(t, baseType, name)
			assert.Equal(t, "8080", port)

			// Verify normalization
			normalized := NormalizeChallengeType(baseType + "-8080")
			assert.Equal(t, standard, normalized)
		})
	}
}

func TestParseDynamicChallenge_BoundaryPorts(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		wantName      string
		wantPort      string
		wantErr       error
	}{
		{
			name:          "port exactly 65535",
			challengeType: "http-65535",
			wantName:      "http",
			wantPort:      "65535",
			wantErr:       nil,
		},
		{
			name:          "port exactly 1",
			challengeType: "http-1",
			wantName:      "http",
			wantPort:      "1",
			wantErr:       nil,
		},
		{
			name:          "port exactly 0 invalid",
			challengeType: "http-0",
			wantName:      "",
			wantPort:      "",
			wantErr:       ErrInvalidChallengeFormat,
		},
		{
			name:          "port 65536 invalid",
			challengeType: "http-65536",
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
			name:          "port with max 5 digits valid",
			challengeType: "http-12345",
			wantName:      "http",
			wantPort:      "12345",
			wantErr:       nil,
		},
		{
			name:          "port 10000 valid",
			challengeType: "enroll-10000",
			wantName:      "enroll",
			wantPort:      "10000",
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotPort, err := ParseDynamicChallenge(tt.challengeType)

			if err != tt.wantErr {
				t.Errorf("ParseDynamicChallenge(%q) error = %v, wantErr %v",
					tt.challengeType, err, tt.wantErr)
				return
			}

			if gotName != tt.wantName {
				t.Errorf("ParseDynamicChallenge(%q) gotName = %q, want %q",
					tt.challengeType, gotName, tt.wantName)
			}

			if gotPort != tt.wantPort {
				t.Errorf("ParseDynamicChallenge(%q) gotPort = %q, want %q",
					tt.challengeType, gotPort, tt.wantPort)
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

func TestIsDynamicChallenge_AllKnownTypes(t *testing.T) {
	// Test all base types from DynamicChallengePatterns with various ports
	for baseType := range DynamicChallengePatterns {
		t.Run(baseType+" with port 8080", func(t *testing.T) {
			challenge := FormatDynamicChallenge(baseType, "8080")
			if !IsDynamicChallenge(challenge) {
				t.Errorf("IsDynamicChallenge(%q) = false, want true", challenge)
			}
		})

		t.Run(baseType+" with port 443", func(t *testing.T) {
			challenge := FormatDynamicChallenge(baseType, "443")
			if !IsDynamicChallenge(challenge) {
				t.Errorf("IsDynamicChallenge(%q) = false, want true", challenge)
			}
		})

		t.Run(baseType+" with port 1", func(t *testing.T) {
			challenge := FormatDynamicChallenge(baseType, "1")
			if !IsDynamicChallenge(challenge) {
				t.Errorf("IsDynamicChallenge(%q) = false, want true", challenge)
			}
		})
	}
}

func TestIsDynamicChallenge_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          bool
	}{
		{
			name:          "standard_two_digit_suffix",
			challengeType: "http-01",
			want:          false,
		},
		{
			name:          "dynamic_three_digit_port",
			challengeType: "http-100",
			want:          true,
		},
		{
			name:          "dynamic_five_digit_port",
			challengeType: "http-65535",
			want:          true,
		},
		{
			name:          "invalid_no_digits",
			challengeType: "http-",
			want:          false,
		},
		{
			name:          "invalid_no_hyphen",
			challengeType: "http01",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDynamicChallenge(tt.challengeType)
			require.Equal(t, tt.want, result)
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
			want:          DefaultHTTPPort,
		},
		{
			name:          "standard https-01",
			challengeType: "https-01",
			want:          DefaultHTTPSPort,
		},
		{
			name:          "standard enroll-01",
			challengeType: "enroll-01",
			want:          DefaultEnrollPort,
		},
		{
			name:          "standard endorse-01",
			challengeType: "endorse-01",
			want:          DefaultEnrollPort,
		},
		{
			name:          "standard dns-01",
			challengeType: "dns-01",
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

func TestGetChallengePort_UnknownStandardTypes(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "unknown standard type returns empty",
			challengeType: "unknown-01",
			want:          "", // Falls through to default case
		},
		{
			name:          "custom standard type returns empty",
			challengeType: "custom-01",
			want:          "", // Falls through to default case
		},
		{
			name:          "test standard type returns empty",
			challengeType: "test-99",
			want:          "", // Falls through to default case
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetChallengePort(tt.challengeType)
			if got != tt.want {
				t.Errorf("GetChallengePort(%q) = %q, want %q", tt.challengeType, got, tt.want)
			}
		})
	}
}

func TestGetChallengePort_FallThroughCases(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "unknown_standard_type",
			challengeType: "unknown-01",
			want:          "",
		},
		{
			name:          "alpn_standard",
			challengeType: "alpn-01",
			want:          "",
		},
		{
			name:          "custom_standard",
			challengeType: "custom-99",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetChallengePort(tt.challengeType)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestGetChallengePort_ErrorPathFromParseDynamic(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "invalid_challenge_returns_empty",
			challengeType: "invalid-challenge",
			want:          "",
		},
		{
			name:          "empty_challenge_returns_empty",
			challengeType: "",
			want:          "",
		},
		{
			name:          "unknown_dynamic_returns_empty",
			challengeType: "unknown-8080",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetChallengePort(tt.challengeType)
			require.Equal(t, tt.want, result)
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

func TestNormalizeChallengeType_ReturnsEmptyForInvalid(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "unsupported_dynamic_base",
			challengeType: "unknown-8080",
			want:          "",
		},
		{
			name:          "invalid_format_no_hyphen",
			challengeType: "invalid",
			want:          "",
		},
		{
			name:          "empty_string",
			challengeType: "",
			want:          "",
		},
		{
			name:          "port_out_of_range",
			challengeType: "http-65536",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeChallengeType(tt.challengeType)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestNormalizeChallengeType_DynamicToStandard(t *testing.T) {
	tests := []struct {
		challengeType string
		want          string
	}{
		{"http-8080", "http-01"},
		{"http-443", "http-01"},
		{"http-1", "http-01"},
		{"http-65535", "http-01"},
		{"dns-5353", "dns-01"},
		{"enroll-8443", "enroll-01"},
		{"endorse-9000", "endorse-01"},
	}

	for _, tt := range tests {
		t.Run(tt.challengeType, func(t *testing.T) {
			result := NormalizeChallengeType(tt.challengeType)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestNormalizeChallengeType_StandardPassthrough(t *testing.T) {
	tests := []struct {
		challengeType string
		want          string
	}{
		{"http-01", "http-01"},
		{"dns-01", "dns-01"},
		{"enroll-01", "enroll-01"},
		{"endorse-01", "endorse-01"},
	}

	for _, tt := range tests {
		t.Run(tt.challengeType, func(t *testing.T) {
			result := NormalizeChallengeType(tt.challengeType)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestNormalizeChallengeType_OutOfRangePortErrorPath(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "out_of_range_port_65536",
			challengeType: "http-65536",
			want:          "",
		},
		{
			name:          "zero_port",
			challengeType: "dns-0",
			want:          "",
		},
		{
			name:          "very_large_port",
			challengeType: "enroll-99999",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeChallengeType(tt.challengeType)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestNormalizeChallengeType_UnsupportedBaseDynamic(t *testing.T) {
	tests := []struct {
		name          string
		challengeType string
		want          string
	}{
		{
			name:          "unsupported_dynamic_base_type",
			challengeType: "custom-8080",
			want:          "",
		},
		{
			name:          "unsupported_another_type",
			challengeType: "acme-9000",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeChallengeType(tt.challengeType)
			require.Equal(t, tt.want, result)
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

func TestFormatDynamicChallenge_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		baseType string
		port     string
		want     string
	}{
		{
			name:     "whitespace base type",
			baseType: " ",
			port:     "8080",
			want:     " -8080",
		},
		{
			name:     "whitespace port",
			baseType: "http",
			port:     " ",
			want:     "http- ",
		},
		{
			name:     "both whitespace",
			baseType: " ",
			port:     " ",
			want:     " - ",
		},
		{
			name:     "very long base type",
			baseType: "verylongchallengetypename",
			port:     "8080",
			want:     "verylongchallengetypename-8080",
		},
		{
			name:     "very long port string",
			baseType: "http",
			port:     "123456789",
			want:     "http-123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDynamicChallenge(tt.baseType, tt.port)
			if got != tt.want {
				t.Errorf("FormatDynamicChallenge(%q, %q) = %q, want %q",
					tt.baseType, tt.port, got, tt.want)
			}
		})
	}
}

func TestFormatDynamicChallenge_ValidCombinations(t *testing.T) {
	for baseType, standard := range DynamicChallengePatterns {
		t.Run(baseType, func(t *testing.T) {
			// Format it
			formatted := FormatDynamicChallenge(baseType, "8080")
			require.Equal(t, baseType+"-8080", formatted)

			// Verify it parses correctly
			parsed, _, err := ParseDynamicChallenge(formatted)
			require.NoError(t, err)
			require.Equal(t, baseType, parsed)

			// Verify it normalizes correctly
			normalized := NormalizeChallengeType(formatted)
			require.Equal(t, standard, normalized)
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

func TestNormalizeAndParse(t *testing.T) {
	tests := []struct {
		name           string
		challengeType  string
		wantNormalized string
		wantIsDynamic  bool
	}{
		{
			name:           "dynamic http",
			challengeType:  "http-8080",
			wantNormalized: "http-01",
			wantIsDynamic:  true,
		},
		{
			name:           "standard http",
			challengeType:  "http-01",
			wantNormalized: "http-01",
			wantIsDynamic:  false,
		},
		{
			name:           "dynamic enroll",
			challengeType:  "enroll-8443",
			wantNormalized: "enroll-01",
			wantIsDynamic:  true,
		},
		{
			name:           "standard enroll",
			challengeType:  "enroll-01",
			wantNormalized: "enroll-01",
			wantIsDynamic:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if it's dynamic
			isDynamic := IsDynamicChallenge(tt.challengeType)
			if isDynamic != tt.wantIsDynamic {
				t.Errorf("IsDynamicChallenge() = %v, want %v", isDynamic, tt.wantIsDynamic)
			}

			// Normalize it
			normalized := NormalizeChallengeType(tt.challengeType)
			if normalized != tt.wantNormalized {
				t.Errorf("NormalizeChallengeType() = %v, want %v", normalized, tt.wantNormalized)
			}
		})
	}
}

// =============================================================================
// Constants Tests
// =============================================================================

func TestConstants(t *testing.T) {
	if DefaultHTTPPort != "80" {
		t.Errorf("DefaultHTTPPort = %v, want 80", DefaultHTTPPort)
	}
	if DefaultHTTPSPort != "443" {
		t.Errorf("DefaultHTTPSPort = %v, want 443", DefaultHTTPSPort)
	}
	if DefaultEnrollPort != "8443" {
		t.Errorf("DefaultEnrollPort = %v, want 8443", DefaultEnrollPort)
	}
}

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
