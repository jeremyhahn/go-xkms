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

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACMEClientConfig_ToConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    *ACMEClientConfig
		expected *Config
	}{
		{
			name: "complete configuration",
			input: &ACMEClientConfig{
				DirectoryURL:        "https://acme.example.com/directory",
				RequestServerBundle: true,
				TrustedRoots: []string{
					"-----BEGIN CERTIFICATE-----\nROOT1\n-----END CERTIFICATE-----",
					"-----BEGIN CERTIFICATE-----\nROOT2\n-----END CERTIFICATE-----",
				},
			},
			expected: &Config{
				DirectoryURL:        "https://acme.example.com/directory",
				RequestServerBundle: true,
				TrustedRoots: []string{
					"-----BEGIN CERTIFICATE-----\nROOT1\n-----END CERTIFICATE-----",
					"-----BEGIN CERTIFICATE-----\nROOT2\n-----END CERTIFICATE-----",
				},
			},
		},
		{
			name: "minimal configuration",
			input: &ACMEClientConfig{
				DirectoryURL: "https://acme.example.com/directory",
			},
			expected: &Config{
				DirectoryURL:        "https://acme.example.com/directory",
				RequestServerBundle: false,
				TrustedRoots:        nil,
			},
		},
		{
			name: "empty directory URL",
			input: &ACMEClientConfig{
				DirectoryURL:        "",
				RequestServerBundle: true,
				TrustedRoots:        []string{},
			},
			expected: &Config{
				DirectoryURL:        "",
				RequestServerBundle: true,
				TrustedRoots:        []string{},
			},
		},
		{
			name: "nil trusted roots",
			input: &ACMEClientConfig{
				DirectoryURL:        "https://acme.example.com/directory",
				RequestServerBundle: false,
				TrustedRoots:        nil,
			},
			expected: &Config{
				DirectoryURL:        "https://acme.example.com/directory",
				RequestServerBundle: false,
				TrustedRoots:        nil,
			},
		},
		{
			name: "localhost directory URL",
			input: &ACMEClientConfig{
				DirectoryURL:        "http://localhost:8080/directory",
				RequestServerBundle: false,
				TrustedRoots:        nil,
			},
			expected: &Config{
				DirectoryURL:        "http://localhost:8080/directory",
				RequestServerBundle: false,
				TrustedRoots:        nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.ToConfig()

			assert.NotNil(t, result, "ToConfig should never return nil")
			assert.Equal(t, tt.expected.DirectoryURL, result.DirectoryURL, "DirectoryURL should match")
			assert.Equal(t, tt.expected.RequestServerBundle, result.RequestServerBundle, "RequestServerBundle should match")
			assert.Equal(t, tt.expected.TrustedRoots, result.TrustedRoots, "TrustedRoots should match")
		})
	}
}

func TestACMEClientConfig_ToConfig_FieldMapping(t *testing.T) {
	input := &ACMEClientConfig{
		DirectoryURL:        "https://test.acme.com/dir",
		RequestServerBundle: true,
		TrustedRoots: []string{
			"root1",
			"root2",
		},
	}

	result := input.ToConfig()

	assert.Equal(t, input.DirectoryURL, result.DirectoryURL, "DirectoryURL field should be mapped")
	assert.Equal(t, input.RequestServerBundle, result.RequestServerBundle, "RequestServerBundle field should be mapped")
	assert.Equal(t, input.TrustedRoots, result.TrustedRoots, "TrustedRoots field should be mapped")
}

func TestACMEClientConfig_ToConfig_DefaultValues(t *testing.T) {
	input := &ACMEClientConfig{}

	result := input.ToConfig()

	assert.NotNil(t, result, "ToConfig should return a non-nil Config even for empty input")
	assert.Equal(t, "", result.DirectoryURL, "Default DirectoryURL should be empty string")
	assert.False(t, result.RequestServerBundle, "Default RequestServerBundle should be false")
	assert.Nil(t, result.TrustedRoots, "Default TrustedRoots should be nil")
}

func TestACMEClientConfig_ToConfig_MultipleInvocations(t *testing.T) {
	input := &ACMEClientConfig{
		DirectoryURL:        "https://acme.example.com/directory",
		RequestServerBundle: true,
		TrustedRoots:        []string{"root1"},
	}

	result1 := input.ToConfig()
	result2 := input.ToConfig()

	assert.Equal(t, result1.DirectoryURL, result2.DirectoryURL)
	assert.Equal(t, result1.RequestServerBundle, result2.RequestServerBundle)
	assert.Equal(t, result1.TrustedRoots, result2.TrustedRoots)
	assert.NotSame(t, result1, result2, "Each call to ToConfig should return a new instance")
}
