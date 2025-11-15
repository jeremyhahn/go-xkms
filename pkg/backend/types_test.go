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

package backend_test

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
)

func TestKeyAlgorithm_IsSymmetric(t *testing.T) {
	tests := []struct {
		name     string
		algo     backend.KeyAlgorithm
		expected bool
	}{
		{"AES-128-GCM is symmetric", backend.ALG_AES128_GCM, true},
		{"AES-192-GCM is symmetric", backend.ALG_AES192_GCM, true},
		{"AES-256-GCM is symmetric", backend.ALG_AES256_GCM, true},
		{"ChaCha20-Poly1305 is symmetric", backend.ALG_CHACHA20_POLY1305, true},
		{"RSA is not symmetric", backend.ALG_RSA, false},
		{"ECDSA is not symmetric", backend.ALG_ECDSA, false},
		{"Ed25519 is not symmetric", backend.ALG_ED25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.algo.IsSymmetric()
			if result != tt.expected {
				t.Errorf("IsSymmetric() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestKeyAlgorithm_IsAsymmetric(t *testing.T) {
	tests := []struct {
		name     string
		algo     backend.KeyAlgorithm
		expected bool
	}{
		{"RSA is asymmetric", backend.ALG_RSA, true},
		{"ECDSA is asymmetric", backend.ALG_ECDSA, true},
		{"Ed25519 is asymmetric", backend.ALG_ED25519, true},
		{"AES-128-GCM is not asymmetric", backend.ALG_AES128_GCM, false},
		{"AES-192-GCM is not asymmetric", backend.ALG_AES192_GCM, false},
		{"AES-256-GCM is not asymmetric", backend.ALG_AES256_GCM, false},
		{"ChaCha20-Poly1305 is not asymmetric", backend.ALG_CHACHA20_POLY1305, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.algo.IsAsymmetric()
			if result != tt.expected {
				t.Errorf("IsAsymmetric() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestKeyAlgorithm_String(t *testing.T) {
	tests := []struct {
		name     string
		algo     backend.KeyAlgorithm
		expected string
	}{
		{"RSA string", backend.ALG_RSA, "rsa"},
		{"ECDSA string", backend.ALG_ECDSA, "ecdsa"},
		{"Ed25519 string", backend.ALG_ED25519, "ed25519"},
		{"AES-128-GCM string", backend.ALG_AES128_GCM, "aes128-gcm"},
		{"AES-256-GCM string", backend.ALG_AES256_GCM, "aes256-gcm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.algo.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestStaticPassword(t *testing.T) {
	t.Run("Bytes returns correct byte slice", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		result := pw.Bytes()
		expected := []byte("test123")

		if len(result) != len(expected) {
			t.Errorf("Bytes() length = %v, want %v", len(result), len(expected))
		}

		for i := range result {
			if result[i] != expected[i] {
				t.Errorf("Bytes()[%d] = %v, want %v", i, result[i], expected[i])
			}
		}
	})

	t.Run("String returns correct string", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		result, err := pw.String()
		if err != nil {
			t.Errorf("String() unexpected error: %v", err)
		}
		if result != "test123" {
			t.Errorf("String() = %v, want %v", result, "test123")
		}
	})

	t.Run("Clear does not panic", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		// Should not panic
		pw.Clear()
	})
}

func TestNoPassword(t *testing.T) {
	t.Run("Bytes returns nil", func(t *testing.T) {
		pw := backend.NoPassword{}
		result := pw.Bytes()
		if result != nil {
			t.Errorf("Bytes() = %v, want nil", result)
		}
	})

	t.Run("String returns empty string", func(t *testing.T) {
		pw := backend.NoPassword{}
		result, err := pw.String()
		if err != nil {
			t.Errorf("String() unexpected error: %v", err)
		}
		if result != "" {
			t.Errorf("String() = %v, want empty string", result)
		}
	})

	t.Run("Clear does not panic", func(t *testing.T) {
		pw := backend.NoPassword{}
		// Should not panic
		pw.Clear()
	})
}
