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

package grpc

import (
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		hashStr  string
		expected crypto.Hash
		wantErr  bool
	}{
		{
			name:     "Empty string defaults to SHA256",
			hashStr:  "",
			expected: crypto.SHA256,
		},
		{
			name:     "SHA256",
			hashStr:  "SHA256",
			expected: crypto.SHA256,
		},
		{
			name:     "SHA384",
			hashStr:  "SHA384",
			expected: crypto.SHA384,
		},
		{
			name:     "SHA512",
			hashStr:  "SHA512",
			expected: crypto.SHA512,
		},
		{
			name:     "SHA3-256",
			hashStr:  "SHA3-256",
			expected: crypto.SHA3_256,
		},
		// A name the caller did supply that does not resolve is an error, not
		// a SHA-256 substitution: the caller cannot tell a downgrade from
		// having got what it asked for.
		{
			name:    "Unknown is an error",
			hashStr: "unknown",
			wantErr: true,
		},
		{
			name:    "Weak hash is refused",
			hashStr: "MD5",
			wantErr: true,
		},
		{
			name:    "SHA-1 is refused",
			hashStr: "SHA-1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHashAlgorithm(tt.hashStr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Expected an error for %q, got hash %v", tt.hashStr, result)
				}
				if !errors.Is(err, xkms.ErrInvalidHashFunction) {
					t.Errorf("Expected ErrInvalidHashFunction, got %v", err)
				}
				if result != 0 {
					t.Errorf("Expected the zero hash on refusal, got %v", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected string
	}{
		{
			name: "Symmetric algorithm",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			expected: string(types.SymmetricAES256GCM),
		},
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			expected: x509.RSA.String(),
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			expected: x509.ECDSA.String(),
		},
		{
			name: "Ed25519 algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			expected: x509.Ed25519.String(),
		},
		{
			name: "Unknown algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs.AlgorithmString()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}

	// A descriptor claiming both families must display the family
	// KeyAttributes.ID addresses it under. This transport's local
	// getAlgorithmString used to give SymmetricAlgorithm precedence over
	// KeyAlgorithm — the opposite of ID's order (go-xkms#336). The expected
	// value is computed from ID's own resolution (its final colon-separated
	// segment, lowercased there for storage) rather than hardcoded.
	t.Run("Two-family descriptor agrees with ID", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyAlgorithm:       x509.RSA,
		}
		id := attrs.ID()
		want := id[strings.LastIndex(id, ":")+1:]
		result := attrs.AlgorithmString()
		if !strings.EqualFold(result, want) {
			t.Errorf("displayed algorithm %q disagrees with ID's family %q", result, want)
		}
	})
}
