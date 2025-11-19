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

package symmetric

import (
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestNewChaCha20Key tests ChaCha20 key creation with valid key sizes.
func TestNewChaCha20Key(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keySize   int
		wantErr   bool
	}{
		{
			name:      "ChaCha20Poly1305_Valid256Bit",
			algorithm: string(types.SymmetricChaCha20Poly1305),
			keySize:   32, // 256 bits
			wantErr:   false,
		},
		{
			name:      "XChaCha20Poly1305_Valid256Bit",
			algorithm: string(types.SymmetricXChaCha20Poly1305),
			keySize:   32, // 256 bits
			wantErr:   false,
		},
		{
			name:      "ChaCha20_Invalid128BitKey",
			algorithm: string(types.SymmetricChaCha20Poly1305),
			keySize:   16, // 128 bits - invalid for ChaCha20
			wantErr:   true,
		},
		{
			name:      "ChaCha20_Invalid192BitKey",
			algorithm: string(types.SymmetricChaCha20Poly1305),
			keySize:   24, // 192 bits - invalid for ChaCha20
			wantErr:   true,
		},
		{
			name:      "XChaCha20_Invalid128BitKey",
			algorithm: string(types.SymmetricXChaCha20Poly1305),
			keySize:   16, // 128 bits - invalid for ChaCha20
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random key of the specified size
			keyData := make([]byte, tt.keySize)
			if _, err := rand.Read(keyData); err != nil {
				t.Fatalf("failed to generate random key: %v", err)
			}

			key, err := NewChaCha20Key(tt.algorithm, keyData)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewChaCha20Key() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && key == nil {
				t.Fatal("NewChaCha20Key() returned nil key for valid input")
			}

			if !tt.wantErr {
				// Verify key properties
				if key.Algorithm() != tt.algorithm {
					t.Errorf("Algorithm() = %s, want %s", key.Algorithm(), tt.algorithm)
				}
				if key.KeySize() != tt.keySize*8 {
					t.Errorf("KeySize() = %d, want %d", key.KeySize(), tt.keySize*8)
				}

				// Verify raw key access
				rawKey, err := key.Raw()
				if err != nil {
					t.Fatalf("Raw() failed: %v", err)
				}
				if len(rawKey) != tt.keySize {
					t.Errorf("Raw() length = %d, want %d", len(rawKey), tt.keySize)
				}
			}
		})
	}
}

// TestChaCha20KeyRawCopiesData tests that Raw() returns a copy, not the original.
func TestChaCha20KeyRawCopiesData(t *testing.T) {
	// Generate a key
	keyData := make([]byte, 32)
	if _, err := rand.Read(keyData); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	key, err := NewChaCha20Key(string(types.SymmetricChaCha20Poly1305), keyData)
	if err != nil {
		t.Fatalf("NewChaCha20Key() failed: %v", err)
	}

	// Get raw key
	rawKey, err := key.Raw()
	if err != nil {
		t.Fatalf("Raw() failed: %v", err)
	}

	// Modify the returned raw key
	originalValue := rawKey[0]
	rawKey[0] = ^rawKey[0] // Flip bits

	// Get raw key again
	rawKey2, err := key.Raw()
	if err != nil {
		t.Fatalf("Raw() failed on second call: %v", err)
	}

	// Verify the key wasn't modified
	if rawKey2[0] != originalValue {
		t.Errorf("Raw() returned modifiable data: first byte changed from %d to %d", originalValue, rawKey2[0])
	}
}

// TestChaCha20KeyInterfaceCompliance verifies the key implements SymmetricKey.
func TestChaCha20KeyInterfaceCompliance(t *testing.T) {
	keyData := make([]byte, 32)
	if _, err := rand.Read(keyData); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	key, err := NewChaCha20Key(string(types.SymmetricChaCha20Poly1305), keyData)
	if err != nil {
		t.Fatalf("NewChaCha20Key() failed: %v", err)
	}

	// Verify it satisfies the SymmetricKey interface
	_ = key
}

// BenchmarkNewChaCha20Key benchmarks ChaCha20 key creation.
func BenchmarkNewChaCha20Key(b *testing.B) {
	keyData := make([]byte, 32)
	if _, err := rand.Read(keyData); err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewChaCha20Key(string(types.SymmetricChaCha20Poly1305), keyData)
		if err != nil {
			b.Fatalf("NewChaCha20Key() failed: %v", err)
		}
	}
}

// BenchmarkChaCha20KeyRaw benchmarks Raw() method.
func BenchmarkChaCha20KeyRaw(b *testing.B) {
	keyData := make([]byte, 32)
	if _, err := rand.Read(keyData); err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	key, err := NewChaCha20Key(string(types.SymmetricChaCha20Poly1305), keyData)
	if err != nil {
		b.Fatalf("NewChaCha20Key() failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := key.Raw()
		if err != nil {
			b.Fatalf("Raw() failed: %v", err)
		}
	}
}
