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
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		data *types.EncryptedData
	}{
		{
			name: "AES-256-GCM",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("encrypted data here"),
			},
		},
		{
			name: "AES-128-GCM",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES128_GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			marshaled, err := Marshal(tt.data)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Unmarshal
			unmarshaled, err := Unmarshal(marshaled)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify
			if unmarshaled.Algorithm != tt.data.Algorithm {
				t.Errorf("Algorithm mismatch: got %s, want %s", unmarshaled.Algorithm, tt.data.Algorithm)
			}
			if !bytes.Equal(unmarshaled.Nonce, tt.data.Nonce) {
				t.Errorf("Nonce mismatch")
			}
			if !bytes.Equal(unmarshaled.Tag, tt.data.Tag) {
				t.Errorf("Tag mismatch")
			}
			if !bytes.Equal(unmarshaled.Ciphertext, tt.data.Ciphertext) {
				t.Errorf("Ciphertext mismatch")
			}
		})
	}
}

func TestMarshalNil(t *testing.T) {
	_, err := Marshal(nil)
	if err == nil {
		t.Error("Expected error for nil EncryptedData")
	}
}

func TestUnmarshalInvalidVersion(t *testing.T) {
	data := []byte{0x02} // Invalid version
	_, err := Unmarshal(data)
	if err == nil {
		t.Error("Expected error for invalid version")
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	data := []byte{}
	_, err := Unmarshal(data)
	if err == nil {
		t.Error("Expected error for too short data")
	}
}

func TestMarshalEdgeCases(t *testing.T) {
	t.Run("algorithm too long", func(t *testing.T) {
		// Create an algorithm string longer than 65535 bytes
		longAlg := make([]byte, 65536)
		for i := range longAlg {
			longAlg[i] = 'A'
		}
		data := &types.EncryptedData{
			Algorithm:  string(longAlg),
			Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Ciphertext: []byte("test"),
		}
		_, err := Marshal(data)
		if err == nil {
			t.Error("Expected error for algorithm too long")
		}
	})

	t.Run("nonce too long", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(backend.ALG_AES256_GCM),
			Nonce:      make([]byte, 65536),
			Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Ciphertext: []byte("test"),
		}
		_, err := Marshal(data)
		if err == nil {
			t.Error("Expected error for nonce too long")
		}
	})

	t.Run("tag too long", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(backend.ALG_AES256_GCM),
			Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			Tag:        make([]byte, 65536),
			Ciphertext: []byte("test"),
		}
		_, err := Marshal(data)
		if err == nil {
			t.Error("Expected error for tag too long")
		}
	})
}

func TestUnmarshalEdgeCases(t *testing.T) {
	t.Run("truncated at algorithm length", func(t *testing.T) {
		data := []byte{0x01} // Just version, no algorithm length
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at algorithm length")
		}
	})

	t.Run("truncated at algorithm data", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x05} // Version + algo length = 5, but no algo data
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at algorithm")
		}
	})

	t.Run("truncated at nonce length", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S'} // Version + algo, no nonce length
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at nonce length")
		}
	})

	t.Run("truncated at nonce data", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S', 0x00, 0x0C} // + nonce len = 12, no data
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at nonce")
		}
	})

	t.Run("truncated at tag length", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S', 0x00, 0x02, 1, 2} // Version + algo + nonce, no tag len
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at tag length")
		}
	})

	t.Run("truncated at tag data", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S', 0x00, 0x02, 1, 2, 0x00, 0x04} // + tag len = 4, no data
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at tag")
		}
	})

	t.Run("truncated at ciphertext length", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S', 0x00, 0x02, 1, 2, 0x00, 0x02, 3, 4} // No ciphertext len
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at ciphertext length")
		}
	})

	t.Run("truncated at ciphertext data", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x03, 'A', 'E', 'S', 0x00, 0x02, 1, 2, 0x00, 0x02, 3, 4, 0x00, 0x00, 0x00, 0x05} // cipher len = 5, no data
		_, err := Unmarshal(data)
		if err == nil {
			t.Error("Expected error for truncated data at ciphertext")
		}
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		data    *types.EncryptedData
		wantErr bool
	}{
		{
			name: "valid AES-256-GCM",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: false,
		},
		{
			name: "valid ChaCha20-Poly1305",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricChaCha20Poly1305),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: false,
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name: "missing algorithm",
			data: &types.EncryptedData{
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "missing nonce",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "missing tag",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "missing ciphertext",
			data: &types.EncryptedData{
				Algorithm: string(backend.ALG_AES256_GCM),
				Nonce:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			wantErr: true,
		},
		{
			name: "nonce too short for GCM",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Nonce:      []byte{1, 2, 3},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "tag wrong size for GCM",
			data: &types.EncryptedData{
				Algorithm:  string(backend.ALG_AES256_GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "nonce wrong size for ChaCha20-Poly1305",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricChaCha20Poly1305),
				Nonce:      []byte{1, 2, 3}, // Wrong size
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "tag wrong size for ChaCha20-Poly1305",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricChaCha20Poly1305),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3}, // Wrong size
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMarshalEmpty tests marshaling with empty (but not nil) fields
func TestMarshalEmpty(t *testing.T) {
	// Empty algorithm - should succeed (marshals 0-length string)
	data := &types.EncryptedData{
		Algorithm:  "",
		Nonce:      []byte{1, 2, 3},
		Tag:        []byte{1, 2, 3},
		Ciphertext: []byte("test"),
	}
	marshaled, err := Marshal(data)
	if err != nil {
		t.Errorf("Marshal with empty algorithm failed: %v", err)
	}
	if marshaled == nil {
		t.Error("Expected non-nil result for empty algorithm")
	}

	// Empty nonce - should succeed
	data2 := &types.EncryptedData{
		Algorithm:  string(backend.ALG_AES256_GCM),
		Nonce:      []byte{},
		Tag:        []byte{1, 2, 3},
		Ciphertext: []byte("test"),
	}
	marshaled2, err := Marshal(data2)
	if err != nil {
		t.Errorf("Marshal with empty nonce failed: %v", err)
	}
	if marshaled2 == nil {
		t.Error("Expected non-nil result for empty nonce")
	}

	// Empty tag - should succeed
	data3 := &types.EncryptedData{
		Algorithm:  string(backend.ALG_AES256_GCM),
		Nonce:      []byte{1, 2, 3},
		Tag:        []byte{},
		Ciphertext: []byte("test"),
	}
	marshaled3, err := Marshal(data3)
	if err != nil {
		t.Errorf("Marshal with empty tag failed: %v", err)
	}
	if marshaled3 == nil {
		t.Error("Expected non-nil result for empty tag")
	}

	// Empty ciphertext - should succeed
	data4 := &types.EncryptedData{
		Algorithm:  string(backend.ALG_AES256_GCM),
		Nonce:      []byte{1, 2, 3},
		Tag:        []byte{1, 2, 3},
		Ciphertext: []byte{},
	}
	marshaled4, err := Marshal(data4)
	if err != nil {
		t.Errorf("Marshal with empty ciphertext failed: %v", err)
	}
	if marshaled4 == nil {
		t.Error("Expected non-nil result for empty ciphertext")
	}
}

// TestMarshalCiphertextTooLong tests marshaling with ciphertext exceeding uint32 max
func TestMarshalCiphertextTooLong(t *testing.T) {
	// This test would require creating a byte slice larger than 4GB
	// which is impractical in unit tests. Just document the edge case.
	t.Skip("Skipping test for ciphertext > 4GB - impractical for unit tests")
}

// TestMarshalWithLargeFields tests marshal with fields at boundary sizes
func TestMarshalWithLargeFields(t *testing.T) {
	t.Run("algorithm at max size", func(t *testing.T) {
		// Algorithm at exactly 65535 bytes (max uint16)
		alg := make([]byte, 65535)
		for i := range alg {
			alg[i] = 'A'
		}
		data := &types.EncryptedData{
			Algorithm:  string(alg),
			Nonce:      []byte{1, 2, 3},
			Tag:        []byte{1, 2, 3},
			Ciphertext: []byte("test"),
		}
		marshaled, err := Marshal(data)
		if err != nil {
			t.Errorf("Marshal with max algorithm size failed: %v", err)
		}
		if marshaled == nil {
			t.Error("Expected non-nil result")
		}

		// Verify round-trip
		unmarshaled, err := Unmarshal(marshaled)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if unmarshaled.Algorithm != string(alg) {
			t.Error("Algorithm mismatch after round-trip")
		}
	})

	t.Run("nonce at max size", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(backend.ALG_AES256_GCM),
			Nonce:      make([]byte, 65535), // Max uint16
			Tag:        []byte{1, 2, 3},
			Ciphertext: []byte("test"),
		}
		marshaled, err := Marshal(data)
		if err != nil {
			t.Errorf("Marshal with max nonce size failed: %v", err)
		}
		if marshaled == nil {
			t.Error("Expected non-nil result")
		}
	})

	t.Run("tag at max size", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(backend.ALG_AES256_GCM),
			Nonce:      []byte{1, 2, 3},
			Tag:        make([]byte, 65535), // Max uint16
			Ciphertext: []byte("test"),
		}
		marshaled, err := Marshal(data)
		if err != nil {
			t.Errorf("Marshal with max tag size failed: %v", err)
		}
		if marshaled == nil {
			t.Error("Expected non-nil result")
		}
	})

	t.Run("large ciphertext", func(t *testing.T) {
		// Test with 10MB ciphertext
		data := &types.EncryptedData{
			Algorithm:  string(backend.ALG_AES256_GCM),
			Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Ciphertext: make([]byte, 10*1024*1024), // 10 MB
		}
		marshaled, err := Marshal(data)
		if err != nil {
			t.Fatalf("Marshal with 10MB ciphertext failed: %v", err)
		}

		// Verify round-trip
		unmarshaled, err := Unmarshal(marshaled)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if len(unmarshaled.Ciphertext) != len(data.Ciphertext) {
			t.Errorf("Ciphertext length mismatch: got %d, want %d", len(unmarshaled.Ciphertext), len(data.Ciphertext))
		}
	})
}

// TestValidateXChaCha20Poly1305 tests validation for XChaCha20-Poly1305
func TestValidateXChaCha20Poly1305(t *testing.T) {
	t.Run("valid XChaCha20-Poly1305", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(types.SymmetricXChaCha20Poly1305),
			Nonce:      make([]byte, 24), // 24-byte nonce
			Tag:        make([]byte, 16), // 16-byte tag
			Ciphertext: []byte("test"),
		}
		err := Validate(data)
		if err != nil {
			t.Errorf("Validate() failed for valid XChaCha20-Poly1305: %v", err)
		}
	})

	t.Run("XChaCha20-Poly1305 nonce wrong size", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(types.SymmetricXChaCha20Poly1305),
			Nonce:      make([]byte, 12), // Wrong size, should be 24
			Tag:        make([]byte, 16),
			Ciphertext: []byte("test"),
		}
		err := Validate(data)
		if err == nil {
			t.Error("Expected error for XChaCha20-Poly1305 with wrong nonce size")
		}
	})

	t.Run("XChaCha20-Poly1305 tag wrong size", func(t *testing.T) {
		data := &types.EncryptedData{
			Algorithm:  string(types.SymmetricXChaCha20Poly1305),
			Nonce:      make([]byte, 24),
			Tag:        make([]byte, 8), // Wrong size, should be 16
			Ciphertext: []byte("test"),
		}
		err := Validate(data)
		if err == nil {
			t.Error("Expected error for XChaCha20-Poly1305 with wrong tag size")
		}
	})
}

// TestValidateAES variants
func TestValidateAESVariants(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"AES-128-GCM", string(types.SymmetricAES128GCM)},
		{"AES-192-GCM", string(types.SymmetricAES192GCM)},
		{"AES-256-GCM", string(types.SymmetricAES256GCM)},
	}

	for _, tt := range tests {
		t.Run(tt.name+" valid", func(t *testing.T) {
			data := &types.EncryptedData{
				Algorithm:  tt.algorithm,
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test"),
			}
			err := Validate(data)
			if err != nil {
				t.Errorf("Validate() failed for valid %s: %v", tt.name, err)
			}
		})

		t.Run(tt.name+" nonce too short", func(t *testing.T) {
			data := &types.EncryptedData{
				Algorithm:  tt.algorithm,
				Nonce:      make([]byte, 8), // Too short
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test"),
			}
			err := Validate(data)
			if err == nil {
				t.Errorf("Expected error for %s with short nonce", tt.name)
			}
		})

		t.Run(tt.name+" tag wrong size", func(t *testing.T) {
			data := &types.EncryptedData{
				Algorithm:  tt.algorithm,
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 12), // Wrong size
				Ciphertext: []byte("test"),
			}
			err := Validate(data)
			if err == nil {
				t.Errorf("Expected error for %s with wrong tag size", tt.name)
			}
		})
	}
}

// TestValidateUnknownAlgorithm tests validation with unknown algorithm
func TestValidateUnknownAlgorithm(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  "unknown-algorithm",
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
		Ciphertext: []byte("test"),
	}
	// Should pass basic validation even with unknown algorithm
	err := Validate(data)
	if err != nil {
		t.Errorf("Validate() failed for unknown algorithm: %v", err)
	}
}

// TestMarshalUnmarshalRoundTrip tests various algorithms through marshal/unmarshal
func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data *types.EncryptedData
	}{
		{
			name: "AES-128-GCM",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricAES128GCM),
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test data"),
			},
		},
		{
			name: "AES-192-GCM",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricAES192GCM),
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test data"),
			},
		},
		{
			name: "ChaCha20-Poly1305",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricChaCha20Poly1305),
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test data"),
			},
		},
		{
			name: "XChaCha20-Poly1305",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricXChaCha20Poly1305),
				Nonce:      make([]byte, 24),
				Tag:        make([]byte, 16),
				Ciphertext: []byte("test data"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			marshaled, err := Marshal(tt.data)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			// Unmarshal
			unmarshaled, err := Unmarshal(marshaled)
			if err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			// Validate
			if err := Validate(unmarshaled); err != nil {
				t.Errorf("Validate() failed: %v", err)
			}

			// Verify fields match
			if unmarshaled.Algorithm != tt.data.Algorithm {
				t.Errorf("Algorithm mismatch: got %s, want %s", unmarshaled.Algorithm, tt.data.Algorithm)
			}
			if !bytes.Equal(unmarshaled.Nonce, tt.data.Nonce) {
				t.Error("Nonce mismatch")
			}
			if !bytes.Equal(unmarshaled.Tag, tt.data.Tag) {
				t.Error("Tag mismatch")
			}
			if !bytes.Equal(unmarshaled.Ciphertext, tt.data.Ciphertext) {
				t.Error("Ciphertext mismatch")
			}
		})
	}
}

// TestMarshalLargeData tests marshaling and unmarshaling with large data
func TestMarshalLargeData(t *testing.T) {
	// Test with 1MB of ciphertext
	largeData := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
		Ciphertext: make([]byte, 1024*1024), // 1 MB
	}

	marshaled, err := Marshal(largeData)
	if err != nil {
		t.Fatalf("Marshal() failed for large data: %v", err)
	}

	unmarshaled, err := Unmarshal(marshaled)
	if err != nil {
		t.Fatalf("Unmarshal() failed for large data: %v", err)
	}

	if len(unmarshaled.Ciphertext) != len(largeData.Ciphertext) {
		t.Errorf("Ciphertext length mismatch: got %d, want %d", len(unmarshaled.Ciphertext), len(largeData.Ciphertext))
	}
}

// TestMarshalAllFields tests marshaling with all fields populated
func TestMarshalAllFields(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Ciphertext: []byte("test ciphertext data"),
	}

	marshaled, err := Marshal(data)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	// Verify the marshaled data contains expected structure
	if len(marshaled) == 0 {
		t.Error("Marshal() returned empty data")
	}

	// Verify version byte
	if marshaled[0] != 0x01 {
		t.Errorf("Expected version 0x01, got 0x%02x", marshaled[0])
	}

	// Round-trip test
	unmarshaled, err := Unmarshal(marshaled)
	if err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if unmarshaled.Algorithm != data.Algorithm {
		t.Errorf("Algorithm mismatch: got %s, want %s", unmarshaled.Algorithm, data.Algorithm)
	}
	if !bytes.Equal(unmarshaled.Nonce, data.Nonce) {
		t.Error("Nonce mismatch")
	}
	if !bytes.Equal(unmarshaled.Tag, data.Tag) {
		t.Error("Tag mismatch")
	}
	if !bytes.Equal(unmarshaled.Ciphertext, data.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

// TestMarshalDifferentAlgorithms tests marshaling with different algorithm strings
func TestMarshalDifferentAlgorithms(t *testing.T) {
	algorithms := []string{
		string(types.SymmetricAES128GCM),
		string(types.SymmetricAES192GCM),
		string(types.SymmetricAES256GCM),
		string(types.SymmetricChaCha20Poly1305),
		string(types.SymmetricXChaCha20Poly1305),
		"custom-algorithm-name",
		"a", // Single character
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			data := &types.EncryptedData{
				Algorithm:  algo,
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			}

			marshaled, err := Marshal(data)
			if err != nil {
				t.Fatalf("Marshal() failed for algorithm %s: %v", algo, err)
			}

			unmarshaled, err := Unmarshal(marshaled)
			if err != nil {
				t.Fatalf("Unmarshal() failed for algorithm %s: %v", algo, err)
			}

			if unmarshaled.Algorithm != algo {
				t.Errorf("Algorithm mismatch: got %s, want %s", unmarshaled.Algorithm, algo)
			}
		})
	}
}

// TestMarshalVaryingSizes tests marshaling with various field sizes
func TestMarshalVaryingSizes(t *testing.T) {
	tests := []struct {
		name       string
		nonceSize  int
		tagSize    int
		cipherSize int
	}{
		{"tiny", 1, 1, 1},
		{"small", 8, 8, 16},
		{"medium", 16, 16, 256},
		{"large", 32, 32, 4096},
		{"very large nonce", 1024, 16, 128},
		{"very large tag", 12, 1024, 128},
		{"very large cipher", 12, 16, 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &types.EncryptedData{
				Algorithm:  string(types.SymmetricAES256GCM),
				Nonce:      make([]byte, tt.nonceSize),
				Tag:        make([]byte, tt.tagSize),
				Ciphertext: make([]byte, tt.cipherSize),
			}

			// Fill with pattern data
			for i := range data.Nonce {
				data.Nonce[i] = byte(i % 256)
			}
			for i := range data.Tag {
				data.Tag[i] = byte(i % 256)
			}
			for i := range data.Ciphertext {
				data.Ciphertext[i] = byte(i % 256)
			}

			marshaled, err := Marshal(data)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			unmarshaled, err := Unmarshal(marshaled)
			if err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if !bytes.Equal(unmarshaled.Nonce, data.Nonce) {
				t.Error("Nonce mismatch")
			}
			if !bytes.Equal(unmarshaled.Tag, data.Tag) {
				t.Error("Tag mismatch")
			}
			if !bytes.Equal(unmarshaled.Ciphertext, data.Ciphertext) {
				t.Error("Ciphertext mismatch")
			}
		})
	}
}
