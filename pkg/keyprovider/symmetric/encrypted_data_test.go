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

package symmetric

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		data *types.EncryptedData
	}{
		{
			name: "AES-256-GCM",
			data: &types.EncryptedData{
				Algorithm:  "aes256-gcm",
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("encrypted data here"),
			},
		},
		{
			name: "AES-128-GCM",
			data: &types.EncryptedData{
				Algorithm:  "aes128-gcm",
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
			Algorithm:  "aes256-gcm",
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
			Algorithm:  "aes256-gcm",
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
				Algorithm:  "aes256-gcm",
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
				Algorithm:  "aes256-gcm",
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "missing tag",
			data: &types.EncryptedData{
				Algorithm:  "aes256-gcm",
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "missing ciphertext",
			data: &types.EncryptedData{
				Algorithm: "aes256-gcm",
				Nonce:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			wantErr: true,
		},
		{
			name: "nonce too short for GCM",
			data: &types.EncryptedData{
				Algorithm:  "aes256-gcm",
				Nonce:      []byte{1, 2, 3},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "tag wrong size for GCM",
			data: &types.EncryptedData{
				Algorithm:  "aes256-gcm",
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
		Algorithm:  "aes256-gcm",
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
		Algorithm:  "aes256-gcm",
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
		Algorithm:  "aes256-gcm",
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
			Algorithm:  "aes256-gcm",
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
			Algorithm:  "aes256-gcm",
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
			Algorithm:  "aes256-gcm",
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

// TestMarshalUnmarshalRoundTrip_EmptyCiphertext verifies that empty ciphertext
// survives a marshal/unmarshal roundtrip correctly. This is a regression test
// to ensure the wire format correctly handles zero-length ciphertext.
func TestMarshalUnmarshalRoundTrip_EmptyCiphertext(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Ciphertext: []byte{},
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err, "Marshal should succeed with empty ciphertext")

	unmarshaled, err := Unmarshal(marshaled)
	require.NoError(t, err, "Unmarshal should succeed with empty ciphertext")

	assert.Equal(t, data.Algorithm, unmarshaled.Algorithm, "algorithm must survive roundtrip")
	assert.Equal(t, data.Nonce, unmarshaled.Nonce, "nonce must survive roundtrip")
	assert.Equal(t, data.Tag, unmarshaled.Tag, "tag must survive roundtrip")
	assert.Equal(t, 0, len(unmarshaled.Ciphertext), "ciphertext must be empty after roundtrip")
}

// TestMarshalUnmarshalRoundTrip_ZeroLengthFields verifies that zero-length
// nonce, tag, and algorithm all survive a marshal/unmarshal roundtrip. This
// exercises the wire format's handling of uint16(0) length prefixes.
func TestMarshalUnmarshalRoundTrip_ZeroLengthFields(t *testing.T) {
	tests := []struct {
		name string
		data *types.EncryptedData
	}{
		{
			name: "empty algorithm with populated fields",
			data: &types.EncryptedData{
				Algorithm:  "",
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("ciphertext payload"),
			},
		},
		{
			name: "empty nonce",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricAES256GCM),
				Nonce:      []byte{},
				Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Ciphertext: []byte("ciphertext payload"),
			},
		},
		{
			name: "empty tag",
			data: &types.EncryptedData{
				Algorithm:  string(types.SymmetricAES256GCM),
				Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Tag:        []byte{},
				Ciphertext: []byte("ciphertext payload"),
			},
		},
		{
			name: "all fields empty",
			data: &types.EncryptedData{
				Algorithm:  "",
				Nonce:      []byte{},
				Tag:        []byte{},
				Ciphertext: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marshaled, err := Marshal(tt.data)
			require.NoError(t, err, "Marshal should succeed")

			unmarshaled, err := Unmarshal(marshaled)
			require.NoError(t, err, "Unmarshal should succeed")

			assert.Equal(t, tt.data.Algorithm, unmarshaled.Algorithm, "algorithm mismatch")
			assert.Equal(t, len(tt.data.Nonce), len(unmarshaled.Nonce), "nonce length mismatch")
			assert.Equal(t, len(tt.data.Tag), len(unmarshaled.Tag), "tag length mismatch")
			assert.Equal(t, len(tt.data.Ciphertext), len(unmarshaled.Ciphertext), "ciphertext length mismatch")

			if len(tt.data.Nonce) > 0 {
				assert.Equal(t, tt.data.Nonce, unmarshaled.Nonce, "nonce content mismatch")
			}
			if len(tt.data.Tag) > 0 {
				assert.Equal(t, tt.data.Tag, unmarshaled.Tag, "tag content mismatch")
			}
			if len(tt.data.Ciphertext) > 0 {
				assert.Equal(t, tt.data.Ciphertext, unmarshaled.Ciphertext, "ciphertext content mismatch")
			}
		})
	}
}

// TestMarshalErrorMessages verifies that Marshal returns descriptive error
// messages for each invalid input, so callers can diagnose the issue.
func TestMarshalErrorMessages(t *testing.T) {
	t.Run("nil returns descriptive error", func(t *testing.T) {
		_, err := Marshal(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil", "error should mention nil")
	})

	t.Run("algorithm too long includes byte count", func(t *testing.T) {
		longAlg := strings.Repeat("X", 65536)
		ed := &types.EncryptedData{
			Algorithm:  longAlg,
			Nonce:      []byte{1},
			Tag:        []byte{1},
			Ciphertext: []byte{1},
		}
		_, err := Marshal(ed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm string too long")
		assert.Contains(t, err.Error(), "65536")
	})

	t.Run("nonce too long includes byte count", func(t *testing.T) {
		ed := &types.EncryptedData{
			Algorithm:  "alg",
			Nonce:      make([]byte, 65536),
			Tag:        []byte{1},
			Ciphertext: []byte{1},
		}
		_, err := Marshal(ed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce too long")
		assert.Contains(t, err.Error(), "65536")
	})

	t.Run("tag too long includes byte count", func(t *testing.T) {
		ed := &types.EncryptedData{
			Algorithm:  "alg",
			Nonce:      []byte{1},
			Tag:        make([]byte, 65536),
			Ciphertext: []byte{1},
		}
		_, err := Marshal(ed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tag too long")
		assert.Contains(t, err.Error(), "65536")
	})
}

// TestUnmarshalErrorMessages verifies that Unmarshal returns descriptive error
// messages that help diagnose truncated or malformed wire data.
func TestUnmarshalErrorMessages(t *testing.T) {
	t.Run("empty data mentions minimum size", func(t *testing.T) {
		_, err := Unmarshal([]byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("wrong version includes version byte", func(t *testing.T) {
		_, err := Unmarshal([]byte{0xFF})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported version")
		assert.Contains(t, err.Error(), "0xff")
	})

	t.Run("version 0x00 is rejected", func(t *testing.T) {
		_, err := Unmarshal([]byte{0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported version")
	})

	t.Run("truncated algorithm length mentions failure", func(t *testing.T) {
		// Version byte only, no room for the uint16 algorithm length
		_, err := Unmarshal([]byte{0x01, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm")
	})

	t.Run("truncated ciphertext data mentions failure", func(t *testing.T) {
		// Valid header up through ciphertext length, but ciphertext data missing
		data := []byte{
			0x01,       // version
			0x00, 0x01, // algo len = 1
			'A',        // algo
			0x00, 0x01, // nonce len = 1
			0x01,       // nonce
			0x00, 0x01, // tag len = 1
			0x01,                   // tag
			0x00, 0x00, 0x00, 0x0A, // ciphertext len = 10 (but no data follows)
		}
		_, err := Unmarshal(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext")
	})
}

// TestValidateErrorMessages verifies that Validate returns specific error
// messages for each invalid condition.
func TestValidateErrorMessages(t *testing.T) {
	t.Run("nil mentions nil", func(t *testing.T) {
		err := Validate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("empty algorithm", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Nonce:      []byte{1},
			Tag:        []byte{1},
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm is required")
	})

	t.Run("empty nonce", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  "alg",
			Tag:        []byte{1},
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce is required")
	})

	t.Run("empty tag", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  "alg",
			Nonce:      []byte{1},
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tag is required")
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm: "alg",
			Nonce:     []byte{1},
			Tag:       []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext is required")
	})

	t.Run("GCM nonce too short includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricAES256GCM),
			Nonce:      make([]byte, 4),
			Tag:        make([]byte, 16),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GCM nonce must be at least 12 bytes")
		assert.Contains(t, err.Error(), "4")
	})

	t.Run("GCM tag wrong size includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricAES128GCM),
			Nonce:      make([]byte, 12),
			Tag:        make([]byte, 8),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GCM tag must be 16 bytes")
		assert.Contains(t, err.Error(), "8")
	})

	t.Run("ChaCha20 nonce wrong size includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricChaCha20Poly1305),
			Nonce:      make([]byte, 16),
			Tag:        make([]byte, 16),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ChaCha20-Poly1305 nonce must be 12 bytes")
		assert.Contains(t, err.Error(), "16")
	})

	t.Run("ChaCha20 tag wrong size includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricChaCha20Poly1305),
			Nonce:      make([]byte, 12),
			Tag:        make([]byte, 32),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Poly1305 tag must be 16 bytes")
		assert.Contains(t, err.Error(), "32")
	})

	t.Run("XChaCha20 nonce wrong size includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricXChaCha20Poly1305),
			Nonce:      make([]byte, 12),
			Tag:        make([]byte, 16),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "XChaCha20-Poly1305 nonce must be 24 bytes")
		assert.Contains(t, err.Error(), "12")
	})

	t.Run("XChaCha20 tag wrong size includes size", func(t *testing.T) {
		err := Validate(&types.EncryptedData{
			Algorithm:  string(types.SymmetricXChaCha20Poly1305),
			Nonce:      make([]byte, 24),
			Tag:        make([]byte, 4),
			Ciphertext: []byte{1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Poly1305 tag must be 16 bytes")
		assert.Contains(t, err.Error(), "4")
	})
}

// TestMarshalUnmarshalRoundTrip_NilFields verifies that nil nonce, tag, and
// ciphertext slices behave identically to empty slices through the wire format,
// since the wire format encodes length 0 for nil slices.
func TestMarshalUnmarshalRoundTrip_NilFields(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      nil,
		Tag:        nil,
		Ciphertext: nil,
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err, "Marshal should succeed with nil fields")

	unmarshaled, err := Unmarshal(marshaled)
	require.NoError(t, err, "Unmarshal should succeed with nil fields")

	assert.Equal(t, data.Algorithm, unmarshaled.Algorithm)
	// After roundtrip, nil slices become zero-length allocated slices
	assert.Equal(t, 0, len(unmarshaled.Nonce), "nonce should be zero-length")
	assert.Equal(t, 0, len(unmarshaled.Tag), "tag should be zero-length")
	assert.Equal(t, 0, len(unmarshaled.Ciphertext), "ciphertext should be zero-length")
}

// TestMarshalWireFormatStructure verifies the exact wire format layout produced
// by Marshal: version byte, then length-prefixed algorithm, nonce, tag, and
// ciphertext. This ensures forward compatibility with other implementations.
func TestMarshalWireFormatStructure(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  "AES",
		Nonce:      []byte{0xAA, 0xBB},
		Tag:        []byte{0xCC},
		Ciphertext: []byte{0xDD, 0xEE, 0xFF},
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err)

	// Expected wire layout:
	// [0x01]                      version
	// [0x00, 0x03]                algorithm length = 3
	// [0x41, 0x45, 0x53]          "AES"
	// [0x00, 0x02]                nonce length = 2
	// [0xAA, 0xBB]                nonce
	// [0x00, 0x01]                tag length = 1
	// [0xCC]                      tag
	// [0x00, 0x00, 0x00, 0x03]    ciphertext length = 3
	// [0xDD, 0xEE, 0xFF]          ciphertext
	expected := []byte{
		0x01,       // version
		0x00, 0x03, // algorithm length
		0x41, 0x45, 0x53, // "AES"
		0x00, 0x02, // nonce length
		0xAA, 0xBB, // nonce
		0x00, 0x01, // tag length
		0xCC,                   // tag
		0x00, 0x00, 0x00, 0x03, // ciphertext length
		0xDD, 0xEE, 0xFF, // ciphertext
	}

	assert.Equal(t, expected, marshaled, "wire format mismatch")
}

// TestUnmarshalPartialByte verifies unmarshal rejects data that has only a
// partial uint16 length field (1 byte instead of 2).
func TestUnmarshalPartialLengthFields(t *testing.T) {
	t.Run("single byte after version for algorithm length", func(t *testing.T) {
		// Version + only 1 byte of 2-byte algorithm length
		_, err := Unmarshal([]byte{0x01, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm length")
	})

	t.Run("partial nonce length", func(t *testing.T) {
		// Version + algo (len=0) + only 1 byte of nonce length
		_, err := Unmarshal([]byte{0x01, 0x00, 0x00, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")
	})

	t.Run("partial tag length", func(t *testing.T) {
		// Version + algo (len=0) + nonce (len=0) + 1 byte of tag length
		_, err := Unmarshal([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tag")
	})

	t.Run("partial ciphertext length", func(t *testing.T) {
		// Version + algo (len=0) + nonce (len=0) + tag (len=0) + 2 bytes of 4-byte cipher length
		_, err := Unmarshal([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext")
	})
}

// TestMarshalUnmarshalRoundTrip_BinaryData verifies that binary data including
// null bytes, high bytes, and control characters survives roundtrip correctly.
func TestMarshalUnmarshalRoundTrip_BinaryData(t *testing.T) {
	// Build a nonce and tag with all possible byte values
	nonce := make([]byte, 12)
	tag := make([]byte, 16)
	ciphertext := make([]byte, 256)
	for i := range nonce {
		nonce[i] = byte(i * 21) // Various byte values
	}
	for i := range tag {
		tag[i] = byte(255 - i)
	}
	for i := range ciphertext {
		ciphertext[i] = byte(i) // Full range 0x00..0xFF
	}

	data := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      nonce,
		Tag:        tag,
		Ciphertext: ciphertext,
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err)

	unmarshaled, err := Unmarshal(marshaled)
	require.NoError(t, err)

	assert.Equal(t, data.Algorithm, unmarshaled.Algorithm)
	assert.Equal(t, data.Nonce, unmarshaled.Nonce)
	assert.Equal(t, data.Tag, unmarshaled.Tag)
	assert.Equal(t, data.Ciphertext, unmarshaled.Ciphertext)
}

// TestMarshalUnmarshalRoundTrip_SingleByteCiphertext verifies the edge case
// of a single-byte ciphertext, which is the minimum non-empty payload.
func TestMarshalUnmarshalRoundTrip_SingleByteCiphertext(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  string(types.SymmetricAES256GCM),
		Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Tag:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Ciphertext: []byte{0x42},
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err)

	unmarshaled, err := Unmarshal(marshaled)
	require.NoError(t, err)

	assert.Equal(t, data.Ciphertext, unmarshaled.Ciphertext)
}

// TestMarshalUnmarshalRoundTrip_UnicodeAlgorithm verifies that algorithm
// strings containing multi-byte UTF-8 characters survive roundtrip.
func TestMarshalUnmarshalRoundTrip_UnicodeAlgorithm(t *testing.T) {
	data := &types.EncryptedData{
		Algorithm:  "aes-256-gcm-\xc3\xa9", // UTF-8 for 'e' with accent
		Nonce:      []byte{1, 2, 3},
		Tag:        []byte{4, 5, 6},
		Ciphertext: []byte{7, 8, 9},
	}

	marshaled, err := Marshal(data)
	require.NoError(t, err)

	unmarshaled, err := Unmarshal(marshaled)
	require.NoError(t, err)

	assert.Equal(t, data.Algorithm, unmarshaled.Algorithm)
}
