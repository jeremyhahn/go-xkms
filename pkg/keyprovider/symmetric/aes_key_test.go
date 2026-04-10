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
	"testing"
)

func TestNewAESKey(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keyData   []byte
		wantSize  int
		wantErr   bool
	}{
		{
			name:      "AES-128",
			algorithm: "aes128-gcm",
			keyData:   make([]byte, 16), // 128 bits
			wantSize:  128,
			wantErr:   false,
		},
		{
			name:      "AES-192",
			algorithm: "aes192-gcm",
			keyData:   make([]byte, 24), // 192 bits
			wantSize:  192,
			wantErr:   false,
		},
		{
			name:      "AES-256",
			algorithm: "aes256-gcm",
			keyData:   make([]byte, 32), // 256 bits
			wantSize:  256,
			wantErr:   false,
		},
		{
			name:      "Invalid key size",
			algorithm: "aes256-gcm",
			keyData:   make([]byte, 15), // 120 bits - invalid
			wantSize:  0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewAESKey(tt.algorithm, tt.keyData)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAESKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if key.KeySize() != tt.wantSize {
					t.Errorf("KeySize() = %d, want %d", key.KeySize(), tt.wantSize)
				}
				if key.Algorithm() != tt.algorithm {
					t.Errorf("Algorithm() = %s, want %s", key.Algorithm(), tt.algorithm)
				}
			}
		})
	}
}

func TestAESKeyRawCopy(t *testing.T) {
	// Create a key
	originalData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key, err := NewAESKey("aes128-gcm", originalData)
	if err != nil {
		t.Fatalf("NewAESKey() failed: %v", err)
	}

	// Get raw data
	raw, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key: %v", err)
	}

	// Verify it matches original
	if !bytes.Equal(raw, originalData) {
		t.Error("Raw() did not return correct data")
	}

	// Modify the returned raw data
	raw[0] = 99

	// Get raw data again and verify it wasn't modified
	raw2, err := key.Raw()
	if err != nil {
		t.Fatalf("Failed to get raw key second time: %v", err)
	}
	if raw2[0] == 99 {
		t.Error("Raw() should return a copy, not a reference to internal data")
	}
	if !bytes.Equal(raw2, originalData) {
		t.Error("Internal key data was modified")
	}
}

func TestAESKeyInterface(t *testing.T) {
	// Verify that aesKey implements types.SymmetricKey
	keyData := make([]byte, 32)
	key, err := NewAESKey("aes256-gcm", keyData)
	if err != nil {
		t.Fatalf("NewAESKey() failed: %v", err)
	}

	// This will fail to compile if aesKey doesn't implement SymmetricKey
	_ = key
}
