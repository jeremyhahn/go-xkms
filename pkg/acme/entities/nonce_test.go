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

package entities

import (
	"encoding/json"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestACMENonce_EntityID(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		expected uint64
	}{
		{
			name:     "Zero ID",
			id:       0,
			expected: 0,
		},
		{
			name:     "Positive ID",
			id:       42,
			expected: 42,
		},
		{
			name:     "Large ID",
			id:       18446744073709551615,
			expected: 18446744073709551615,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := &ACMENonce{}
			nonce.SetEntityID(tt.id)

			if got := nonce.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMENonce_SetEntityID(t *testing.T) {
	nonce := &ACMENonce{ID: 1}
	newID := uint64(999)

	nonce.SetEntityID(newID)

	if nonce.ID != newID {
		t.Errorf("SetEntityID() set ID = %v, want %v", nonce.ID, newID)
	}
}

func TestACMENonce_JSONMarshaling(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	tests := []struct {
		name    string
		nonce   *ACMENonce
		wantErr bool
	}{
		{
			name: "Valid nonce",
			nonce: &ACMENonce{
				ID:        1,
				Value:     []byte("test-nonce-value-12345"),
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Empty value nonce",
			nonce: &ACMENonce{
				ID:        2,
				Value:     []byte{},
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Nil value nonce",
			nonce: &ACMENonce{
				ID:        3,
				Value:     nil,
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
		{
			name: "Large value nonce",
			nonce: &ACMENonce{
				ID:        4,
				Value:     make([]byte, 1024),
				ExpiresAt: expiresAt,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMENonce
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.nonce.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.nonce.ID)
			}
			if unmarshaled.ExpiresAt != tt.nonce.ExpiresAt {
				t.Errorf("ExpiresAt mismatch: got %v, want %v", unmarshaled.ExpiresAt, tt.nonce.ExpiresAt)
			}

			// Verify value (byte slices need special handling)
			if len(tt.nonce.Value) > 0 {
				if len(unmarshaled.Value) != len(tt.nonce.Value) {
					t.Errorf("Value length mismatch: got %v, want %v", len(unmarshaled.Value), len(tt.nonce.Value))
				}
			}
		})
	}
}

func TestACMENonce_YAMLMarshaling(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	nonce := &ACMENonce{
		ID:        1,
		Value:     []byte("test-nonce"),
		ExpiresAt: expiresAt,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(nonce)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal from YAML
	var unmarshaled ACMENonce
	if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	// Verify fields
	if unmarshaled.ID != nonce.ID {
		t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, nonce.ID)
	}
	if unmarshaled.ExpiresAt != nonce.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", unmarshaled.ExpiresAt, nonce.ExpiresAt)
	}
}

func TestACMENonce_Expiration(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name      string
		expiresAt int64
		want      string
	}{
		{
			name:      "Future expiration",
			expiresAt: now + 300, // 5 minutes from now
			want:      "not expired",
		},
		{
			name:      "Past expiration",
			expiresAt: now - 300, // 5 minutes ago
			want:      "expired",
		},
		{
			name:      "Current time",
			expiresAt: now,
			want:      "expired or about to expire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := &ACMENonce{
				ID:        1,
				Value:     []byte("test"),
				ExpiresAt: tt.expiresAt,
			}

			// Check if nonce is expired
			isExpired := time.Now().Unix() >= nonce.ExpiresAt

			switch tt.want {
			case "expired", "expired or about to expire":
				if !isExpired {
					t.Errorf("Expected nonce to be expired")
				}
			case "not expired":
				if isExpired {
					t.Errorf("Expected nonce to not be expired")
				}
			}
		})
	}
}

func TestACMENonce_ByteValueHandling(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{
			name:  "ASCII bytes",
			value: []byte("simple-ascii-nonce"),
		},
		{
			name:  "Binary bytes",
			value: []byte{0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		},
		{
			name:  "UTF-8 bytes",
			value: []byte("nonce-with-特殊字符"),
		},
		{
			name:  "Base64-like bytes",
			value: []byte("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := &ACMENonce{
				ID:        1,
				Value:     tt.value,
				ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			}

			jsonData, err := json.Marshal(nonce)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var unmarshaled ACMENonce
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			if len(unmarshaled.Value) != len(tt.value) {
				t.Errorf("Value length mismatch: got %v, want %v", len(unmarshaled.Value), len(tt.value))
			}

			// Compare byte values
			for i := range tt.value {
				if i < len(unmarshaled.Value) && unmarshaled.Value[i] != tt.value[i] {
					t.Errorf("Byte[%d] mismatch: got %v, want %v", i, unmarshaled.Value[i], tt.value[i])
				}
			}
		})
	}
}

func TestACMENonce_ZeroValue(t *testing.T) {
	var nonce ACMENonce

	if nonce.ID != 0 {
		t.Errorf("Expected zero ID, got %v", nonce.ID)
	}

	if nonce.Value != nil {
		t.Errorf("Expected nil Value, got %v", nonce.Value)
	}

	if nonce.ExpiresAt != 0 {
		t.Errorf("Expected zero ExpiresAt, got %v", nonce.ExpiresAt)
	}
}
