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
