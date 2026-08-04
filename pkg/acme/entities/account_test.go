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

func TestACMEAccount_EntityID(t *testing.T) {
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
			id:       12345,
			expected: 12345,
		},
		{
			name:     "Large ID",
			id:       18446744073709551615, // max uint64
			expected: 18446744073709551615,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &ACMEAccount{}
			account.SetEntityID(tt.id)

			if got := account.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMEAccount_SetEntityID(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		expected uint64
	}{
		{
			name:     "Set zero ID",
			id:       0,
			expected: 0,
		},
		{
			name:     "Set positive ID",
			id:       999,
			expected: 999,
		},
		{
			name:     "Overwrite existing ID",
			id:       555,
			expected: 555,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &ACMEAccount{ID: 123}
			account.SetEntityID(tt.id)

			if account.ID != tt.expected {
				t.Errorf("SetEntityID() set ID = %v, want %v", account.ID, tt.expected)
			}
		})
	}
}

func TestACMEAccount_JSONMarshaling(t *testing.T) {
	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		account *ACMEAccount
		wantErr bool
	}{
		{
			name: "Full account",
			account: &ACMEAccount{
				ID:                   1,
				Contact:              []string{"mailto:admin@example.com"},
				CreatedAt:            createdAt,
				Key:                  "test-key",
				Orders:               "https://example.com/orders",
				Status:               "valid",
				TermsOfServiceAgreed: true,
				URL:                  "https://example.com/account/1",
			},
			wantErr: false,
		},
		{
			name: "Minimal account",
			account: &ACMEAccount{
				ID:        2,
				CreatedAt: createdAt,
				Key:       "minimal-key",
				Orders:    "https://example.com/orders/2",
				Status:    "pending",
				URL:       "https://example.com/account/2",
			},
			wantErr: false,
		},
		{
			name: "Account with external account binding",
			account: &ACMEAccount{
				ID:        3,
				CreatedAt: createdAt,
				Key:       "eab-key",
				ExternalAccountBinding: map[string]interface{}{
					"protected": "eyJhbGciOiJIUzI1NiJ9",
					"payload":   "eyJjb250YWN0IjpbIm1haWx0bzphZG1pbkBleGFtcGxlLmNvbSJdfQ",
					"signature": "dGVzdC1zaWduYXR1cmU",
				},
				Orders: "https://example.com/orders/3",
				Status: "valid",
				URL:    "https://example.com/account/3",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMEAccount
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.account.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.account.ID)
			}
			if unmarshaled.Status != tt.account.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.account.Status)
			}
			if unmarshaled.Key != tt.account.Key {
				t.Errorf("Key mismatch: got %v, want %v", unmarshaled.Key, tt.account.Key)
			}
		})
	}
}

func TestACMEAccount_YAMLMarshaling(t *testing.T) {
	createdAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		account *ACMEAccount
		wantErr bool
	}{
		{
			name: "Full account",
			account: &ACMEAccount{
				ID:                   1,
				Contact:              []string{"mailto:admin@example.com"},
				CreatedAt:            createdAt,
				Key:                  "test-key",
				Orders:               "https://example.com/orders",
				Status:               "valid",
				TermsOfServiceAgreed: true,
				URL:                  "https://example.com/account/1",
			},
			wantErr: false,
		},
		{
			name: "Empty account",
			account: &ACMEAccount{
				ID:        0,
				CreatedAt: time.Time{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to YAML
			yamlData, err := yaml.Marshal(tt.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from YAML
			var unmarshaled ACMEAccount
			if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
				t.Errorf("yaml.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.account.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.account.ID)
			}
			if unmarshaled.Status != tt.account.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.account.Status)
			}
		})
	}
}

func TestACMEAccount_OmitEmptyFields(t *testing.T) {
	account := &ACMEAccount{
		ID:        1,
		CreatedAt: time.Now(),
		Key:       "test-key",
		Orders:    "https://example.com/orders",
		Status:    "valid",
		URL:       "https://example.com/account/1",
	}

	jsonData, err := json.Marshal(account)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify omitempty works - these fields should not be in JSON when empty
	if _, exists := result["contact"]; exists && len(account.Contact) == 0 {
		t.Error("Expected 'contact' to be omitted when empty")
	}
	if _, exists := result["externalAccountBinding"]; exists && account.ExternalAccountBinding == nil {
		t.Error("Expected 'externalAccountBinding' to be omitted when nil")
	}
	if _, exists := result["onlyReturnExisting"]; exists && !account.OnlyReturnExisting {
		t.Error("Expected 'onlyReturnExisting' to be omitted when false")
	}
	if _, exists := result["termsOfServiceAgreed"]; exists && !account.TermsOfServiceAgreed {
		t.Error("Expected 'termsOfServiceAgreed' to be omitted when false")
	}
}
