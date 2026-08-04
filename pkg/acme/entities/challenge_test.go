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

	"gopkg.in/yaml.v3"
)

func TestACMEChallenge_EntityID(t *testing.T) {
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
			id:       999,
			expected: 999,
		},
		{
			name:     "Large ID",
			id:       9999999999,
			expected: 9999999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := &ACMEChallenge{}
			challenge.SetEntityID(tt.id)

			if got := challenge.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMEChallenge_SetEntityID(t *testing.T) {
	challenge := &ACMEChallenge{ID: 1}
	newID := uint64(2)

	challenge.SetEntityID(newID)

	if challenge.ID != newID {
		t.Errorf("SetEntityID() set ID = %v, want %v", challenge.ID, newID)
	}
}

func TestACMEChallenge_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name      string
		challenge *ACMEChallenge
		wantErr   bool
	}{
		{
			name: "HTTP-01 challenge",
			challenge: &ACMEChallenge{
				ID:              1,
				Type:            "http-01",
				URL:             "https://example.com/challenge/1",
				Status:          "pending",
				Token:           "test-token-12345",
				AccountID:       1,
				AuthorizationID: 1,
			},
			wantErr: false,
		},
		{
			name: "DNS-01 challenge",
			challenge: &ACMEChallenge{
				ID:              2,
				Type:            "dns-01",
				URL:             "https://example.com/challenge/2",
				Status:          "valid",
				Token:           "dns-token-67890",
				Validated:       "2024-01-01T12:00:00Z",
				AccountID:       2,
				AuthorizationID: 2,
			},
			wantErr: false,
		},
		{
			name: "Challenge with error",
			challenge: &ACMEChallenge{
				ID:     3,
				Type:   "http-01",
				URL:    "https://example.com/challenge/3",
				Status: "invalid",
				Token:  "error-token",
				Error: &Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Detail: "Invalid response",
					Status: 403,
				},
				AccountID:       3,
				AuthorizationID: 3,
			},
			wantErr: false,
		},
		{
			name: "TLS-ALPN-01 challenge",
			challenge: &ACMEChallenge{
				ID:              4,
				Type:            "tls-alpn-01",
				URL:             "https://example.com/challenge/4",
				Status:          "processing",
				Token:           "tls-token",
				AccountID:       4,
				AuthorizationID: 4,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.challenge)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMEChallenge
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.challenge.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.challenge.ID)
			}
			if unmarshaled.Type != tt.challenge.Type {
				t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, tt.challenge.Type)
			}
			if unmarshaled.Status != tt.challenge.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.challenge.Status)
			}
			if unmarshaled.Token != tt.challenge.Token {
				t.Errorf("Token mismatch: got %v, want %v", unmarshaled.Token, tt.challenge.Token)
			}
			if unmarshaled.AccountID != tt.challenge.AccountID {
				t.Errorf("AccountID mismatch: got %v, want %v", unmarshaled.AccountID, tt.challenge.AccountID)
			}
		})
	}
}

func TestACMEChallenge_YAMLMarshaling(t *testing.T) {
	challenge := &ACMEChallenge{
		ID:              1,
		Type:            "http-01",
		URL:             "https://example.com/challenge/1",
		Status:          "valid",
		Token:           "test-token",
		Validated:       "2024-01-01T00:00:00Z",
		AccountID:       1,
		AuthorizationID: 1,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(challenge)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal from YAML
	var unmarshaled ACMEChallenge
	if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	// Verify fields
	if unmarshaled.ID != challenge.ID {
		t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, challenge.ID)
	}
	if unmarshaled.Type != challenge.Type {
		t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, challenge.Type)
	}
	if unmarshaled.Status != challenge.Status {
		t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, challenge.Status)
	}
}

func TestACMEChallenge_OmitEmptyFields(t *testing.T) {
	challenge := &ACMEChallenge{
		ID:              1,
		Type:            "http-01",
		URL:             "https://example.com/challenge/1",
		Status:          "pending",
		Token:           "token",
		AccountID:       1,
		AuthorizationID: 1,
	}

	jsonData, err := json.Marshal(challenge)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Validated should be omitted when empty
	if _, exists := result["validated"]; exists && challenge.Validated == "" {
		t.Error("Expected 'validated' to be omitted when empty")
	}

	// Error should be omitted when nil
	if _, exists := result["error"]; exists && challenge.Error == nil {
		t.Error("Expected 'error' to be omitted when nil")
	}
}

func TestACMEChallenge_WithError(t *testing.T) {
	acmeError := &Error{
		Type:   "urn:ietf:params:acme:error:connection",
		Detail: "Connection refused",
		Status: 500,
	}

	challenge := &ACMEChallenge{
		ID:              1,
		Type:            "http-01",
		URL:             "https://example.com/challenge/1",
		Status:          "invalid",
		Token:           "test-token",
		Error:           acmeError,
		AccountID:       1,
		AuthorizationID: 1,
	}

	jsonData, err := json.Marshal(challenge)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled ACMEChallenge
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if unmarshaled.Error == nil {
		t.Fatal("Expected error to be present")
	}

	if unmarshaled.Error.Type != acmeError.Type {
		t.Errorf("Error.Type mismatch: got %v, want %v", unmarshaled.Error.Type, acmeError.Type)
	}
	if unmarshaled.Error.Detail != acmeError.Detail {
		t.Errorf("Error.Detail mismatch: got %v, want %v", unmarshaled.Error.Detail, acmeError.Detail)
	}
}
