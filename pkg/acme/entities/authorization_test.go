// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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

func TestACMEAuthorization_EntityID(t *testing.T) {
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
			name:     "Max uint64",
			id:       18446744073709551615,
			expected: 18446744073709551615,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authz := &ACMEAuthorization{}
			authz.SetEntityID(tt.id)

			if got := authz.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMEAuthorization_SetEntityID(t *testing.T) {
	authz := &ACMEAuthorization{ID: 100}
	newID := uint64(200)

	authz.SetEntityID(newID)

	if authz.ID != newID {
		t.Errorf("SetEntityID() set ID = %v, want %v", authz.ID, newID)
	}
}

func TestACMEAuthorization_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		authz   *ACMEAuthorization
		wantErr bool
	}{
		{
			name: "Full authorization",
			authz: &ACMEAuthorization{
				ID: 1,
				Identifier: ACMEIdentifier{
					Type:  "dns",
					Value: "example.com",
				},
				Status:  "valid",
				Expires: "2024-12-31T23:59:59Z",
				Challenges: []ACMEChallenge{
					{
						ID:              1,
						Type:            "http-01",
						URL:             "https://example.com/challenge/1",
						Status:          "valid",
						Token:           "test-token",
						AccountID:       1,
						AuthorizationID: 1,
					},
				},
				Wildcard:  false,
				AccountID: 1,
				OrderID:   1,
				URL:       "https://example.com/authz/1",
			},
			wantErr: false,
		},
		{
			name: "Wildcard authorization",
			authz: &ACMEAuthorization{
				ID: 2,
				Identifier: ACMEIdentifier{
					Type:  "dns",
					Value: "*.example.com",
				},
				Status:     "pending",
				Expires:    "2024-12-31T23:59:59Z",
				Challenges: []ACMEChallenge{},
				Wildcard:   true,
				AccountID:  2,
				OrderID:    2,
				URL:        "https://example.com/authz/2",
			},
			wantErr: false,
		},
		{
			name: "Minimal authorization",
			authz: &ACMEAuthorization{
				ID: 3,
				Identifier: ACMEIdentifier{
					Type:  "dns",
					Value: "minimal.example.com",
				},
				Status:    "pending",
				AccountID: 3,
				OrderID:   3,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.authz)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMEAuthorization
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.authz.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.authz.ID)
			}
			if unmarshaled.Status != tt.authz.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.authz.Status)
			}
			if unmarshaled.Identifier.Type != tt.authz.Identifier.Type {
				t.Errorf("Identifier.Type mismatch: got %v, want %v", unmarshaled.Identifier.Type, tt.authz.Identifier.Type)
			}
			if unmarshaled.Identifier.Value != tt.authz.Identifier.Value {
				t.Errorf("Identifier.Value mismatch: got %v, want %v", unmarshaled.Identifier.Value, tt.authz.Identifier.Value)
			}
			if unmarshaled.Wildcard != tt.authz.Wildcard {
				t.Errorf("Wildcard mismatch: got %v, want %v", unmarshaled.Wildcard, tt.authz.Wildcard)
			}
		})
	}
}

func TestACMEAuthorization_YAMLMarshaling(t *testing.T) {
	authz := &ACMEAuthorization{
		ID: 1,
		Identifier: ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:  "valid",
		Expires: "2024-12-31T23:59:59Z",
		Challenges: []ACMEChallenge{
			{
				ID:              1,
				Type:            "http-01",
				Status:          "valid",
				AccountID:       1,
				AuthorizationID: 1,
			},
		},
		Wildcard:  false,
		AccountID: 1,
		OrderID:   1,
		URL:       "https://example.com/authz/1",
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(authz)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal from YAML
	var unmarshaled ACMEAuthorization
	if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	// Verify fields
	if unmarshaled.ID != authz.ID {
		t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, authz.ID)
	}
	if unmarshaled.Status != authz.Status {
		t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, authz.Status)
	}
	if len(unmarshaled.Challenges) != len(authz.Challenges) {
		t.Errorf("Challenges length mismatch: got %v, want %v", len(unmarshaled.Challenges), len(authz.Challenges))
	}
}

func TestAuthorizationIndexURL_Constant(t *testing.T) {
	expected := "url"
	if AUTHORIZATION_INDEX_URL != expected {
		t.Errorf("AUTHORIZATION_INDEX_URL = %v, want %v", AUTHORIZATION_INDEX_URL, expected)
	}
}

func TestACMEAuthorization_WithMultipleChallenges(t *testing.T) {
	authz := &ACMEAuthorization{
		ID: 1,
		Identifier: ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status: "pending",
		Challenges: []ACMEChallenge{
			{ID: 1, Type: "http-01", Status: "pending"},
			{ID: 2, Type: "dns-01", Status: "pending"},
			{ID: 3, Type: "tls-alpn-01", Status: "pending"},
		},
		AccountID: 1,
		OrderID:   1,
	}

	jsonData, err := json.Marshal(authz)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled ACMEAuthorization
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(unmarshaled.Challenges) != 3 {
		t.Errorf("Expected 3 challenges, got %d", len(unmarshaled.Challenges))
	}

	for i, challenge := range unmarshaled.Challenges {
		if challenge.Type != authz.Challenges[i].Type {
			t.Errorf("Challenge[%d] type mismatch: got %v, want %v", i, challenge.Type, authz.Challenges[i].Type)
		}
	}
}
