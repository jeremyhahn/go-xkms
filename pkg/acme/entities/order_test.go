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
)

func TestACMEOrder_EntityID(t *testing.T) {
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
			name:     "Max uint64",
			id:       18446744073709551615,
			expected: 18446744073709551615,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order := &ACMEOrder{}
			order.SetEntityID(tt.id)

			if got := order.EntityID(); got != tt.expected {
				t.Errorf("EntityID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestACMEOrder_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		order   *ACMEOrder
		wantErr bool
	}{
		{
			name: "Pending order",
			order: &ACMEOrder{
				ID:     1,
				Status: "pending",
				Identifiers: []ACMEIdentifier{
					{Type: "dns", Value: "example.com"},
					{Type: "dns", Value: "www.example.com"},
				},
				Expires:        "2024-12-31T23:59:59Z",
				Authorizations: []string{"https://example.com/authz/1", "https://example.com/authz/2"},
				Finalize:       "https://example.com/order/1/finalize",
				AccountID:      1,
				URL:            "https://example.com/order/1",
			},
			wantErr: false,
		},
		{
			name: "Valid order with certificate",
			order: &ACMEOrder{
				ID:             2,
				Status:         "valid",
				Identifiers:    []ACMEIdentifier{{Type: "dns", Value: "example.com"}},
				Expires:        "2024-12-31T23:59:59Z",
				Authorizations: []string{"https://example.com/authz/1"},
				Finalize:       "https://example.com/order/2/finalize",
				Certificate:    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
				CertificateURL: "https://example.com/cert/2",
				AccountID:      2,
				URL:            "https://example.com/order/2",
			},
			wantErr: false,
		},
		{
			name: "Order with error",
			order: &ACMEOrder{
				ID:          3,
				Status:      "invalid",
				Identifiers: []ACMEIdentifier{{Type: "dns", Value: "example.com"}},
				Error: &Error{
					Type:   "urn:ietf:params:acme:error:unauthorized",
					Detail: "Authorization failed",
					Status: 403,
				},
				Expires:        "2024-12-31T23:59:59Z",
				Authorizations: []string{"https://example.com/authz/1"},
				Finalize:       "https://example.com/order/3/finalize",
				AccountID:      3,
				URL:            "https://example.com/order/3",
			},
			wantErr: false,
		},
		{
			name: "Order with NotBefore and NotAfter",
			order: &ACMEOrder{
				ID:             4,
				Status:         "pending",
				Identifiers:    []ACMEIdentifier{{Type: "dns", Value: "example.com"}},
				NotBefore:      "2024-01-01T00:00:00Z",
				NotAfter:       "2024-12-31T23:59:59Z",
				Expires:        "2024-12-31T23:59:59Z",
				Authorizations: []string{"https://example.com/authz/1"},
				Finalize:       "https://example.com/order/4/finalize",
				AccountID:      4,
				URL:            "https://example.com/order/4",
			},
			wantErr: false,
		},
		{
			name: "Order with wildcard",
			order: &ACMEOrder{
				ID:     5,
				Status: "pending",
				Identifiers: []ACMEIdentifier{
					{Type: "dns", Value: "*.example.com"},
					{Type: "dns", Value: "example.com"},
				},
				Expires:        "2024-12-31T23:59:59Z",
				Authorizations: []string{"https://example.com/authz/1", "https://example.com/authz/2"},
				Finalize:       "https://example.com/order/5/finalize",
				AccountID:      5,
				URL:            "https://example.com/order/5",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.order)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMEOrder
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.ID != tt.order.ID {
				t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, tt.order.ID)
			}
			if unmarshaled.Status != tt.order.Status {
				t.Errorf("Status mismatch: got %v, want %v", unmarshaled.Status, tt.order.Status)
			}
			if len(unmarshaled.Identifiers) != len(tt.order.Identifiers) {
				t.Errorf("Identifiers length mismatch: got %v, want %v", len(unmarshaled.Identifiers), len(tt.order.Identifiers))
			}
			if len(unmarshaled.Authorizations) != len(tt.order.Authorizations) {
				t.Errorf("Authorizations length mismatch: got %v, want %v", len(unmarshaled.Authorizations), len(tt.order.Authorizations))
			}
		})
	}
}

func TestACMEOrder_OmitEmptyFields(t *testing.T) {
	order := &ACMEOrder{
		ID:             1,
		Status:         "pending",
		Identifiers:    []ACMEIdentifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://example.com/authz/1"},
		Finalize:       "https://example.com/order/1/finalize",
		AccountID:      1,
		URL:            "https://example.com/order/1",
	}

	jsonData, err := json.Marshal(order)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify omitempty fields are not present when empty
	if _, exists := result["expires"]; exists && order.Expires == "" {
		t.Error("Expected 'expires' to be omitted when empty")
	}
	if _, exists := result["notBefore"]; exists && order.NotBefore == "" {
		t.Error("Expected 'notBefore' to be omitted when empty")
	}
	if _, exists := result["notAfter"]; exists && order.NotAfter == "" {
		t.Error("Expected 'notAfter' to be omitted when empty")
	}
	if _, exists := result["certificate"]; exists && order.Certificate == "" {
		t.Error("Expected 'certificate' to be omitted when empty")
	}
	if _, exists := result["error"]; exists && order.Error == nil {
		t.Error("Expected 'error' to be omitted when nil")
	}
}

func TestACMEOrder_XSignedOrder(t *testing.T) {
	innerOrder := &ACMEOrder{
		ID:     2,
		Status: "pending",
		Identifiers: []ACMEIdentifier{
			{Type: "dns", Value: "inner.example.com"},
		},
		AccountID: 2,
	}

	order := &ACMEOrder{
		ID:     1,
		Status: "pending",
		Identifiers: []ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        "2024-12-31T23:59:59Z",
		Authorizations: []string{"https://example.com/authz/1"},
		Finalize:       "https://example.com/order/1/finalize",
		XSignedOrder:   innerOrder,
		AccountID:      1,
		URL:            "https://example.com/order/1",
	}

	jsonData, err := json.Marshal(order)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled ACMEOrder
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if unmarshaled.XSignedOrder == nil {
		t.Fatal("Expected XSignedOrder to be present")
	}

	if unmarshaled.XSignedOrder.ID != innerOrder.ID {
		t.Errorf("XSignedOrder ID mismatch: got %v, want %v", unmarshaled.XSignedOrder.ID, innerOrder.ID)
	}
}
