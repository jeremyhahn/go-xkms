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

func TestACMEIdentifier_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name       string
		identifier ACMEIdentifier
		wantErr    bool
	}{
		{
			name: "DNS identifier",
			identifier: ACMEIdentifier{
				Type:  "dns",
				Value: "example.com",
			},
			wantErr: false,
		},
		{
			name: "Wildcard DNS identifier",
			identifier: ACMEIdentifier{
				Type:  "dns",
				Value: "*.example.com",
			},
			wantErr: false,
		},
		{
			name: "IP identifier",
			identifier: ACMEIdentifier{
				Type:  "ip",
				Value: "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "IPv6 identifier",
			identifier: ACMEIdentifier{
				Type:  "ip",
				Value: "2001:db8::1",
			},
			wantErr: false,
		},
		{
			name: "Empty identifier",
			identifier: ACMEIdentifier{
				Type:  "",
				Value: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.identifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled ACMEIdentifier
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify fields
			if unmarshaled.Type != tt.identifier.Type {
				t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, tt.identifier.Type)
			}
			if unmarshaled.Value != tt.identifier.Value {
				t.Errorf("Value mismatch: got %v, want %v", unmarshaled.Value, tt.identifier.Value)
			}
		})
	}
}

func TestACMEIdentifier_YAMLMarshaling(t *testing.T) {
	tests := []struct {
		name       string
		identifier ACMEIdentifier
		wantErr    bool
	}{
		{
			name: "DNS identifier",
			identifier: ACMEIdentifier{
				Type:  "dns",
				Value: "example.com",
			},
			wantErr: false,
		},
		{
			name: "IP identifier",
			identifier: ACMEIdentifier{
				Type:  "ip",
				Value: "10.0.0.1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to YAML
			yamlData, err := yaml.Marshal(tt.identifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from YAML
			var unmarshaled ACMEIdentifier
			if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
				t.Errorf("yaml.Unmarshal() error = %v", err)
				return
			}

			// Verify fields
			if unmarshaled.Type != tt.identifier.Type {
				t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, tt.identifier.Type)
			}
			if unmarshaled.Value != tt.identifier.Value {
				t.Errorf("Value mismatch: got %v, want %v", unmarshaled.Value, tt.identifier.Value)
			}
		})
	}
}

func TestACMEIdentifier_MultipleIdentifiers(t *testing.T) {
	identifiers := []ACMEIdentifier{
		{Type: "dns", Value: "example.com"},
		{Type: "dns", Value: "www.example.com"},
		{Type: "dns", Value: "*.example.com"},
		{Type: "ip", Value: "192.168.1.1"},
	}

	// Marshal slice to JSON
	jsonData, err := json.Marshal(identifiers)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Unmarshal from JSON
	var unmarshaled []ACMEIdentifier
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify count
	if len(unmarshaled) != len(identifiers) {
		t.Errorf("Length mismatch: got %v, want %v", len(unmarshaled), len(identifiers))
	}

	// Verify each identifier
	for i, id := range unmarshaled {
		if id.Type != identifiers[i].Type {
			t.Errorf("Identifier[%d] Type mismatch: got %v, want %v", i, id.Type, identifiers[i].Type)
		}
		if id.Value != identifiers[i].Value {
			t.Errorf("Identifier[%d] Value mismatch: got %v, want %v", i, id.Value, identifiers[i].Value)
		}
	}
}

func TestACMEIdentifier_EqualityComparison(t *testing.T) {
	id1 := ACMEIdentifier{Type: "dns", Value: "example.com"}
	id2 := ACMEIdentifier{Type: "dns", Value: "example.com"}
	id3 := ACMEIdentifier{Type: "dns", Value: "different.com"}
	id4 := ACMEIdentifier{Type: "ip", Value: "example.com"}

	// Test equality
	if id1 != id2 {
		t.Error("Expected id1 and id2 to be equal")
	}

	// Test inequality by value
	if id1 == id3 {
		t.Error("Expected id1 and id3 to be different")
	}

	// Test inequality by type
	if id1 == id4 {
		t.Error("Expected id1 and id4 to be different")
	}
}

func TestACMEIdentifier_ZeroValue(t *testing.T) {
	var id ACMEIdentifier

	if id.Type != "" {
		t.Errorf("Expected empty Type, got %v", id.Type)
	}

	if id.Value != "" {
		t.Errorf("Expected empty Value, got %v", id.Value)
	}
}

func TestACMEIdentifier_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "Internationalized domain",
			value: "münchen.de",
		},
		{
			name:  "Punycode domain",
			value: "xn--mnchen-3ya.de",
		},
		{
			name:  "Hyphenated domain",
			value: "my-example-domain.com",
		},
		{
			name:  "Numeric domain",
			value: "123.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := ACMEIdentifier{
				Type:  "dns",
				Value: tt.value,
			}

			jsonData, err := json.Marshal(id)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var unmarshaled ACMEIdentifier
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			if unmarshaled.Value != tt.value {
				t.Errorf("Value mismatch: got %v, want %v", unmarshaled.Value, tt.value)
			}
		})
	}
}
