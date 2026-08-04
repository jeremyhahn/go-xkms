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

func TestError_Error(t *testing.T) {
	tests := []struct {
		name   string
		err    *Error
		expect string
	}{
		{
			name: "Simple error",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:badNonce",
				Detail: "Invalid nonce",
				Status: 400,
			},
			expect: "Invalid nonce",
		},
		{
			name: "Unauthorized error",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:unauthorized",
				Detail: "Account does not exist",
				Status: 401,
			},
			expect: "Account does not exist",
		},
		{
			name: "Empty detail",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:serverInternal",
				Detail: "",
				Status: 500,
			},
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expect {
				t.Errorf("Error() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestNewError(t *testing.T) {
	tests := []struct {
		name        string
		errType     string
		detail      string
		status      int
		subproblems []SubProblem
	}{
		{
			name:        "BadNonce error",
			errType:     "badNonce",
			detail:      "The nonce was invalid",
			status:      400,
			subproblems: nil,
		},
		{
			name:    "Error with subproblems",
			errType: "compound",
			detail:  "Multiple validation failures",
			status:  400,
			subproblems: []SubProblem{
				{
					Type:   "urn:ietf:params:acme:error:dns",
					Detail: "DNS query failed",
				},
			},
		},
		{
			name:        "Server internal error",
			errType:     "serverInternal",
			detail:      "An unexpected error occurred",
			status:      500,
			subproblems: []SubProblem{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.errType, tt.detail, tt.status, tt.subproblems)

			expectedType := "urn:ietf:params:acme:error:" + tt.errType
			if err.Type != expectedType {
				t.Errorf("Type = %v, want %v", err.Type, expectedType)
			}

			if err.Detail != tt.detail {
				t.Errorf("Detail = %v, want %v", err.Detail, tt.detail)
			}

			if err.Status != tt.status {
				t.Errorf("Status = %v, want %v", err.Status, tt.status)
			}

			if len(err.SubProblems) != len(tt.subproblems) {
				t.Errorf("SubProblems length = %v, want %v", len(err.SubProblems), len(tt.subproblems))
			}
		})
	}
}

func TestError_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		err     *Error
		wantErr bool
	}{
		{
			name: "Simple error",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:badNonce",
				Detail: "Invalid nonce",
				Status: 400,
			},
			wantErr: false,
		},
		{
			name: "Error with identifier",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:unauthorized",
				Detail: "Unauthorized",
				Status: 403,
				Identifier: &ACMEIdentifier{
					Type:  "dns",
					Value: "example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "Error with subproblems",
			err: &Error{
				Type:   "urn:ietf:params:acme:error:compound",
				Detail: "Multiple failures",
				Status: 400,
				SubProblems: []SubProblem{
					{
						Type:   "urn:ietf:params:acme:error:dns",
						Detail: "DNS validation failed",
						Identifier: &ACMEIdentifier{
							Type:  "dns",
							Value: "www.example.com",
						},
					},
					{
						Type:   "urn:ietf:params:acme:error:connection",
						Detail: "Connection timeout",
						Identifier: &ACMEIdentifier{
							Type:  "dns",
							Value: "api.example.com",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Error with instance",
			err: &Error{
				Type:     "urn:ietf:params:acme:error:rateLimited",
				Detail:   "Too many requests",
				Status:   429,
				Instance: "https://example.com/errors/rate-limit-123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.err)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled Error
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify key fields
			if unmarshaled.Type != tt.err.Type {
				t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, tt.err.Type)
			}
			if unmarshaled.Detail != tt.err.Detail {
				t.Errorf("Detail mismatch: got %v, want %v", unmarshaled.Detail, tt.err.Detail)
			}
			// Note: Status is not marshaled to JSON (json:"-" tag)
			if len(unmarshaled.SubProblems) != len(tt.err.SubProblems) {
				t.Errorf("SubProblems length mismatch: got %v, want %v", len(unmarshaled.SubProblems), len(tt.err.SubProblems))
			}
		})
	}
}

func TestError_YAMLMarshaling(t *testing.T) {
	acmeErr := &Error{
		Type:   "urn:ietf:params:acme:error:badNonce",
		Detail: "Invalid nonce",
		Status: 400,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(acmeErr)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}

	// Unmarshal from YAML
	var unmarshaled Error
	if err := yaml.Unmarshal(yamlData, &unmarshaled); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	// Verify fields
	if unmarshaled.Type != acmeErr.Type {
		t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, acmeErr.Type)
	}
	if unmarshaled.Detail != acmeErr.Detail {
		t.Errorf("Detail mismatch: got %v, want %v", unmarshaled.Detail, acmeErr.Detail)
	}
}

func TestError_StatusNotInJSON(t *testing.T) {
	acmeErr := &Error{
		Type:   "urn:ietf:params:acme:error:badNonce",
		Detail: "Invalid nonce",
		Status: 400,
	}

	jsonData, err := json.Marshal(acmeErr)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Status should not be present in JSON (json:"-" tag)
	if _, exists := result["status"]; exists {
		t.Error("Expected 'status' to not be in JSON output")
	}
}

func TestError_OmitEmptyFields(t *testing.T) {
	acmeErr := &Error{
		Type:   "urn:ietf:params:acme:error:badNonce",
		Detail: "Invalid nonce",
		Status: 400,
	}

	jsonData, err := json.Marshal(acmeErr)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// These fields should be omitted when empty/nil
	if _, exists := result["subproblems"]; exists && acmeErr.SubProblems == nil {
		t.Error("Expected 'subproblems' to be omitted when nil")
	}
	if _, exists := result["identifier"]; exists && acmeErr.Identifier == nil {
		t.Error("Expected 'identifier' to be omitted when nil")
	}
	if _, exists := result["instance"]; exists && acmeErr.Instance == "" {
		t.Error("Expected 'instance' to be omitted when empty")
	}
}

func TestSubProblem_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name       string
		subproblem SubProblem
		wantErr    bool
	}{
		{
			name: "Simple subproblem",
			subproblem: SubProblem{
				Type:   "urn:ietf:params:acme:error:dns",
				Detail: "DNS validation failed",
			},
			wantErr: false,
		},
		{
			name: "Subproblem with identifier",
			subproblem: SubProblem{
				Type:   "urn:ietf:params:acme:error:connection",
				Detail: "Connection timeout",
				Identifier: &ACMEIdentifier{
					Type:  "dns",
					Value: "example.com",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.subproblem)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Unmarshal from JSON
			var unmarshaled SubProblem
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Verify fields
			if unmarshaled.Type != tt.subproblem.Type {
				t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, tt.subproblem.Type)
			}
			if unmarshaled.Detail != tt.subproblem.Detail {
				t.Errorf("Detail mismatch: got %v, want %v", unmarshaled.Detail, tt.subproblem.Detail)
			}
		})
	}
}

func TestError_CommonACMEErrors(t *testing.T) {
	// Test creation of common ACME error types
	errorTypes := []struct {
		errType string
		detail  string
		status  int
	}{
		{"badNonce", "The nonce was unacceptable", 400},
		{"badSignatureAlgorithm", "The JWS was signed with an algorithm the server does not support", 400},
		{"invalidContact", "The contact URI for an account was invalid", 400},
		{"unauthorized", "The client lacks sufficient authorization", 403},
		{"unsupportedContact", "A contact URL for an account used an unsupported protocol scheme", 400},
		{"accountDoesNotExist", "The request specified an account that does not exist", 400},
		{"malformed", "The request message was malformed", 400},
		{"rateLimited", "The request exceeds a rate limit", 429},
		{"rejectedIdentifier", "The server will not issue certificates for the identifier", 400},
		{"serverInternal", "The server experienced an internal error", 500},
		{"unauthorized", "The client lacks sufficient authorization", 403},
		{"unsupportedIdentifier", "An identifier is of an unsupported type", 400},
		{"userActionRequired", "Visit the URL given to take actions specified by the server", 403},
		{"badRevocationReason", "The revocation reason provided is not allowed by the server", 400},
		{"dns", "There was a problem with a DNS query during identifier validation", 400},
		{"connection", "The server could not connect to validation target", 400},
		{"tls", "The server received a TLS error during validation", 400},
		{"incorrectResponse", "Response received didn't match the challenge's requirements", 400},
	}

	for _, et := range errorTypes {
		t.Run(et.errType, func(t *testing.T) {
			err := NewError(et.errType, et.detail, et.status, nil)

			expectedType := "urn:ietf:params:acme:error:" + et.errType
			if err.Type != expectedType {
				t.Errorf("Type = %v, want %v", err.Type, expectedType)
			}

			if err.Detail != et.detail {
				t.Errorf("Detail = %v, want %v", err.Detail, et.detail)
			}

			if err.Status != et.status {
				t.Errorf("Status = %v, want %v", err.Status, et.status)
			}

			// Verify it implements error interface
			if err.Error() != et.detail {
				t.Errorf("Error() = %v, want %v", err.Error(), et.detail)
			}
		})
	}
}
