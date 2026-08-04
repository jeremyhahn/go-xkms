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

package errors

import (
	"errors"
	"testing"
)

func TestACMEConstructors(t *testing.T) {
	tests := []struct {
		name     string
		err      *CAError
		expected ErrorCode
	}{
		{"NewACMEAccountDoesNotExist", NewACMEAccountDoesNotExist("Op", "msg"), CodeACMEAccountDoesNotExist},
		{"NewACMEAlreadyRevoked", NewACMEAlreadyRevoked("Op", "msg"), CodeACMEAlreadyRevoked},
		{"NewACMEBadCSR", NewACMEBadCSR("Op", "msg"), CodeACMEBadCSR},
		{"NewACMEBadNonce", NewACMEBadNonce("Op", "msg"), CodeACMEBadNonce},
		{"NewACMEBadPublicKey", NewACMEBadPublicKey("Op", "msg"), CodeACMEBadPublicKey},
		{"NewACMEBadRevocationReason", NewACMEBadRevocationReason("Op", "msg"), CodeACMEBadRevocationReason},
		{"NewACMEBadSignatureAlgorithm", NewACMEBadSignatureAlgorithm("Op", "msg"), CodeACMEBadSignatureAlgorithm},
		{"NewACMECAA", NewACMECAA("Op", "msg"), CodeACMECAA},
		{"NewACMECompound", NewACMECompound("Op", "msg"), CodeACMECompound},
		{"NewACMEConnection", NewACMEConnection("Op", "msg"), CodeACMEConnection},
		{"NewACMEDNS", NewACMEDNS("Op", "msg"), CodeACMEDNS},
		{"NewACMEExternalAccountRequired", NewACMEExternalAccountRequired("Op", "msg"), CodeACMEExternalAccountRequired},
		{"NewACMEIncorrectResponse", NewACMEIncorrectResponse("Op", "msg"), CodeACMEIncorrectResponse},
		{"NewACMEInvalidContact", NewACMEInvalidContact("Op", "msg"), CodeACMEInvalidContact},
		{"NewACMEMalformed", NewACMEMalformed("Op", "msg"), CodeACMEMalformed},
		{"NewACMEOrderNotReady", NewACMEOrderNotReady("Op", "msg"), CodeACMEOrderNotReady},
		{"NewACMERateLimited", NewACMERateLimited("Op", "msg"), CodeACMERateLimited},
		{"NewACMERejectedIdentifier", NewACMERejectedIdentifier("Op", "msg"), CodeACMERejectedIdentifier},
		{"NewACMEServerInternal", NewACMEServerInternal("Op", "msg"), CodeACMEServerInternal},
		{"NewACMETLS", NewACMETLS("Op", "msg"), CodeACMETLS},
		{"NewACMEUnauthorized", NewACMEUnauthorized("Op", "msg"), CodeACMEUnauthorized},
		{"NewACMEUnsupportedContact", NewACMEUnsupportedContact("Op", "msg"), CodeACMEUnsupportedContact},
		{"NewACMEUnsupportedIdentifier", NewACMEUnsupportedIdentifier("Op", "msg"), CodeACMEUnsupportedIdentifier},
		{"NewACMEUserActionRequired", NewACMEUserActionRequired("Op", "msg"), CodeACMEUserActionRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.expected {
				t.Errorf("expected code %v, got %v", tt.expected, tt.err.Code)
			}
			if tt.err.Op != "Op" {
				t.Errorf("expected op 'Op', got %q", tt.err.Op)
			}
			if tt.err.Message != "msg" {
				t.Errorf("expected message 'msg', got %q", tt.err.Message)
			}
		})
	}
}

func TestACMEPredicates(t *testing.T) {
	tests := []struct {
		err      error
		fn       func(error) bool
		expected bool
	}{
		{NewACMEAccountDoesNotExist("Op", "msg"), IsACMEAccountDoesNotExist, true},
		{NewACMEAlreadyRevoked("Op", "msg"), IsACMEAlreadyRevoked, true},
		{NewACMEBadCSR("Op", "msg"), IsACMEBadCSR, true},
		{NewACMEBadNonce("Op", "msg"), IsACMEBadNonce, true},
		{NewACMEBadPublicKey("Op", "msg"), IsACMEBadPublicKey, true},
		{NewACMEBadRevocationReason("Op", "msg"), IsACMEBadRevocationReason, true},
		{NewACMEBadSignatureAlgorithm("Op", "msg"), IsACMEBadSignatureAlgorithm, true},
		{NewACMECAA("Op", "msg"), IsACMECAA, true},
		{NewACMECompound("Op", "msg"), IsACMECompound, true},
		{NewACMEConnection("Op", "msg"), IsACMEConnection, true},
		{NewACMEDNS("Op", "msg"), IsACMEDNS, true},
		{NewACMEExternalAccountRequired("Op", "msg"), IsACMEExternalAccountRequired, true},
		{NewACMEIncorrectResponse("Op", "msg"), IsACMEIncorrectResponse, true},
		{NewACMEInvalidContact("Op", "msg"), IsACMEInvalidContact, true},
		{NewACMEMalformed("Op", "msg"), IsACMEMalformed, true},
		{NewACMEOrderNotReady("Op", "msg"), IsACMEOrderNotReady, true},
		{NewACMERateLimited("Op", "msg"), IsACMERateLimited, true},
		{NewACMERejectedIdentifier("Op", "msg"), IsACMERejectedIdentifier, true},
		{NewACMEServerInternal("Op", "msg"), IsACMEServerInternal, true},
		{NewACMETLS("Op", "msg"), IsACMETLS, true},
		{NewACMEUnauthorized("Op", "msg"), IsACMEUnauthorized, true},
		{NewACMEUnsupportedContact("Op", "msg"), IsACMEUnsupportedContact, true},
		{NewACMEUnsupportedIdentifier("Op", "msg"), IsACMEUnsupportedIdentifier, true},
		{NewACMEUserActionRequired("Op", "msg"), IsACMEUserActionRequired, true},
		// False cases
		{NewACMEBadNonce("Op", "msg"), IsACMEBadCSR, false},
		{NewInternal("Op", "msg"), IsACMEBadNonce, false},
		{errors.New("standard error"), IsACMEBadNonce, false},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			if got := tt.fn(tt.err); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestIsACME(t *testing.T) {
	acmeErr := NewACMEBadNonce("Op", "msg")
	if !IsACME(acmeErr) {
		t.Error("expected IsACME to return true for ACME error")
	}

	generalErr := NewInternal("Op", "msg")
	if IsACME(generalErr) {
		t.Error("expected IsACME to return false for non-ACME error")
	}

	stdErr := errors.New("standard error")
	if IsACME(stdErr) {
		t.Error("expected IsACME to return false for standard error")
	}
}

func TestACMEError_New(t *testing.T) {
	err := NewACMEError(CodeACMEBadNonce, "ValidateNonce", "invalid nonce")

	if err.CAError == nil {
		t.Fatal("expected non-nil CAError")
	}
	if err.Code != CodeACMEBadNonce {
		t.Errorf("expected code %v, got %v", CodeACMEBadNonce, err.Code)
	}
	if err.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Errorf("expected type urn, got %q", err.Type)
	}
	if err.Detail != "invalid nonce" {
		t.Errorf("expected detail 'invalid nonce', got %q", err.Detail)
	}
}

func TestACMEError_Error(t *testing.T) {
	err := NewACMEError(CodeACMEBadNonce, "ValidateNonce", "invalid nonce")
	expected := "urn:ietf:params:acme:error:badNonce: ValidateNonce: invalid nonce"

	if got := err.Error(); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestACMEError_Unwrap(t *testing.T) {
	err := NewACMEError(CodeACMEBadNonce, "Op", "msg")
	unwrapped := err.Unwrap()

	if unwrapped != err.CAError {
		t.Error("expected Unwrap to return underlying CAError")
	}
}

func TestACMEError_Is(t *testing.T) {
	err1 := NewACMEError(CodeACMEBadNonce, "Op1", "msg1")
	err2 := NewACMEError(CodeACMEBadNonce, "Op2", "msg2")
	err3 := NewACMEError(CodeACMEBadCSR, "Op3", "msg3")

	if !err1.Is(err2) {
		t.Error("expected ACMEErrors with same code to match")
	}
	if err1.Is(err3) {
		t.Error("expected ACMEErrors with different codes to not match")
	}

	// Test against CAError
	caErr := New(CodeACMEBadNonce, "Op", "msg")
	if !err1.Is(caErr) {
		t.Error("expected ACMEError to match CAError with same code")
	}
}

func TestACMEError_Is_NonACMEError(t *testing.T) {
	err := NewACMEError(CodeACMEBadNonce, "Op", "msg")
	stdErr := errors.New("standard error")

	if err.Is(stdErr) {
		t.Error("expected Is to return false for standard error")
	}
}

func TestACMEError_WithInstance(t *testing.T) {
	err := NewACMEError(CodeACMEUserActionRequired, "Op", "action required").
		WithInstance("https://example.com/action")

	if err.Instance != "https://example.com/action" {
		t.Errorf("expected instance URL, got %q", err.Instance)
	}
}

func TestACMEError_WithSubproblems(t *testing.T) {
	subproblems := []ACMESubproblem{
		{
			Type:   "urn:ietf:params:acme:error:caa",
			Detail: "CAA record prevents issuance",
			Identifier: &ACMEIdentifier{
				Type:  "dns",
				Value: "example.com",
			},
		},
	}

	err := NewACMEError(CodeACMECompound, "Op", "multiple errors").
		WithSubproblems(subproblems)

	if len(err.Subproblems) != 1 {
		t.Fatalf("expected 1 subproblem, got %d", len(err.Subproblems))
	}
	if err.Subproblems[0].Identifier.Value != "example.com" {
		t.Error("expected subproblem identifier to be preserved")
	}
}

func TestACMEError_AddSubproblem(t *testing.T) {
	err := NewACMEError(CodeACMECompound, "Op", "multiple errors").
		AddSubproblem(ACMESubproblem{
			Type:   "urn:ietf:params:acme:error:caa",
			Detail: "CAA error",
		}).
		AddSubproblem(ACMESubproblem{
			Type:   "urn:ietf:params:acme:error:dns",
			Detail: "DNS error",
		})

	if len(err.Subproblems) != 2 {
		t.Fatalf("expected 2 subproblems, got %d", len(err.Subproblems))
	}
}

func TestAsACMEError(t *testing.T) {
	acmeErr := NewACMEError(CodeACMEBadNonce, "Op", "msg")

	extracted, ok := AsACMEError(acmeErr)
	if !ok {
		t.Fatal("expected AsACMEError to succeed")
	}
	if extracted != acmeErr {
		t.Error("expected extracted error to be the original")
	}
}

func TestAsACMEError_NonACMEError(t *testing.T) {
	caErr := NewInternal("Op", "msg")

	_, ok := AsACMEError(caErr)
	if ok {
		t.Error("expected AsACMEError to return false for non-ACMEError")
	}

	stdErr := errors.New("standard error")
	_, ok = AsACMEError(stdErr)
	if ok {
		t.Error("expected AsACMEError to return false for standard error")
	}
}

func TestACMEError_HTTPStatus(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected int
	}{
		{CodeACMEAccountDoesNotExist, 400},
		{CodeACMEAlreadyRevoked, 400},
		{CodeACMEBadCSR, 400},
		{CodeACMEBadNonce, 400},
		{CodeACMEBadPublicKey, 400},
		{CodeACMEBadRevocationReason, 400},
		{CodeACMEBadSignatureAlgorithm, 400},
		{CodeACMECAA, 403},
		{CodeACMECompound, 400},
		{CodeACMEConnection, 400},
		{CodeACMEDNS, 400},
		{CodeACMEExternalAccountRequired, 403},
		{CodeACMEIncorrectResponse, 403},
		{CodeACMEInvalidContact, 400},
		{CodeACMEMalformed, 400},
		{CodeACMEOrderNotReady, 403},
		{CodeACMERateLimited, 429},
		{CodeACMERejectedIdentifier, 400},
		{CodeACMEServerInternal, 500},
		{CodeACMETLS, 400},
		{CodeACMEUnauthorized, 403},
		{CodeACMEUnsupportedContact, 400},
		{CodeACMEUnsupportedIdentifier, 400},
		{CodeACMEUserActionRequired, 403},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			err := NewACMEError(tt.code, "Op", "msg")
			if got := err.HTTPStatus(); got != tt.expected {
				t.Errorf("HTTPStatus() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestACMEHTTPStatus(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected int
	}{
		// ACME codes
		{CodeACMEBadNonce, 400},
		{CodeACMERateLimited, 429},
		{CodeACMEServerInternal, 500},
		{CodeACMEUnauthorized, 403},
		// General codes
		{CodeUnknown, 500},
		{CodeInvalidInput, 400},
		{CodeNotFound, 404},
		{CodeAlreadyExists, 409},
		{CodeUnauthorized, 401},
		{CodeForbidden, 403},
		{CodeConflict, 409},
		{CodeTimeout, 504},
		{CodeUnavailable, 503},
		{CodeInternal, 500},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			if got := ACMEHTTPStatus(tt.code); got != tt.expected {
				t.Errorf("ACMEHTTPStatus(%v) = %d, expected %d", tt.code, got, tt.expected)
			}
		})
	}
}

func TestACMEHTTPStatus_UnknownCode(t *testing.T) {
	unknownCode := ErrorCode(9999)
	if got := ACMEHTTPStatus(unknownCode); got != 500 {
		t.Errorf("expected 500 for unknown code, got %d", got)
	}
}

func TestACMEIdentifier(t *testing.T) {
	id := &ACMEIdentifier{
		Type:  "dns",
		Value: "example.com",
	}

	if id.Type != "dns" {
		t.Errorf("expected type 'dns', got %q", id.Type)
	}
	if id.Value != "example.com" {
		t.Errorf("expected value 'example.com', got %q", id.Value)
	}
}

func TestACMESubproblem(t *testing.T) {
	sp := ACMESubproblem{
		Type:   "urn:ietf:params:acme:error:caa",
		Detail: "CAA record prevents issuance",
		Identifier: &ACMEIdentifier{
			Type:  "dns",
			Value: "sub.example.com",
		},
	}

	if sp.Type != "urn:ietf:params:acme:error:caa" {
		t.Errorf("expected type urn, got %q", sp.Type)
	}
	if sp.Identifier == nil {
		t.Fatal("expected non-nil identifier")
	}
	if sp.Identifier.Value != "sub.example.com" {
		t.Errorf("expected identifier value, got %q", sp.Identifier.Value)
	}
}

func TestACMESubproblem_NilIdentifier(t *testing.T) {
	sp := ACMESubproblem{
		Type:   "urn:ietf:params:acme:error:dns",
		Detail: "DNS error",
	}

	if sp.Identifier != nil {
		t.Error("expected nil identifier")
	}
}

func TestACMEErrorChaining(t *testing.T) {
	err := NewACMEError(CodeACMECompound, "ValidateOrder", "validation failed").
		WithInstance("https://ca.example.com/errors/12345").
		AddSubproblem(ACMESubproblem{
			Type:   "urn:ietf:params:acme:error:caa",
			Detail: "CAA prevents issuance",
			Identifier: &ACMEIdentifier{
				Type:  "dns",
				Value: "example.com",
			},
		}).
		AddSubproblem(ACMESubproblem{
			Type:   "urn:ietf:params:acme:error:dns",
			Detail: "DNS lookup failed",
			Identifier: &ACMEIdentifier{
				Type:  "dns",
				Value: "www.example.com",
			},
		})

	if err.Instance != "https://ca.example.com/errors/12345" {
		t.Error("expected instance to be set")
	}
	if len(err.Subproblems) != 2 {
		t.Fatalf("expected 2 subproblems, got %d", len(err.Subproblems))
	}
	if err.Code != CodeACMECompound {
		t.Error("expected compound error code")
	}
}

func TestACMEError_ErrorsAs(t *testing.T) {
	err := NewACMEError(CodeACMEBadNonce, "Op", "msg")

	var acmeErr *ACMEError
	if !errors.As(err, &acmeErr) {
		t.Fatal("expected errors.As to succeed for ACMEError")
	}
	if acmeErr.Code != CodeACMEBadNonce {
		t.Error("expected code to be preserved")
	}
}

func TestACMEError_ErrorsIs(t *testing.T) {
	err1 := NewACMEError(CodeACMEBadNonce, "Op1", "msg1")
	err2 := NewACMEError(CodeACMEBadNonce, "Op2", "msg2")

	if !errors.Is(err1, err2) {
		t.Error("expected errors.Is to match ACMEErrors with same code")
	}
}
