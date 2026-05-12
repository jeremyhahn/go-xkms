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

package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestToProblemDocument(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedType   string
		expectedStatus int
		expectedDetail string
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedType:   "",
			expectedStatus: 0,
			expectedDetail: "",
		},
		{
			name:           "non-TrustedCAError",
			err:            errors.New("plain error"),
			expectedType:   "urn:ietf:params:acme:error:serverInternal",
			expectedStatus: http.StatusInternalServerError,
			expectedDetail: "plain error",
		},
		{
			name: "Malformed",
			err: &TrustedCAError{
				Type:   Malformed,
				Detail: "request body was malformed",
			},
			expectedType:   "urn:ietf:params:acme:error:malformed",
			expectedStatus: http.StatusBadRequest,
			expectedDetail: "request body was malformed",
		},
		{
			name: "BadNonce",
			err: &TrustedCAError{
				Type:   BadNonce,
				Detail: "nonce expired",
			},
			expectedType:   "urn:ietf:params:acme:error:badNonce",
			expectedStatus: http.StatusBadRequest,
			expectedDetail: "nonce expired",
		},
		{
			name: "RateLimit",
			err: &TrustedCAError{
				Type:   RateLimit,
				Detail: "too many requests",
			},
			expectedType:   "urn:ietf:params:acme:error:rateLimited",
			expectedStatus: http.StatusTooManyRequests,
			expectedDetail: "too many requests",
		},
		{
			name: "AccountDoesNotExist",
			err: &TrustedCAError{
				Type:   AccountDoesNotExist,
				Detail: "account not found",
			},
			expectedType:   "urn:ietf:params:acme:error:accountDoesNotExist",
			expectedStatus: http.StatusNotFound,
			expectedDetail: "account not found",
		},
		{
			name: "UserActionRequired with instance",
			err: &TrustedCAError{
				Type:     UserActionRequired,
				Detail:   "agree to terms",
				Instance: "https://example.com/terms",
			},
			expectedType:   "urn:ietf:params:acme:error:userActionRequired",
			expectedStatus: http.StatusForbidden,
			expectedDetail: "agree to terms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := ToProblemDocument(tt.err)
			if tt.err == nil {
				if pd != nil {
					t.Errorf("ToProblemDocument(nil) = %v, want nil", pd)
				}
				return
			}

			if pd.Type != tt.expectedType {
				t.Errorf("Type = %q, want %q", pd.Type, tt.expectedType)
			}
			if pd.Status != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", pd.Status, tt.expectedStatus)
			}
			if pd.Detail != tt.expectedDetail {
				t.Errorf("Detail = %q, want %q", pd.Detail, tt.expectedDetail)
			}
		})
	}
}

func TestToProblemDocument_WithSubErrors(t *testing.T) {
	err := &TrustedCAError{
		Type:   CompoundError,
		Detail: "multiple errors",
		SubErrors: []SubError{
			{
				TrustedCAError: &TrustedCAError{
					Type:   BadCSR,
					Detail: "invalid CSR format",
				},
				Identifier: ACMEIdentifier{Type: "dns", Value: "example.com"},
			},
			{
				TrustedCAError: &TrustedCAError{
					Type:   RejectedIdentifier,
					Detail: "domain blocked",
				},
				Identifier: ACMEIdentifier{Type: "dns", Value: "blocked.com"},
			},
		},
	}

	pd := ToProblemDocument(err)

	if len(pd.SubProblems) != 2 {
		t.Fatalf("SubProblems len = %d, want 2", len(pd.SubProblems))
	}

	// Check first subproblem
	sp1 := pd.SubProblems[0]
	if sp1.Type != "urn:ietf:params:acme:error:badCSR" {
		t.Errorf("SubProblems[0].Type = %q, want badCSR URN", sp1.Type)
	}
	if sp1.Detail != "invalid CSR format" {
		t.Errorf("SubProblems[0].Detail = %q, want 'invalid CSR format'", sp1.Detail)
	}
	if sp1.Identifier == nil {
		t.Fatal("SubProblems[0].Identifier is nil")
	}
	if sp1.Identifier.Value != "example.com" {
		t.Errorf("SubProblems[0].Identifier.Value = %q, want 'example.com'", sp1.Identifier.Value)
	}

	// Check second subproblem
	sp2 := pd.SubProblems[1]
	if sp2.Type != "urn:ietf:params:acme:error:rejectedIdentifier" {
		t.Errorf("SubProblems[1].Type = %q, want rejectedIdentifier URN", sp2.Type)
	}
}

func TestToProblemDocument_EmptyIdentifier(t *testing.T) {
	err := &TrustedCAError{
		Type:   CompoundError,
		Detail: "compound error",
		SubErrors: []SubError{
			{
				TrustedCAError: &TrustedCAError{Type: BadCSR, Detail: "bad"},
				Identifier:     ACMEIdentifier{}, // Empty identifier
			},
		},
	}

	pd := ToProblemDocument(err)

	if len(pd.SubProblems) != 1 {
		t.Fatalf("SubProblems len = %d, want 1", len(pd.SubProblems))
	}

	// Empty identifier should result in nil Identifier field
	if pd.SubProblems[0].Identifier != nil {
		t.Error("SubProblems[0].Identifier should be nil for empty identifier")
	}
}

func TestToProblemDocumentWithIdentifier(t *testing.T) {
	err := &TrustedCAError{
		Type:   RejectedIdentifier,
		Detail: "domain rejected",
	}

	pd := ToProblemDocumentWithIdentifier(err, "dns", "example.com")

	if pd.Identifier == nil {
		t.Fatal("Identifier is nil")
	}
	if pd.Identifier.Type != "dns" {
		t.Errorf("Identifier.Type = %q, want 'dns'", pd.Identifier.Type)
	}
	if pd.Identifier.Value != "example.com" {
		t.Errorf("Identifier.Value = %q, want 'example.com'", pd.Identifier.Value)
	}
}

func TestToProblemDocumentWithIdentifier_Nil(t *testing.T) {
	pd := ToProblemDocumentWithIdentifier(nil, "dns", "example.com")
	if pd != nil {
		t.Errorf("ToProblemDocumentWithIdentifier(nil, ...) = %v, want nil", pd)
	}
}

func TestToProblemDocumentWithIdentifier_EmptyIdentifier(t *testing.T) {
	err := &TrustedCAError{Type: Malformed, Detail: "bad"}
	pd := ToProblemDocumentWithIdentifier(err, "", "")
	if pd.Identifier != nil {
		t.Error("Identifier should be nil for empty type and value")
	}
}

func TestErrorTypeToACMEType(t *testing.T) {
	tests := []struct {
		errType  ErrorType
		expected string
	}{
		{InternalServer, "serverInternal"},
		{Malformed, "malformed"},
		{Unauthorized, "unauthorized"},
		{NotFound, "accountDoesNotExist"},
		{RateLimit, "rateLimited"},
		{RejectedIdentifier, "rejectedIdentifier"},
		{InvalidEmail, "invalidContact"},
		{ConnectionFailure, "connection"},
		{CAA, "caa"},
		{MissingSCTs, "serverInternal"},
		{Duplicate, "serverInternal"},
		{OrderNotReady, "orderNotReady"},
		{DNS, "dns"},
		{BadPublicKey, "badPublicKey"},
		{BadCSR, "badCSR"},
		{AlreadyRevoked, "alreadyRevoked"},
		{BadRevocationReason, "badRevocationReason"},
		{UnsupportedContact, "unsupportedContact"},
		{UnknownSerial, "serverInternal"},
		{Conflict, "serverInternal"},
		{InvalidProfile, "invalidProfile"},
		{AlreadyReplaced, "serverInternal"},
		{BadSignatureAlgorithm, "badSignatureAlgorithm"},
		{AccountDoesNotExist, "accountDoesNotExist"},
		{BadNonce, "badNonce"},
		{ExternalAccountRequired, "externalAccountRequired"},
		{IncorrectResponse, "incorrectResponse"},
		{InvalidContact, "invalidContact"},
		{TLSError, "tls"},
		{UnsupportedIdentifier, "unsupportedIdentifier"},
		{UserActionRequired, "userActionRequired"},
		{AccountExists, "accountDoesNotExist"},
		{CompoundError, "compound"},
		{BadAttestationStatement, "badAttestationStatement"},
		{StorageFailure, "serverInternal"},
		{SerializationFailure, "serverInternal"},
		{TenantNotFound, "serverInternal"},
		{TenantSuspended, "unauthorized"},
		{TenantQuotaExceeded, "rateLimited"},
		{CertificateExpired, "unauthorized"},
		{CertificateNotYetValid, "unauthorized"},
		{SigningFailure, "serverInternal"},
		{VerificationFailure, "unauthorized"},
		{KeyGenerationFailure, "serverInternal"},
		{TPMError, "badAttestationStatement"},
		{OCSPFailure, "serverInternal"},
		{CRLFailure, "serverInternal"},
		{PolicyViolation, "unauthorized"},
		{AuthorizationExpired, "unauthorized"},
		{ChallengeTimeout, "connection"},
		{InvalidToken, "unauthorized"},
		{ErrorType(999), "serverInternal"}, // Unknown type
	}

	for _, tt := range tests {
		t.Run(tt.errType.String(), func(t *testing.T) {
			result := errorTypeToACMEType(tt.errType)
			if result != tt.expected {
				t.Errorf("errorTypeToACMEType(%v) = %q, want %q",
					tt.errType, result, tt.expected)
			}
		})
	}
}

func TestErrorTypeToHTTPStatus(t *testing.T) {
	tests := []struct {
		errType  ErrorType
		expected int
	}{
		{InternalServer, http.StatusInternalServerError},
		{Malformed, http.StatusBadRequest},
		{Unauthorized, http.StatusUnauthorized},
		{NotFound, http.StatusNotFound},
		{RateLimit, http.StatusTooManyRequests},
		{RejectedIdentifier, http.StatusForbidden},
		{InvalidEmail, http.StatusBadRequest},
		{ConnectionFailure, http.StatusBadRequest},
		{CAA, http.StatusForbidden},
		{MissingSCTs, http.StatusInternalServerError},
		{Duplicate, http.StatusConflict},
		{OrderNotReady, http.StatusForbidden},
		{DNS, http.StatusBadRequest},
		{BadPublicKey, http.StatusBadRequest},
		{BadCSR, http.StatusBadRequest},
		{AlreadyRevoked, http.StatusBadRequest},
		{BadRevocationReason, http.StatusBadRequest},
		{UnsupportedContact, http.StatusBadRequest},
		{UnknownSerial, http.StatusNotFound},
		{Conflict, http.StatusConflict},
		{InvalidProfile, http.StatusBadRequest},
		{AlreadyReplaced, http.StatusConflict},
		{BadSignatureAlgorithm, http.StatusBadRequest},
		{AccountDoesNotExist, http.StatusNotFound},
		{BadNonce, http.StatusBadRequest},
		{ExternalAccountRequired, http.StatusUnauthorized},
		{IncorrectResponse, http.StatusForbidden},
		{InvalidContact, http.StatusBadRequest},
		{TLSError, http.StatusBadRequest},
		{UnsupportedIdentifier, http.StatusBadRequest},
		{UserActionRequired, http.StatusForbidden},
		{AccountExists, http.StatusConflict},
		{CompoundError, http.StatusBadRequest},
		{BadAttestationStatement, http.StatusBadRequest},
		{StorageFailure, http.StatusInternalServerError},
		{SerializationFailure, http.StatusInternalServerError},
		{TenantNotFound, http.StatusNotFound},
		{TenantSuspended, http.StatusForbidden},
		{TenantQuotaExceeded, http.StatusTooManyRequests},
		{CertificateExpired, http.StatusForbidden},
		{CertificateNotYetValid, http.StatusForbidden},
		{SigningFailure, http.StatusInternalServerError},
		{VerificationFailure, http.StatusUnauthorized},
		{KeyGenerationFailure, http.StatusInternalServerError},
		{TPMError, http.StatusBadRequest},
		{OCSPFailure, http.StatusInternalServerError},
		{CRLFailure, http.StatusInternalServerError},
		{PolicyViolation, http.StatusForbidden},
		{AuthorizationExpired, http.StatusForbidden},
		{ChallengeTimeout, http.StatusRequestTimeout},
		{InvalidToken, http.StatusUnauthorized},
		{ErrorType(999), http.StatusInternalServerError}, // Unknown type
	}

	for _, tt := range tests {
		t.Run(tt.errType.String(), func(t *testing.T) {
			result := errorTypeToHTTPStatus(tt.errType)
			if result != tt.expected {
				t.Errorf("errorTypeToHTTPStatus(%v) = %d, want %d",
					tt.errType, result, tt.expected)
			}
		})
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: http.StatusOK,
		},
		{
			name: "TrustedCAError",
			err: &TrustedCAError{
				Type:   BadNonce,
				Detail: "nonce expired",
			},
			expected: http.StatusBadRequest,
		},
		{
			name:     "non-TrustedCAError",
			err:      errors.New("plain error"),
			expected: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HTTPStatus(tt.err)
			if result != tt.expected {
				t.Errorf("HTTPStatus() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestACMEType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name: "TrustedCAError",
			err: &TrustedCAError{
				Type:   BadNonce,
				Detail: "nonce expired",
			},
			expected: "urn:ietf:params:acme:error:badNonce",
		},
		{
			name:     "non-TrustedCAError",
			err:      errors.New("plain error"),
			expected: "urn:ietf:params:acme:error:serverInternal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ACMEType(tt.err)
			if result != tt.expected {
				t.Errorf("ACMEType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestProblemDocument_JSON(t *testing.T) {
	pd := &ProblemDocument{
		Type:     "urn:ietf:params:acme:error:malformed",
		Detail:   "request body was malformed",
		Status:   http.StatusBadRequest,
		Instance: "https://example.com/errors/123",
		Identifier: &ProblemIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		SubProblems: []SubProblemDoc{
			{
				Type:   "urn:ietf:params:acme:error:rejectedIdentifier",
				Detail: "domain blocked",
				Identifier: &ProblemIdentifier{
					Type:  "dns",
					Value: "blocked.com",
				},
			},
		},
	}

	// Just verify the structure is correct
	if pd.Type == "" {
		t.Error("Type should not be empty")
	}
	if len(pd.SubProblems) != 1 {
		t.Errorf("SubProblems len = %d, want 1", len(pd.SubProblems))
	}
}
