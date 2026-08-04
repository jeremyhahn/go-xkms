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

package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

func TestErrorTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		// RFC 8555 error types
		{"AccountDoesNotExist", ErrTypeAccountDoesNotExist, "urn:ietf:params:acme:error:accountDoesNotExist"},
		{"AlreadyRevoked", ErrTypeAlreadyRevoked, "urn:ietf:params:acme:error:alreadyRevoked"},
		{"BadCSR", ErrTypeBadCSR, "urn:ietf:params:acme:error:badCSR"},
		{"BadNonce", ErrTypeBadNonce, "urn:ietf:params:acme:error:badNonce"},
		{"BadPublicKey", ErrTypeBadPublicKey, "urn:ietf:params:acme:error:badPublicKey"},
		{"BadRevocationReason", ErrTypeBadRevocationReason, "urn:ietf:params:acme:error:badRevocationReason"},
		{"BadSignatureAlgorithm", ErrTypeBadSignatureAlgorithm, "urn:ietf:params:acme:error:badSignatureAlgorithm"},
		{"CAA", ErrTypeCAA, "urn:ietf:params:acme:error:caa"},
		{"Compound", ErrTypeCompound, "urn:ietf:params:acme:error:compound"},
		{"Connection", ErrTypeConnection, "urn:ietf:params:acme:error:connection"},
		{"DNS", ErrTypeDNS, "urn:ietf:params:acme:error:dns"},
		{"ExternalAccountRequired", ErrTypeExternalAccountRequired, "urn:ietf:params:acme:error:externalAccountRequired"},
		{"IncorrectResponse", ErrTypeIncorrectResponse, "urn:ietf:params:acme:error:incorrectResponse"},
		{"InvalidContact", ErrTypeInvalidContact, "urn:ietf:params:acme:error:invalidContact"},
		{"Malformed", ErrTypeMalformed, "urn:ietf:params:acme:error:malformed"},
		{"OrderNotReady", ErrTypeOrderNotReady, "urn:ietf:params:acme:error:orderNotReady"},
		{"RateLimited", ErrTypeRateLimited, "urn:ietf:params:acme:error:rateLimited"},
		{"RejectedIdentifier", ErrTypeRejectedIdentifier, "urn:ietf:params:acme:error:rejectedIdentifier"},
		{"ServerInternal", ErrTypeServerInternal, "urn:ietf:params:acme:error:serverInternal"},
		{"TLS", ErrTypeTLS, "urn:ietf:params:acme:error:tls"},
		{"Unauthorized", ErrTypeUnauthorized, "urn:ietf:params:acme:error:unauthorized"},
		{"UnsupportedContact", ErrTypeUnsupportedContact, "urn:ietf:params:acme:error:unsupportedContact"},
		{"UnsupportedIdentifier", ErrTypeUnsupportedIdentifier, "urn:ietf:params:acme:error:unsupportedIdentifier"},
		{"UserActionRequired", ErrTypeUserActionRequired, "urn:ietf:params:acme:error:userActionRequired"},
		// RFC 9773 ARI error types
		{"AutoRenewalCanceled", ErrTypeAutoRenewalCanceled, "urn:ietf:params:acme:error:autoRenewalCanceled"},
		{"AutoRenewalExpired", ErrTypeAutoRenewalExpired, "urn:ietf:params:acme:error:autoRenewalExpired"},
		{"AutoRenewalCancellationInvalid", ErrTypeAutoRenewalCancellationInvalid, "urn:ietf:params:acme:error:autoRenewalCancellationInvalid"},
		{"AutoRenewalRevocationNotSupported", ErrTypeAutoRenewalRevocationNotSupported, "urn:ietf:params:acme:error:autoRenewalRevocationNotSupported"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.constant)
			}
		})
	}
}

func TestACMEErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ACMEError
		expected string
	}{
		{
			name: "with detail",
			err: &ACMEError{
				Type:   ErrTypeBadNonce,
				Detail: "Invalid nonce value",
			},
			expected: "Invalid nonce value",
		},
		{
			name: "without detail",
			err: &ACMEError{
				Type: ErrTypeBadNonce,
			},
			expected: ErrTypeBadNonce,
		},
		{
			name: "empty error",
			err: &ACMEError{
				Type: ErrTypeMalformed,
			},
			expected: ErrTypeMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.err.Error()
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestACMEErrorUnwrap(t *testing.T) {
	err := &ACMEError{
		Type:   ErrTypeBadNonce,
		Detail: "test",
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap should return nil")
	}
}

func TestACMEErrorShortType(t *testing.T) {
	tests := []struct {
		name     string
		errType  string
		expected string
	}{
		{"with prefix", ErrTypeBadNonce, "badNonce"},
		{"with prefix 2", ErrTypeServerInternal, "serverInternal"},
		{"without prefix", "badNonce", "badNonce"},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &ACMEError{Type: tc.errType}
			result := err.ShortType()
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestACMEErrorIs(t *testing.T) {
	tests := []struct {
		name     string
		err      *ACMEError
		target   error
		expected bool
	}{
		{
			name:     "same type",
			err:      &ACMEError{Type: ErrTypeBadNonce},
			target:   &ACMEError{Type: ErrTypeBadNonce},
			expected: true,
		},
		{
			name:     "different type",
			err:      &ACMEError{Type: ErrTypeBadNonce},
			target:   &ACMEError{Type: ErrTypeServerInternal},
			expected: false,
		},
		{
			name:     "non-ACME error",
			err:      &ACMEError{Type: ErrTypeBadNonce},
			target:   errors.New("some error"),
			expected: false,
		},
		{
			name:     "nil target",
			err:      &ACMEError{Type: ErrTypeBadNonce},
			target:   nil,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.err.Is(tc.target)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestACMEErrorIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		errType  string
		expected bool
	}{
		{"BadNonce", ErrTypeBadNonce, true},
		{"Connection", ErrTypeConnection, true},
		{"DNS", ErrTypeDNS, true},
		{"ServerInternal", ErrTypeServerInternal, true},
		{"RateLimited", ErrTypeRateLimited, true},
		{"Unauthorized", ErrTypeUnauthorized, false},
		{"BadCSR", ErrTypeBadCSR, false},
		{"Malformed", ErrTypeMalformed, false},
		{"AccountDoesNotExist", ErrTypeAccountDoesNotExist, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &ACMEError{Type: tc.errType}
			result := err.IsRetryable()
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseACMEError(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		statusCode     int
		expectedType   string
		expectedDetail string
		expectedStatus int
	}{
		{
			name: "valid ACME error",
			body: `{
				"type": "urn:ietf:params:acme:error:badNonce",
				"detail": "Invalid nonce",
				"status": 400
			}`,
			statusCode:     400,
			expectedType:   ErrTypeBadNonce,
			expectedDetail: "Invalid nonce",
			expectedStatus: 400,
		},
		{
			name: "ACME error without status in JSON",
			body: `{
				"type": "urn:ietf:params:acme:error:serverInternal",
				"detail": "Internal server error"
			}`,
			statusCode:     500,
			expectedType:   ErrTypeServerInternal,
			expectedDetail: "Internal server error",
			expectedStatus: 500,
		},
		{
			name:           "invalid JSON",
			body:           "not json",
			statusCode:     400,
			expectedType:   ErrTypeMalformed,
			expectedDetail: "not json",
			expectedStatus: 400,
		},
		{
			name: "with subproblems",
			body: `{
				"type": "urn:ietf:params:acme:error:compound",
				"detail": "Multiple errors",
				"status": 400,
				"subproblems": [
					{
						"type": "urn:ietf:params:acme:error:dns",
						"detail": "DNS lookup failed"
					}
				]
			}`,
			statusCode:     400,
			expectedType:   ErrTypeCompound,
			expectedDetail: "Multiple errors",
			expectedStatus: 400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.statusCode,
				Body:       io.NopCloser(bytes.NewBufferString(tc.body)),
			}

			acmeErr, err := ParseACMEError(resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if acmeErr.Type != tc.expectedType {
				t.Errorf("expected type %q, got %q", tc.expectedType, acmeErr.Type)
			}
			if acmeErr.Detail != tc.expectedDetail {
				t.Errorf("expected detail %q, got %q", tc.expectedDetail, acmeErr.Detail)
			}
			if acmeErr.Status != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, acmeErr.Status)
			}
		})
	}
}

func TestParseACMEErrorNilResponse(t *testing.T) {
	_, err := ParseACMEError(nil)
	if !errors.Is(err, ErrNilResponse) {
		t.Errorf("expected ErrNilResponse, got %v", err)
	}
}

func TestParseACMEErrorNilBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: 400,
		Body:       nil,
	}
	acmeErr, err := ParseACMEError(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acmeErr.Type != ErrTypeMalformed {
		t.Errorf("expected type %q, got %q", ErrTypeMalformed, acmeErr.Type)
	}
	if acmeErr.Detail != "empty response body" {
		t.Errorf("expected detail 'empty response body', got %q", acmeErr.Detail)
	}
}

func TestParseACMEErrorWithSubproblems(t *testing.T) {
	body := `{
		"type": "urn:ietf:params:acme:error:compound",
		"detail": "Multiple errors occurred",
		"status": 400,
		"subproblems": [
			{
				"type": "urn:ietf:params:acme:error:dns",
				"detail": "DNS resolution failed",
				"identifier": {"type": "dns", "value": "example.com"}
			},
			{
				"type": "urn:ietf:params:acme:error:caa",
				"detail": "CAA record forbids issuance",
				"identifier": {"type": "dns", "value": "example.org"}
			}
		]
	}`

	resp := &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}

	acmeErr, err := ParseACMEError(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(acmeErr.Subproblems) != 2 {
		t.Fatalf("expected 2 subproblems, got %d", len(acmeErr.Subproblems))
	}

	if acmeErr.Subproblems[0].Type != ErrTypeDNS {
		t.Errorf("expected first subproblem type %q, got %q", ErrTypeDNS, acmeErr.Subproblems[0].Type)
	}
	if acmeErr.Subproblems[0].Identifier == nil {
		t.Error("expected first subproblem to have identifier")
	} else {
		if acmeErr.Subproblems[0].Identifier.Type != "dns" {
			t.Errorf("expected identifier type 'dns', got %q", acmeErr.Subproblems[0].Identifier.Type)
		}
		if acmeErr.Subproblems[0].Identifier.Value != "example.com" {
			t.Errorf("expected identifier value 'example.com', got %q", acmeErr.Subproblems[0].Identifier.Value)
		}
	}

	if acmeErr.Subproblems[1].Type != ErrTypeCAA {
		t.Errorf("expected second subproblem type %q, got %q", ErrTypeCAA, acmeErr.Subproblems[1].Type)
	}
}

func TestParseACMEErrorFromBytes(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		statusCode     int
		expectedType   string
		expectedDetail string
		expectedStatus int
	}{
		{
			name: "valid JSON",
			data: []byte(`{
				"type": "urn:ietf:params:acme:error:unauthorized",
				"detail": "Account not found"
			}`),
			statusCode:     401,
			expectedType:   ErrTypeUnauthorized,
			expectedDetail: "Account not found",
			expectedStatus: 401,
		},
		{
			name:           "empty data",
			data:           []byte{},
			statusCode:     400,
			expectedType:   ErrTypeMalformed,
			expectedDetail: "empty response body",
			expectedStatus: 400,
		},
		{
			name:           "invalid JSON",
			data:           []byte("not valid json"),
			statusCode:     500,
			expectedType:   ErrTypeMalformed,
			expectedDetail: "not valid json",
			expectedStatus: 500,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acmeErr, err := ParseACMEErrorFromBytes(tc.data, tc.statusCode)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if acmeErr.Type != tc.expectedType {
				t.Errorf("expected type %q, got %q", tc.expectedType, acmeErr.Type)
			}
			if acmeErr.Detail != tc.expectedDetail {
				t.Errorf("expected detail %q, got %q", tc.expectedDetail, acmeErr.Detail)
			}
			if acmeErr.Status != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, acmeErr.Status)
			}
		})
	}
}

func TestNewACMEError(t *testing.T) {
	tests := []struct {
		name           string
		errType        string
		detail         string
		status         int
		expectedType   string
		expectedDetail string
		expectedStatus int
	}{
		{
			name:           "with URN prefix",
			errType:        ErrTypeBadNonce,
			detail:         "Bad nonce",
			status:         400,
			expectedType:   ErrTypeBadNonce,
			expectedDetail: "Bad nonce",
			expectedStatus: 400,
		},
		{
			name:           "without URN prefix",
			errType:        "badNonce",
			detail:         "Bad nonce",
			status:         400,
			expectedType:   ErrTypeBadNonce,
			expectedDetail: "Bad nonce",
			expectedStatus: 400,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewACMEError(tc.errType, tc.detail, tc.status)

			if err.Type != tc.expectedType {
				t.Errorf("expected type %q, got %q", tc.expectedType, err.Type)
			}
			if err.Detail != tc.expectedDetail {
				t.Errorf("expected detail %q, got %q", tc.expectedDetail, err.Detail)
			}
			if err.Status != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, err.Status)
			}
		})
	}
}

func TestNewACMEErrorWithSubproblems(t *testing.T) {
	subproblems := []Subproblem{
		{
			Type:   ErrTypeDNS,
			Detail: "DNS lookup failed",
			Identifier: &Identifier{
				Type:  "dns",
				Value: "example.com",
			},
		},
	}

	err := NewACMEErrorWithSubproblems(ErrTypeCompound, "Multiple errors", 400, subproblems)

	if err.Type != ErrTypeCompound {
		t.Errorf("expected type %q, got %q", ErrTypeCompound, err.Type)
	}
	if len(err.Subproblems) != 1 {
		t.Fatalf("expected 1 subproblem, got %d", len(err.Subproblems))
	}
	if err.Subproblems[0].Type != ErrTypeDNS {
		t.Errorf("expected subproblem type %q, got %q", ErrTypeDNS, err.Subproblems[0].Type)
	}
}

func TestErrorTypeHelperFunctions(t *testing.T) {
	tests := []struct {
		name       string
		errType    string
		checkFunc  func(error) bool
		shouldPass bool
	}{
		// RFC 8555 error types - positive tests
		{"IsAccountDoesNotExist", ErrTypeAccountDoesNotExist, IsAccountDoesNotExist, true},
		{"IsAlreadyRevoked", ErrTypeAlreadyRevoked, IsAlreadyRevoked, true},
		{"IsBadCSR", ErrTypeBadCSR, IsBadCSR, true},
		{"IsBadNonce", ErrTypeBadNonce, IsBadNonce, true},
		{"IsBadPublicKey", ErrTypeBadPublicKey, IsBadPublicKey, true},
		{"IsBadRevocationReason", ErrTypeBadRevocationReason, IsBadRevocationReason, true},
		{"IsBadSignatureAlgorithm", ErrTypeBadSignatureAlgorithm, IsBadSignatureAlgorithm, true},
		{"IsCAA", ErrTypeCAA, IsCAA, true},
		{"IsCompound", ErrTypeCompound, IsCompound, true},
		{"IsConnection", ErrTypeConnection, IsConnection, true},
		{"IsDNS", ErrTypeDNS, IsDNS, true},
		{"IsExternalAccountRequired", ErrTypeExternalAccountRequired, IsExternalAccountRequired, true},
		{"IsIncorrectResponse", ErrTypeIncorrectResponse, IsIncorrectResponse, true},
		{"IsInvalidContact", ErrTypeInvalidContact, IsInvalidContact, true},
		{"IsMalformed", ErrTypeMalformed, IsMalformed, true},
		{"IsOrderNotReady", ErrTypeOrderNotReady, IsOrderNotReady, true},
		{"IsRateLimited", ErrTypeRateLimited, IsRateLimited, true},
		{"IsRejectedIdentifier", ErrTypeRejectedIdentifier, IsRejectedIdentifier, true},
		{"IsServerInternal", ErrTypeServerInternal, IsServerInternal, true},
		{"IsTLS", ErrTypeTLS, IsTLS, true},
		{"IsUnauthorized", ErrTypeUnauthorized, IsUnauthorized, true},
		{"IsUnsupportedContact", ErrTypeUnsupportedContact, IsUnsupportedContact, true},
		{"IsUnsupportedIdentifier", ErrTypeUnsupportedIdentifier, IsUnsupportedIdentifier, true},
		{"IsUserActionRequired", ErrTypeUserActionRequired, IsUserActionRequired, true},
		// RFC 9773 ARI error types - positive tests
		{"IsAutoRenewalCanceled", ErrTypeAutoRenewalCanceled, IsAutoRenewalCanceled, true},
		{"IsAutoRenewalExpired", ErrTypeAutoRenewalExpired, IsAutoRenewalExpired, true},
		{"IsAutoRenewalCancellationInvalid", ErrTypeAutoRenewalCancellationInvalid, IsAutoRenewalCancellationInvalid, true},
		{"IsAutoRenewalRevocationNotSupported", ErrTypeAutoRenewalRevocationNotSupported, IsAutoRenewalRevocationNotSupported, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acmeErr := &ACMEError{Type: tc.errType}
			result := tc.checkFunc(acmeErr)
			if result != tc.shouldPass {
				t.Errorf("expected %v, got %v", tc.shouldPass, result)
			}
		})
	}
}

func TestErrorTypeHelperFunctionsNegative(t *testing.T) {
	// Use a different error type for all checks
	acmeErr := &ACMEError{Type: ErrTypeBadNonce}

	tests := []struct {
		name      string
		checkFunc func(error) bool
	}{
		{"IsAccountDoesNotExist", IsAccountDoesNotExist},
		{"IsAlreadyRevoked", IsAlreadyRevoked},
		{"IsBadCSR", IsBadCSR},
		// Skip IsBadNonce as it matches our test error
		{"IsBadPublicKey", IsBadPublicKey},
		{"IsBadRevocationReason", IsBadRevocationReason},
		{"IsBadSignatureAlgorithm", IsBadSignatureAlgorithm},
		{"IsCAA", IsCAA},
		{"IsCompound", IsCompound},
		{"IsConnection", IsConnection},
		{"IsDNS", IsDNS},
		{"IsExternalAccountRequired", IsExternalAccountRequired},
		{"IsIncorrectResponse", IsIncorrectResponse},
		{"IsInvalidContact", IsInvalidContact},
		{"IsMalformed", IsMalformed},
		{"IsOrderNotReady", IsOrderNotReady},
		{"IsRateLimited", IsRateLimited},
		{"IsRejectedIdentifier", IsRejectedIdentifier},
		{"IsServerInternal", IsServerInternal},
		{"IsTLS", IsTLS},
		{"IsUnauthorized", IsUnauthorized},
		{"IsUnsupportedContact", IsUnsupportedContact},
		{"IsUnsupportedIdentifier", IsUnsupportedIdentifier},
		{"IsUserActionRequired", IsUserActionRequired},
		{"IsAutoRenewalCanceled", IsAutoRenewalCanceled},
		{"IsAutoRenewalExpired", IsAutoRenewalExpired},
		{"IsAutoRenewalCancellationInvalid", IsAutoRenewalCancellationInvalid},
		{"IsAutoRenewalRevocationNotSupported", IsAutoRenewalRevocationNotSupported},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.checkFunc(acmeErr) {
				t.Errorf("expected false for %s with badNonce error", tc.name)
			}
		})
	}
}

func TestErrorTypeHelperFunctionsWithNonACMEError(t *testing.T) {
	regularErr := errors.New("regular error")

	tests := []struct {
		name      string
		checkFunc func(error) bool
	}{
		{"IsAccountDoesNotExist", IsAccountDoesNotExist},
		{"IsAlreadyRevoked", IsAlreadyRevoked},
		{"IsBadCSR", IsBadCSR},
		{"IsBadNonce", IsBadNonce},
		{"IsBadPublicKey", IsBadPublicKey},
		{"IsBadRevocationReason", IsBadRevocationReason},
		{"IsBadSignatureAlgorithm", IsBadSignatureAlgorithm},
		{"IsCAA", IsCAA},
		{"IsCompound", IsCompound},
		{"IsConnection", IsConnection},
		{"IsDNS", IsDNS},
		{"IsExternalAccountRequired", IsExternalAccountRequired},
		{"IsIncorrectResponse", IsIncorrectResponse},
		{"IsInvalidContact", IsInvalidContact},
		{"IsMalformed", IsMalformed},
		{"IsOrderNotReady", IsOrderNotReady},
		{"IsRateLimited", IsRateLimited},
		{"IsRejectedIdentifier", IsRejectedIdentifier},
		{"IsServerInternal", IsServerInternal},
		{"IsTLS", IsTLS},
		{"IsUnauthorized", IsUnauthorized},
		{"IsUnsupportedContact", IsUnsupportedContact},
		{"IsUnsupportedIdentifier", IsUnsupportedIdentifier},
		{"IsUserActionRequired", IsUserActionRequired},
		{"IsAutoRenewalCanceled", IsAutoRenewalCanceled},
		{"IsAutoRenewalExpired", IsAutoRenewalExpired},
		{"IsAutoRenewalCancellationInvalid", IsAutoRenewalCancellationInvalid},
		{"IsAutoRenewalRevocationNotSupported", IsAutoRenewalRevocationNotSupported},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.checkFunc(regularErr) {
				t.Errorf("expected false for non-ACME error")
			}
		})
	}
}

func TestGetACMEError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		shouldExist bool
	}{
		{
			name:        "direct ACME error",
			err:         &ACMEError{Type: ErrTypeBadNonce},
			shouldExist: true,
		},
		{
			name:        "wrapped ACME error",
			err:         &errs.Wrapped{Msg: "wrapped", Err: &ACMEError{Type: ErrTypeBadNonce}},
			shouldExist: true,
		},
		{
			name:        "regular error",
			err:         errors.New("not an ACME error"),
			shouldExist: false,
		},
		{
			name:        "nil error",
			err:         nil,
			shouldExist: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetACMEError(tc.err)
			if tc.shouldExist && result == nil {
				t.Error("expected ACMEError, got nil")
			}
			if !tc.shouldExist && result != nil {
				t.Error("expected nil, got ACMEError")
			}
		})
	}
}

func TestIsACMEError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ACME error",
			err:      &ACMEError{Type: ErrTypeBadNonce},
			expected: true,
		},
		{
			name:     "wrapped ACME error",
			err:      &errs.Wrapped{Msg: "context", Err: &ACMEError{Type: ErrTypeBadNonce}},
			expected: true,
		},
		{
			name:     "regular error",
			err:      errors.New("not ACME"),
			expected: false,
		},
		{
			name:     "nil",
			err:      nil,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsACMEError(tc.err)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseACMEErrorWithIdentifier(t *testing.T) {
	body := `{
		"type": "urn:ietf:params:acme:error:rejectedIdentifier",
		"detail": "Identifier rejected",
		"status": 403,
		"identifier": {
			"type": "dns",
			"value": "forbidden.example.com"
		}
	}`

	resp := &http.Response{
		StatusCode: 403,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}

	acmeErr, err := ParseACMEError(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if acmeErr.Identifier == nil {
		t.Fatal("expected identifier, got nil")
	}
	if acmeErr.Identifier.Type != "dns" {
		t.Errorf("expected identifier type 'dns', got %q", acmeErr.Identifier.Type)
	}
	if acmeErr.Identifier.Value != "forbidden.example.com" {
		t.Errorf("expected identifier value 'forbidden.example.com', got %q", acmeErr.Identifier.Value)
	}
}

func TestParseACMEErrorWithInstance(t *testing.T) {
	body := `{
		"type": "urn:ietf:params:acme:error:userActionRequired",
		"detail": "Terms of service have changed",
		"status": 403,
		"instance": "https://example.com/acme/tos"
	}`

	resp := &http.Response{
		StatusCode: 403,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}

	acmeErr, err := ParseACMEError(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if acmeErr.Instance != "https://example.com/acme/tos" {
		t.Errorf("expected instance URL, got %q", acmeErr.Instance)
	}
}

func TestClientSpecificErrors(t *testing.T) {
	t.Run("ErrNilResponse", func(t *testing.T) {
		if ErrNilResponse.Error() != "acme-client: nil HTTP response" {
			t.Errorf("unexpected error message: %s", ErrNilResponse.Error())
		}
	})

	t.Run("ErrResponseReadFailed", func(t *testing.T) {
		if ErrResponseReadFailed.Error() != "acme-client: failed to read response body" {
			t.Errorf("unexpected error message: %s", ErrResponseReadFailed.Error())
		}
	})
}

// errReader is a helper that always returns an error when Read is called
type errReader struct{}

func (e errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read error")
}

func TestParseACMEErrorReadError(t *testing.T) {
	resp := &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(errReader{}),
	}

	_, err := ParseACMEError(resp)
	if !errors.Is(err, ErrResponseReadFailed) {
		t.Errorf("expected ErrResponseReadFailed, got %v", err)
	}
}

func TestWrappedACMEErrorMatching(t *testing.T) {
	originalErr := &ACMEError{
		Type:   ErrTypeBadNonce,
		Detail: "original error",
	}

	wrappedOnce := &errs.Wrapped{Msg: "context", Err: originalErr}
	wrappedTwice := &errs.Wrapped{Msg: "more context", Err: wrappedOnce}

	t.Run("errors.Is with wrapped error", func(t *testing.T) {
		if !errors.Is(wrappedTwice, originalErr) {
			t.Error("errors.Is should match wrapped error")
		}
	})

	t.Run("IsBadNonce with wrapped error", func(t *testing.T) {
		if !IsBadNonce(wrappedTwice) {
			t.Error("IsBadNonce should match wrapped error")
		}
	})

	t.Run("GetACMEError with wrapped error", func(t *testing.T) {
		extracted := GetACMEError(wrappedTwice)
		if extracted == nil {
			t.Fatal("expected to extract ACME error")
		}
		if extracted.Type != ErrTypeBadNonce {
			t.Errorf("expected type %q, got %q", ErrTypeBadNonce, extracted.Type)
		}
	})
}
