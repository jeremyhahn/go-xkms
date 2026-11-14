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
	"testing"
)

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected string
	}{
		// General codes
		{CodeUnknown, "UNKNOWN"},
		{CodeInvalidInput, "INVALID_INPUT"},
		{CodeNotFound, "NOT_FOUND"},
		{CodeAlreadyExists, "ALREADY_EXISTS"},
		{CodeUnauthorized, "UNAUTHORIZED"},
		{CodeForbidden, "FORBIDDEN"},
		{CodeConflict, "CONFLICT"},
		{CodePreconditionFailed, "PRECONDITION_FAILED"},
		{CodeRateLimited, "RATE_LIMITED"},
		{CodeInternal, "INTERNAL"},
		{CodeUnavailable, "UNAVAILABLE"},
		{CodeTimeout, "TIMEOUT"},
		{CodeCanceled, "CANCELED"},
		{CodeUnimplemented, "UNIMPLEMENTED"},
		{CodeResourceExhausted, "RESOURCE_EXHAUSTED"},
		{CodeNotInitialized, "NOT_INITIALIZED"},
		{CodeConfiguration, "CONFIGURATION"},
		{CodeConnection, "CONNECTION"},
		{CodeTransport, "TRANSPORT"},
		// ACME codes
		{CodeACMEAccountDoesNotExist, "urn:ietf:params:acme:error:accountDoesNotExist"},
		{CodeACMEAlreadyRevoked, "urn:ietf:params:acme:error:alreadyRevoked"},
		{CodeACMEBadCSR, "urn:ietf:params:acme:error:badCSR"},
		{CodeACMEBadNonce, "urn:ietf:params:acme:error:badNonce"},
		{CodeACMEBadPublicKey, "urn:ietf:params:acme:error:badPublicKey"},
		{CodeACMEBadRevocationReason, "urn:ietf:params:acme:error:badRevocationReason"},
		{CodeACMEBadSignatureAlgorithm, "urn:ietf:params:acme:error:badSignatureAlgorithm"},
		{CodeACMECAA, "urn:ietf:params:acme:error:caa"},
		{CodeACMECompound, "urn:ietf:params:acme:error:compound"},
		{CodeACMEConnection, "urn:ietf:params:acme:error:connection"},
		{CodeACMEDNS, "urn:ietf:params:acme:error:dns"},
		{CodeACMEExternalAccountRequired, "urn:ietf:params:acme:error:externalAccountRequired"},
		{CodeACMEIncorrectResponse, "urn:ietf:params:acme:error:incorrectResponse"},
		{CodeACMEInvalidContact, "urn:ietf:params:acme:error:invalidContact"},
		{CodeACMEMalformed, "urn:ietf:params:acme:error:malformed"},
		{CodeACMEOrderNotReady, "urn:ietf:params:acme:error:orderNotReady"},
		{CodeACMERateLimited, "urn:ietf:params:acme:error:rateLimited"},
		{CodeACMERejectedIdentifier, "urn:ietf:params:acme:error:rejectedIdentifier"},
		{CodeACMEServerInternal, "urn:ietf:params:acme:error:serverInternal"},
		{CodeACMETLS, "urn:ietf:params:acme:error:tls"},
		{CodeACMEUnauthorized, "urn:ietf:params:acme:error:unauthorized"},
		{CodeACMEUnsupportedContact, "urn:ietf:params:acme:error:unsupportedContact"},
		{CodeACMEUnsupportedIdentifier, "urn:ietf:params:acme:error:unsupportedIdentifier"},
		{CodeACMEUserActionRequired, "urn:ietf:params:acme:error:userActionRequired"},
		// Unknown code
		{ErrorCode(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("String() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrorCode_String_InvalidCode(t *testing.T) {
	code := ErrorCode(9999)
	if got := code.String(); got != "UNKNOWN" {
		t.Errorf("String() for invalid code = %q, expected 'UNKNOWN'", got)
	}
}

func TestErrorCode_IsRetryable(t *testing.T) {
	retryableCodes := []ErrorCode{
		CodeUnavailable,
		CodeTimeout,
		CodeResourceExhausted,
		CodeACMEBadNonce,
		CodeACMEConnection,
		CodeACMEDNS,
		CodeACMERateLimited,
		CodeACMEServerInternal,
	}

	nonRetryableCodes := []ErrorCode{
		CodeUnknown,
		CodeInvalidInput,
		CodeNotFound,
		CodeAlreadyExists,
		CodeUnauthorized,
		CodeForbidden,
		CodeConflict,
		CodePreconditionFailed,
		CodeRateLimited,
		CodeInternal,
		CodeCanceled,
		CodeUnimplemented,
		CodeNotInitialized,
		CodeConfiguration,
		CodeConnection,
		CodeTransport,
		CodeACMEAccountDoesNotExist,
		CodeACMEAlreadyRevoked,
		CodeACMEBadCSR,
		CodeACMEBadPublicKey,
		CodeACMEBadRevocationReason,
		CodeACMEBadSignatureAlgorithm,
		CodeACMECAA,
		CodeACMECompound,
		CodeACMEExternalAccountRequired,
		CodeACMEIncorrectResponse,
		CodeACMEInvalidContact,
		CodeACMEMalformed,
		CodeACMEOrderNotReady,
		CodeACMERejectedIdentifier,
		CodeACMETLS,
		CodeACMEUnauthorized,
		CodeACMEUnsupportedContact,
		CodeACMEUnsupportedIdentifier,
		CodeACMEUserActionRequired,
	}

	for _, code := range retryableCodes {
		t.Run(code.String()+"_retryable", func(t *testing.T) {
			if !code.IsRetryable() {
				t.Errorf("expected %v to be retryable", code)
			}
		})
	}

	for _, code := range nonRetryableCodes {
		t.Run(code.String()+"_not_retryable", func(t *testing.T) {
			if code.IsRetryable() {
				t.Errorf("expected %v to not be retryable", code)
			}
		})
	}
}

func TestErrorCode_IsClientError(t *testing.T) {
	clientErrorCodes := []ErrorCode{
		CodeInvalidInput,
		CodeNotFound,
		CodeAlreadyExists,
		CodeUnauthorized,
		CodeForbidden,
		CodeConflict,
		CodePreconditionFailed,
		CodeRateLimited,
		CodeACMEAccountDoesNotExist,
		CodeACMEAlreadyRevoked,
		CodeACMEBadCSR,
		CodeACMEBadNonce,
		CodeACMEBadPublicKey,
		CodeACMEBadRevocationReason,
		CodeACMEBadSignatureAlgorithm,
		CodeACMECAA,
		CodeACMECompound,
		CodeACMEExternalAccountRequired,
		CodeACMEIncorrectResponse,
		CodeACMEInvalidContact,
		CodeACMEMalformed,
		CodeACMEOrderNotReady,
		CodeACMERateLimited,
		CodeACMERejectedIdentifier,
		CodeACMEUnauthorized,
		CodeACMEUnsupportedContact,
		CodeACMEUnsupportedIdentifier,
		CodeACMEUserActionRequired,
	}

	nonClientErrorCodes := []ErrorCode{
		CodeUnknown,
		CodeInternal,
		CodeUnavailable,
		CodeTimeout,
		CodeCanceled,
		CodeUnimplemented,
		CodeResourceExhausted,
		CodeNotInitialized,
		CodeConfiguration,
		CodeConnection,
		CodeTransport,
		CodeACMEConnection,
		CodeACMEDNS,
		CodeACMEServerInternal,
		CodeACMETLS,
	}

	for _, code := range clientErrorCodes {
		t.Run(code.String()+"_is_client", func(t *testing.T) {
			if !code.IsClientError() {
				t.Errorf("expected %v to be client error", code)
			}
		})
	}

	for _, code := range nonClientErrorCodes {
		t.Run(code.String()+"_not_client", func(t *testing.T) {
			if code.IsClientError() {
				t.Errorf("expected %v to not be client error", code)
			}
		})
	}
}

func TestErrorCode_IsServerError(t *testing.T) {
	serverErrorCodes := []ErrorCode{
		CodeInternal,
		CodeUnavailable,
		CodeTimeout,
		CodeUnimplemented,
		CodeResourceExhausted,
		CodeACMEConnection,
		CodeACMEDNS,
		CodeACMEServerInternal,
		CodeACMETLS,
	}

	nonServerErrorCodes := []ErrorCode{
		CodeUnknown,
		CodeInvalidInput,
		CodeNotFound,
		CodeAlreadyExists,
		CodeUnauthorized,
		CodeForbidden,
		CodeConflict,
		CodePreconditionFailed,
		CodeRateLimited,
		CodeCanceled,
		CodeNotInitialized,
		CodeConfiguration,
		CodeConnection,
		CodeTransport,
		CodeACMEAccountDoesNotExist,
		CodeACMEAlreadyRevoked,
		CodeACMEBadCSR,
		CodeACMEBadNonce,
		CodeACMEBadPublicKey,
		CodeACMEBadRevocationReason,
		CodeACMEBadSignatureAlgorithm,
		CodeACMECAA,
		CodeACMECompound,
		CodeACMEExternalAccountRequired,
		CodeACMEIncorrectResponse,
		CodeACMEInvalidContact,
		CodeACMEMalformed,
		CodeACMEOrderNotReady,
		CodeACMERateLimited,
		CodeACMERejectedIdentifier,
		CodeACMEUnauthorized,
		CodeACMEUnsupportedContact,
		CodeACMEUnsupportedIdentifier,
		CodeACMEUserActionRequired,
	}

	for _, code := range serverErrorCodes {
		t.Run(code.String()+"_is_server", func(t *testing.T) {
			if !code.IsServerError() {
				t.Errorf("expected %v to be server error", code)
			}
		})
	}

	for _, code := range nonServerErrorCodes {
		t.Run(code.String()+"_not_server", func(t *testing.T) {
			if code.IsServerError() {
				t.Errorf("expected %v to not be server error", code)
			}
		})
	}
}

func TestErrorCode_IsACME(t *testing.T) {
	acmeCodes := []ErrorCode{
		CodeACMEAccountDoesNotExist,
		CodeACMEAlreadyRevoked,
		CodeACMEBadCSR,
		CodeACMEBadNonce,
		CodeACMEBadPublicKey,
		CodeACMEBadRevocationReason,
		CodeACMEBadSignatureAlgorithm,
		CodeACMECAA,
		CodeACMECompound,
		CodeACMEConnection,
		CodeACMEDNS,
		CodeACMEExternalAccountRequired,
		CodeACMEIncorrectResponse,
		CodeACMEInvalidContact,
		CodeACMEMalformed,
		CodeACMEOrderNotReady,
		CodeACMERateLimited,
		CodeACMERejectedIdentifier,
		CodeACMEServerInternal,
		CodeACMETLS,
		CodeACMEUnauthorized,
		CodeACMEUnsupportedContact,
		CodeACMEUnsupportedIdentifier,
		CodeACMEUserActionRequired,
	}

	nonACMECodes := []ErrorCode{
		CodeUnknown,
		CodeInvalidInput,
		CodeNotFound,
		CodeAlreadyExists,
		CodeUnauthorized,
		CodeForbidden,
		CodeConflict,
		CodeInternal,
		CodeUnavailable,
		CodeTimeout,
	}

	for _, code := range acmeCodes {
		t.Run(code.String()+"_is_acme", func(t *testing.T) {
			if !code.IsACME() {
				t.Errorf("expected %v to be ACME error", code)
			}
		})
	}

	for _, code := range nonACMECodes {
		t.Run(code.String()+"_not_acme", func(t *testing.T) {
			if code.IsACME() {
				t.Errorf("expected %v to not be ACME error", code)
			}
		})
	}
}

func TestParseACMEErrorType(t *testing.T) {
	tests := []struct {
		urn      string
		expected ErrorCode
	}{
		{"urn:ietf:params:acme:error:accountDoesNotExist", CodeACMEAccountDoesNotExist},
		{"urn:ietf:params:acme:error:alreadyRevoked", CodeACMEAlreadyRevoked},
		{"urn:ietf:params:acme:error:badCSR", CodeACMEBadCSR},
		{"urn:ietf:params:acme:error:badNonce", CodeACMEBadNonce},
		{"urn:ietf:params:acme:error:badPublicKey", CodeACMEBadPublicKey},
		{"urn:ietf:params:acme:error:badRevocationReason", CodeACMEBadRevocationReason},
		{"urn:ietf:params:acme:error:badSignatureAlgorithm", CodeACMEBadSignatureAlgorithm},
		{"urn:ietf:params:acme:error:caa", CodeACMECAA},
		{"urn:ietf:params:acme:error:compound", CodeACMECompound},
		{"urn:ietf:params:acme:error:connection", CodeACMEConnection},
		{"urn:ietf:params:acme:error:dns", CodeACMEDNS},
		{"urn:ietf:params:acme:error:externalAccountRequired", CodeACMEExternalAccountRequired},
		{"urn:ietf:params:acme:error:incorrectResponse", CodeACMEIncorrectResponse},
		{"urn:ietf:params:acme:error:invalidContact", CodeACMEInvalidContact},
		{"urn:ietf:params:acme:error:malformed", CodeACMEMalformed},
		{"urn:ietf:params:acme:error:orderNotReady", CodeACMEOrderNotReady},
		{"urn:ietf:params:acme:error:rateLimited", CodeACMERateLimited},
		{"urn:ietf:params:acme:error:rejectedIdentifier", CodeACMERejectedIdentifier},
		{"urn:ietf:params:acme:error:serverInternal", CodeACMEServerInternal},
		{"urn:ietf:params:acme:error:tls", CodeACMETLS},
		{"urn:ietf:params:acme:error:unauthorized", CodeACMEUnauthorized},
		{"urn:ietf:params:acme:error:unsupportedContact", CodeACMEUnsupportedContact},
		{"urn:ietf:params:acme:error:unsupportedIdentifier", CodeACMEUnsupportedIdentifier},
		{"urn:ietf:params:acme:error:userActionRequired", CodeACMEUserActionRequired},
	}

	for _, tt := range tests {
		t.Run(tt.urn, func(t *testing.T) {
			got := ParseACMEErrorType(tt.urn)
			if got != tt.expected {
				t.Errorf("ParseACMEErrorType(%q) = %v, expected %v", tt.urn, got, tt.expected)
			}
		})
	}
}

func TestParseACMEErrorType_Unknown(t *testing.T) {
	unknownURNs := []string{
		"",
		"invalid",
		"urn:ietf:params:acme:error:unknown",
		"urn:ietf:params:acme:error:",
		"some:random:urn",
	}

	for _, urn := range unknownURNs {
		t.Run(urn, func(t *testing.T) {
			got := ParseACMEErrorType(urn)
			if got != CodeUnknown {
				t.Errorf("ParseACMEErrorType(%q) = %v, expected CodeUnknown", urn, got)
			}
		})
	}
}
