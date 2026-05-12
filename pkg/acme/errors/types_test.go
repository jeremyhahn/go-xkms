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
	"testing"
)

func TestErrorType_Error(t *testing.T) {
	tests := []struct {
		name     string
		errType  ErrorType
		expected string
	}{
		{
			name:     "InternalServer error returns URN",
			errType:  InternalServer,
			expected: "urn:ietf:params:acme:error",
		},
		{
			name:     "Malformed error returns URN",
			errType:  Malformed,
			expected: "urn:ietf:params:acme:error",
		},
		{
			name:     "Unknown error type returns URN",
			errType:  ErrorType(999),
			expected: "urn:ietf:params:acme:error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errType.Error()
			if result != tt.expected {
				t.Errorf("ErrorType.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrorType_String(t *testing.T) {
	tests := []struct {
		name     string
		errType  ErrorType
		expected string
	}{
		{name: "InternalServer", errType: InternalServer, expected: "InternalServer"},
		{name: "Malformed", errType: Malformed, expected: "Malformed"},
		{name: "Unauthorized", errType: Unauthorized, expected: "Unauthorized"},
		{name: "NotFound", errType: NotFound, expected: "NotFound"},
		{name: "RateLimit", errType: RateLimit, expected: "RateLimit"},
		{name: "RejectedIdentifier", errType: RejectedIdentifier, expected: "RejectedIdentifier"},
		{name: "InvalidEmail", errType: InvalidEmail, expected: "InvalidEmail"},
		{name: "ConnectionFailure", errType: ConnectionFailure, expected: "ConnectionFailure"},
		{name: "CAA", errType: CAA, expected: "CAA"},
		{name: "MissingSCTs", errType: MissingSCTs, expected: "MissingSCTs"},
		{name: "Duplicate", errType: Duplicate, expected: "Duplicate"},
		{name: "OrderNotReady", errType: OrderNotReady, expected: "OrderNotReady"},
		{name: "DNS", errType: DNS, expected: "DNS"},
		{name: "BadPublicKey", errType: BadPublicKey, expected: "BadPublicKey"},
		{name: "BadCSR", errType: BadCSR, expected: "BadCSR"},
		{name: "AlreadyRevoked", errType: AlreadyRevoked, expected: "AlreadyRevoked"},
		{name: "BadRevocationReason", errType: BadRevocationReason, expected: "BadRevocationReason"},
		{name: "UnsupportedContact", errType: UnsupportedContact, expected: "UnsupportedContact"},
		{name: "UnknownSerial", errType: UnknownSerial, expected: "UnknownSerial"},
		{name: "Conflict", errType: Conflict, expected: "Conflict"},
		{name: "InvalidProfile", errType: InvalidProfile, expected: "InvalidProfile"},
		{name: "AlreadyReplaced", errType: AlreadyReplaced, expected: "AlreadyReplaced"},
		{name: "BadSignatureAlgorithm", errType: BadSignatureAlgorithm, expected: "BadSignatureAlgorithm"},
		{name: "AccountDoesNotExist", errType: AccountDoesNotExist, expected: "AccountDoesNotExist"},
		{name: "BadNonce", errType: BadNonce, expected: "BadNonce"},
		{name: "ExternalAccountRequired", errType: ExternalAccountRequired, expected: "ExternalAccountRequired"},
		{name: "IncorrectResponse", errType: IncorrectResponse, expected: "IncorrectResponse"},
		{name: "InvalidContact", errType: InvalidContact, expected: "InvalidContact"},
		{name: "TLSError", errType: TLSError, expected: "TLSError"},
		{name: "UnsupportedIdentifier", errType: UnsupportedIdentifier, expected: "UnsupportedIdentifier"},
		{name: "UserActionRequired", errType: UserActionRequired, expected: "UserActionRequired"},
		{name: "AccountExists", errType: AccountExists, expected: "AccountExists"},
		{name: "CompoundError", errType: CompoundError, expected: "CompoundError"},
		{name: "BadAttestationStatement", errType: BadAttestationStatement, expected: "BadAttestationStatement"},
		{name: "StorageFailure", errType: StorageFailure, expected: "StorageFailure"},
		{name: "SerializationFailure", errType: SerializationFailure, expected: "SerializationFailure"},
		{name: "TenantNotFound", errType: TenantNotFound, expected: "TenantNotFound"},
		{name: "TenantSuspended", errType: TenantSuspended, expected: "TenantSuspended"},
		{name: "TenantQuotaExceeded", errType: TenantQuotaExceeded, expected: "TenantQuotaExceeded"},
		{name: "CertificateExpired", errType: CertificateExpired, expected: "CertificateExpired"},
		{name: "CertificateNotYetValid", errType: CertificateNotYetValid, expected: "CertificateNotYetValid"},
		{name: "SigningFailure", errType: SigningFailure, expected: "SigningFailure"},
		{name: "VerificationFailure", errType: VerificationFailure, expected: "VerificationFailure"},
		{name: "KeyGenerationFailure", errType: KeyGenerationFailure, expected: "KeyGenerationFailure"},
		{name: "TPMError", errType: TPMError, expected: "TPMError"},
		{name: "OCSPFailure", errType: OCSPFailure, expected: "OCSPFailure"},
		{name: "CRLFailure", errType: CRLFailure, expected: "CRLFailure"},
		{name: "PolicyViolation", errType: PolicyViolation, expected: "PolicyViolation"},
		{name: "AuthorizationExpired", errType: AuthorizationExpired, expected: "AuthorizationExpired"},
		{name: "ChallengeTimeout", errType: ChallengeTimeout, expected: "ChallengeTimeout"},
		{name: "InvalidToken", errType: InvalidToken, expected: "InvalidToken"},
		{name: "Unknown", errType: ErrorType(999), expected: "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errType.String()
			if result != tt.expected {
				t.Errorf("ErrorType.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrorType_Values(t *testing.T) {
	// Ensure error types have expected iota values for gRPC compatibility
	if InternalServer != 0 {
		t.Errorf("InternalServer = %d, want 0", InternalServer)
	}
	if Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", Malformed)
	}
	if Unauthorized != 2 {
		t.Errorf("Unauthorized = %d, want 2", Unauthorized)
	}
}

func TestErrorType_AsError(t *testing.T) {
	// ErrorType implements error interface
	var err error = InternalServer
	if err.Error() != "urn:ietf:params:acme:error" {
		t.Errorf("ErrorType as error = %q, want URN", err.Error())
	}
}
