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
	"time"
)

func TestInternalServerError(t *testing.T) {
	err := InternalServerError("database connection failed: %s", "timeout")
	tce := assertTrustedCAError(t, err, InternalServer)
	if tce.Detail != "database connection failed: timeout" {
		t.Errorf("Detail = %q, want formatted message", tce.Detail)
	}
}

func TestMalformedError(t *testing.T) {
	err := MalformedError("invalid JSON at position %d", 42)
	tce := assertTrustedCAError(t, err, Malformed)
	if tce.Detail != "invalid JSON at position 42" {
		t.Errorf("Detail = %q, want formatted message", tce.Detail)
	}
}

func TestUnauthorizedError(t *testing.T) {
	err := UnauthorizedError("account %s not authorized", "abc123")
	assertTrustedCAError(t, err, Unauthorized)
}

func TestNotFoundError(t *testing.T) {
	err := NotFoundError("order %s not found", "order-123")
	assertTrustedCAError(t, err, NotFound)
}

func TestRateLimitedError(t *testing.T) {
	err := RateLimitedError(60*time.Second, "too many requests from IP %s", "1.2.3.4")
	tce := assertTrustedCAError(t, err, RateLimit)
	if tce.RetryAfter != 60*time.Second {
		t.Errorf("RetryAfter = %v, want 60s", tce.RetryAfter)
	}
}

func TestRejectedIdentifierError(t *testing.T) {
	err := RejectedIdentifierError("domain %s is blocklisted", "bad.com")
	assertTrustedCAError(t, err, RejectedIdentifier)
}

func TestInvalidEmailError(t *testing.T) {
	err := InvalidEmailError("invalid email format: %s", "not-an-email")
	assertTrustedCAError(t, err, InvalidEmail)
}

func TestConnectionFailureError(t *testing.T) {
	err := ConnectionFailureError("failed to connect to %s:%d", "example.com", 80)
	assertTrustedCAError(t, err, ConnectionFailure)
}

func TestCAAError(t *testing.T) {
	err := CAAError("CAA record forbids issuance for %s", "example.com")
	assertTrustedCAError(t, err, CAA)
}

func TestMissingSCTsError(t *testing.T) {
	err := MissingSCTsError("no SCTs available from CT logs")
	assertTrustedCAError(t, err, MissingSCTs)
}

func TestDuplicateError(t *testing.T) {
	err := DuplicateError("order %s already exists", "order-123")
	assertTrustedCAError(t, err, Duplicate)
}

func TestOrderNotReadyError(t *testing.T) {
	err := OrderNotReadyError("order status is %s, not ready", "pending")
	assertTrustedCAError(t, err, OrderNotReady)
}

func TestDNSError(t *testing.T) {
	err := DNSError("DNS lookup failed for %s: NXDOMAIN", "example.com")
	assertTrustedCAError(t, err, DNS)
}

func TestBadPublicKeyError(t *testing.T) {
	err := BadPublicKeyError("key size %d bits is too small", 1024)
	assertTrustedCAError(t, err, BadPublicKey)
}

func TestBadCSRError(t *testing.T) {
	err := BadCSRError("CSR signature verification failed")
	assertTrustedCAError(t, err, BadCSR)
}

func TestAlreadyRevokedError(t *testing.T) {
	err := AlreadyRevokedError("certificate with serial %s already revoked", "abc123")
	assertTrustedCAError(t, err, AlreadyRevoked)
}

func TestBadRevocationReasonError(t *testing.T) {
	err := BadRevocationReasonError(99)
	tce := assertTrustedCAError(t, err, BadRevocationReason)
	if tce.Detail != "disallowed revocation reason: 99" {
		t.Errorf("Detail = %q, want formatted reason message", tce.Detail)
	}
}

func TestUnsupportedContactError(t *testing.T) {
	err := UnsupportedContactError("contact scheme %s not supported", "xmpp")
	assertTrustedCAError(t, err, UnsupportedContact)
}

func TestUnknownSerialError(t *testing.T) {
	err := UnknownSerialError()
	tce := assertTrustedCAError(t, err, UnknownSerial)
	if tce.Detail != "unknown serial" {
		t.Errorf("Detail = %q, want 'unknown serial'", tce.Detail)
	}
}

func TestConflictError(t *testing.T) {
	err := ConflictError("resource conflict: %s", "version mismatch")
	assertTrustedCAError(t, err, Conflict)
}

func TestInvalidProfileError(t *testing.T) {
	err := InvalidProfileError("profile %s not found", "custom-profile")
	assertTrustedCAError(t, err, InvalidProfile)
}

func TestAlreadyReplacedError(t *testing.T) {
	err := AlreadyReplacedError("certificate already has replacement order")
	assertTrustedCAError(t, err, AlreadyReplaced)
}

func TestBadSignatureAlgorithmError(t *testing.T) {
	err := BadSignatureAlgorithmError("algorithm %s not supported", "MD5")
	assertTrustedCAError(t, err, BadSignatureAlgorithm)
}

func TestAccountDoesNotExistError(t *testing.T) {
	err := AccountDoesNotExistError("no account found for key ID %s", "key-123")
	assertTrustedCAError(t, err, AccountDoesNotExist)
}

func TestBadNonceError(t *testing.T) {
	err := BadNonceError("nonce %s is expired or invalid", "abc123")
	assertTrustedCAError(t, err, BadNonce)
}

func TestExternalAccountRequiredError(t *testing.T) {
	err := ExternalAccountRequiredError("external account binding required for this CA")
	assertTrustedCAError(t, err, ExternalAccountRequired)
}

func TestIncorrectResponseError(t *testing.T) {
	err := IncorrectResponseError("challenge response mismatch")
	assertTrustedCAError(t, err, IncorrectResponse)
}

func TestInvalidContactError(t *testing.T) {
	err := InvalidContactError("contact URL %s is invalid", "not-a-url")
	assertTrustedCAError(t, err, InvalidContact)
}

func TestTLSErrorCreate(t *testing.T) {
	err := TLSErrorCreate("TLS handshake failed: %s", "certificate expired")
	assertTrustedCAError(t, err, TLSError)
}

func TestUnsupportedIdentifierError(t *testing.T) {
	err := UnsupportedIdentifierError("identifier type %s not supported", "email")
	assertTrustedCAError(t, err, UnsupportedIdentifier)
}

func TestUserActionRequiredError(t *testing.T) {
	err := UserActionRequiredError("https://example.com/tos", "please accept terms of service")
	tce := assertTrustedCAError(t, err, UserActionRequired)
	if tce.Instance != "https://example.com/tos" {
		t.Errorf("Instance = %q, want TOS URL", tce.Instance)
	}
}

func TestAccountExistsError(t *testing.T) {
	err := AccountExistsError("https://example.com/acme/acct/123", "account already exists")
	tce := assertTrustedCAError(t, err, AccountExists)
	if tce.Instance != "https://example.com/acme/acct/123" {
		t.Errorf("Instance = %q, want account URL", tce.Instance)
	}
}

func TestCompoundErr(t *testing.T) {
	subErrors := []SubError{
		{
			TrustedCAError: &TrustedCAError{Type: BadCSR, Detail: "bad CSR"},
			Identifier:     ACMEIdentifier{Type: "dns", Value: "example.com"},
		},
		{
			TrustedCAError: &TrustedCAError{Type: RejectedIdentifier, Detail: "rejected"},
			Identifier:     ACMEIdentifier{Type: "dns", Value: "blocked.com"},
		},
	}

	err := CompoundErr("multiple validation errors", subErrors)
	tce := assertTrustedCAError(t, err, CompoundError)
	if len(tce.SubErrors) != 2 {
		t.Fatalf("SubErrors len = %d, want 2", len(tce.SubErrors))
	}
	if tce.SubErrors[0].Identifier.Value != "example.com" {
		t.Errorf("SubErrors[0].Identifier.Value = %q, want 'example.com'",
			tce.SubErrors[0].Identifier.Value)
	}
}

func TestBadAttestationStatementError(t *testing.T) {
	err := BadAttestationStatementError("attestation signature invalid")
	assertTrustedCAError(t, err, BadAttestationStatement)
}

func TestStorageFailureError(t *testing.T) {
	err := StorageFailureError("failed to write to storage: %s", "disk full")
	assertTrustedCAError(t, err, StorageFailure)
}

func TestSerializationFailureError(t *testing.T) {
	err := SerializationFailureError("failed to serialize account")
	assertTrustedCAError(t, err, SerializationFailure)
}

func TestTenantNotFoundError(t *testing.T) {
	err := TenantNotFoundError("tenant %s not found", "tenant-123")
	assertTrustedCAError(t, err, TenantNotFound)
}

func TestTenantSuspendedError(t *testing.T) {
	err := TenantSuspendedError("tenant %s is suspended", "tenant-123")
	assertTrustedCAError(t, err, TenantSuspended)
}

func TestTenantQuotaExceededError(t *testing.T) {
	err := TenantQuotaExceededError(24*time.Hour, "certificate quota exceeded for tenant %s", "tenant-123")
	tce := assertTrustedCAError(t, err, TenantQuotaExceeded)
	if tce.RetryAfter != 24*time.Hour {
		t.Errorf("RetryAfter = %v, want 24h", tce.RetryAfter)
	}
}

func TestCertificateExpiredError(t *testing.T) {
	err := CertificateExpiredError("certificate expired on %s", "2024-01-01")
	assertTrustedCAError(t, err, CertificateExpired)
}

func TestCertificateNotYetValidError(t *testing.T) {
	err := CertificateNotYetValidError("certificate not valid until %s", "2025-01-01")
	assertTrustedCAError(t, err, CertificateNotYetValid)
}

func TestSigningFailureError(t *testing.T) {
	err := SigningFailureError("HSM signing operation failed")
	assertTrustedCAError(t, err, SigningFailure)
}

func TestVerificationFailureError(t *testing.T) {
	err := VerificationFailureError("signature verification failed")
	assertTrustedCAError(t, err, VerificationFailure)
}

func TestKeyGenerationFailureError(t *testing.T) {
	err := KeyGenerationFailureError("failed to generate %s key", "ECDSA P-384")
	assertTrustedCAError(t, err, KeyGenerationFailure)
}

func TestTPMErr(t *testing.T) {
	err := TPMErr("TPM quote verification failed")
	assertTrustedCAError(t, err, TPMError)
}

func TestOCSPFailureError(t *testing.T) {
	err := OCSPFailureError("OCSP responder unavailable")
	assertTrustedCAError(t, err, OCSPFailure)
}

func TestCRLFailureError(t *testing.T) {
	err := CRLFailureError("failed to generate CRL: %s", "signing failed")
	assertTrustedCAError(t, err, CRLFailure)
}

func TestPolicyViolationError(t *testing.T) {
	err := PolicyViolationError("key usage policy violation: %s", "code signing not allowed")
	assertTrustedCAError(t, err, PolicyViolation)
}

func TestAuthorizationExpiredError(t *testing.T) {
	err := AuthorizationExpiredError("authorization expired on %s", "2024-01-01T00:00:00Z")
	assertTrustedCAError(t, err, AuthorizationExpired)
}

func TestChallengeTimeoutError(t *testing.T) {
	err := ChallengeTimeoutError("challenge validation timed out after %d seconds", 30)
	assertTrustedCAError(t, err, ChallengeTimeout)
}

func TestInvalidTokenError(t *testing.T) {
	err := InvalidTokenError("token signature invalid")
	assertTrustedCAError(t, err, InvalidToken)
}

func TestNewSubError(t *testing.T) {
	se := NewSubError(BadCSR, "invalid CSR format", "dns", "example.com")

	if se.TrustedCAError == nil {
		t.Fatal("TrustedCAError is nil")
	}
	if se.Type != BadCSR {
		t.Errorf("Type = %v, want %v", se.Type, BadCSR)
	}
	if se.Detail != "invalid CSR format" {
		t.Errorf("Detail = %q, want 'invalid CSR format'", se.Detail)
	}
	if se.Identifier.Type != "dns" {
		t.Errorf("Identifier.Type = %q, want 'dns'", se.Identifier.Type)
	}
	if se.Identifier.Value != "example.com" {
		t.Errorf("Identifier.Value = %q, want 'example.com'", se.Identifier.Value)
	}
}

// assertTrustedCAError is a test helper that asserts the error is a TrustedCAError
// with the expected type and returns it for further assertions.
func assertTrustedCAError(t *testing.T, err error, expectedType ErrorType) *TrustedCAError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatalf("expected *TrustedCAError, got %T", err)
	}
	if tce.Type != expectedType {
		t.Errorf("Type = %v, want %v", tce.Type, expectedType)
	}
	return tce
}

func TestHelperErrorsAreTyped(t *testing.T) {
	// Verify all helper functions return properly typed errors
	// that work with IsType()
	tests := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{"InternalServerError", InternalServerError("test"), InternalServer},
		{"MalformedError", MalformedError("test"), Malformed},
		{"UnauthorizedError", UnauthorizedError("test"), Unauthorized},
		{"NotFoundError", NotFoundError("test"), NotFound},
		{"RateLimitedError", RateLimitedError(time.Second, "test"), RateLimit},
		{"RejectedIdentifierError", RejectedIdentifierError("test"), RejectedIdentifier},
		{"InvalidEmailError", InvalidEmailError("test"), InvalidEmail},
		{"ConnectionFailureError", ConnectionFailureError("test"), ConnectionFailure},
		{"CAAError", CAAError("test"), CAA},
		{"MissingSCTsError", MissingSCTsError("test"), MissingSCTs},
		{"DuplicateError", DuplicateError("test"), Duplicate},
		{"OrderNotReadyError", OrderNotReadyError("test"), OrderNotReady},
		{"DNSError", DNSError("test"), DNS},
		{"BadPublicKeyError", BadPublicKeyError("test"), BadPublicKey},
		{"BadCSRError", BadCSRError("test"), BadCSR},
		{"AlreadyRevokedError", AlreadyRevokedError("test"), AlreadyRevoked},
		{"BadRevocationReasonError", BadRevocationReasonError(1), BadRevocationReason},
		{"UnsupportedContactError", UnsupportedContactError("test"), UnsupportedContact},
		{"UnknownSerialError", UnknownSerialError(), UnknownSerial},
		{"ConflictError", ConflictError("test"), Conflict},
		{"InvalidProfileError", InvalidProfileError("test"), InvalidProfile},
		{"AlreadyReplacedError", AlreadyReplacedError("test"), AlreadyReplaced},
		{"BadSignatureAlgorithmError", BadSignatureAlgorithmError("test"), BadSignatureAlgorithm},
		{"AccountDoesNotExistError", AccountDoesNotExistError("test"), AccountDoesNotExist},
		{"BadNonceError", BadNonceError("test"), BadNonce},
		{"ExternalAccountRequiredError", ExternalAccountRequiredError("test"), ExternalAccountRequired},
		{"IncorrectResponseError", IncorrectResponseError("test"), IncorrectResponse},
		{"InvalidContactError", InvalidContactError("test"), InvalidContact},
		{"TLSErrorCreate", TLSErrorCreate("test"), TLSError},
		{"UnsupportedIdentifierError", UnsupportedIdentifierError("test"), UnsupportedIdentifier},
		{"UserActionRequiredError", UserActionRequiredError("url", "test"), UserActionRequired},
		{"AccountExistsError", AccountExistsError("url", "test"), AccountExists},
		{"CompoundErr", CompoundErr("test", nil), CompoundError},
		{"BadAttestationStatementError", BadAttestationStatementError("test"), BadAttestationStatement},
		{"StorageFailureError", StorageFailureError("test"), StorageFailure},
		{"SerializationFailureError", SerializationFailureError("test"), SerializationFailure},
		{"TenantNotFoundError", TenantNotFoundError("test"), TenantNotFound},
		{"TenantSuspendedError", TenantSuspendedError("test"), TenantSuspended},
		{"TenantQuotaExceededError", TenantQuotaExceededError(time.Hour, "test"), TenantQuotaExceeded},
		{"CertificateExpiredError", CertificateExpiredError("test"), CertificateExpired},
		{"CertificateNotYetValidError", CertificateNotYetValidError("test"), CertificateNotYetValid},
		{"SigningFailureError", SigningFailureError("test"), SigningFailure},
		{"VerificationFailureError", VerificationFailureError("test"), VerificationFailure},
		{"KeyGenerationFailureError", KeyGenerationFailureError("test"), KeyGenerationFailure},
		{"TPMErr", TPMErr("test"), TPMError},
		{"OCSPFailureError", OCSPFailureError("test"), OCSPFailure},
		{"CRLFailureError", CRLFailureError("test"), CRLFailure},
		{"PolicyViolationError", PolicyViolationError("test"), PolicyViolation},
		{"AuthorizationExpiredError", AuthorizationExpiredError("test"), AuthorizationExpired},
		{"ChallengeTimeoutError", ChallengeTimeoutError("test"), ChallengeTimeout},
		{"InvalidTokenError", InvalidTokenError("test"), InvalidToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsType(tt.err, tt.expected) {
				t.Errorf("IsType(%s, %v) = false, want true", tt.name, tt.expected)
			}
		})
	}
}
