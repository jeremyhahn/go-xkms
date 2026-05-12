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
	"time"
)

// Wrap creates a TrustedCAError that wraps a cause error, preserving
// the error chain for errors.Is and errors.As.
func Wrap(errType ErrorType, cause error, msg string, args ...any) error {
	return newTrustedCAErrorWithCause(errType, cause, msg, args...)
}

// InternalServerError creates an internal server error.
func InternalServerError(msg string, args ...any) error {
	return newTrustedCAErrorf(InternalServer, msg, args...)
}

// MalformedError creates a malformed request error.
func MalformedError(msg string, args ...any) error {
	return newTrustedCAErrorf(Malformed, msg, args...)
}

// UnauthorizedError creates an unauthorized error.
func UnauthorizedError(msg string, args ...any) error {
	return newTrustedCAErrorf(Unauthorized, msg, args...)
}

// NotFoundError creates a not found error.
func NotFoundError(msg string, args ...any) error {
	return newTrustedCAErrorf(NotFound, msg, args...)
}

// RateLimitedError creates a rate limit error with a retry duration.
// Note: This is distinct from RateLimitError struct used for rate limiting internals.
func RateLimitedError(retryAfter time.Duration, msg string, args ...any) error {
	return NewTrustedCAErrorWithRetryAfter(RateLimit, retryAfter, msg, args...)
}

// RejectedIdentifierError creates a rejected identifier error.
func RejectedIdentifierError(msg string, args ...any) error {
	return newTrustedCAErrorf(RejectedIdentifier, msg, args...)
}

// InvalidEmailError creates an invalid email error.
func InvalidEmailError(msg string, args ...any) error {
	return newTrustedCAErrorf(InvalidEmail, msg, args...)
}

// ConnectionFailureError creates a connection failure error.
func ConnectionFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(ConnectionFailure, msg, args...)
}

// CAAError creates a CAA check failure error.
func CAAError(msg string, args ...any) error {
	return newTrustedCAErrorf(CAA, msg, args...)
}

// MissingSCTsError creates a missing SCTs error.
func MissingSCTsError(msg string, args ...any) error {
	return newTrustedCAErrorf(MissingSCTs, msg, args...)
}

// DuplicateError creates a duplicate resource error.
func DuplicateError(msg string, args ...any) error {
	return newTrustedCAErrorf(Duplicate, msg, args...)
}

// OrderNotReadyError creates an order not ready error.
func OrderNotReadyError(msg string, args ...any) error {
	return newTrustedCAErrorf(OrderNotReady, msg, args...)
}

// DNSError creates a DNS resolution failure error.
func DNSError(msg string, args ...any) error {
	return newTrustedCAErrorf(DNS, msg, args...)
}

// BadPublicKeyError creates a bad public key error.
func BadPublicKeyError(msg string, args ...any) error {
	return newTrustedCAErrorf(BadPublicKey, msg, args...)
}

// BadCSRError creates a bad CSR error.
func BadCSRError(msg string, args ...any) error {
	return newTrustedCAErrorf(BadCSR, msg, args...)
}

// AlreadyRevokedError creates an already revoked error.
func AlreadyRevokedError(msg string, args ...any) error {
	return newTrustedCAErrorf(AlreadyRevoked, msg, args...)
}

// BadRevocationReasonError creates a bad revocation reason error.
func BadRevocationReasonError(reason int64) error {
	return newTrustedCAErrorf(BadRevocationReason, "disallowed revocation reason: %d", reason)
}

// UnsupportedContactError creates an unsupported contact error.
func UnsupportedContactError(msg string, args ...any) error {
	return newTrustedCAErrorf(UnsupportedContact, msg, args...)
}

// UnknownSerialError creates an unknown serial error.
func UnknownSerialError() error {
	return NewTrustedCAError(UnknownSerial, "unknown serial")
}

// ConflictError creates a resource conflict error.
func ConflictError(msg string, args ...any) error {
	return newTrustedCAErrorf(Conflict, msg, args...)
}

// InvalidProfileError creates an invalid profile error.
func InvalidProfileError(msg string, args ...any) error {
	return newTrustedCAErrorf(InvalidProfile, msg, args...)
}

// AlreadyReplacedError creates an already replaced error.
func AlreadyReplacedError(msg string, args ...any) error {
	return newTrustedCAErrorf(AlreadyReplaced, msg, args...)
}

// BadSignatureAlgorithmError creates a bad signature algorithm error.
func BadSignatureAlgorithmError(msg string, args ...any) error {
	return newTrustedCAErrorf(BadSignatureAlgorithm, msg, args...)
}

// AccountDoesNotExistError creates an account does not exist error.
func AccountDoesNotExistError(msg string, args ...any) error {
	return newTrustedCAErrorf(AccountDoesNotExist, msg, args...)
}

// BadNonceError creates a bad nonce error.
func BadNonceError(msg string, args ...any) error {
	return newTrustedCAErrorf(BadNonce, msg, args...)
}

// ExternalAccountRequiredError creates an external account required error.
func ExternalAccountRequiredError(msg string, args ...any) error {
	return newTrustedCAErrorf(ExternalAccountRequired, msg, args...)
}

// IncorrectResponseError creates an incorrect response error.
func IncorrectResponseError(msg string, args ...any) error {
	return newTrustedCAErrorf(IncorrectResponse, msg, args...)
}

// InvalidContactError creates an invalid contact error.
func InvalidContactError(msg string, args ...any) error {
	return newTrustedCAErrorf(InvalidContact, msg, args...)
}

// TLSErrorCreate creates a TLS error.
func TLSErrorCreate(msg string, args ...any) error {
	return newTrustedCAErrorf(TLSError, msg, args...)
}

// UnsupportedIdentifierError creates an unsupported identifier error.
func UnsupportedIdentifierError(msg string, args ...any) error {
	return newTrustedCAErrorf(UnsupportedIdentifier, msg, args...)
}

// UserActionRequiredError creates a user action required error with instance URI.
func UserActionRequiredError(instance, msg string, args ...any) error {
	return NewTrustedCAErrorWithInstance(UserActionRequired, instance, msg, args...)
}

// AccountExistsError creates an account exists error with instance (location) URI.
func AccountExistsError(location, msg string, args ...any) error {
	return NewTrustedCAErrorWithInstance(AccountExists, location, msg, args...)
}

// CompoundErr creates a compound error with sub-errors.
func CompoundErr(msg string, subErrors []SubError) error {
	return &TrustedCAError{
		Type:      CompoundError,
		Detail:    msg,
		SubErrors: subErrors,
	}
}

// BadAttestationStatementError creates a bad attestation statement error.
func BadAttestationStatementError(msg string, args ...any) error {
	return newTrustedCAErrorf(BadAttestationStatement, msg, args...)
}

// StorageFailureError creates a storage failure error.
func StorageFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(StorageFailure, msg, args...)
}

// SerializationFailureError creates a serialization failure error.
func SerializationFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(SerializationFailure, msg, args...)
}

// TenantNotFoundError creates a tenant not found error.
func TenantNotFoundError(msg string, args ...any) error {
	return newTrustedCAErrorf(TenantNotFound, msg, args...)
}

// TenantSuspendedError creates a tenant suspended error.
func TenantSuspendedError(msg string, args ...any) error {
	return newTrustedCAErrorf(TenantSuspended, msg, args...)
}

// TenantQuotaExceededError creates a tenant quota exceeded error with retry duration.
func TenantQuotaExceededError(retryAfter time.Duration, msg string, args ...any) error {
	return NewTrustedCAErrorWithRetryAfter(TenantQuotaExceeded, retryAfter, msg, args...)
}

// CertificateExpiredError creates a certificate expired error.
func CertificateExpiredError(msg string, args ...any) error {
	return newTrustedCAErrorf(CertificateExpired, msg, args...)
}

// CertificateNotYetValidError creates a certificate not yet valid error.
func CertificateNotYetValidError(msg string, args ...any) error {
	return newTrustedCAErrorf(CertificateNotYetValid, msg, args...)
}

// SigningFailureError creates a signing failure error.
func SigningFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(SigningFailure, msg, args...)
}

// VerificationFailureError creates a verification failure error.
func VerificationFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(VerificationFailure, msg, args...)
}

// KeyGenerationFailureError creates a key generation failure error.
func KeyGenerationFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(KeyGenerationFailure, msg, args...)
}

// TPMErr creates a TPM error.
func TPMErr(msg string, args ...any) error {
	return newTrustedCAErrorf(TPMError, msg, args...)
}

// OCSPFailureError creates an OCSP failure error.
func OCSPFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(OCSPFailure, msg, args...)
}

// CRLFailureError creates a CRL failure error.
func CRLFailureError(msg string, args ...any) error {
	return newTrustedCAErrorf(CRLFailure, msg, args...)
}

// PolicyViolationError creates a policy violation error.
func PolicyViolationError(msg string, args ...any) error {
	return newTrustedCAErrorf(PolicyViolation, msg, args...)
}

// AuthorizationExpiredError creates an authorization expired error.
func AuthorizationExpiredError(msg string, args ...any) error {
	return newTrustedCAErrorf(AuthorizationExpired, msg, args...)
}

// ChallengeTimeoutError creates a challenge timeout error.
func ChallengeTimeoutError(msg string, args ...any) error {
	return newTrustedCAErrorf(ChallengeTimeout, msg, args...)
}

// InvalidTokenError creates an invalid token error.
func InvalidTokenError(msg string, args ...any) error {
	return newTrustedCAErrorf(InvalidToken, msg, args...)
}

// NewSubError creates a SubError for use in compound errors.
func NewSubError(errType ErrorType, detail string, identifierType, identifierValue string) SubError {
	return SubError{
		TrustedCAError: &TrustedCAError{
			Type:   errType,
			Detail: detail,
		},
		Identifier: ACMEIdentifier{
			Type:  identifierType,
			Value: identifierValue,
		},
	}
}
