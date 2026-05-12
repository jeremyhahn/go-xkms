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

// ErrorType provides a coarse category for TrustedCAError.
// These numeric constants are used when sending errors through gRPC.
// Objects of type ErrorType should never be directly returned by other
// functions; instead use the helper functions to create an appropriate
// TrustedCAError wrapping one of these types.
type ErrorType int

// Error types covering ACME protocol, CA operations, storage, and TPM/attestation.
const (
	// InternalServer indicates an internal server error.
	// Maps to ACME "serverInternal" problem type.
	InternalServer ErrorType = iota

	// Malformed indicates a malformed request.
	// Maps to ACME "malformed" problem type.
	Malformed

	// Unauthorized indicates an unauthorized request.
	// Maps to ACME "unauthorized" problem type.
	Unauthorized

	// NotFound indicates a requested resource was not found.
	// Maps to ACME "accountDoesNotExist" or HTTP 404.
	NotFound

	// RateLimit indicates rate limit exceeded.
	// Maps to ACME "rateLimited" problem type.
	RateLimit

	// RejectedIdentifier indicates an identifier was rejected.
	// Maps to ACME "rejectedIdentifier" problem type.
	RejectedIdentifier

	// InvalidEmail indicates an invalid email address.
	// Maps to ACME "invalidContact" problem type.
	InvalidEmail

	// ConnectionFailure indicates a connection failure.
	// Maps to ACME "connection" problem type.
	ConnectionFailure

	// CAA indicates a CAA record check failure.
	// Maps to ACME "caa" problem type.
	CAA

	// MissingSCTs indicates missing signed certificate timestamps.
	// Maps to internal error handling.
	MissingSCTs

	// Duplicate indicates a duplicate resource.
	// Maps to HTTP 409 Conflict.
	Duplicate

	// OrderNotReady indicates an order is not ready for finalization.
	// Maps to ACME "orderNotReady" problem type.
	OrderNotReady

	// DNS indicates a DNS resolution failure.
	// Maps to ACME "dns" problem type.
	DNS

	// BadPublicKey indicates an invalid public key.
	// Maps to ACME "badPublicKey" problem type.
	BadPublicKey

	// BadCSR indicates an invalid certificate signing request.
	// Maps to ACME "badCSR" problem type.
	BadCSR

	// AlreadyRevoked indicates a certificate was already revoked.
	// Maps to ACME "alreadyRevoked" problem type.
	AlreadyRevoked

	// BadRevocationReason indicates an invalid revocation reason.
	// Maps to ACME "badRevocationReason" problem type.
	BadRevocationReason

	// UnsupportedContact indicates an unsupported contact URL scheme.
	// Maps to ACME "unsupportedContact" problem type.
	UnsupportedContact

	// UnknownSerial indicates the certificate serial is not found.
	// Maps to internal not found handling.
	UnknownSerial

	// Conflict indicates a resource conflict.
	// Maps to HTTP 409 Conflict.
	Conflict

	// InvalidProfile indicates an invalid certificate profile.
	// Maps to draft ACME profiles error type.
	InvalidProfile

	// AlreadyReplaced indicates a certificate replacement already exists.
	// Maps to internal conflict handling.
	AlreadyReplaced

	// BadSignatureAlgorithm indicates an unsupported signature algorithm.
	// Maps to ACME "badSignatureAlgorithm" problem type.
	BadSignatureAlgorithm

	// AccountDoesNotExist indicates the account does not exist.
	// Maps to ACME "accountDoesNotExist" problem type.
	AccountDoesNotExist

	// BadNonce indicates an invalid or expired nonce.
	// Maps to ACME "badNonce" problem type.
	BadNonce

	// ExternalAccountRequired indicates external account binding is required.
	// Maps to ACME "externalAccountRequired" problem type.
	ExternalAccountRequired

	// IncorrectResponse indicates an incorrect challenge response.
	// Maps to ACME "incorrectResponse" problem type.
	IncorrectResponse

	// InvalidContact indicates invalid contact information.
	// Maps to ACME "invalidContact" problem type.
	InvalidContact

	// TLSError indicates a TLS-related failure.
	// Maps to ACME "tls" problem type.
	TLSError

	// UnsupportedIdentifier indicates an unsupported identifier type.
	// Maps to ACME "unsupportedIdentifier" problem type.
	UnsupportedIdentifier

	// UserActionRequired indicates user action is required.
	// Maps to ACME "userActionRequired" problem type.
	UserActionRequired

	// AccountExists indicates the account already exists.
	// Maps to HTTP 409 Conflict with Location header.
	AccountExists

	// CompoundError indicates multiple sub-errors.
	// Maps to ACME "compound" problem type.
	CompoundError

	// BadAttestationStatement indicates an invalid TPM attestation statement.
	// Maps to ACME "badAttestationStatement" problem type.
	BadAttestationStatement

	// StorageFailure indicates a storage backend failure.
	// Maps to internal server error.
	StorageFailure

	// SerializationFailure indicates a serialization failure.
	// Maps to internal server error.
	SerializationFailure

	// TenantNotFound indicates the tenant does not exist.
	// Maps to not found handling.
	TenantNotFound

	// TenantSuspended indicates the tenant is suspended.
	// Maps to forbidden handling.
	TenantSuspended

	// TenantQuotaExceeded indicates the tenant quota was exceeded.
	// Maps to rate limit handling.
	TenantQuotaExceeded

	// CertificateExpired indicates the certificate has expired.
	// Maps to forbidden handling.
	CertificateExpired

	// CertificateNotYetValid indicates the certificate is not yet valid.
	// Maps to forbidden handling.
	CertificateNotYetValid

	// SigningFailure indicates a signing operation failed.
	// Maps to internal server error.
	SigningFailure

	// VerificationFailure indicates a verification operation failed.
	// Maps to unauthorized handling.
	VerificationFailure

	// KeyGenerationFailure indicates a key generation failure.
	// Maps to internal server error.
	KeyGenerationFailure

	// TPMError indicates a TPM operation failure.
	// Maps to internal server error or bad attestation.
	TPMError

	// OCSPFailure indicates an OCSP operation failure.
	// Maps to internal server error.
	OCSPFailure

	// CRLFailure indicates a CRL operation failure.
	// Maps to internal server error.
	CRLFailure

	// PolicyViolation indicates a policy violation.
	// Maps to forbidden handling.
	PolicyViolation

	// AuthorizationExpired indicates the authorization has expired.
	// Maps to forbidden handling.
	AuthorizationExpired

	// ChallengeTimeout indicates a challenge validation timeout.
	// Maps to connection failure handling.
	ChallengeTimeout

	// InvalidToken indicates an invalid token.
	// Maps to unauthorized handling.
	InvalidToken
)

// errorTypeStrings maps ErrorType to human-readable string representations.
var errorTypeStrings = map[ErrorType]string{
	InternalServer:          "InternalServer",
	Malformed:               "Malformed",
	Unauthorized:            "Unauthorized",
	NotFound:                "NotFound",
	RateLimit:               "RateLimit",
	RejectedIdentifier:      "RejectedIdentifier",
	InvalidEmail:            "InvalidEmail",
	ConnectionFailure:       "ConnectionFailure",
	CAA:                     "CAA",
	MissingSCTs:             "MissingSCTs",
	Duplicate:               "Duplicate",
	OrderNotReady:           "OrderNotReady",
	DNS:                     "DNS",
	BadPublicKey:            "BadPublicKey",
	BadCSR:                  "BadCSR",
	AlreadyRevoked:          "AlreadyRevoked",
	BadRevocationReason:     "BadRevocationReason",
	UnsupportedContact:      "UnsupportedContact",
	UnknownSerial:           "UnknownSerial",
	Conflict:                "Conflict",
	InvalidProfile:          "InvalidProfile",
	AlreadyReplaced:         "AlreadyReplaced",
	BadSignatureAlgorithm:   "BadSignatureAlgorithm",
	AccountDoesNotExist:     "AccountDoesNotExist",
	BadNonce:                "BadNonce",
	ExternalAccountRequired: "ExternalAccountRequired",
	IncorrectResponse:       "IncorrectResponse",
	InvalidContact:          "InvalidContact",
	TLSError:                "TLSError",
	UnsupportedIdentifier:   "UnsupportedIdentifier",
	UserActionRequired:      "UserActionRequired",
	AccountExists:           "AccountExists",
	CompoundError:           "CompoundError",
	BadAttestationStatement: "BadAttestationStatement",
	StorageFailure:          "StorageFailure",
	SerializationFailure:    "SerializationFailure",
	TenantNotFound:          "TenantNotFound",
	TenantSuspended:         "TenantSuspended",
	TenantQuotaExceeded:     "TenantQuotaExceeded",
	CertificateExpired:      "CertificateExpired",
	CertificateNotYetValid:  "CertificateNotYetValid",
	SigningFailure:          "SigningFailure",
	VerificationFailure:     "VerificationFailure",
	KeyGenerationFailure:    "KeyGenerationFailure",
	TPMError:                "TPMError",
	OCSPFailure:             "OCSPFailure",
	CRLFailure:              "CRLFailure",
	PolicyViolation:         "PolicyViolation",
	AuthorizationExpired:    "AuthorizationExpired",
	ChallengeTimeout:        "ChallengeTimeout",
	InvalidToken:            "InvalidToken",
}

// Error implements the error interface for ErrorType.
// This allows ErrorType to be used with errors.Is() for type checking.
func (ErrorType) Error() string {
	return "urn:ietf:params:acme:error"
}

// String returns a human-readable string representation of the error type.
func (e ErrorType) String() string {
	if s, ok := errorTypeStrings[e]; ok {
		return s
	}
	return "Unknown"
}
