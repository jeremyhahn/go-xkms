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

package common

import (
	"errors"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// ACME error type constants as per RFC 8555.
// These define the standard error types that can occur during ACME protocol operations.
const (
	ErrTypeAccountDoesNotExist     = "accountDoesNotExist"
	ErrTypeAlreadyRevoked          = "alreadyRevoked"
	ErrTypeBadCSR                  = "badCSR"
	ErrTypeBadNonce                = "badNonce"
	ErrTypeBadPublicKey            = "badPublicKey"
	ErrTypeBadRevocationReason     = "badRevocationReason"
	ErrTypeBadSignatureAlgorithm   = "badSignatureAlgorithm"
	ErrTypeCAAError                = "caa"
	ErrTypeCompoundError           = "compound"
	ErrTypeConnectionError         = "connection"
	ErrTypeDNSError                = "dns"
	ErrTypeExternalAccountRequired = "externalAccountRequired"
	ErrTypeIncorrectResponse       = "incorrectResponse"
	ErrTypeInvalidContact          = "invalidContact"
	ErrTypeInvalidProfile          = "invalidProfile"
	ErrTypeMalformedError          = "malformed"
	ErrTypeOrderNotReady           = "orderNotReady"
	ErrTypeRateLimited             = "rateLimited"
	ErrTypeRejectedIdentifier      = "rejectedIdentifier"
	ErrTypeServerInternal          = "serverInternal"
	ErrTypeTLSError                = "tls"
	ErrTypeUnauthorized            = "unauthorized"
	ErrTypeUnsupportedContact      = "unsupportedContact"
	ErrTypeUnsupportedIdentifier   = "unsupportedIdentifier"
	ErrTypeUserActionRequired      = "userActionRequired"
	ErrTypeAccountExists           = "accountExists"
)

// Non-ACME protocol errors for internal use.
var (
	ErrInvalidChallengeFormat = errors.New("acme: invalid challenge format")
	ErrUnsupportedChallenge   = errors.New("acme: unsupported challenge type")
)

// AccountDoesNotExist creates an ACME error for non-existent accounts.
func AccountDoesNotExist(detail string) *entities.Error {
	return entities.NewError(ErrTypeAccountDoesNotExist, detail, http.StatusNotFound, nil)
}

// AlreadyRevoked creates an ACME error for already revoked certificates.
func AlreadyRevoked(detail string) *entities.Error {
	return entities.NewError(ErrTypeAlreadyRevoked, detail, http.StatusBadRequest, nil)
}

// BadAttestationStatement creates an ACME error for invalid attestation statements.
func BadAttestationStatement(detail string) *entities.Error {
	return entities.NewError("badAttestationStatement", detail, http.StatusBadRequest, nil)
}

// BadCSR creates an ACME error for malformed or invalid certificate signing requests.
func BadCSR(detail string) *entities.Error {
	return entities.NewError(ErrTypeBadCSR, detail, http.StatusBadRequest, nil)
}

// BadNonce creates an ACME error for invalid or expired nonces.
func BadNonce(detail string) *entities.Error {
	return entities.NewError(ErrTypeBadNonce, detail, http.StatusBadRequest, nil)
}

// BadPublicKey creates an ACME error for invalid public keys.
func BadPublicKey(detail string) *entities.Error {
	return entities.NewError(ErrTypeBadPublicKey, detail, http.StatusBadRequest, nil)
}

// BadRevocationReason creates an ACME error for invalid revocation reasons.
func BadRevocationReason(detail string) *entities.Error {
	return entities.NewError(ErrTypeBadRevocationReason, detail, http.StatusBadRequest, nil)
}

// BadSignatureAlgorithm creates an ACME error for unsupported signature algorithms.
func BadSignatureAlgorithm(detail string) *entities.Error {
	return entities.NewError(ErrTypeBadSignatureAlgorithm, detail, http.StatusBadRequest, nil)
}

// CAAError creates an ACME error for CAA (Certificate Authority Authorization) failures.
func CAAError(detail string) *entities.Error {
	return entities.NewError(ErrTypeCAAError, detail, http.StatusUnauthorized, nil)
}

// CompoundError creates an ACME error that contains multiple sub-problems.
func CompoundError(detail string, subproblems []entities.SubProblem) *entities.Error {
	return entities.NewError(ErrTypeCompoundError, detail, http.StatusBadRequest, subproblems)
}

// ConnectionError creates an ACME error for connection failures.
func ConnectionError(detail string) *entities.Error {
	return entities.NewError(ErrTypeConnectionError, detail, http.StatusBadRequest, nil)
}

// DNSError creates an ACME error for DNS resolution failures.
func DNSError(detail string) *entities.Error {
	return entities.NewError(ErrTypeDNSError, detail, http.StatusBadRequest, nil)
}

// ExternalAccountRequired creates an ACME error when external account binding is required.
func ExternalAccountRequired(detail string) *entities.Error {
	return entities.NewError(ErrTypeExternalAccountRequired, detail, http.StatusUnauthorized, nil)
}

// IncorrectResponse creates an ACME error for incorrect challenge responses.
func IncorrectResponse(detail string) *entities.Error {
	return entities.NewError(ErrTypeIncorrectResponse, detail, http.StatusUnauthorized, nil)
}

// InvalidContact creates an ACME error for invalid contact information.
func InvalidContact(detail string) *entities.Error {
	return entities.NewError(ErrTypeInvalidContact, detail, http.StatusBadRequest, nil)
}

// InvalidProfile creates an ACME error for a newOrder profile the server
// does not offer (draft-aaron-acme-profiles).
func InvalidProfile(detail string) *entities.Error {
	return entities.NewError(ErrTypeInvalidProfile, detail, http.StatusBadRequest, nil)
}

// MalformedError creates an ACME error for malformed requests.
func MalformedError(detail string, subproblems []entities.SubProblem) *entities.Error {
	return entities.NewError(ErrTypeMalformedError, detail, http.StatusBadRequest, subproblems)
}

// OrderNotReady creates an ACME error when an order is not yet ready for finalization.
func OrderNotReady(detail string) *entities.Error {
	return entities.NewError(ErrTypeOrderNotReady, detail, http.StatusForbidden, nil)
}

// RateLimited creates an ACME error for rate limit violations.
func RateLimited(detail string) *entities.Error {
	return entities.NewError(ErrTypeRateLimited, detail, http.StatusTooManyRequests, nil)
}

// RequestTooLarge creates an ACME error for a request body larger than the
// server accepts. RFC 8555 Section 6.7 defines no dedicated type for this, so
// it is "malformed" — the request cannot be processed as sent — carried with
// HTTP 413 Content Too Large (RFC 9110 Section 15.5.14).
func RequestTooLarge(detail string) *entities.Error {
	return entities.NewError(ErrTypeMalformedError, detail, http.StatusRequestEntityTooLarge, nil)
}

// RejectedIdentifier creates an ACME error for identifiers the server's
// issuance policy refuses: blocklisted domains/FQDNs/wildcards/IPs,
// non-public-suffix domains, and reserved-range IPs. HTTP 403 per the
// documented error mapping (docs/acme-issuance/engineering.md): the
// identifier is well-formed but the server will not issue for it.
func RejectedIdentifier(detail string) *entities.Error {
	return entities.NewError(ErrTypeRejectedIdentifier, detail, http.StatusForbidden, nil)
}

// ServerInternal creates an ACME error for internal server errors.
func ServerInternal(detail string) *entities.Error {
	return entities.NewError(ErrTypeServerInternal, detail, http.StatusInternalServerError, nil)
}

// TLSError creates an ACME error for TLS-related failures.
func TLSError(detail string) *entities.Error {
	return entities.NewError(ErrTypeTLSError, detail, http.StatusBadRequest, nil)
}

// Unauthorized creates an ACME error for unauthorized requests.
func Unauthorized(detail string) *entities.Error {
	return entities.NewError(ErrTypeUnauthorized, detail, http.StatusUnauthorized, nil)
}

// UnsupportedContact creates an ACME error for unsupported contact URL schemes.
func UnsupportedContact(detail string) *entities.Error {
	return entities.NewError(ErrTypeUnsupportedContact, detail, http.StatusBadRequest, nil)
}

// UnsupportedIdentifier creates an ACME error for unsupported identifier pki.
func UnsupportedIdentifier(detail string) *entities.Error {
	return entities.NewError(ErrTypeUnsupportedIdentifier, detail, http.StatusBadRequest, nil)
}

// UserActionRequired creates an ACME error when user action is required.
// The instance parameter provides a URL where the user can take action.
func UserActionRequired(detail, instance string) *entities.Error {
	err := entities.NewError(ErrTypeUserActionRequired, detail, http.StatusForbidden, nil)
	err.Instance = instance
	return err
}

// AccountExistsError creates an ACME error for duplicate account creation attempts.
// The location parameter provides the URL of the existing account.
func AccountExistsError(detail, location string) *entities.Error {
	err := entities.NewError(ErrTypeAccountExists, detail, http.StatusConflict, nil)
	err.Instance = location
	return err
}
