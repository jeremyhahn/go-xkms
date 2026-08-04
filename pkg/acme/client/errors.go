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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ACME error type URN prefix as defined in RFC 8555 Section 6.7
const acmeErrorURNPrefix = "urn:ietf:params:acme:error:"

// RFC 8555 Section 6.7 Error Types
const (
	// ErrTypeAccountDoesNotExist indicates the request specified an account that does not exist.
	ErrTypeAccountDoesNotExist = acmeErrorURNPrefix + "accountDoesNotExist"

	// ErrTypeAlreadyRevoked indicates the request specified a certificate to be revoked that has already been revoked.
	ErrTypeAlreadyRevoked = acmeErrorURNPrefix + "alreadyRevoked"

	// ErrTypeBadCSR indicates the CSR is unacceptable (e.g., due to a short key).
	ErrTypeBadCSR = acmeErrorURNPrefix + "badCSR"

	// ErrTypeBadNonce indicates the client sent an unacceptable anti-replay nonce.
	ErrTypeBadNonce = acmeErrorURNPrefix + "badNonce"

	// ErrTypeBadPublicKey indicates the JWS was signed by a public key the server does not support.
	ErrTypeBadPublicKey = acmeErrorURNPrefix + "badPublicKey"

	// ErrTypeBadRevocationReason indicates the revocation reason provided is not allowed by the server.
	ErrTypeBadRevocationReason = acmeErrorURNPrefix + "badRevocationReason"

	// ErrTypeBadSignatureAlgorithm indicates the JWS was signed with an algorithm the server does not support.
	ErrTypeBadSignatureAlgorithm = acmeErrorURNPrefix + "badSignatureAlgorithm"

	// ErrTypeCAA indicates Certificate Authority Authorization (CAA) records forbid the CA from issuing a certificate.
	ErrTypeCAA = acmeErrorURNPrefix + "caa"

	// ErrTypeCompound indicates specific error conditions are indicated in the subproblems array.
	ErrTypeCompound = acmeErrorURNPrefix + "compound"

	// ErrTypeConnection indicates the server could not connect to validation target.
	ErrTypeConnection = acmeErrorURNPrefix + "connection"

	// ErrTypeDNS indicates there was a problem with a DNS query during identifier validation.
	ErrTypeDNS = acmeErrorURNPrefix + "dns"

	// ErrTypeExternalAccountRequired indicates the request must include a value for the externalAccountBinding field.
	ErrTypeExternalAccountRequired = acmeErrorURNPrefix + "externalAccountRequired"

	// ErrTypeIncorrectResponse indicates response received didn't match the challenge's requirements.
	ErrTypeIncorrectResponse = acmeErrorURNPrefix + "incorrectResponse"

	// ErrTypeInvalidContact indicates a contact URL for an account was invalid.
	ErrTypeInvalidContact = acmeErrorURNPrefix + "invalidContact"

	// ErrTypeMalformed indicates the request message was malformed.
	ErrTypeMalformed = acmeErrorURNPrefix + "malformed"

	// ErrTypeOrderNotReady indicates the request attempted to finalize an order that is not ready to be finalized.
	ErrTypeOrderNotReady = acmeErrorURNPrefix + "orderNotReady"

	// ErrTypeRateLimited indicates the request exceeds a rate limit.
	ErrTypeRateLimited = acmeErrorURNPrefix + "rateLimited"

	// ErrTypeRejectedIdentifier indicates the server will not issue certificates for the identifier.
	ErrTypeRejectedIdentifier = acmeErrorURNPrefix + "rejectedIdentifier"

	// ErrTypeServerInternal indicates the server experienced an internal error.
	ErrTypeServerInternal = acmeErrorURNPrefix + "serverInternal"

	// ErrTypeTLS indicates the server received a TLS error during validation.
	ErrTypeTLS = acmeErrorURNPrefix + "tls"

	// ErrTypeUnauthorized indicates the client lacks sufficient authorization.
	ErrTypeUnauthorized = acmeErrorURNPrefix + "unauthorized"

	// ErrTypeUnsupportedContact indicates a contact URL for an account used an unsupported protocol scheme.
	ErrTypeUnsupportedContact = acmeErrorURNPrefix + "unsupportedContact"

	// ErrTypeUnsupportedIdentifier indicates an identifier is of an unsupported type.
	ErrTypeUnsupportedIdentifier = acmeErrorURNPrefix + "unsupportedIdentifier"

	// ErrTypeUserActionRequired indicates visit the instance URL and take actions specified there.
	ErrTypeUserActionRequired = acmeErrorURNPrefix + "userActionRequired"

	// RFC 9773 ARI (ACME Renewal Information) Error Types

	// ErrTypeAutoRenewalCanceled indicates the server has canceled automatic renewal for this certificate.
	ErrTypeAutoRenewalCanceled = acmeErrorURNPrefix + "autoRenewalCanceled"

	// ErrTypeAutoRenewalExpired indicates the automatic renewal subscription has expired.
	ErrTypeAutoRenewalExpired = acmeErrorURNPrefix + "autoRenewalExpired"

	// ErrTypeAutoRenewalCancellationInvalid indicates the cancellation request was invalid.
	ErrTypeAutoRenewalCancellationInvalid = acmeErrorURNPrefix + "autoRenewalCancellationInvalid"

	// ErrTypeAutoRenewalRevocationNotSupported indicates revocation is not supported for auto-renewed certificates.
	ErrTypeAutoRenewalRevocationNotSupported = acmeErrorURNPrefix + "autoRenewalRevocationNotSupported"
)

// ACMEError represents a client-side ACME protocol error received from a server.
// It implements the error interface and provides detailed information about
// the failure as defined in RFC 8555 Section 6.7.
type ACMEError struct {
	// Type is the error type URN (e.g., "urn:ietf:params:acme:error:malformed")
	Type string `json:"type"`

	// Detail is a human-readable explanation of the error
	Detail string `json:"detail,omitempty"`

	// Status is the HTTP status code returned by the server
	Status int `json:"status,omitempty"`

	// Subproblems provides detailed error information for compound errors
	Subproblems []Subproblem `json:"subproblems,omitempty"`

	// Instance provides a URI reference identifying the specific occurrence
	Instance string `json:"instance,omitempty"`

	// Identifier specifies which identifier the error relates to
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Subproblem represents a sub-error in a compound ACME error.
// Subproblems allow the server to communicate multiple distinct errors
// that occurred while processing a single request.
type Subproblem struct {
	// Type is the error type URN for this subproblem
	Type string `json:"type"`

	// Detail is a human-readable explanation of this subproblem
	Detail string `json:"detail,omitempty"`

	// Identifier specifies which identifier this subproblem relates to
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Identifier represents an ACME identifier (domain, IP, etc.)
type Identifier struct {
	// Type is the identifier type (e.g., "dns", "ip")
	Type string `json:"type"`

	// Value is the identifier value (e.g., "example.com", "192.0.2.1")
	Value string `json:"value"`
}

// Error implements the error interface.
func (e *ACMEError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Type
}

// Unwrap returns nil as ACMEError is a terminal error type.
func (e *ACMEError) Unwrap() error {
	return nil
}

// ShortType returns the error type without the URN prefix.
func (e *ACMEError) ShortType() string {
	return strings.TrimPrefix(e.Type, acmeErrorURNPrefix)
}

// Is implements error matching for ACMEError.
// It returns true if target is an *ACMEError with the same Type.
func (e *ACMEError) Is(target error) bool {
	var acmeErr *ACMEError
	if errors.As(target, &acmeErr) {
		return e.Type == acmeErr.Type
	}
	return false
}

// IsRetryable returns true if the error indicates a temporary condition
// that may be resolved by retrying the request.
func (e *ACMEError) IsRetryable() bool {
	switch e.Type {
	case ErrTypeBadNonce, ErrTypeConnection, ErrTypeDNS, ErrTypeServerInternal, ErrTypeRateLimited:
		return true
	default:
		return false
	}
}

// ParseACMEError parses an ACME error from an HTTP response.
// It reads the response body and attempts to parse it as an ACME error.
// If the response is not an ACME error or parsing fails, it returns
// a generic ACMEError with the HTTP status information.
func ParseACMEError(resp *http.Response) (*ACMEError, error) {
	if resp == nil {
		return nil, ErrNilResponse
	}

	if resp.Body == nil {
		return &ACMEError{
			Type:   ErrTypeMalformed,
			Detail: "empty response body",
			Status: resp.StatusCode,
		}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrResponseReadFailed
	}

	// Try to parse as ACME error JSON
	var acmeErr ACMEError
	if err := json.Unmarshal(body, &acmeErr); err != nil {
		// If JSON parsing fails, create a generic error
		return &ACMEError{
			Type:   ErrTypeMalformed,
			Detail: string(body),
			Status: resp.StatusCode,
		}, nil
	}

	// Set status from response if not in JSON
	if acmeErr.Status == 0 {
		acmeErr.Status = resp.StatusCode
	}

	return &acmeErr, nil
}

// ParseACMEErrorFromBytes parses an ACME error from raw JSON bytes.
func ParseACMEErrorFromBytes(data []byte, statusCode int) (*ACMEError, error) {
	if len(data) == 0 {
		return &ACMEError{
			Type:   ErrTypeMalformed,
			Detail: "empty response body",
			Status: statusCode,
		}, nil
	}

	var acmeErr ACMEError
	if err := json.Unmarshal(data, &acmeErr); err != nil {
		return &ACMEError{
			Type:   ErrTypeMalformed,
			Detail: string(data),
			Status: statusCode,
		}, nil
	}

	if acmeErr.Status == 0 {
		acmeErr.Status = statusCode
	}

	return &acmeErr, nil
}

// NewACMEError creates a new ACMEError with the specified parameters.
func NewACMEError(errType, detail string, status int) *ACMEError {
	// Ensure the type has the URN prefix
	if !strings.HasPrefix(errType, acmeErrorURNPrefix) {
		errType = acmeErrorURNPrefix + errType
	}
	return &ACMEError{
		Type:   errType,
		Detail: detail,
		Status: status,
	}
}

// NewACMEErrorWithSubproblems creates a new compound ACMEError with subproblems.
func NewACMEErrorWithSubproblems(errType, detail string, status int, subproblems []Subproblem) *ACMEError {
	err := NewACMEError(errType, detail, status)
	err.Subproblems = subproblems
	return err
}

// Error type checking helper functions

// IsAccountDoesNotExist returns true if the error indicates the account does not exist.
func IsAccountDoesNotExist(err error) bool {
	return isACMEErrorType(err, ErrTypeAccountDoesNotExist)
}

// IsAlreadyRevoked returns true if the error indicates the certificate is already revoked.
func IsAlreadyRevoked(err error) bool {
	return isACMEErrorType(err, ErrTypeAlreadyRevoked)
}

// IsBadCSR returns true if the error indicates the CSR is unacceptable.
func IsBadCSR(err error) bool {
	return isACMEErrorType(err, ErrTypeBadCSR)
}

// IsBadNonce returns true if the error indicates an invalid nonce.
func IsBadNonce(err error) bool {
	return isACMEErrorType(err, ErrTypeBadNonce)
}

// IsBadPublicKey returns true if the error indicates the public key is not supported.
func IsBadPublicKey(err error) bool {
	return isACMEErrorType(err, ErrTypeBadPublicKey)
}

// IsBadRevocationReason returns true if the error indicates an invalid revocation reason.
func IsBadRevocationReason(err error) bool {
	return isACMEErrorType(err, ErrTypeBadRevocationReason)
}

// IsBadSignatureAlgorithm returns true if the error indicates an unsupported signature algorithm.
func IsBadSignatureAlgorithm(err error) bool {
	return isACMEErrorType(err, ErrTypeBadSignatureAlgorithm)
}

// IsCAA returns true if the error indicates a CAA record failure.
func IsCAA(err error) bool {
	return isACMEErrorType(err, ErrTypeCAA)
}

// IsCompound returns true if the error is a compound error with subproblems.
func IsCompound(err error) bool {
	return isACMEErrorType(err, ErrTypeCompound)
}

// IsConnection returns true if the error indicates a connection failure.
func IsConnection(err error) bool {
	return isACMEErrorType(err, ErrTypeConnection)
}

// IsDNS returns true if the error indicates a DNS problem.
func IsDNS(err error) bool {
	return isACMEErrorType(err, ErrTypeDNS)
}

// IsExternalAccountRequired returns true if the error indicates external account binding is required.
func IsExternalAccountRequired(err error) bool {
	return isACMEErrorType(err, ErrTypeExternalAccountRequired)
}

// IsIncorrectResponse returns true if the error indicates an incorrect challenge response.
func IsIncorrectResponse(err error) bool {
	return isACMEErrorType(err, ErrTypeIncorrectResponse)
}

// IsInvalidContact returns true if the error indicates an invalid contact URL.
func IsInvalidContact(err error) bool {
	return isACMEErrorType(err, ErrTypeInvalidContact)
}

// IsMalformed returns true if the error indicates a malformed request.
func IsMalformed(err error) bool {
	return isACMEErrorType(err, ErrTypeMalformed)
}

// IsOrderNotReady returns true if the error indicates the order is not ready for finalization.
func IsOrderNotReady(err error) bool {
	return isACMEErrorType(err, ErrTypeOrderNotReady)
}

// IsRateLimited returns true if the error indicates a rate limit was exceeded.
func IsRateLimited(err error) bool {
	return isACMEErrorType(err, ErrTypeRateLimited)
}

// IsRejectedIdentifier returns true if the error indicates a rejected identifier.
func IsRejectedIdentifier(err error) bool {
	return isACMEErrorType(err, ErrTypeRejectedIdentifier)
}

// IsServerInternal returns true if the error indicates a server internal error.
func IsServerInternal(err error) bool {
	return isACMEErrorType(err, ErrTypeServerInternal)
}

// IsTLS returns true if the error indicates a TLS error.
func IsTLS(err error) bool {
	return isACMEErrorType(err, ErrTypeTLS)
}

// IsUnauthorized returns true if the error indicates insufficient authorization.
func IsUnauthorized(err error) bool {
	return isACMEErrorType(err, ErrTypeUnauthorized)
}

// IsUnsupportedContact returns true if the error indicates an unsupported contact scheme.
func IsUnsupportedContact(err error) bool {
	return isACMEErrorType(err, ErrTypeUnsupportedContact)
}

// IsUnsupportedIdentifier returns true if the error indicates an unsupported identifier type.
func IsUnsupportedIdentifier(err error) bool {
	return isACMEErrorType(err, ErrTypeUnsupportedIdentifier)
}

// IsUserActionRequired returns true if the error indicates user action is required.
func IsUserActionRequired(err error) bool {
	return isACMEErrorType(err, ErrTypeUserActionRequired)
}

// RFC 9773 ARI error type checking functions

// IsAutoRenewalCanceled returns true if automatic renewal has been canceled.
func IsAutoRenewalCanceled(err error) bool {
	return isACMEErrorType(err, ErrTypeAutoRenewalCanceled)
}

// IsAutoRenewalExpired returns true if the automatic renewal subscription has expired.
func IsAutoRenewalExpired(err error) bool {
	return isACMEErrorType(err, ErrTypeAutoRenewalExpired)
}

// IsAutoRenewalCancellationInvalid returns true if the cancellation request was invalid.
func IsAutoRenewalCancellationInvalid(err error) bool {
	return isACMEErrorType(err, ErrTypeAutoRenewalCancellationInvalid)
}

// IsAutoRenewalRevocationNotSupported returns true if revocation is not supported for auto-renewed certificates.
func IsAutoRenewalRevocationNotSupported(err error) bool {
	return isACMEErrorType(err, ErrTypeAutoRenewalRevocationNotSupported)
}

// isACMEErrorType checks if an error is an ACMEError of the specified type.
func isACMEErrorType(err error, errType string) bool {
	var acmeErr *ACMEError
	if errors.As(err, &acmeErr) {
		return acmeErr.Type == errType
	}
	return false
}

// GetACMEError extracts an ACMEError from an error chain.
// Returns nil if the error is not or does not wrap an ACMEError.
func GetACMEError(err error) *ACMEError {
	var acmeErr *ACMEError
	if errors.As(err, &acmeErr) {
		return acmeErr
	}
	return nil
}

// IsACMEError returns true if the error is or wraps an ACMEError.
func IsACMEError(err error) bool {
	return GetACMEError(err) != nil
}

// Client-specific errors for parsing failures
var (
	// ErrNilResponse indicates the HTTP response was nil
	ErrNilResponse = errors.New("acme-client: nil HTTP response")

	// ErrResponseReadFailed indicates the response body could not be read
	ErrResponseReadFailed = errors.New("acme-client: failed to read response body")
)
