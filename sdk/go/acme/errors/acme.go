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

import "errors"

// ACME error constructors per RFC 8555 Section 6.7

// NewACMEAccountDoesNotExist creates an error indicating the request
// specified an account that does not exist.
func NewACMEAccountDoesNotExist(op, message string) *CAError {
	return New(CodeACMEAccountDoesNotExist, op, message)
}

// NewACMEAlreadyRevoked creates an error indicating the request specified
// a certificate to be revoked that has already been revoked.
func NewACMEAlreadyRevoked(op, message string) *CAError {
	return New(CodeACMEAlreadyRevoked, op, message)
}

// NewACMEBadCSR creates an error indicating the CSR is unacceptable.
func NewACMEBadCSR(op, message string) *CAError {
	return New(CodeACMEBadCSR, op, message)
}

// NewACMEBadNonce creates an error indicating the client sent an
// unacceptable anti-replay nonce.
func NewACMEBadNonce(op, message string) *CAError {
	return New(CodeACMEBadNonce, op, message)
}

// NewACMEBadPublicKey creates an error indicating the JWS was signed
// by a public key the server does not support.
func NewACMEBadPublicKey(op, message string) *CAError {
	return New(CodeACMEBadPublicKey, op, message)
}

// NewACMEBadRevocationReason creates an error indicating the revocation
// reason provided is not allowed by the server.
func NewACMEBadRevocationReason(op, message string) *CAError {
	return New(CodeACMEBadRevocationReason, op, message)
}

// NewACMEBadSignatureAlgorithm creates an error indicating the JWS was
// signed with an algorithm the server does not support.
func NewACMEBadSignatureAlgorithm(op, message string) *CAError {
	return New(CodeACMEBadSignatureAlgorithm, op, message)
}

// NewACMECAA creates an error indicating CAA records forbid the CA
// from issuing a certificate.
func NewACMECAA(op, message string) *CAError {
	return New(CodeACMECAA, op, message)
}

// NewACMECompound creates an error indicating the request comprises
// multiple problems.
func NewACMECompound(op, message string) *CAError {
	return New(CodeACMECompound, op, message)
}

// NewACMEConnection creates an error indicating the server could not
// connect to validation target.
func NewACMEConnection(op, message string) *CAError {
	return New(CodeACMEConnection, op, message)
}

// NewACMEDNS creates an error indicating there was a problem with a
// DNS query during identifier validation.
func NewACMEDNS(op, message string) *CAError {
	return New(CodeACMEDNS, op, message)
}

// NewACMEExternalAccountRequired creates an error indicating the request
// must include a value for the "externalAccountBinding" field.
func NewACMEExternalAccountRequired(op, message string) *CAError {
	return New(CodeACMEExternalAccountRequired, op, message)
}

// NewACMEIncorrectResponse creates an error indicating response received
// didn't match the challenge's requirements.
func NewACMEIncorrectResponse(op, message string) *CAError {
	return New(CodeACMEIncorrectResponse, op, message)
}

// NewACMEInvalidContact creates an error indicating a contact URL for
// an account was invalid.
func NewACMEInvalidContact(op, message string) *CAError {
	return New(CodeACMEInvalidContact, op, message)
}

// NewACMEMalformed creates an error indicating the request message was malformed.
func NewACMEMalformed(op, message string) *CAError {
	return New(CodeACMEMalformed, op, message)
}

// NewACMEOrderNotReady creates an error indicating the request attempted
// to finalize an order that is not ready to be finalized.
func NewACMEOrderNotReady(op, message string) *CAError {
	return New(CodeACMEOrderNotReady, op, message)
}

// NewACMERateLimited creates an error indicating the request exceeds a rate limit.
func NewACMERateLimited(op, message string) *CAError {
	return New(CodeACMERateLimited, op, message)
}

// NewACMERejectedIdentifier creates an error indicating the server will
// not issue certificates for the identifier.
func NewACMERejectedIdentifier(op, message string) *CAError {
	return New(CodeACMERejectedIdentifier, op, message)
}

// NewACMEServerInternal creates an error indicating the server experienced
// an internal error.
func NewACMEServerInternal(op, message string) *CAError {
	return New(CodeACMEServerInternal, op, message)
}

// NewACMETLS creates an error indicating the server received a TLS error
// during validation.
func NewACMETLS(op, message string) *CAError {
	return New(CodeACMETLS, op, message)
}

// NewACMEUnauthorized creates an error indicating the client lacks
// sufficient authorization.
func NewACMEUnauthorized(op, message string) *CAError {
	return New(CodeACMEUnauthorized, op, message)
}

// NewACMEUnsupportedContact creates an error indicating a contact URL
// for an account used an unsupported protocol scheme.
func NewACMEUnsupportedContact(op, message string) *CAError {
	return New(CodeACMEUnsupportedContact, op, message)
}

// NewACMEUnsupportedIdentifier creates an error indicating an identifier
// is of an unsupported type.
func NewACMEUnsupportedIdentifier(op, message string) *CAError {
	return New(CodeACMEUnsupportedIdentifier, op, message)
}

// NewACMEUserActionRequired creates an error indicating the user must
// visit the "instance" URL and take actions specified there.
func NewACMEUserActionRequired(op, message string) *CAError {
	return New(CodeACMEUserActionRequired, op, message)
}

// ACME error predicates

// IsACME returns true if the error is an ACME-specific error.
func IsACME(err error) bool {
	return Code(err).IsACME()
}

// IsACMEAccountDoesNotExist returns true if the error indicates the
// account does not exist.
func IsACMEAccountDoesNotExist(err error) bool {
	return Code(err) == CodeACMEAccountDoesNotExist
}

// IsACMEAlreadyRevoked returns true if the error indicates the certificate
// has already been revoked.
func IsACMEAlreadyRevoked(err error) bool {
	return Code(err) == CodeACMEAlreadyRevoked
}

// IsACMEBadCSR returns true if the error indicates an unacceptable CSR.
func IsACMEBadCSR(err error) bool {
	return Code(err) == CodeACMEBadCSR
}

// IsACMEBadNonce returns true if the error indicates an unacceptable nonce.
func IsACMEBadNonce(err error) bool {
	return Code(err) == CodeACMEBadNonce
}

// IsACMEBadPublicKey returns true if the error indicates an unsupported
// public key.
func IsACMEBadPublicKey(err error) bool {
	return Code(err) == CodeACMEBadPublicKey
}

// IsACMEBadRevocationReason returns true if the error indicates an
// invalid revocation reason.
func IsACMEBadRevocationReason(err error) bool {
	return Code(err) == CodeACMEBadRevocationReason
}

// IsACMEBadSignatureAlgorithm returns true if the error indicates an
// unsupported signature algorithm.
func IsACMEBadSignatureAlgorithm(err error) bool {
	return Code(err) == CodeACMEBadSignatureAlgorithm
}

// IsACMECAA returns true if the error indicates CAA records forbid issuance.
func IsACMECAA(err error) bool {
	return Code(err) == CodeACMECAA
}

// IsACMECompound returns true if the error comprises multiple problems.
func IsACMECompound(err error) bool {
	return Code(err) == CodeACMECompound
}

// IsACMEConnection returns true if the error indicates a connection problem.
func IsACMEConnection(err error) bool {
	return Code(err) == CodeACMEConnection
}

// IsACMEDNS returns true if the error indicates a DNS problem.
func IsACMEDNS(err error) bool {
	return Code(err) == CodeACMEDNS
}

// IsACMEExternalAccountRequired returns true if the error indicates
// external account binding is required.
func IsACMEExternalAccountRequired(err error) bool {
	return Code(err) == CodeACMEExternalAccountRequired
}

// IsACMEIncorrectResponse returns true if the error indicates the
// challenge response was incorrect.
func IsACMEIncorrectResponse(err error) bool {
	return Code(err) == CodeACMEIncorrectResponse
}

// IsACMEInvalidContact returns true if the error indicates an invalid
// contact URL.
func IsACMEInvalidContact(err error) bool {
	return Code(err) == CodeACMEInvalidContact
}

// IsACMEMalformed returns true if the error indicates a malformed request.
func IsACMEMalformed(err error) bool {
	return Code(err) == CodeACMEMalformed
}

// IsACMEOrderNotReady returns true if the error indicates the order is
// not ready to be finalized.
func IsACMEOrderNotReady(err error) bool {
	return Code(err) == CodeACMEOrderNotReady
}

// IsACMERateLimited returns true if the error indicates rate limiting.
func IsACMERateLimited(err error) bool {
	return Code(err) == CodeACMERateLimited
}

// IsACMERejectedIdentifier returns true if the error indicates the
// identifier was rejected.
func IsACMERejectedIdentifier(err error) bool {
	return Code(err) == CodeACMERejectedIdentifier
}

// IsACMEServerInternal returns true if the error indicates an internal
// server error.
func IsACMEServerInternal(err error) bool {
	return Code(err) == CodeACMEServerInternal
}

// IsACMETLS returns true if the error indicates a TLS validation error.
func IsACMETLS(err error) bool {
	return Code(err) == CodeACMETLS
}

// IsACMEUnauthorized returns true if the error indicates insufficient
// authorization.
func IsACMEUnauthorized(err error) bool {
	return Code(err) == CodeACMEUnauthorized
}

// IsACMEUnsupportedContact returns true if the error indicates an
// unsupported contact protocol.
func IsACMEUnsupportedContact(err error) bool {
	return Code(err) == CodeACMEUnsupportedContact
}

// IsACMEUnsupportedIdentifier returns true if the error indicates an
// unsupported identifier type.
func IsACMEUnsupportedIdentifier(err error) bool {
	return Code(err) == CodeACMEUnsupportedIdentifier
}

// IsACMEUserActionRequired returns true if the error indicates user
// action is required.
func IsACMEUserActionRequired(err error) bool {
	return Code(err) == CodeACMEUserActionRequired
}

// ACMEError provides additional ACME-specific error fields per RFC 8555.
type ACMEError struct {
	*CAError

	// Type is the ACME error type URN.
	Type string

	// Detail provides additional human-readable detail.
	Detail string

	// Instance is a URL that identifies the specific error occurrence.
	Instance string

	// Subproblems contains additional problem documents for compound errors.
	Subproblems []ACMESubproblem
}

// ACMESubproblem represents a subproblem in a compound ACME error.
type ACMESubproblem struct {
	// Type is the ACME error type URN.
	Type string

	// Detail provides additional human-readable detail.
	Detail string

	// Identifier is the identifier that caused this subproblem.
	Identifier *ACMEIdentifier
}

// ACMEIdentifier represents an ACME identifier.
type ACMEIdentifier struct {
	// Type is the identifier type (e.g., "dns").
	Type string

	// Value is the identifier value (e.g., "example.com").
	Value string
}

// NewACMEError creates a new ACMEError with full RFC 8555 fields.
func NewACMEError(code ErrorCode, op, detail string) *ACMEError {
	return &ACMEError{
		CAError: New(code, op, detail),
		Type:    code.String(),
		Detail:  detail,
	}
}

// Error implements the error interface.
func (e *ACMEError) Error() string {
	return e.CAError.Error()
}

// Unwrap returns the underlying CAError.
func (e *ACMEError) Unwrap() error {
	return e.CAError
}

// Is reports whether the error matches the target.
func (e *ACMEError) Is(target error) bool {
	if t, ok := target.(*ACMEError); ok {
		return e.Code == t.Code
	}
	if t, ok := target.(*CAError); ok {
		return e.Code == t.Code
	}
	return false
}

// WithInstance sets the instance URL and returns the error for chaining.
func (e *ACMEError) WithInstance(instance string) *ACMEError {
	e.Instance = instance
	return e
}

// WithSubproblems sets the subproblems and returns the error for chaining.
func (e *ACMEError) WithSubproblems(subproblems []ACMESubproblem) *ACMEError {
	e.Subproblems = subproblems
	return e
}

// AddSubproblem adds a subproblem and returns the error for chaining.
func (e *ACMEError) AddSubproblem(sp ACMESubproblem) *ACMEError {
	e.Subproblems = append(e.Subproblems, sp)
	return e
}

// AsACMEError attempts to extract an ACMEError from an error chain.
func AsACMEError(err error) (*ACMEError, bool) {
	var ae *ACMEError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// HTTPStatus returns the appropriate HTTP status code for this ACME error.
func (e *ACMEError) HTTPStatus() int {
	return ACMEHTTPStatus(e.Code)
}

// acmeHTTPStatusMap maps ACME error codes to HTTP status codes per RFC 8555.
var acmeHTTPStatusMap = map[ErrorCode]int{
	CodeACMEAccountDoesNotExist:     400,
	CodeACMEAlreadyRevoked:          400,
	CodeACMEBadCSR:                  400,
	CodeACMEBadNonce:                400,
	CodeACMEBadPublicKey:            400,
	CodeACMEBadRevocationReason:     400,
	CodeACMEBadSignatureAlgorithm:   400,
	CodeACMECAA:                     403,
	CodeACMECompound:                400,
	CodeACMEConnection:              400,
	CodeACMEDNS:                     400,
	CodeACMEExternalAccountRequired: 403,
	CodeACMEIncorrectResponse:       403,
	CodeACMEInvalidContact:          400,
	CodeACMEMalformed:               400,
	CodeACMEOrderNotReady:           403,
	CodeACMERateLimited:             429,
	CodeACMERejectedIdentifier:      400,
	CodeACMEServerInternal:          500,
	CodeACMETLS:                     400,
	CodeACMEUnauthorized:            403,
	CodeACMEUnsupportedContact:      400,
	CodeACMEUnsupportedIdentifier:   400,
	CodeACMEUserActionRequired:      403,
	// General codes
	CodeUnknown:       500,
	CodeInvalidInput:  400,
	CodeNotFound:      404,
	CodeAlreadyExists: 409,
	CodeUnauthorized:  401,
	CodeForbidden:     403,
	CodeConflict:      409,
	CodeTimeout:       504,
	CodeUnavailable:   503,
	CodeInternal:      500,
}

// ACMEHTTPStatus returns the appropriate HTTP status code for an error code.
func ACMEHTTPStatus(code ErrorCode) int {
	if status, ok := acmeHTTPStatusMap[code]; ok {
		return status
	}
	return 500
}
