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

// ErrorCode represents a categorized error code.
type ErrorCode int

const (
	// CodeUnknown is an unknown error.
	CodeUnknown ErrorCode = iota

	// General client errors (4xx equivalent)

	// CodeInvalidInput indicates invalid input parameters.
	CodeInvalidInput

	// CodeNotFound indicates the requested resource was not found.
	CodeNotFound

	// CodeAlreadyExists indicates the resource already exists.
	CodeAlreadyExists

	// CodeUnauthorized indicates authentication is required.
	CodeUnauthorized

	// CodeForbidden indicates the operation is not permitted.
	CodeForbidden

	// CodeConflict indicates a conflict with the current state.
	CodeConflict

	// CodePreconditionFailed indicates a precondition was not met.
	CodePreconditionFailed

	// CodeRateLimited indicates the client is rate limited.
	CodeRateLimited

	// General server errors (5xx equivalent)

	// CodeInternal indicates an internal server error.
	CodeInternal

	// CodeUnavailable indicates the service is unavailable.
	CodeUnavailable

	// CodeTimeout indicates the operation timed out.
	CodeTimeout

	// CodeCanceled indicates the operation was canceled.
	CodeCanceled

	// CodeUnimplemented indicates the operation is not implemented.
	CodeUnimplemented

	// CodeResourceExhausted indicates resources are exhausted.
	CodeResourceExhausted

	// Specialized errors

	// CodeNotInitialized indicates the server is not initialized.
	CodeNotInitialized

	// CodeConfiguration indicates a configuration error.
	CodeConfiguration

	// CodeConnection indicates a connection error.
	CodeConnection

	// CodeTransport indicates a transport-level error.
	CodeTransport

	// ACME-specific error codes per RFC 8555 Section 6.7

	// CodeACMEAccountDoesNotExist indicates the request specified an account
	// that does not exist.
	CodeACMEAccountDoesNotExist

	// CodeACMEAlreadyRevoked indicates the request specified a certificate
	// to be revoked that has already been revoked.
	CodeACMEAlreadyRevoked

	// CodeACMEBadCSR indicates the CSR is unacceptable (e.g., due to a short
	// key).
	CodeACMEBadCSR

	// CodeACMEBadNonce indicates the client sent an unacceptable anti-replay
	// nonce.
	CodeACMEBadNonce

	// CodeACMEBadPublicKey indicates the JWS was signed by a public key the
	// server does not support.
	CodeACMEBadPublicKey

	// CodeACMEBadRevocationReason indicates the revocation reason provided is
	// not allowed by the server.
	CodeACMEBadRevocationReason

	// CodeACMEBadSignatureAlgorithm indicates the JWS was signed with an
	// algorithm the server does not support.
	CodeACMEBadSignatureAlgorithm

	// CodeACMECAA indicates Certificate Authority Authorization (CAA)
	// records forbid the CA from issuing a certificate.
	CodeACMECAA

	// CodeACMECompound indicates the request comprises multiple problems
	// (subproblems field present).
	CodeACMECompound

	// CodeACMEConnection indicates the server could not connect to validation
	// target.
	CodeACMEConnection

	// CodeACMEDNS indicates there was a problem with a DNS query during
	// identifier validation.
	CodeACMEDNS

	// CodeACMEExternalAccountRequired indicates the request must include a
	// value for the "externalAccountBinding" field.
	CodeACMEExternalAccountRequired

	// CodeACMEIncorrectResponse indicates response received didn't match the
	// challenge's requirements.
	CodeACMEIncorrectResponse

	// CodeACMEInvalidContact indicates a contact URL for an account was invalid.
	CodeACMEInvalidContact

	// CodeACMEMalformed indicates the request message was malformed.
	CodeACMEMalformed

	// CodeACMEOrderNotReady indicates the request attempted to finalize an
	// order that is not ready to be finalized.
	CodeACMEOrderNotReady

	// CodeACMERateLimited indicates the request exceeds a rate limit.
	CodeACMERateLimited

	// CodeACMERejectedIdentifier indicates the server will not issue
	// certificates for the identifier.
	CodeACMERejectedIdentifier

	// CodeACMEServerInternal indicates the server experienced an internal error.
	CodeACMEServerInternal

	// CodeACMETLS indicates the server received a TLS error during validation.
	CodeACMETLS

	// CodeACMEUnauthorized indicates the client lacks sufficient authorization.
	CodeACMEUnauthorized

	// CodeACMEUnsupportedContact indicates a contact URL for an account used
	// an unsupported protocol scheme.
	CodeACMEUnsupportedContact

	// CodeACMEUnsupportedIdentifier indicates an identifier is of an
	// unsupported type.
	CodeACMEUnsupportedIdentifier

	// CodeACMEUserActionRequired indicates Visit the "instance" URL and take
	// actions specified there.
	CodeACMEUserActionRequired
)

// codeStrings maps error codes to their string representations.
var codeStrings = map[ErrorCode]string{
	CodeUnknown:                     "UNKNOWN",
	CodeInvalidInput:                "INVALID_INPUT",
	CodeNotFound:                    "NOT_FOUND",
	CodeAlreadyExists:               "ALREADY_EXISTS",
	CodeUnauthorized:                "UNAUTHORIZED",
	CodeForbidden:                   "FORBIDDEN",
	CodeConflict:                    "CONFLICT",
	CodePreconditionFailed:          "PRECONDITION_FAILED",
	CodeRateLimited:                 "RATE_LIMITED",
	CodeInternal:                    "INTERNAL",
	CodeUnavailable:                 "UNAVAILABLE",
	CodeTimeout:                     "TIMEOUT",
	CodeCanceled:                    "CANCELED",
	CodeUnimplemented:               "UNIMPLEMENTED",
	CodeResourceExhausted:           "RESOURCE_EXHAUSTED",
	CodeNotInitialized:              "NOT_INITIALIZED",
	CodeConfiguration:               "CONFIGURATION",
	CodeConnection:                  "CONNECTION",
	CodeTransport:                   "TRANSPORT",
	CodeACMEAccountDoesNotExist:     "urn:ietf:params:acme:error:accountDoesNotExist",
	CodeACMEAlreadyRevoked:          "urn:ietf:params:acme:error:alreadyRevoked",
	CodeACMEBadCSR:                  "urn:ietf:params:acme:error:badCSR",
	CodeACMEBadNonce:                "urn:ietf:params:acme:error:badNonce",
	CodeACMEBadPublicKey:            "urn:ietf:params:acme:error:badPublicKey",
	CodeACMEBadRevocationReason:     "urn:ietf:params:acme:error:badRevocationReason",
	CodeACMEBadSignatureAlgorithm:   "urn:ietf:params:acme:error:badSignatureAlgorithm",
	CodeACMECAA:                     "urn:ietf:params:acme:error:caa",
	CodeACMECompound:                "urn:ietf:params:acme:error:compound",
	CodeACMEConnection:              "urn:ietf:params:acme:error:connection",
	CodeACMEDNS:                     "urn:ietf:params:acme:error:dns",
	CodeACMEExternalAccountRequired: "urn:ietf:params:acme:error:externalAccountRequired",
	CodeACMEIncorrectResponse:       "urn:ietf:params:acme:error:incorrectResponse",
	CodeACMEInvalidContact:          "urn:ietf:params:acme:error:invalidContact",
	CodeACMEMalformed:               "urn:ietf:params:acme:error:malformed",
	CodeACMEOrderNotReady:           "urn:ietf:params:acme:error:orderNotReady",
	CodeACMERateLimited:             "urn:ietf:params:acme:error:rateLimited",
	CodeACMERejectedIdentifier:      "urn:ietf:params:acme:error:rejectedIdentifier",
	CodeACMEServerInternal:          "urn:ietf:params:acme:error:serverInternal",
	CodeACMETLS:                     "urn:ietf:params:acme:error:tls",
	CodeACMEUnauthorized:            "urn:ietf:params:acme:error:unauthorized",
	CodeACMEUnsupportedContact:      "urn:ietf:params:acme:error:unsupportedContact",
	CodeACMEUnsupportedIdentifier:   "urn:ietf:params:acme:error:unsupportedIdentifier",
	CodeACMEUserActionRequired:      "urn:ietf:params:acme:error:userActionRequired",
}

// String returns the string representation of the error code.
func (c ErrorCode) String() string {
	if s, ok := codeStrings[c]; ok {
		return s
	}
	return "UNKNOWN"
}

// retryableCodes contains error codes that indicate retryable errors.
var retryableCodes = map[ErrorCode]struct{}{
	CodeUnavailable:        {},
	CodeTimeout:            {},
	CodeResourceExhausted:  {},
	CodeACMEBadNonce:       {},
	CodeACMEConnection:     {},
	CodeACMEDNS:            {},
	CodeACMERateLimited:    {},
	CodeACMEServerInternal: {},
}

// IsRetryable returns true if errors with this code can be retried.
func (c ErrorCode) IsRetryable() bool {
	_, ok := retryableCodes[c]
	return ok
}

// clientErrorCodes contains error codes that indicate client errors.
var clientErrorCodes = map[ErrorCode]struct{}{
	CodeInvalidInput:                {},
	CodeNotFound:                    {},
	CodeAlreadyExists:               {},
	CodeUnauthorized:                {},
	CodeForbidden:                   {},
	CodeConflict:                    {},
	CodePreconditionFailed:          {},
	CodeRateLimited:                 {},
	CodeACMEAccountDoesNotExist:     {},
	CodeACMEAlreadyRevoked:          {},
	CodeACMEBadCSR:                  {},
	CodeACMEBadNonce:                {},
	CodeACMEBadPublicKey:            {},
	CodeACMEBadRevocationReason:     {},
	CodeACMEBadSignatureAlgorithm:   {},
	CodeACMECAA:                     {},
	CodeACMECompound:                {},
	CodeACMEExternalAccountRequired: {},
	CodeACMEIncorrectResponse:       {},
	CodeACMEInvalidContact:          {},
	CodeACMEMalformed:               {},
	CodeACMEOrderNotReady:           {},
	CodeACMERateLimited:             {},
	CodeACMERejectedIdentifier:      {},
	CodeACMEUnauthorized:            {},
	CodeACMEUnsupportedContact:      {},
	CodeACMEUnsupportedIdentifier:   {},
	CodeACMEUserActionRequired:      {},
}

// IsClientError returns true if this is a client-side error.
func (c ErrorCode) IsClientError() bool {
	_, ok := clientErrorCodes[c]
	return ok
}

// serverErrorCodes contains error codes that indicate server errors.
var serverErrorCodes = map[ErrorCode]struct{}{
	CodeInternal:           {},
	CodeUnavailable:        {},
	CodeTimeout:            {},
	CodeUnimplemented:      {},
	CodeResourceExhausted:  {},
	CodeACMEConnection:     {},
	CodeACMEDNS:            {},
	CodeACMEServerInternal: {},
	CodeACMETLS:            {},
}

// IsServerError returns true if this is a server-side error.
func (c ErrorCode) IsServerError() bool {
	_, ok := serverErrorCodes[c]
	return ok
}

// IsACME returns true if this is an ACME-specific error code.
func (c ErrorCode) IsACME() bool {
	return c >= CodeACMEAccountDoesNotExist && c <= CodeACMEUserActionRequired
}

// acmeCodeFromURN maps ACME URN strings to error codes for parsing.
var acmeCodeFromURN = map[string]ErrorCode{
	"urn:ietf:params:acme:error:accountDoesNotExist":     CodeACMEAccountDoesNotExist,
	"urn:ietf:params:acme:error:alreadyRevoked":          CodeACMEAlreadyRevoked,
	"urn:ietf:params:acme:error:badCSR":                  CodeACMEBadCSR,
	"urn:ietf:params:acme:error:badNonce":                CodeACMEBadNonce,
	"urn:ietf:params:acme:error:badPublicKey":            CodeACMEBadPublicKey,
	"urn:ietf:params:acme:error:badRevocationReason":     CodeACMEBadRevocationReason,
	"urn:ietf:params:acme:error:badSignatureAlgorithm":   CodeACMEBadSignatureAlgorithm,
	"urn:ietf:params:acme:error:caa":                     CodeACMECAA,
	"urn:ietf:params:acme:error:compound":                CodeACMECompound,
	"urn:ietf:params:acme:error:connection":              CodeACMEConnection,
	"urn:ietf:params:acme:error:dns":                     CodeACMEDNS,
	"urn:ietf:params:acme:error:externalAccountRequired": CodeACMEExternalAccountRequired,
	"urn:ietf:params:acme:error:incorrectResponse":       CodeACMEIncorrectResponse,
	"urn:ietf:params:acme:error:invalidContact":          CodeACMEInvalidContact,
	"urn:ietf:params:acme:error:malformed":               CodeACMEMalformed,
	"urn:ietf:params:acme:error:orderNotReady":           CodeACMEOrderNotReady,
	"urn:ietf:params:acme:error:rateLimited":             CodeACMERateLimited,
	"urn:ietf:params:acme:error:rejectedIdentifier":      CodeACMERejectedIdentifier,
	"urn:ietf:params:acme:error:serverInternal":          CodeACMEServerInternal,
	"urn:ietf:params:acme:error:tls":                     CodeACMETLS,
	"urn:ietf:params:acme:error:unauthorized":            CodeACMEUnauthorized,
	"urn:ietf:params:acme:error:unsupportedContact":      CodeACMEUnsupportedContact,
	"urn:ietf:params:acme:error:unsupportedIdentifier":   CodeACMEUnsupportedIdentifier,
	"urn:ietf:params:acme:error:userActionRequired":      CodeACMEUserActionRequired,
}

// ParseACMEErrorType parses an ACME error type URN string and returns
// the corresponding ErrorCode. Returns CodeUnknown if the URN is not recognized.
func ParseACMEErrorType(urn string) ErrorCode {
	if code, ok := acmeCodeFromURN[urn]; ok {
		return code
	}
	return CodeUnknown
}
