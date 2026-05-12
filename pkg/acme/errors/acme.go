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
	"net/http"
)

// ACME problem type URN prefix per RFC 8555.
const acmeURNPrefix = "urn:ietf:params:acme:error:"

// ProblemDocument represents an RFC 8555 ACME Problem Document.
// This structure is returned to ACME clients when errors occur.
type ProblemDocument struct {
	Type        string             `json:"type"`
	Detail      string             `json:"detail"`
	Status      int                `json:"status,omitempty"`
	SubProblems []SubProblemDoc    `json:"subproblems,omitempty"`
	Identifier  *ProblemIdentifier `json:"identifier,omitempty"`
	Instance    string             `json:"instance,omitempty"`
}

// SubProblemDoc represents a subproblem in a compound error per RFC 8555.
type SubProblemDoc struct {
	Type       string             `json:"type"`
	Detail     string             `json:"detail"`
	Identifier *ProblemIdentifier `json:"identifier,omitempty"`
}

// ProblemIdentifier represents an identifier in a problem document.
type ProblemIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// acmeTypeMap maps ErrorType to ACME problem type strings.
var acmeTypeMap = map[ErrorType]string{
	InternalServer:          "serverInternal",
	Malformed:               "malformed",
	Unauthorized:            "unauthorized",
	NotFound:                "accountDoesNotExist",
	RateLimit:               "rateLimited",
	RejectedIdentifier:      "rejectedIdentifier",
	InvalidEmail:            "invalidContact",
	ConnectionFailure:       "connection",
	CAA:                     "caa",
	MissingSCTs:             "serverInternal",
	Duplicate:               "serverInternal",
	OrderNotReady:           "orderNotReady",
	DNS:                     "dns",
	BadPublicKey:            "badPublicKey",
	BadCSR:                  "badCSR",
	AlreadyRevoked:          "alreadyRevoked",
	BadRevocationReason:     "badRevocationReason",
	UnsupportedContact:      "unsupportedContact",
	UnknownSerial:           "serverInternal",
	Conflict:                "serverInternal",
	InvalidProfile:          "invalidProfile",
	AlreadyReplaced:         "serverInternal",
	BadSignatureAlgorithm:   "badSignatureAlgorithm",
	AccountDoesNotExist:     "accountDoesNotExist",
	BadNonce:                "badNonce",
	ExternalAccountRequired: "externalAccountRequired",
	IncorrectResponse:       "incorrectResponse",
	InvalidContact:          "invalidContact",
	TLSError:                "tls",
	UnsupportedIdentifier:   "unsupportedIdentifier",
	UserActionRequired:      "userActionRequired",
	AccountExists:           "accountDoesNotExist", // Returns with Location header
	CompoundError:           "compound",
	BadAttestationStatement: "badAttestationStatement",
	StorageFailure:          "serverInternal",
	SerializationFailure:    "serverInternal",
	TenantNotFound:          "serverInternal",
	TenantSuspended:         "unauthorized",
	TenantQuotaExceeded:     "rateLimited",
	CertificateExpired:      "unauthorized",
	CertificateNotYetValid:  "unauthorized",
	SigningFailure:          "serverInternal",
	VerificationFailure:     "unauthorized",
	KeyGenerationFailure:    "serverInternal",
	TPMError:                "badAttestationStatement",
	OCSPFailure:             "serverInternal",
	CRLFailure:              "serverInternal",
	PolicyViolation:         "unauthorized",
	AuthorizationExpired:    "unauthorized",
	ChallengeTimeout:        "connection",
	InvalidToken:            "unauthorized",
}

// httpStatusMap maps ErrorType to HTTP status codes.
var httpStatusMap = map[ErrorType]int{
	InternalServer:          http.StatusInternalServerError,
	Malformed:               http.StatusBadRequest,
	Unauthorized:            http.StatusUnauthorized,
	NotFound:                http.StatusNotFound,
	RateLimit:               http.StatusTooManyRequests,
	RejectedIdentifier:      http.StatusForbidden,
	InvalidEmail:            http.StatusBadRequest,
	ConnectionFailure:       http.StatusBadRequest,
	CAA:                     http.StatusForbidden,
	MissingSCTs:             http.StatusInternalServerError,
	Duplicate:               http.StatusConflict,
	OrderNotReady:           http.StatusForbidden,
	DNS:                     http.StatusBadRequest,
	BadPublicKey:            http.StatusBadRequest,
	BadCSR:                  http.StatusBadRequest,
	AlreadyRevoked:          http.StatusBadRequest,
	BadRevocationReason:     http.StatusBadRequest,
	UnsupportedContact:      http.StatusBadRequest,
	UnknownSerial:           http.StatusNotFound,
	Conflict:                http.StatusConflict,
	InvalidProfile:          http.StatusBadRequest,
	AlreadyReplaced:         http.StatusConflict,
	BadSignatureAlgorithm:   http.StatusBadRequest,
	AccountDoesNotExist:     http.StatusNotFound,
	BadNonce:                http.StatusBadRequest,
	ExternalAccountRequired: http.StatusUnauthorized,
	IncorrectResponse:       http.StatusForbidden,
	InvalidContact:          http.StatusBadRequest,
	TLSError:                http.StatusBadRequest,
	UnsupportedIdentifier:   http.StatusBadRequest,
	UserActionRequired:      http.StatusForbidden,
	AccountExists:           http.StatusConflict,
	CompoundError:           http.StatusBadRequest,
	BadAttestationStatement: http.StatusBadRequest,
	StorageFailure:          http.StatusInternalServerError,
	SerializationFailure:    http.StatusInternalServerError,
	TenantNotFound:          http.StatusNotFound,
	TenantSuspended:         http.StatusForbidden,
	TenantQuotaExceeded:     http.StatusTooManyRequests,
	CertificateExpired:      http.StatusForbidden,
	CertificateNotYetValid:  http.StatusForbidden,
	SigningFailure:          http.StatusInternalServerError,
	VerificationFailure:     http.StatusUnauthorized,
	KeyGenerationFailure:    http.StatusInternalServerError,
	TPMError:                http.StatusBadRequest,
	OCSPFailure:             http.StatusInternalServerError,
	CRLFailure:              http.StatusInternalServerError,
	PolicyViolation:         http.StatusForbidden,
	AuthorizationExpired:    http.StatusForbidden,
	ChallengeTimeout:        http.StatusRequestTimeout,
	InvalidToken:            http.StatusUnauthorized,
}

// ToProblemDocument converts a TrustedCAError to an RFC 8555 Problem Document.
func ToProblemDocument(err error) *ProblemDocument {
	if err == nil {
		return nil
	}

	tce, ok := err.(*TrustedCAError)
	if !ok {
		// Wrap non-TrustedCAError as internal server error
		return &ProblemDocument{
			Type:   acmeURNPrefix + "serverInternal",
			Detail: err.Error(),
			Status: http.StatusInternalServerError,
		}
	}

	pd := &ProblemDocument{
		Type:     acmeURNPrefix + errorTypeToACMEType(tce.Type),
		Detail:   tce.Detail,
		Status:   errorTypeToHTTPStatus(tce.Type),
		Instance: tce.Instance,
	}

	// Convert sub-errors to sub-problems
	for _, se := range tce.SubErrors {
		sp := SubProblemDoc{
			Type:   acmeURNPrefix + errorTypeToACMEType(se.TrustedCAError.Type),
			Detail: se.TrustedCAError.Detail,
		}
		if se.Identifier.Type != "" || se.Identifier.Value != "" {
			sp.Identifier = &ProblemIdentifier{
				Type:  se.Identifier.Type,
				Value: se.Identifier.Value,
			}
		}
		pd.SubProblems = append(pd.SubProblems, sp)
	}

	return pd
}

// ToProblemDocumentWithIdentifier converts a TrustedCAError to a Problem Document
// with an identifier attached.
func ToProblemDocumentWithIdentifier(err error, idType, idValue string) *ProblemDocument {
	pd := ToProblemDocument(err)
	if pd != nil && (idType != "" || idValue != "") {
		pd.Identifier = &ProblemIdentifier{
			Type:  idType,
			Value: idValue,
		}
	}
	return pd
}

// errorTypeToACMEType maps ErrorType to ACME problem type strings.
func errorTypeToACMEType(t ErrorType) string {
	if s, ok := acmeTypeMap[t]; ok {
		return s
	}
	return "serverInternal"
}

// errorTypeToHTTPStatus maps ErrorType to HTTP status codes.
func errorTypeToHTTPStatus(t ErrorType) int {
	if s, ok := httpStatusMap[t]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// HTTPStatus returns the appropriate HTTP status code for the given error.
func HTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if tce, ok := err.(*TrustedCAError); ok {
		return errorTypeToHTTPStatus(tce.Type)
	}
	return http.StatusInternalServerError
}

// ACMEType returns the ACME problem type URN for the given error.
func ACMEType(err error) string {
	if err == nil {
		return ""
	}
	if tce, ok := err.(*TrustedCAError); ok {
		return acmeURNPrefix + errorTypeToACMEType(tce.Type)
	}
	return acmeURNPrefix + "serverInternal"
}
