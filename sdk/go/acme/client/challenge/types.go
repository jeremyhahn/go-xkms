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

// Package challenge provides the ACME challenge client operations.
package challenge

// Status represents the status of an ACME challenge.
type Status string

const (
	// StatusPending indicates the challenge is waiting to be answered.
	StatusPending Status = "pending"

	// StatusProcessing indicates the challenge is being validated.
	StatusProcessing Status = "processing"

	// StatusValid indicates the challenge has been validated successfully.
	StatusValid Status = "valid"

	// StatusInvalid indicates the challenge validation failed.
	StatusInvalid Status = "invalid"
)

// ChallengeType represents the type of ACME challenge.
type ChallengeType string

const (
	// TypeHTTP01 is the HTTP-01 challenge type.
	TypeHTTP01 ChallengeType = "http-01"

	// TypeDNS01 is the DNS-01 challenge type.
	TypeDNS01 ChallengeType = "dns-01"

	// TypeTLSALPN01 is the TLS-ALPN-01 challenge type.
	TypeTLSALPN01 ChallengeType = "tls-alpn-01"
)

// Identifier represents an ACME identifier as defined in RFC 8555.
type Identifier struct {
	// Type is the identifier type (e.g., "dns", "ip").
	Type string `json:"type"`

	// Value is the identifier value (e.g., domain name, IP address).
	Value string `json:"value"`
}

// Error represents an ACME error object as defined in RFC 8555.
type Error struct {
	// Type is the error type URN.
	Type string `json:"type"`

	// Detail is a human-readable description of the error.
	Detail string `json:"detail,omitempty"`

	// Status is the HTTP status code.
	Status int `json:"status,omitempty"`

	// Subproblems contains additional error information.
	Subproblems []Error `json:"subproblems,omitempty"`

	// Identifier is the identifier associated with the error.
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Challenge represents an ACME challenge as defined in RFC 8555.
type Challenge struct {
	// ID is the unique identifier for the challenge.
	ID uint64 `json:"id,omitempty"`

	// Type is the challenge type (e.g., "http-01", "dns-01", "tls-alpn-01").
	Type ChallengeType `json:"type"`

	// URL is the challenge URL.
	URL string `json:"url"`

	// Status is the current status of the challenge.
	Status Status `json:"status"`

	// Token is the token for this challenge.
	Token string `json:"token"`

	// Validated is the timestamp when the challenge was validated.
	Validated string `json:"validated,omitempty"`

	// Error contains any error that occurred during validation.
	Error *Error `json:"error,omitempty"`

	// AccountID is the ID of the account that owns the challenge.
	AccountID uint64 `json:"accountId,omitempty"`

	// AuthorizationID is the ID of the authorization this challenge belongs to.
	AuthorizationID uint64 `json:"authorizationId,omitempty"`
}

// GetRequest contains the parameters for retrieving a challenge.
type GetRequest struct {
	// ChallengeURL is the URL of the challenge to retrieve.
	ChallengeURL string `json:"challengeUrl"`
}

// GetResponse contains the response from retrieving a challenge.
type GetResponse struct {
	// Challenge is the retrieved challenge.
	Challenge *Challenge `json:"challenge"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// RespondRequest contains the parameters for responding to a challenge.
type RespondRequest struct {
	// ChallengeURL is the URL of the challenge to respond to.
	ChallengeURL string `json:"challengeUrl"`

	// KeyAuthorization is the key authorization string (optional, some servers compute this).
	KeyAuthorization string `json:"keyAuthorization,omitempty"`
}

// RespondResponse contains the response from responding to a challenge.
type RespondResponse struct {
	// Challenge is the challenge after the response.
	Challenge *Challenge `json:"challenge"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}
