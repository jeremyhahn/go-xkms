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

// Package authorization provides the ACME authorization client operations.
package authorization

// Status represents the status of an ACME authorization.
type Status string

const (
	// StatusPending indicates the authorization is waiting for validation.
	StatusPending Status = "pending"

	// StatusValid indicates the authorization has been validated.
	StatusValid Status = "valid"

	// StatusInvalid indicates the authorization validation failed.
	StatusInvalid Status = "invalid"

	// StatusDeactivated indicates the authorization has been deactivated.
	StatusDeactivated Status = "deactivated"

	// StatusExpired indicates the authorization has expired.
	StatusExpired Status = "expired"

	// StatusRevoked indicates the authorization has been revoked.
	StatusRevoked Status = "revoked"
)

// Identifier represents an ACME identifier as defined in RFC 8555.
type Identifier struct {
	// Type is the identifier type (e.g., "dns", "ip").
	Type string `json:"type"`

	// Value is the identifier value (e.g., domain name, IP address).
	Value string `json:"value"`
}

// Challenge represents an ACME challenge as defined in RFC 8555.
type Challenge struct {
	// Type is the challenge type (e.g., "http-01", "dns-01", "tls-alpn-01").
	Type string `json:"type"`

	// URL is the challenge URL.
	URL string `json:"url"`

	// Status is the current status of the challenge.
	Status string `json:"status"`

	// Token is the token for this challenge.
	Token string `json:"token"`

	// Validated is the timestamp when the challenge was validated.
	Validated string `json:"validated,omitempty"`

	// Error contains any error that occurred during validation.
	Error *Error `json:"error,omitempty"`
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

// Authorization represents an ACME authorization as defined in RFC 8555.
type Authorization struct {
	// ID is the unique identifier for the authorization.
	ID uint64 `json:"id,omitempty"`

	// Identifier is the identifier being authorized.
	Identifier Identifier `json:"identifier"`

	// Status is the current status of the authorization.
	Status Status `json:"status"`

	// Expires is the timestamp after which the authorization is invalid.
	Expires string `json:"expires,omitempty"`

	// Challenges is the list of challenges for this authorization.
	Challenges []Challenge `json:"challenges"`

	// Wildcard indicates whether this is a wildcard authorization.
	Wildcard bool `json:"wildcard,omitempty"`

	// URL is the authorization's URL.
	URL string `json:"url,omitempty"`

	// AccountID is the ID of the account that requested the authorization.
	AccountID uint64 `json:"accountId,omitempty"`

	// OrderID is the ID of the order this authorization belongs to.
	OrderID uint64 `json:"orderId,omitempty"`
}

// GetRequest contains the parameters for retrieving an authorization.
type GetRequest struct {
	// AuthorizationURL is the URL of the authorization to retrieve.
	AuthorizationURL string `json:"authorizationUrl"`
}

// GetResponse contains the response from retrieving an authorization.
type GetResponse struct {
	// Authorization is the retrieved authorization.
	Authorization *Authorization `json:"authorization"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// DeactivateRequest contains the parameters for deactivating an authorization.
type DeactivateRequest struct {
	// AuthorizationURL is the URL of the authorization to deactivate.
	AuthorizationURL string `json:"authorizationUrl"`
}

// DeactivateResponse contains the response from deactivating an authorization.
type DeactivateResponse struct {
	// Authorization is the deactivated authorization.
	Authorization *Authorization `json:"authorization"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}
