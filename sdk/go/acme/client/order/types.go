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

// Package order provides the ACME order client operations.
package order

// Status represents the status of an ACME order.
type Status string

const (
	// StatusPending indicates the order is waiting for authorization.
	StatusPending Status = "pending"

	// StatusReady indicates the order is ready for finalization.
	StatusReady Status = "ready"

	// StatusProcessing indicates the certificate is being issued.
	StatusProcessing Status = "processing"

	// StatusValid indicates the certificate has been issued.
	StatusValid Status = "valid"

	// StatusInvalid indicates the order failed.
	StatusInvalid Status = "invalid"
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

// Order represents an ACME order as defined in RFC 8555.
type Order struct {
	// ID is the unique identifier for the order.
	ID uint64 `json:"id,omitempty"`

	// Status is the current status of the order.
	Status Status `json:"status"`

	// Expires is the timestamp after which the order is invalid.
	Expires string `json:"expires,omitempty"`

	// Identifiers is the list of identifiers for the certificate.
	Identifiers []Identifier `json:"identifiers"`

	// NotBefore is the requested notBefore date for the certificate.
	NotBefore string `json:"notBefore,omitempty"`

	// NotAfter is the requested notAfter date for the certificate.
	NotAfter string `json:"notAfter,omitempty"`

	// Error contains any error that occurred during order processing.
	Error *Error `json:"error,omitempty"`

	// Authorizations is the list of authorization URLs.
	Authorizations []string `json:"authorizations"`

	// Finalize is the URL to finalize the order.
	Finalize string `json:"finalize"`

	// Certificate is the URL to download the certificate (when ready).
	Certificate string `json:"certificate,omitempty"`

	// URL is the order's URL.
	URL string `json:"url,omitempty"`

	// AccountID is the ID of the account that created the order.
	AccountID uint64 `json:"accountId,omitempty"`
}

// CreateRequest contains the parameters for creating a new ACME order.
type CreateRequest struct {
	// Identifiers is the list of identifiers for the certificate.
	Identifiers []Identifier `json:"identifiers"`

	// NotBefore is the requested notBefore date for the certificate (optional).
	NotBefore string `json:"notBefore,omitempty"`

	// NotAfter is the requested notAfter date for the certificate (optional).
	NotAfter string `json:"notAfter,omitempty"`
}

// CreateResponse contains the response from creating an ACME order.
type CreateResponse struct {
	// Order is the created order.
	Order *Order `json:"order"`

	// Location is the URL of the order resource.
	Location string `json:"location"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// GetRequest contains the parameters for retrieving an ACME order.
type GetRequest struct {
	// OrderURL is the URL of the order to retrieve.
	OrderURL string `json:"orderUrl"`
}

// GetResponse contains the response from retrieving an ACME order.
type GetResponse struct {
	// Order is the retrieved order.
	Order *Order `json:"order"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// ListRequest contains the parameters for listing account orders.
type ListRequest struct {
	// AccountURL is the URL of the account.
	AccountURL string `json:"accountUrl"`

	// Cursor is the pagination cursor for the next page.
	Cursor string `json:"cursor,omitempty"`
}

// ListResponse contains the response from listing account orders.
type ListResponse struct {
	// Orders is the list of order URLs.
	Orders []string `json:"orders"`

	// NextCursor is the pagination cursor for the next page.
	NextCursor string `json:"nextCursor,omitempty"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// FinalizeRequest contains the parameters for finalizing an ACME order.
type FinalizeRequest struct {
	// FinalizeURL is the URL to finalize the order.
	FinalizeURL string `json:"finalizeUrl"`

	// CSR is the Certificate Signing Request in DER format, base64url-encoded.
	CSR string `json:"csr"`
}

// FinalizeResponse contains the response from finalizing an ACME order.
type FinalizeResponse struct {
	// Order is the finalized order.
	Order *Order `json:"order"`

	// Location is the URL of the order resource.
	Location string `json:"location"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}
