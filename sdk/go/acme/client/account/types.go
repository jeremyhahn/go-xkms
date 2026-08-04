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

// Package account provides the ACME account client operations.
package account

import "time"

// Status represents the status of an ACME account.
type Status string

const (
	// StatusValid indicates the account is active and in good standing.
	StatusValid Status = "valid"

	// StatusDeactivated indicates the account has been deactivated.
	StatusDeactivated Status = "deactivated"

	// StatusRevoked indicates the account has been revoked by the server.
	StatusRevoked Status = "revoked"
)

// Account represents an ACME account as defined in RFC 8555.
type Account struct {
	// ID is the unique identifier for the account.
	ID uint64 `json:"id,omitempty"`

	// Status is the current status of the account.
	Status Status `json:"status"`

	// Contact contains contact URLs for the account holder (e.g., mailto:).
	Contact []string `json:"contact,omitempty"`

	// TermsOfServiceAgreed indicates whether the account holder has agreed to the ToS.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`

	// ExternalAccountBinding contains the external account binding if required.
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`

	// Orders is the URL to retrieve the account's orders.
	Orders string `json:"orders,omitempty"`

	// URL is the account's URL.
	URL string `json:"url,omitempty"`

	// Key is the JWK public key associated with the account.
	Key interface{} `json:"key,omitempty"`

	// CreatedAt is the timestamp when the account was created.
	CreatedAt time.Time `json:"created,omitempty"`

	// TenantID is the tenant this account belongs to in multi-tenant deployments.
	TenantID string `json:"tenantId,omitempty"`
}

// CreateRequest contains the parameters for creating a new ACME account.
type CreateRequest struct {
	// Contact contains contact URLs for the account holder.
	Contact []string `json:"contact,omitempty"`

	// TermsOfServiceAgreed must be true to create the account.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed"`

	// OnlyReturnExisting if true, only returns an existing account.
	OnlyReturnExisting bool `json:"onlyReturnExisting,omitempty"`

	// ExternalAccountBinding contains the external account binding if required.
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
}

// CreateResponse contains the response from creating an ACME account.
type CreateResponse struct {
	// Account is the created or existing account.
	Account *Account `json:"account"`

	// Location is the URL of the account resource.
	Location string `json:"location"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// GetRequest contains the parameters for retrieving an ACME account.
type GetRequest struct {
	// AccountURL is the URL of the account to retrieve.
	AccountURL string `json:"accountUrl"`
}

// GetResponse contains the response from retrieving an ACME account.
type GetResponse struct {
	// Account is the retrieved account.
	Account *Account `json:"account"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// UpdateRequest contains the parameters for updating an ACME account.
type UpdateRequest struct {
	// AccountURL is the URL of the account to update.
	AccountURL string `json:"accountUrl"`

	// Contact contains the new contact URLs for the account holder.
	Contact []string `json:"contact,omitempty"`

	// TermsOfServiceAgreed indicates agreement to new terms.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`
}

// UpdateResponse contains the response from updating an ACME account.
type UpdateResponse struct {
	// Account is the updated account.
	Account *Account `json:"account"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// DeactivateRequest contains the parameters for deactivating an ACME account.
type DeactivateRequest struct {
	// AccountURL is the URL of the account to deactivate.
	AccountURL string `json:"accountUrl"`
}

// DeactivateResponse contains the response from deactivating an ACME account.
type DeactivateResponse struct {
	// Account is the deactivated account.
	Account *Account `json:"account"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}

// KeyChangeRequest contains the parameters for changing an account's key.
type KeyChangeRequest struct {
	// AccountURL is the URL of the account.
	AccountURL string `json:"accountUrl"`

	// OldKey is the current account key (JWK).
	OldKey interface{} `json:"oldKey"`

	// NewKey is the new account key (JWK).
	NewKey interface{} `json:"newKey"`
}

// KeyChangeResponse contains the response from changing an account's key.
type KeyChangeResponse struct {
	// Account is the account with the updated key.
	Account *Account `json:"account"`

	// Nonce is the new nonce for the next request.
	Nonce string `json:"nonce,omitempty"`
}
