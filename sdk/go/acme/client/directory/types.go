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

// Package directory provides the ACME directory client operations.
package directory

// Meta contains metadata about the ACME server.
type Meta struct {
	// TermsOfService is the URL for the current terms of service.
	TermsOfService string `json:"termsOfService,omitempty"`

	// Website is the URL for the CA's website.
	Website string `json:"website,omitempty"`

	// CAAIdentities is a list of hostnames that the CA recognizes for CAA records.
	CAAIdentities []string `json:"caaIdentities,omitempty"`

	// ExternalAccountRequired indicates if external account binding is required.
	ExternalAccountRequired bool `json:"externalAccountRequired,omitempty"`
}

// Directory represents the ACME directory resource as defined in RFC 8555.
type Directory struct {
	// NewNonce is the URL to retrieve a new nonce.
	NewNonce string `json:"newNonce"`

	// NewAccount is the URL to create a new account.
	NewAccount string `json:"newAccount"`

	// NewOrder is the URL to create a new order.
	NewOrder string `json:"newOrder"`

	// NewAuthz is the URL to create a new authorization (pre-authorization).
	NewAuthz string `json:"newAuthz,omitempty"`

	// RevokeCert is the URL to revoke a certificate.
	RevokeCert string `json:"revokeCert"`

	// KeyChange is the URL to change account key.
	KeyChange string `json:"keyChange"`

	// Meta contains additional server metadata.
	Meta *Meta `json:"meta,omitempty"`
}

// GetRequest contains the parameters for retrieving the directory.
type GetRequest struct {
	// URL is the directory URL (optional, uses default if not specified).
	URL string `json:"url,omitempty"`
}

// GetResponse contains the response from retrieving the directory.
type GetResponse struct {
	// Directory is the ACME directory resource.
	Directory *Directory `json:"directory"`

	// Nonce is a new nonce from the response headers (if available).
	Nonce string `json:"nonce,omitempty"`
}
