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

package oidc

import "strings"

// TokenStore defines the interface for persistent token storage.
//
// DAOStore (dao_store.go) is the one implementation: tokens are go-qrdb
// entities on the DAO factory the composition root injects. There is no
// file-backed store. A key compiled into the binary gives a file on disk no
// real confidentiality, so tokens are encrypted at rest only by the store
// behind the factory -- the go-qrdb barrier -- and a host without one hands
// in a factory over a memory store, so its tokens never touch disk.
type TokenStore interface {
	// Save stores tokens for the given issuer.
	Save(issuer string, tokens *TokenResponse) error

	// Load retrieves tokens for the given issuer.
	Load(issuer string) (*TokenResponse, error)

	// Delete removes tokens for the given issuer.
	Delete(issuer string) error

	// List returns all issuers with stored tokens.
	List() ([]string, error)

	// Close closes the store and releases resources.
	Close() error
}

// normalizeIssuer normalizes an issuer URL for consistent storage.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(strings.ToLower(issuer), "/")
}
