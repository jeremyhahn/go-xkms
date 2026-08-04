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

// Package nonce provides the ACME nonce client operations.
package nonce

// NewRequest contains the parameters for requesting a new nonce.
// This is typically empty as nonces are obtained via HEAD request.
type NewRequest struct{}

// NewResponse contains the response from retrieving a nonce.
type NewResponse struct {
	// Nonce is the replay-prevention nonce value.
	Nonce string `json:"nonce"`
}
