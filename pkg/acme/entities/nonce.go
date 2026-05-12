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

package entities

// ACMENonce represents a replay-prevention nonce as defined in RFC 8555.
// Nonces are used to prevent replay attacks by ensuring each request is unique.
type ACMENonce struct {
	ID        uint64 `json:"id" yaml:"id"`
	Value     []byte `json:"value" yaml:"value"`
	ExpiresAt int64  `json:"expires" yaml:"expires"`
}

// SetEntityID sets the unique identifier for the nonce.
func (nonce *ACMENonce) SetEntityID(id uint64) {
	nonce.ID = id
}

// EntityID returns the unique identifier for the nonce.
func (nonce *ACMENonce) EntityID() uint64 {
	return nonce.ID
}
