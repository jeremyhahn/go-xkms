// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package aeadnonce

// Claim is the DAO entity of one claimed (key, nonce) entry. Entry, the hex
// of the bytes pkg/crypto/aead.KeyNonceGuard derives, is its natural key: the
// entity ID is derived from it, so a second claim on one entry finds the
// first one's entity already there.
type Claim struct {
	ID    uint64 `json:"id"`
	Entry string `json:"entry"`
}

// EntityID returns the entity's unique identifier.
func (c *Claim) EntityID() uint64 { return c.ID }

// SetEntityID sets the entity's unique identifier.
func (c *Claim) SetEntityID(id uint64) { c.ID = id }

func newClaim() *Claim { return &Claim{} }
