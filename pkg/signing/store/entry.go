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

package store

import (
	"github.com/cespare/xxhash/v2"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// SignerEntry represents a persisted crypto.Signer as a DAO entity.
// The private key is stored in PEM-encoded PKCS8 format.
type SignerEntry struct {
	// ID is the unique entity identifier for DAO persistence.
	ID uint64 `json:"id"`

	// CN is the Common Name used as the primary lookup key.
	CN string `json:"cn"`

	// KeyPEM holds the PEM-encoded private key (PKCS8 format).
	KeyPEM []byte `json:"key_pem"`

	// Algorithm is the key algorithm type (e.g., "RSA", "ECDSA", "Ed25519").
	Algorithm string `json:"algorithm"`
}

// EntityID returns the unique identifier for this entity.
func (e *SignerEntry) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *SignerEntry) SetEntityID(id uint64) { e.ID = id }

// SignatureEntry represents a persisted signature for auditing/verification.
type SignatureEntry struct {
	// ID is the unique entity identifier for DAO persistence.
	ID uint64 `json:"id"`

	// Key is the storage key for this signature (CN + optional blob CN).
	Key string `json:"key"`

	// Data holds the formatted signature and digest data.
	Data string `json:"data"`
}

// EntityID returns the unique identifier for this entity.
func (e *SignatureEntry) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *SignatureEntry) SetEntityID(id uint64) { e.ID = id }

// signerEntryIDGenerator generates deterministic IDs by hashing the CN
// of a SignerEntry using xxhash64.
type signerEntryIDGenerator struct{}

// Compile-time interface compliance check.
var _ qrdbsdk.IDGenerator = (*signerEntryIDGenerator)(nil)

// NextID computes the xxhash64 of the entity's CN field.
// Supports both SignerEntry and SignatureEntry.
func (g *signerEntryIDGenerator) NextID(entity qrdbsdk.Entity) uint64 {
	var key string
	switch e := entity.(type) {
	case *SignerEntry:
		key = e.CN
	case *SignatureEntry:
		key = e.Key
	default:
		return 0
	}

	return xxhash.Sum64String(key)
}
