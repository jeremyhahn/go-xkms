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

// Package aeadnonce is the durable backing for the process-wide AEAD
// (key, nonce) guard, pkg/crypto/aead.KeyNonceGuard, so a claim it makes on
// behalf of the Encrypt RPC or the AES-GCM key wrap survives a process
// restart and is visible to every xkmsd node sharing the datastore
// (go-xkms#1201).
//
// Each claim is one go-qrdb DAO entity (Claim) in the DatabaseName database,
// created with the DAO's SaveIfAbsent: the one write with a defined outcome
// under concurrency, so an entry is claimed once across every process and
// node, never twice. xkmsd builds ONE store for the whole process
// (pkg/server's initializeAEADNonceStore) and attaches it to pkg/crypto/aead's
// shared guard; nothing about the claim is scoped to a tenant or a backend
// name, because the guard's identity already is -- the key's own material
// where a backend releases it, so two names for one key collide on one claim
// regardless of which tenant or backend reached it through.
package aeadnonce

import (
	"context"
	"encoding/hex"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// Compile-time interface compliance check.
var _ aead.PersistentNonceStore = (*Store)(nil)

const (
	// DatabaseName is the go-qrdb database claims live in. A composition
	// root opens it on the datastore before calling NewStore.
	DatabaseName = "aeadnonce"

	// entityType is the DAO entity type of a claim.
	entityType = "aead_nonce_claims"
)

// Store persists AEAD (key, nonce) claims through a go-qrdb DAO,
// implementing pkg/crypto/aead.PersistentNonceStore.
type Store struct {
	claims qrdbsdk.GenericDAO[*Claim]
}

// NewStore returns a Store whose DAO daos builds over DatabaseName.
func NewStore(daos *qrdbsdk.DAOFactory) (*Store, error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	claims, err := newClaimDAO(daos)
	if err != nil {
		return nil, &StoreError{Op: "open", Err: err}
	}
	return &Store{claims: claims}, nil
}

// newClaimDAO builds the claim DAO: entity IDs derive from Entry.
func newClaimDAO(daos *qrdbsdk.DAOFactory) (qrdbsdk.GenericDAO[*Claim], error) {
	return dao.New(daos, DatabaseName, entityType, newClaim,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Entry")))
}

// ClaimNonce atomically records entry -- the HMAC(key material) || nonce
// bytes pkg/crypto/aead.KeyNonceGuard derives -- as consumed, reporting
// claimed=false when it was already recorded by this or any other process
// sharing the datastore. The claim is the DAO's SaveIfAbsent, so this method
// performs no read-then-write of its own that could reintroduce the race the
// guard exists to close. A failure is a *StoreError, never claimed=false.
func (s *Store) ClaimNonce(ctx context.Context, entry []byte) (claimed bool, err error) {
	claimed, err = s.claims.SaveIfAbsent(ctx, &Claim{Entry: hex.EncodeToString(entry)})
	if err != nil {
		return false, &StoreError{Op: "claim", Err: err}
	}
	return claimed, nil
}
