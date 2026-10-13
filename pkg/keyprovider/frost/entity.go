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

//go:build frost

package frost

import (
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// DatabaseName is the go-qrdb database every FROST entity lives in. A
// composition root opens it on its datastore before building a backend;
// this package only names it.
const DatabaseName = "frost"

// Entity types of the FROST DAOs.
const (
	keyEntityType         = "frost_keys"
	shareEntityType       = "frost_verification_shares"
	secretShareEntityType = "frost_secret_shares"
	nonceEntityType       = "frost_nonces"
)

// naturalKeyField is the field every FROST entity's ID is derived from.
const naturalKeyField = "Name"

// listPageSize is the page size of every FROST scan.
const listPageSize = 256

// FrostKey is the stored public half of one FROST key: its metadata and the
// group public key. Name is the key's storage key ID (StorageKeyID).
type FrostKey struct {
	ID             uint64      `json:"id"`
	Name           string      `json:"name"`
	Metadata       KeyMetadata `json:"metadata"`
	GroupPublicKey []byte      `json:"group_public_key"`
}

// EntityID returns the entity's ID.
func (e *FrostKey) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *FrostKey) SetEntityID(id uint64) { e.ID = id }

func newFrostKey() *FrostKey { return &FrostKey{} }

// FrostShare is one participant's public verification share of a FROST
// key. Name is shareName(KeyID, Index).
type FrostShare struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	KeyID string `json:"key_id"`
	Index uint32 `json:"index"`
	Share []byte `json:"share"`
}

// EntityID returns the entity's ID.
func (e *FrostShare) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *FrostShare) SetEntityID(id uint64) { e.ID = id }

func newFrostShare() *FrostShare { return &FrostShare{} }

// FrostSecretShare is this node's secret key share of a FROST key, held only
// as the envelope the secret backend sealed it into: the share itself is
// never stored, in this or any other field. Name is shareName(KeyID, Index),
// where Index is the participant the share belongs to.
type FrostSecretShare struct {
	ID     uint64           `json:"id"`
	Name   string           `json:"name"`
	KeyID  string           `json:"key_id"`
	Index  uint32           `json:"index"`
	Sealed types.SealedData `json:"sealed"`
}

// EntityID returns the entity's ID.
func (e *FrostSecretShare) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *FrostSecretShare) SetEntityID(id uint64) { e.ID = id }

func newFrostSecretShare() *FrostSecretShare { return &FrostSecretShare{} }

// FrostNonce records that the signing nonce behind one commitment has been
// used. Name is nonceName(KeyID, commitment), so a second claim of the same
// commitment finds the first one's entity already there. Commitments are
// public, so the record leaks nothing secret.
type FrostNonce struct {
	ID            uint64 `json:"id"`
	Name          string `json:"name"`
	KeyID         string `json:"key_id"`
	ParticipantID uint32 `json:"participant_id"`
	SessionID     string `json:"session_id"`
}

// EntityID returns the entity's ID.
func (e *FrostNonce) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *FrostNonce) SetEntityID(id uint64) { e.ID = id }

func newFrostNonce() *FrostNonce { return &FrostNonce{} }

// shareName is the natural key of participant index's share of keyID.
func shareName(keyID string, index uint32) string {
	return keyID + "/" + strconv.FormatUint(uint64(index), 10)
}

// newDAO builds the DAO of entityType in DatabaseName; entity IDs derive
// from the natural key, naturalKeyField.
func newDAO[E qrdbsdk.Entity](daos *qrdbsdk.DAOFactory, entityType string, newEntity func() E) (qrdbsdk.GenericDAO[E], error) {
	if daos == nil {
		return nil, ErrNilDAOFactory
	}
	d, err := dao.New(daos, DatabaseName, entityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator(naturalKeyField)))
	if err != nil {
		return nil, &StoreError{Op: "open", Key: entityType, Err: err}
	}
	return d, nil
}

// listQuery is the page query every FROST scan iterates with.
func listQuery() qrdbsdk.PageQuery {
	return qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize, SortOrder: qrdbsdk.DAOSortAscending}
}
