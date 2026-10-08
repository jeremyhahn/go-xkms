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

package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// credentialEntityType is the go-qrdb entity type WebAuthn credentials are
// stored under, in the datastore's default database.
const credentialEntityType = "webauthn_credentials"

// credentialEntity is the go-qrdb entity a WebAuthn credential persists as.
// Its ID is derived from CredentialID, so a credential ID names exactly one
// record; UserID is indexed so a user's credentials are found without a
// scan on stores that maintain indexes.
type credentialEntity struct {
	ID           uint64      `json:"id"`
	CredentialID string      `json:"credential_id"`
	UserID       string      `json:"user_id" index:"true"`
	Credential   *Credential `json:"credential"`
}

// EntityID returns the entity's ID.
func (e *credentialEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *credentialEntity) SetEntityID(id uint64) { e.ID = id }

// daoCredentialStore is the CredentialStore over a go-qrdb DAO.
type daoCredentialStore struct {
	creds qrdbsdk.GenericDAO[*credentialEntity]
}

// Compile-time assertion that daoCredentialStore satisfies CredentialStore.
var _ CredentialStore = (*daoCredentialStore)(nil)

// newCredentialStore builds the credential store on a DAO from factory.
// The entity ID is a SHA-256 hash of the credential ID, so creating a
// credential is a create-if-absent on that ID and a credential ID can be
// claimed by exactly one account (go-xkms#1295).
func newCredentialStore(factory *qrdbsdk.DAOFactory) (*daoCredentialStore, error) {
	creds, err := dao.New(factory, "", credentialEntityType,
		func() *credentialEntity { return &credentialEntity{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("CredentialID")))
	if err != nil {
		return nil, err
	}
	return &daoCredentialStore{creds: creds}, nil
}

// Save stores a NEW credential. A credential ID that is already registered
// — to this account or any other — is refused with
// ErrCredentialAlreadyExists and the stored record is left untouched.
func (s *daoCredentialStore) Save(ctx context.Context, cred *Credential) error {
	if cred == nil || len(cred.ID) == 0 {
		return ErrInvalidCredential
	}
	stored, err := s.creds.SaveIfAbsent(ctx, newCredentialEntity(cred))
	if err != nil {
		return WrapError("persist credential", err)
	}
	if !stored {
		return ErrCredentialAlreadyExists
	}
	return nil
}

// GetByUserID returns all credentials for a user, or an empty slice when the
// user has none.
func (s *daoCredentialStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	entities, err := s.creds.Find(ctx).Where("UserID = ?", encodeID(userID)).Execute()
	if err != nil {
		return nil, WrapError("list user credentials", err)
	}
	creds := make([]*Credential, 0, len(entities))
	for _, e := range entities {
		creds = append(creds, e.Credential)
	}
	return creds, nil
}

// GetByCredentialID retrieves a credential by its ID.
func (s *daoCredentialStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	e, err := s.get(ctx, credID)
	if err != nil {
		return nil, err
	}
	return e.Credential, nil
}

// Update overwrites an existing credential record: the sign counter, clone
// flag and last-used time a login refreshes. The credential must exist and
// belong to the user the update names (ErrCredentialNotFound,
// ErrCredentialOwnerMismatch). The write is a CompareAndSwap against the
// record that was checked, so a credential deleted or replaced concurrently
// is never resurrected or reassigned by a stale update
// (ErrCredentialUpdateConflict).
func (s *daoCredentialStore) Update(ctx context.Context, cred *Credential) error {
	if cred == nil || len(cred.ID) == 0 {
		return ErrInvalidCredential
	}
	existing, err := s.get(ctx, cred.ID)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing.Credential.UserID, cred.UserID) {
		return ErrCredentialOwnerMismatch
	}
	next := newCredentialEntity(cred)
	next.SetEntityID(existing.EntityID())
	swapped, err := s.creds.CompareAndSwap(ctx, existing, next)
	if err != nil {
		return WrapError("update credential", err)
	}
	if !swapped {
		return ErrCredentialUpdateConflict
	}
	return nil
}

// Delete removes a credential by its ID.
func (s *daoCredentialStore) Delete(ctx context.Context, credID []byte) error {
	e, err := s.get(ctx, credID)
	if err != nil {
		return err
	}
	if err := s.creds.Delete(ctx, e); err != nil {
		return WrapError("delete credential", err)
	}
	return nil
}

// DeleteByUserID removes all credentials for a user.
func (s *daoCredentialStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	entities, err := s.creds.Find(ctx).Where("UserID = ?", encodeID(userID)).Execute()
	if err != nil {
		return WrapError("list user credentials", err)
	}
	for _, e := range entities {
		if err := s.creds.Delete(ctx, e); err != nil {
			return WrapError("delete credential", err)
		}
	}
	return nil
}

// get loads the entity for credID, verified against its natural key.
func (s *daoCredentialStore) get(ctx context.Context, credID []byte) (*credentialEntity, error) {
	if len(credID) == 0 {
		return nil, ErrCredentialNotFound
	}
	e, err := s.creds.GetByNaturalKey(ctx, encodeID(credID))
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrCredentialNotFound
		}
		return nil, WrapError("read credential", err)
	}
	return e, nil
}

// encodeID renders an arbitrary-byte credential or user ID in the lossless
// base64url form the entity stores and queries it by.
func encodeID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// newCredentialEntity projects cred into its entity, with the credential
// and user IDs in encodeID's form.
func newCredentialEntity(cred *Credential) *credentialEntity {
	return &credentialEntity{
		CredentialID: encodeID(cred.ID),
		UserID:       encodeID(cred.UserID),
		Credential:   cred,
	}
}
