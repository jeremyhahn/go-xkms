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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

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
	// ClaimToken binds a first credential to the claim it was saved under.
	// Such a credential is readable only while the user's claim is
	// committed with this token, so a stale claimer's save stays invisible
	// even if it crashes before its cleanup.
	ClaimToken string `json:"claim_token,omitempty"`
}

// EntityID returns the entity's ID.
func (e *credentialEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *credentialEntity) SetEntityID(id uint64) { e.ID = id }

// firstCredentialClaimEntityType is the go-qrdb entity type an account's
// first-credential claim is stored under (see ClaimFirstCredential).
const firstCredentialClaimEntityType = "webauthn_first_credential_claims"

// firstCredentialClaimLease is how long a pending first-credential claim
// belongs to the ceremony that took it. It is far longer than any finish
// request lives, so a live ceremony commits or releases well inside it; a
// pending claim past it is an orphan of a crashed ceremony and may be
// recovered. A ceremony that does outlive it is still fenced: its Commit
// loses the compare-and-swap to the recoverer and is refused.
const firstCredentialClaimLease = 10 * time.Minute

// firstCredentialClaimEntity marks that an account's first credential was
// claimed. Its ID is derived from UserID, so an account has at most one
// claim and creating it is a create-if-absent on that ID.
//
// A claim is written Pending with the claimer's random Token and a lease
// expiry (ExpiresAt, Unix nanoseconds), and becomes committed (Pending
// false) once the credential is saved. Every transition is a
// compare-and-swap or compare-and-delete against the exact record a caller
// holds, so the Token makes each claimer's record distinct.
type firstCredentialClaimEntity struct {
	ID        uint64 `json:"id"`
	UserID    string `json:"user_id"`
	Pending   bool   `json:"pending,omitempty"`
	Token     string `json:"token,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// EntityID returns the entity's ID.
func (e *firstCredentialClaimEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *firstCredentialClaimEntity) SetEntityID(id uint64) { e.ID = id }

// daoCredentialStore is the CredentialStore over a go-qrdb DAO.
type daoCredentialStore struct {
	creds  qrdbsdk.GenericDAO[*credentialEntity]
	claims qrdbsdk.GenericDAO[*firstCredentialClaimEntity]
	// now is the clock claim leases are taken and judged by.
	now func() time.Time
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
	claims, err := dao.New(factory, "", firstCredentialClaimEntityType,
		func() *firstCredentialClaimEntity { return &firstCredentialClaimEntity{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("UserID")))
	if err != nil {
		return nil, err
	}
	return &daoCredentialStore{creds: creds, claims: claims, now: time.Now}, nil
}

// ClaimFirstCredential creates the account's first-credential claim, pending
// under a lease, with SaveIfAbsent, so across sessions and replicas exactly
// one caller creates it and every other gets ErrFirstCredentialClaimed.
//
// A claim that already exists is recovered only when it is an orphan: still
// pending, past its lease, and the account has no credential (the claimer
// crashed before its save). Recovery is a CompareAndSwap from the exact
// record read, so of two recoverers one wins, and the crashed or slow
// claimer's own Commit and Release, which compare against its record, can
// no longer touch the recovered claim.
func (s *daoCredentialStore) ClaimFirstCredential(ctx context.Context, userID []byte) (FirstCredentialClaim, error) {
	// Claims live beside the credentials, in their tenant-unbound scope.
	ctx = credentialScope(ctx)
	if len(userID) == 0 {
		return nil, ErrInvalidCredential
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, WrapError("claim first credential", err)
	}
	claim := &firstCredentialClaimEntity{
		UserID:    encodeID(userID),
		Pending:   true,
		Token:     base64.RawURLEncoding.EncodeToString(token),
		ExpiresAt: s.now().Add(firstCredentialClaimLease).UnixNano(),
	}
	stored, err := s.claims.SaveIfAbsent(ctx, claim)
	if err != nil {
		return nil, WrapError("claim first credential", err)
	}
	if stored {
		return &daoFirstCredentialClaim{store: s, claim: claim}, nil
	}

	held, err := s.claims.GetByNaturalKey(ctx, claim.UserID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			// Released between the create and the read: refuse; a retry
			// claims afresh.
			return nil, ErrFirstCredentialClaimed
		}
		return nil, WrapError("read first-credential claim", err)
	}
	if !held.Pending || s.now().UnixNano() < held.ExpiresAt {
		return nil, ErrFirstCredentialClaimed
	}
	saved, err := s.creds.Find(ctx).Where("UserID = ?", claim.UserID).Execute()
	if err != nil {
		return nil, WrapError("claim first credential", err)
	}
	for _, e := range saved {
		switch e.ClaimToken {
		case "":
			// A credential saved outside any claim: the account has one.
			return nil, ErrFirstCredentialClaimed
		case held.Token:
			// The crashed claimer saved its credential but never committed:
			// roll its claim forward so the account keeps that credential.
			committed := &firstCredentialClaimEntity{ID: held.ID, UserID: held.UserID, Token: held.Token}
			if _, err := s.claims.CompareAndSwap(ctx, held, committed); err != nil && !qrdbsdk.IsDAONotFound(err) {
				return nil, WrapError("commit first-credential claim", err)
			}
			return nil, ErrFirstCredentialClaimed
		}
		// Saved under an older claim that lost: never readable, ignored.
	}
	claim.ID = held.ID
	swapped, err := s.claims.CompareAndSwap(ctx, held, claim)
	if err != nil && !qrdbsdk.IsDAONotFound(err) {
		return nil, WrapError("recover first-credential claim", err)
	}
	if !swapped {
		return nil, ErrFirstCredentialClaimed
	}
	return &daoFirstCredentialClaim{store: s, claim: claim}, nil
}

// daoFirstCredentialClaim is a pending claim this store won.
type daoFirstCredentialClaim struct {
	store *daoCredentialStore
	claim *firstCredentialClaimEntity
}

// Commit swaps this pending claim for the committed one. The swap compares
// against this claimer's own record (its Token), so it fails when another
// ceremony recovered the claim: then the credential this claimer saved is
// removed and ErrFirstCredentialClaimed returned.
func (c *daoFirstCredentialClaim) Commit(ctx context.Context, cred *Credential) error {
	ctx = credentialScope(ctx)
	// The committed claim keeps the token: it is what makes the credential
	// saved under this claim readable.
	committed := &firstCredentialClaimEntity{ID: c.claim.ID, UserID: c.claim.UserID, Token: c.claim.Token}
	swapped, err := c.store.claims.CompareAndSwap(ctx, c.claim, committed)
	if err != nil && !qrdbsdk.IsDAONotFound(err) {
		return WrapError("commit first-credential claim", err)
	}
	if swapped {
		return nil
	}
	// A lost swap may mean a recoverer rolled this very claim forward after
	// its lease ran out: the committed claim carries this token, so the
	// credential saved under it is already the account's first. Keep it.
	held, err := c.store.claims.GetByNaturalKey(ctx, c.claim.UserID)
	if err != nil && !qrdbsdk.IsDAONotFound(err) {
		return WrapError("read first-credential claim", err)
	}
	if err == nil && !held.Pending && held.Token == c.claim.Token {
		return nil
	}
	if err := c.store.removeFencedCredential(ctx, cred, c.claim.Token); err != nil {
		return err
	}
	return ErrFirstCredentialClaimed
}

// Save persists cred, the account's first credential, bound to this claim:
// it stays unreadable until Commit makes this claim the committed one.
func (c *daoFirstCredentialClaim) Save(ctx context.Context, cred *Credential) error {
	return c.store.save(ctx, cred, c.claim.Token)
}

// Release deletes this pending claim only if it is still this claimer's:
// a claim another ceremony recovered is left in place.
func (c *daoFirstCredentialClaim) Release(ctx context.Context) error {
	ctx = credentialScope(ctx)
	if _, err := c.store.claims.DeleteIfMatch(ctx, c.claim); err != nil && !qrdbsdk.IsDAONotFound(err) {
		return WrapError("drop first-credential claim", err)
	}
	return nil
}

// removeFencedCredential deletes the credential a claimer fenced out of its
// claim saved. It deletes only that record, compared as read, and never
// drops the account's claim, which now belongs to the recoverer.
func (s *daoCredentialStore) removeFencedCredential(ctx context.Context, cred *Credential, token string) error {
	ctx = credentialScope(ctx)
	if cred == nil {
		return nil
	}
	e, err := s.getRaw(ctx, cred.ID)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil
		}
		return err
	}
	if e.UserID != encodeID(cred.UserID) || e.ClaimToken != token {
		return nil
	}
	if _, err := s.creds.DeleteIfMatch(ctx, e); err != nil && !qrdbsdk.IsDAONotFound(err) {
		return WrapError("remove fenced first credential", err)
	}
	return nil
}

// dropClaim deletes the first-credential claim of the account whose
// encodeID-form ID is userID, if there is one.
func (s *daoCredentialStore) dropClaim(ctx context.Context, userID string) error {
	ctx = credentialScope(ctx)
	claim, err := s.claims.GetByNaturalKey(ctx, userID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil
		}
		return WrapError("read first-credential claim", err)
	}
	// Only the claim generation read above: a cleanup that raced another one
	// must not delete the replacement claim an enrolment committed since.
	if _, err := s.claims.DeleteIfMatch(ctx, claim); err != nil && !qrdbsdk.IsDAONotFound(err) {
		return WrapError("drop first-credential claim", err)
	}
	return nil
}

// Save stores a NEW credential. A credential ID that is already registered
// — to this account or any other — is refused with
// ErrCredentialAlreadyExists and the stored record is left untouched.
//
// A ctx that carries a first-credential claim (WithFirstCredentialClaim)
// stores cred through that claim instead, bound to its token, so a decorator
// over this store sees the claimed save in its own Save.
func (s *daoCredentialStore) Save(ctx context.Context, cred *Credential) error {
	if claim := FirstCredentialClaimFrom(ctx); claim != nil {
		return claim.Save(WithFirstCredentialClaim(ctx, nil), cred)
	}
	return s.save(ctx, cred, "")
}

// save persists cred, bound to the first-credential claim token when token
// is not empty.
func (s *daoCredentialStore) save(ctx context.Context, cred *Credential, token string) error {
	ctx = credentialScope(ctx)
	if cred == nil || len(cred.ID) == 0 {
		return ErrInvalidCredential
	}
	e := newCredentialEntity(cred)
	e.ClaimToken = token
	stored, err := s.creds.SaveIfAbsent(ctx, e)
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
	ctx = credentialScope(ctx)
	userKey := encodeID(userID)
	entities, err := s.creds.Find(ctx).Where("UserID = ?", userKey).Execute()
	if err != nil {
		return nil, WrapError("list user credentials", err)
	}
	readable, err := s.visible(ctx, userKey, entities)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, 0, len(readable))
	for _, e := range readable {
		creds = append(creds, e.Credential)
	}
	return creds, nil
}

// GetByCredentialID retrieves a credential by its ID.
func (s *daoCredentialStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	ctx = credentialScope(ctx)
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
	ctx = credentialScope(ctx)
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
	next.ClaimToken = existing.ClaimToken
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
	ctx = credentialScope(ctx)
	e, err := s.get(ctx, credID)
	if err != nil {
		return err
	}
	if err := s.creds.Delete(ctx, e); err != nil {
		return WrapError("delete credential", err)
	}
	// An account left with no credential may enrol a first one again.
	remaining, err := s.creds.Find(ctx).Where("UserID = ?", e.UserID).Execute()
	if err != nil {
		return WrapError("list user credentials", err)
	}
	readable, err := s.visible(ctx, e.UserID, remaining)
	if err != nil {
		return err
	}
	if len(readable) == 0 {
		return s.dropClaim(ctx, e.UserID)
	}
	return nil
}

// DeleteByUserID removes all credentials for a user.
func (s *daoCredentialStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	ctx = credentialScope(ctx)
	entities, err := s.creds.Find(ctx).Where("UserID = ?", encodeID(userID)).Execute()
	if err != nil {
		return WrapError("list user credentials", err)
	}
	for _, e := range entities {
		if err := s.creds.Delete(ctx, e); err != nil {
			return WrapError("delete credential", err)
		}
	}
	return s.dropClaim(ctx, encodeID(userID))
}

// get loads the entity for credID, verified against its natural key.
func (s *daoCredentialStore) get(ctx context.Context, credID []byte) (*credentialEntity, error) {
	e, err := s.getRaw(ctx, credID)
	if err != nil {
		return nil, err
	}
	visible, err := s.visible(ctx, e.UserID, []*credentialEntity{e})
	if err != nil {
		return nil, err
	}
	if len(visible) == 0 {
		return nil, ErrCredentialNotFound
	}
	return e, nil
}

// getRaw reads a credential entity whether or not it is readable.
func (s *daoCredentialStore) getRaw(ctx context.Context, credID []byte) (*credentialEntity, error) {
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

// visible keeps the readable entities of one user: those saved outside a
// first-credential claim, and the one saved under the user's committed
// claim. A credential a stale claimer saved under a claim that was
// recovered from it is never readable.
func (s *daoCredentialStore) visible(ctx context.Context, userID string, entities []*credentialEntity) ([]*credentialEntity, error) {
	out := make([]*credentialEntity, 0, len(entities))
	var committed *string
	for _, e := range entities {
		if e.ClaimToken == "" {
			out = append(out, e)
			continue
		}
		if committed == nil {
			token, err := s.committedClaimToken(ctx, userID)
			if err != nil {
				return nil, err
			}
			committed = &token
		}
		if *committed != "" && e.ClaimToken == *committed {
			out = append(out, e)
		}
	}
	return out, nil
}

// committedClaimToken returns the token of the user's committed
// first-credential claim, or "" when the claim is absent or pending.
func (s *daoCredentialStore) committedClaimToken(ctx context.Context, userID string) (string, error) {
	ctx = credentialScope(ctx)
	claim, err := s.claims.GetByNaturalKey(ctx, userID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return "", nil
		}
		return "", WrapError("read first-credential claim", err)
	}
	if claim.Pending {
		return "", nil
	}
	return claim.Token, nil
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
