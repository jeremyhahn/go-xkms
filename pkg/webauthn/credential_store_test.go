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
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// Credentials are keyed to 8-byte qrdb user handles.
var (
	uniquenessOwner    = HandleFromUserID(1)
	uniquenessAttacker = HandleFromUserID(2)
)

// newTestCredentialStore builds the DAO credential store over factory.
func newTestCredentialStore(t *testing.T, factory *qrdbsdk.DAOFactory) *daoCredentialStore {
	t.Helper()
	cs, err := newCredentialStore(factory)
	require.NoError(t, err)
	return cs
}

// fullCredential returns a credential with every field set, so a round trip
// that drops or mangles any of them is caught. Times are UTC because a JSON
// round trip does not preserve the Local location.
func fullCredential(id string, userID []byte) *Credential {
	return &Credential{
		ID:              []byte(id),
		UserID:          userID,
		PublicKey:       []byte("cose-public-key"),
		AttestationType: "packed",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Flags:           CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: true},
		Authenticator: AuthenticatorData{
			AAGUID:     []byte("0123456789abcdef"),
			SignCount:  3,
			Attachment: protocol.CrossPlatform,
		},
		CreatedAt:  time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		LastUsedAt: time.Date(2026, 10, 2, 8, 30, 0, 0, time.UTC),
	}
}

// TestCredentialStore_RoundTrip proves a credential survives the DAO intact,
// and is found both by its ID and through its owner, from a second store over
// the same factory — the record is in the datastore, not in the store value.
func TestCredentialStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	cred := fullCredential("round-trip-id", uniquenessOwner)
	require.NoError(t, newTestCredentialStore(t, factory).Save(ctx, cred))

	reader := newTestCredentialStore(t, factory)
	byID, err := reader.GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred, byID)

	byUser, err := reader.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, byUser, 1)
	assert.Equal(t, cred, byUser[0])
}

// TestCredentialStore_GetByUserID_ScopesToOwner proves a user's lookup
// returns exactly that user's credentials, and none for a user without any.
func TestCredentialStore_GetByUserID_ScopesToOwner(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())
	// Binary IDs, including bytes that are not valid UTF-8, must survive.
	ownerIDs := [][]byte{{0x00, 0xff, 0x10}, {0xfe, 0x80}}
	for _, id := range ownerIDs {
		require.NoError(t, cs.Save(ctx, &Credential{ID: id, UserID: uniquenessOwner}))
	}
	require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("other"), UserID: uniquenessAttacker}))

	owned, err := cs.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	gotIDs := make([][]byte, 0, len(owned))
	for _, c := range owned {
		gotIDs = append(gotIDs, c.ID)
	}
	assert.ElementsMatch(t, ownerIDs, gotIDs)

	none, err := cs.GetByUserID(ctx, HandleFromUserID(99))
	require.NoError(t, err)
	assert.Empty(t, none)
}

// TestCredentialStore_NotFound proves every lookup of an absent credential
// answers with the typed ErrCredentialNotFound.
func TestCredentialStore_NotFound(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())

	_, err := cs.GetByCredentialID(ctx, []byte("absent-id"))
	require.ErrorIs(t, err, ErrCredentialNotFound)
	_, err = cs.GetByCredentialID(ctx, nil)
	require.ErrorIs(t, err, ErrCredentialNotFound)
	require.ErrorIs(t, cs.Delete(ctx, []byte("absent-id")), ErrCredentialNotFound)
}

// TestCredentialStore_SaveRejectsInvalid proves a nil credential or one
// without an ID is refused before anything is written.
func TestCredentialStore_SaveRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())

	require.ErrorIs(t, cs.Save(ctx, nil), ErrInvalidCredential)
	require.ErrorIs(t, cs.Save(ctx, &Credential{UserID: uniquenessOwner}), ErrInvalidCredential)
	require.ErrorIs(t, cs.Update(ctx, nil), ErrInvalidCredential)
	require.ErrorIs(t, cs.Update(ctx, &Credential{UserID: uniquenessOwner}), ErrInvalidCredential)
}

// TestCredentialStore_RefusesDuplicateIDUnderAnotherUser is go-xkms#1295: a
// credential ID registered to one account cannot be registered again under
// another, and the owner's record survives the attempt intact.
func TestCredentialStore_RefusesDuplicateIDUnderAnotherUser(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())

	owned := &Credential{ID: []byte("shared-id"), UserID: uniquenessOwner, PublicKey: []byte("owner-key")}
	require.NoError(t, cs.Save(ctx, owned))

	hijack := &Credential{ID: []byte("shared-id"), UserID: uniquenessAttacker, PublicKey: []byte("attacker-key")}
	require.ErrorIs(t, cs.Save(ctx, hijack), ErrCredentialAlreadyExists)

	stored, err := cs.GetByCredentialID(ctx, owned.ID)
	require.NoError(t, err)
	assert.Equal(t, uniquenessOwner, stored.UserID)
	assert.Equal(t, []byte("owner-key"), stored.PublicKey)

	attackerCreds, err := cs.GetByUserID(ctx, uniquenessAttacker)
	require.NoError(t, err)
	assert.Empty(t, attackerCreds, "the refused credential must not be found under the attacker")
}

// TestCredentialStore_UpdatePersistsSignCount proves the update a login
// makes — sign counter, clone flag, last use — reaches the datastore: a
// second store over the same factory reads the new values.
func TestCredentialStore_UpdatePersistsSignCount(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	cs := newTestCredentialStore(t, factory)
	cred := fullCredential("counter-id", uniquenessOwner)
	require.NoError(t, cs.Save(ctx, cred))

	updated := fullCredential("counter-id", uniquenessOwner)
	updated.Authenticator.SignCount = 7
	updated.Authenticator.CloneWarning = true
	updated.LastUsedAt = time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	require.NoError(t, cs.Update(ctx, updated))

	stored, err := newTestCredentialStore(t, factory).GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, uint32(7), stored.Authenticator.SignCount)
	assert.True(t, stored.Authenticator.CloneWarning)
	assert.Equal(t, updated.LastUsedAt, stored.LastUsedAt)

	byUser, err := cs.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, byUser, 1, "an update must not add a second record")
	assert.Equal(t, uint32(7), byUser[0].Authenticator.SignCount)
}

// TestCredentialStore_UpdateRefusesOtherOwner proves an update cannot move a
// credential to another account.
func TestCredentialStore_UpdateRefusesOtherOwner(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())
	require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("owned-id"), UserID: uniquenessOwner}))

	err := cs.Update(ctx, &Credential{ID: []byte("owned-id"), UserID: uniquenessAttacker})
	require.ErrorIs(t, err, ErrCredentialOwnerMismatch)

	stored, err := cs.GetByCredentialID(ctx, []byte("owned-id"))
	require.NoError(t, err)
	assert.Equal(t, uniquenessOwner, stored.UserID)
}

// TestCredentialStore_UpdateRequiresExistingCredential proves Update never
// creates.
func TestCredentialStore_UpdateRequiresExistingCredential(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())

	err := cs.Update(ctx, &Credential{ID: []byte("absent-id"), UserID: uniquenessOwner})
	require.ErrorIs(t, err, ErrCredentialNotFound)

	_, err = cs.GetByCredentialID(ctx, []byte("absent-id"))
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

// TestCredentialStore_DeleteByUserID proves a user's credentials go and
// another user's stay.
func TestCredentialStore_DeleteByUserID(t *testing.T) {
	ctx := context.Background()
	cs := newTestCredentialStore(t, newTestDAOFactory())
	require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("a"), UserID: uniquenessOwner}))
	require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("b"), UserID: uniquenessOwner}))
	require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("c"), UserID: uniquenessAttacker}))

	require.NoError(t, cs.DeleteByUserID(ctx, uniquenessOwner))

	owned, err := cs.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	assert.Empty(t, owned)
	_, err = cs.GetByCredentialID(ctx, []byte("c"))
	require.NoError(t, err, "another user's credential must survive")
}

// atomicKVStore is the conditional-write surface of go-qrdb's in-process
// store, named here so a test double can embed it and override one verb.
type atomicKVStore interface {
	qrdbsdk.KVStore
	PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error)
	CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
	CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
}

// swapLosingKV is an atomic store whose CompareAndSwap always loses the race,
// standing in for a record changed between the owner check and the write.
type swapLosingKV struct {
	atomicKVStore
}

func (k swapLosingKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	return false, nil
}

// TestCredentialStore_UpdateLosesRace proves a stale update is not applied
// when the record changed underneath it.
func TestCredentialStore_UpdateLosesRace(t *testing.T) {
	ctx := context.Background()
	kv := swapLosingKV{atomicKVStore: qrdbsdk.NewMemoryKVStore()}
	factory := qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv })
	cs := newTestCredentialStore(t, factory)

	cred := &Credential{ID: []byte("raced-id"), UserID: uniquenessOwner}
	require.NoError(t, cs.Save(ctx, cred))

	cred.Authenticator.SignCount = 9
	require.ErrorIs(t, cs.Update(ctx, cred), ErrCredentialUpdateConflict)

	stored, err := cs.GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Zero(t, stored.Authenticator.SignCount)
}

// plainKV exposes only the plain KVStore verbs of the in-process store:
// embedding the interface promotes nothing else.
type plainKV struct {
	qrdbsdk.KVStore
}

// TestCredentialStore_RequiresAtomicStore proves a store without atomic
// conditional writes is refused rather than degraded to a racy
// read-then-write, and nothing is written.
func TestCredentialStore_RequiresAtomicStore(t *testing.T) {
	ctx := context.Background()
	kv := plainKV{KVStore: qrdbsdk.NewMemoryKVStore()}
	factory := qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv })
	cs := newTestCredentialStore(t, factory)

	err := cs.Save(ctx, &Credential{ID: []byte("id"), UserID: uniquenessOwner})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrCredentialAlreadyExists)

	_, err = cs.GetByCredentialID(ctx, []byte("id"))
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

// TestNewCredentialStore_NilFactory proves the store cannot be built without
// the injected factory.
func TestNewCredentialStore_NilFactory(t *testing.T) {
	_, err := newCredentialStore(nil)
	require.ErrorIs(t, err, dao.ErrNilFactory)
}

// pastClaimLease returns a clock that reads after every first-credential
// claim lease taken now has expired.
func pastClaimLease() func() time.Time {
	return func() time.Time { return time.Now().Add(firstCredentialClaimLease + time.Minute) }
}

// TestCredentialStore_CrashedFirstCredentialClaimIsRecovered is the Codex
// round-4 P1 fault/restart regression (ruling 952): a ceremony claims the
// account's first credential and crashes before the credential save — it
// neither commits nor releases. A restarted store over the same datastore,
// after the claim's lease, can claim again and enrol the first credential;
// the orphan claim does not block the account for ever.
func TestCredentialStore_CrashedFirstCredentialClaimIsRecovered(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()

	_, err := newTestCredentialStore(t, factory).ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)
	// crash: the claim is never committed nor released.

	restarted := newTestCredentialStore(t, factory)
	_, err = restarted.ClaimFirstCredential(ctx, uniquenessOwner)
	require.ErrorIs(t, err, ErrFirstCredentialClaimed, "a claim inside its lease may belong to a live ceremony")

	restarted.now = pastClaimLease()
	claim, err := restarted.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err, "an expired, uncommitted claim must not block the account")
	cred := &Credential{ID: []byte("recovered-id"), UserID: uniquenessOwner}
	require.NoError(t, claim.Save(ctx, cred))
	require.NoError(t, claim.Commit(ctx, cred))

	owned, err := restarted.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, owned, 1)

	_, err = restarted.ClaimFirstCredential(ctx, uniquenessOwner)
	require.ErrorIs(t, err, ErrFirstCredentialClaimed, "a committed claim is never recovered")
}

// TestCredentialStore_RecoveredClaimFencesSlowClaimer proves the fence: a
// live claimer slower than its lease, whose claim another ceremony
// recovered, loses at commit, and the credential it saved is removed — the
// account ends with exactly the recoverer's first credential.
func TestCredentialStore_RecoveredClaimFencesSlowClaimer(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	slow := newTestCredentialStore(t, factory)
	slowClaim, err := slow.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)

	recoverer := newTestCredentialStore(t, factory)
	recoverer.now = pastClaimLease()
	claim, err := recoverer.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)
	won := &Credential{ID: []byte("recoverer-id"), UserID: uniquenessOwner}
	require.NoError(t, claim.Save(ctx, won))
	require.NoError(t, claim.Commit(ctx, won))

	late := &Credential{ID: []byte("slow-id"), UserID: uniquenessOwner}
	require.NoError(t, slowClaim.Save(ctx, late))
	require.ErrorIs(t, slowClaim.Commit(ctx, late), ErrFirstCredentialClaimed)

	owned, err := slow.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, owned, 1)
	assert.Equal(t, won.ID, owned[0].ID)
}

// TestCredentialStore_StaleClaimerCrashAfterSaveLeavesNoCredential: a slow
// claimer whose claim was recovered saves its credential and crashes before
// Commit, so its cleanup never runs. A restarted store must still expose
// only the recoverer's credential, whether the recoverer has committed or
// is still mid-ceremony (Codex round-5 P1, ruling 968).
func TestCredentialStore_StaleClaimerCrashAfterSaveLeavesNoCredential(t *testing.T) {
	ctx := context.Background()
	won := &Credential{ID: []byte("recoverer-id"), UserID: uniquenessOwner}
	late := &Credential{ID: []byte("slow-id"), UserID: uniquenessOwner}

	assertOnlyWinner := func(t *testing.T, s *daoCredentialStore) {
		t.Helper()
		owned, err := s.GetByUserID(ctx, uniquenessOwner)
		require.NoError(t, err)
		require.Len(t, owned, 1)
		assert.Equal(t, won.ID, owned[0].ID)
		_, err = s.GetByCredentialID(ctx, late.ID)
		require.ErrorIs(t, err, ErrCredentialNotFound)
		got, err := s.GetByCredentialID(ctx, won.ID)
		require.NoError(t, err)
		assert.Equal(t, won.ID, got.ID)
		_, err = s.ClaimFirstCredential(ctx, uniquenessOwner)
		require.ErrorIs(t, err, ErrFirstCredentialClaimed, "the account keeps its committed first credential")
	}

	t.Run("recoverer committed first", func(t *testing.T) {
		factory := newTestDAOFactory()
		slow := newTestCredentialStore(t, factory)
		slowClaim, err := slow.ClaimFirstCredential(ctx, uniquenessOwner)
		require.NoError(t, err)

		recoverer := newTestCredentialStore(t, factory)
		recoverer.now = pastClaimLease()
		claim, err := recoverer.ClaimFirstCredential(ctx, uniquenessOwner)
		require.NoError(t, err)
		require.NoError(t, claim.Save(ctx, won))
		require.NoError(t, claim.Commit(ctx, won))

		require.NoError(t, slowClaim.Save(ctx, late))
		// crash: the slow claimer never reaches Commit or its cleanup.

		restarted := newTestCredentialStore(t, factory)
		restarted.now = pastClaimLease()
		assertOnlyWinner(t, restarted)
		require.ErrorIs(t, restarted.Update(ctx, late), ErrCredentialNotFound)
	})

	t.Run("recoverer still pending", func(t *testing.T) {
		factory := newTestDAOFactory()
		slow := newTestCredentialStore(t, factory)
		slowClaim, err := slow.ClaimFirstCredential(ctx, uniquenessOwner)
		require.NoError(t, err)

		recoverer := newTestCredentialStore(t, factory)
		recoverer.now = pastClaimLease()
		claim, err := recoverer.ClaimFirstCredential(ctx, uniquenessOwner)
		require.NoError(t, err)

		require.NoError(t, slowClaim.Save(ctx, late))
		// crash: the slow claimer never reaches Commit or its cleanup.

		restarted := newTestCredentialStore(t, factory)
		owned, err := restarted.GetByUserID(ctx, uniquenessOwner)
		require.NoError(t, err)
		require.Empty(t, owned, "a stale claimer's credential is never readable")
		_, err = restarted.GetByCredentialID(ctx, late.ID)
		require.ErrorIs(t, err, ErrCredentialNotFound)

		require.NoError(t, claim.Save(ctx, won))
		require.NoError(t, claim.Commit(ctx, won))
		assertOnlyWinner(t, restarted)
	})
}

// TestCredentialStore_ExpiredClaimWithCredentialIsNotRecovered proves a
// ceremony that saved the credential but crashed before committing does not
// let a second first credential in: the account already has a credential.
func TestCredentialStore_ExpiredClaimWithCredentialIsNotRecovered(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	crashed := newTestCredentialStore(t, factory)
	claim, err := crashed.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)
	saved := &Credential{ID: []byte("saved-id"), UserID: uniquenessOwner}
	require.NoError(t, claim.Save(ctx, saved))

	restarted := newTestCredentialStore(t, factory)
	restarted.now = pastClaimLease()
	_, err = restarted.ClaimFirstCredential(ctx, uniquenessOwner)
	require.ErrorIs(t, err, ErrFirstCredentialClaimed)

	// The crashed claimer's own claim is rolled forward: its credential is
	// the account's first.
	owned, err := restarted.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, owned, 1)
	assert.Equal(t, saved.ID, owned[0].ID)
}

// TestCredentialStore_ReleaseLeavesARecoveredClaim proves a slow claimer's
// release cannot delete the claim another ceremony recovered from it.
func TestCredentialStore_ReleaseLeavesARecoveredClaim(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	slowClaim, err := newTestCredentialStore(t, factory).ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)

	recoverer := newTestCredentialStore(t, factory)
	recoverer.now = pastClaimLease()
	_, err = recoverer.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)

	require.NoError(t, slowClaim.Release(ctx))
	_, err = newTestCredentialStore(t, factory).ClaimFirstCredential(ctx, uniquenessOwner)
	require.ErrorIs(t, err, ErrFirstCredentialClaimed, "the recoverer's live claim must survive the slow release")
}

// TestFinishRegistration_RefusesCredentialOwnedByAnotherAccount drives the
// attack end to end: a credential ID already enrolled on one account cannot
// be enrolled on a second account through a real ceremony.
func TestFinishRegistration_RefusesCredentialOwnedByAnotherAccount(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	victim, credential := f.enroll(t, "victim@example.com")

	options, sessionID, err := f.svc.BeginRegistration(ctx, "attacker@example.com", "Attacker")
	require.NoError(t, err)
	_, err = f.attest(t, options, sessionID, credential)
	require.ErrorIs(t, err, ErrCredentialAlreadyExists)

	stored, err := f.creds.GetByCredentialID(ctx, credential.ID)
	require.NoError(t, err)
	assert.Equal(t, victim.WebAuthnID(), stored.UserID, "the credential must stay with its owner")
}
