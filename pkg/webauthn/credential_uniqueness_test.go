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

package webauthn

import (
	"context"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// credentialStoreFactories builds every CredentialStore implementation, so
// the go-xkms#1295 uniqueness contract is asserted on each of them.
func credentialStoreFactories() map[string]func(t *testing.T) CredentialStore {
	return map[string]func(t *testing.T) CredentialStore{
		"memory": func(t *testing.T) CredentialStore { return NewMemoryCredentialStore() },
		"backend": func(t *testing.T) CredentialStore {
			return NewBackendCredentialStore(storage.NewMemory())
		},
		"qrdb": func(t *testing.T) CredentialStore {
			_, cs, _, _ := newTestAdapter(t)
			return cs
		},
	}
}

// Every store keys users by 8-byte handles.
var (
	uniquenessOwner    = HandleFromUserID(1)
	uniquenessAttacker = HandleFromUserID(2)
)

// TestCredentialStore_RefusesDuplicateIDUnderAnotherUser is go-xkms#1295: a
// credential ID registered to one account cannot be registered again under
// another, and the owner's record survives the attempt intact.
func TestCredentialStore_RefusesDuplicateIDUnderAnotherUser(t *testing.T) {
	for name, factory := range credentialStoreFactories() {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs := factory(t)

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
			assert.Empty(t, attackerCreds, "the refused credential must not be indexed under the attacker")
		})
	}
}

// TestCredentialStore_UpdateRefreshesSignCount proves the update path a login
// uses still works: the owner's sign counter and flags are rewritten.
func TestCredentialStore_UpdateRefreshesSignCount(t *testing.T) {
	for name, factory := range credentialStoreFactories() {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs := factory(t)

			cred := &Credential{ID: []byte("counter-id"), UserID: uniquenessOwner}
			cred.Authenticator.SignCount = 1
			require.NoError(t, cs.Save(ctx, cred))

			updated := &Credential{ID: []byte("counter-id"), UserID: uniquenessOwner}
			updated.Authenticator.SignCount = 7
			updated.Authenticator.CloneWarning = true
			require.NoError(t, cs.Update(ctx, updated))

			stored, err := cs.GetByCredentialID(ctx, cred.ID)
			require.NoError(t, err)
			assert.Equal(t, uint32(7), stored.Authenticator.SignCount)
			assert.True(t, stored.Authenticator.CloneWarning)
		})
	}
}

// TestCredentialStore_UpdateRefusesOtherOwner proves an update cannot move a
// credential to another account.
func TestCredentialStore_UpdateRefusesOtherOwner(t *testing.T) {
	for name, factory := range credentialStoreFactories() {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs := factory(t)

			require.NoError(t, cs.Save(ctx, &Credential{ID: []byte("owned-id"), UserID: uniquenessOwner}))

			err := cs.Update(ctx, &Credential{ID: []byte("owned-id"), UserID: uniquenessAttacker})
			require.ErrorIs(t, err, ErrCredentialOwnerMismatch)

			stored, err := cs.GetByCredentialID(ctx, []byte("owned-id"))
			require.NoError(t, err)
			assert.Equal(t, uniquenessOwner, stored.UserID)
		})
	}
}

// TestCredentialStore_UpdateRequiresExistingCredential proves Update never
// creates.
func TestCredentialStore_UpdateRequiresExistingCredential(t *testing.T) {
	for name, factory := range credentialStoreFactories() {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs := factory(t)

			err := cs.Update(ctx, &Credential{ID: []byte("absent-id"), UserID: uniquenessOwner})
			require.ErrorIs(t, err, ErrCredentialNotFound)

			_, err = cs.GetByCredentialID(ctx, []byte("absent-id"))
			require.ErrorIs(t, err, ErrCredentialNotFound)
		})
	}
}

// swapLosingKV is a guarded KV whose CompareAndSwap always loses the race,
// standing in for a record changed between the owner check and the write.
type swapLosingKV struct {
	*fakeKV
}

func (k *swapLosingKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	return false, nil
}

// TestQRDBCredentialStore_UpdateLosesRace proves a stale update is not
// applied when the record changed underneath it.
func TestQRDBCredentialStore_UpdateLosesRace(t *testing.T) {
	ctx := context.Background()
	_, cs, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: newFakeUserClient(), KV: &swapLosingKV{fakeKV: newFakeKV()}, TenantID: "system",
	})
	require.NoError(t, err)

	cred := &Credential{ID: []byte("raced-id"), UserID: uniquenessOwner}
	require.NoError(t, cs.Save(ctx, cred))

	cred.Authenticator.SignCount = 9
	require.ErrorIs(t, cs.Update(ctx, cred), ErrCredentialUpdateConflict)
}

// unguardedKV exposes only the plain KVClient verbs of the in-memory KV:
// embedding the interface promotes nothing else.
type unguardedKV struct {
	qrdbtransport.KVClient
}

// TestNewQRDBUserStoreAdapter_RequiresGuardedKV proves construction fails
// without PutIfAbsent/CompareAndSwap rather than degrading to a racy
// read-then-write.
func TestNewQRDBUserStoreAdapter_RequiresGuardedKV(t *testing.T) {
	_, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: newFakeUserClient(), KV: unguardedKV{KVClient: newFakeKV()}, TenantID: "system",
	})
	var guardErr *GuardedKVUnsupportedError
	require.ErrorAs(t, err, &guardErr)
	assert.Contains(t, guardErr.Error(), "unguardedKV")
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
