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

package staticpw

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// personalSession returns the open personal store of userID in tenant-a.
func personalSession(t *testing.T, mgr *TenantPasswordStoreManager, userID string) *DAOStore {
	t.Helper()
	personal := unlocked(t, mgr, "tenant-a", userID).personal
	require.NotNil(t, personal)
	return personal
}

// TestPersonalNames_TenantKeyRevealsNoNamesOrFolders is the owner's rule for
// what the tenant barrier key may learn about a personal vault: neither an
// entry's name, nor its folder, nor a public hash of either. Every storage
// key under the user's personal keyspace is opaque without the user's DEK.
func TestPersonalNames_TenantKeyRevealsNoNamesOrFolders(t *testing.T) {
	mgr, stores := vaultFixture(t)
	alice := personalSession(t, mgr, "alice")

	require.NoError(t, alice.Add(&StaticPassword{Name: "bank", FolderPath: "Finance/Taxes", Password: "pw"}))
	require.NoError(t, alice.Add(&StaticPassword{Name: "router", Password: "pw"}))
	require.NoError(t, alice.CreateFolder("Secret Projects"))
	require.NoError(t, alice.SetAlias("login", "Finance"))

	revealing := []string{
		"bank", "router", "finance", "taxes", "secret", "projects", "login",
		GenerateID("bank", "Finance/Taxes"), GenerateID("router", ""),
	}
	for _, text := range storedTexts(t, stores, "tenant-a") {
		for _, s := range revealing {
			assert.NotContains(t, text, s, "a stored key or value reveals %q", s)
		}
	}

	records := 0
	for _, kind := range []string{nameKindEntry, nameKindFolder, nameKindAlias} {
		all, err := alice.records.list(t.Context(), alice.dir(kind))
		require.NoError(t, err)
		records += len(all)
	}
	assert.Equal(t, 4, records, "two entries, a folder marker and an alias")
}

// TestPersonalNames_TheOwnerSeesEverything proves the opaque keys change
// nothing the owner sees: lookups by name, folders, aliases, renames and
// moves work through the session as they do on a shared store.
func TestPersonalNames_TheOwnerSeesEverything(t *testing.T) {
	mgr, _ := vaultFixture(t)
	alice := personalSession(t, mgr, "alice")

	require.NoError(t, alice.Add(&StaticPassword{Name: "bank", FolderPath: "Finance/Taxes", Password: "pw"}))
	require.NoError(t, alice.Add(&StaticPassword{Name: "router", Password: "pw"}))
	require.NoError(t, alice.CreateFolder("Secret Projects"))
	require.NoError(t, alice.SetAlias("login", "Finance"))

	got, err := alice.Get("router")
	require.NoError(t, err, "a root entry is found by name")
	assert.Equal(t, "router", got.Name)
	byID, err := alice.Get(got.ID)
	require.NoError(t, err, "and by the ID the store returned")
	assert.Equal(t, "router", byID.Name)
	_, err = alice.Get("bank")
	require.NoError(t, err, "a folder entry is found by name")

	folders, err := alice.ListFolders()
	require.NoError(t, err)
	assert.Equal(t, []string{"Finance", "Finance/Taxes", "Secret Projects"}, folders)

	alias, ok, err := alice.GetAlias("login")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "Finance", alias)

	require.NoError(t, alice.RemoveFolder("Secret Projects"))
	folders, err = alice.ListFolders()
	require.NoError(t, err)
	assert.NotContains(t, folders, "Secret Projects")

	require.NoError(t, alice.MoveToFolder("router", "Home"))
	moved, err := alice.Get("router")
	require.NoError(t, err)
	assert.Equal(t, "Home", moved.FolderPath)
	assert.NotEqual(t, got.ID, moved.ID, "a move re-keys the entry")

	moved.Name = "gateway"
	require.NoError(t, alice.Update(moved))
	_, err = alice.Get("gateway")
	require.NoError(t, err)
	_, err = alice.Get("router")
	assert.ErrorIs(t, err, ErrPasswordNotFound)

	require.NoError(t, alice.Add(&StaticPassword{Name: "dup", Password: "pw"}))
	assert.ErrorIs(t, alice.Add(&StaticPassword{Name: "DUP", Password: "pw"}), ErrPasswordExists,
		"names stay case-insensitive")
}

// TestPersonalNames_IDsAreKeyedPerUser proves a personal entry ID is a keyed
// MAC: the same name gets different IDs for different users, none equal to
// the public ID, and the same ID across that user's sessions.
func TestPersonalNames_IDsAreKeyedPerUser(t *testing.T) {
	mgr, _ := vaultFixture(t)
	ctx := context.Background()

	alice := personalSession(t, mgr, "alice")
	bob := personalSession(t, mgr, "bob")
	require.NoError(t, alice.Add(&StaticPassword{Name: "bank", Password: "pw"}))
	require.NoError(t, bob.Add(&StaticPassword{Name: "bank", Password: "pw"}))
	a, err := alice.Get("bank")
	require.NoError(t, err)
	b, err := bob.Get("bank")
	require.NoError(t, err)

	assert.NotEqual(t, a.ID, b.ID)
	assert.NotEqual(t, GenerateID("bank", ""), a.ID)
	assert.Regexp(t, `^[0-9a-f]{32}$`, a.ID)

	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", pass(t, "alice")))
	again := personalSession(t, mgr, "alice")
	reopened, err := again.Get(a.ID)
	require.NoError(t, err, "the ID is stable across sessions: it is keyed by the DEK, which never changes")
	assert.Equal(t, "bank", reopened.Name)
}

// TestPersonalNames_SharedStoreKeepsPublicIDs proves the shared scope, which
// every tenant user reads, keeps the public deterministic ID scheme.
func TestPersonalNames_SharedStoreKeepsPublicIDs(t *testing.T) {
	mgr, _ := vaultFixture(t)
	alice := unlocked(t, mgr, "tenant-a", "alice")
	require.NoError(t, alice.Add(&StaticPassword{Name: "wifi", Password: "pw", Shared: true}))
	got, err := alice.Get("wifi")
	require.NoError(t, err)
	assert.Equal(t, GenerateID("wifi", ""), got.ID)
}
