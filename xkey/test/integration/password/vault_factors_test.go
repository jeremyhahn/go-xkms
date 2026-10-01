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

//go:build integration && passwordvault

package password

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVault_Passphrase enrolls a passphrase, then unlocks with the right
// one, and is refused with a wrong one and with none.
func TestVault_Passphrase(t *testing.T) {
	u := newUser(t, "vault-passphrase")
	assert.False(t, u.status(t).Initialized, "a new user has no vault")

	u.enrollPassphrase(t)
	s := u.status(t)
	assert.True(t, s.Initialized)
	assert.True(t, s.Unlocked, "the first enrollment opens the session")
	assert.Equal(t, 1, u.factors(t, "passphrase"))
	assert.Equal(t, 1, u.factors(t, "recovery"))
	u.lock(t)

	t.Run("wrong passphrase", func(t *testing.T) {
		out, err := u.ctl("not the passphrase", "password", "unlock", "--passphrase", "-")
		require.Error(t, err, out)
		assert.Contains(t, out, "Credential rejected")
		u.requireLocked(t)
	})
	t.Run("missing passphrase", func(t *testing.T) {
		// No passphrase and no terminal to prompt on.
		out, err := u.ctl("", "password", "unlock")
		require.Error(t, err, out)
		assert.Contains(t, out, "vault passphrase is required")
		u.requireLocked(t)
	})
	t.Run("right passphrase", func(t *testing.T) {
		u.mustCtl(t, passphrase, "password", "unlock", "--passphrase", "-")
		u.requireUnlocked(t)
	})
}

// TestVault_RecoveryCode recovers a vault whose passphrase is lost with the
// one-time recovery code: the code enrolls a new passphrase, is replaced by
// a new code, and is refused the second time; a wrong code is refused.
func TestVault_RecoveryCode(t *testing.T) {
	u := newUser(t, "vault-recovery")
	code := u.enrollPassphrase(t)
	u.lock(t)

	out, err := u.ctl("new passphrase after loss", "password", "vault", "recover",
		"--recovery-code", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", "--passphrase", "-", "--label", "recovered")
	require.Error(t, err, "a wrong recovery code is refused: %s", out)
	u.requireLocked(t)

	out = u.mustCtl(t, "new passphrase after loss", "password", "vault", "recover",
		"--recovery-code", code, "--passphrase", "-", "--label", "recovered")
	next := recoveryCodeOf(t, out)
	assert.NotEqual(t, code, next, "recovery replaces the code")
	u.requireUnlocked(t)
	assert.Equal(t, 2, u.factors(t, "passphrase"), "the recovered passphrase is a new factor")
	u.lock(t)

	out, err = u.ctl("another passphrase", "password", "vault", "recover",
		"--recovery-code", code, "--passphrase", "-")
	require.Error(t, err, "a used recovery code is refused: %s", out)
	u.requireLocked(t)

	u.mustCtl(t, "new passphrase after loss", "password", "unlock", "--passphrase", "-")
	u.requireUnlocked(t)
}

// TestVault_CertificateKey enrolls a certificate's key as a factor: the
// server seals the factor's secret to the certificate's public key and only
// that key opens it.
func TestVault_CertificateKey(t *testing.T) {
	u := newUser(t, "vault-certificate")
	dir := t.TempDir()
	keyFile, certFile := writeKeyPair(t, dir, "client")
	otherKey, _ := writeKeyPair(t, dir, "other")

	out := u.mustCtl(t, "", "password", "vault", "enroll", "--key-factor", "certificate",
		"--key-file", keyFile, "--cert-file", certFile, "--label", "client certificate")
	recoveryCodeOf(t, out)
	assert.Equal(t, 1, u.factors(t, "certificate"))
	u.lock(t)

	t.Run("wrong key", func(t *testing.T) {
		out, err := u.ctl("", "password", "unlock", "--key", "--key-file", otherKey)
		require.Error(t, err, out)
		assert.Contains(t, out, "this token's key is not the factor's key")
		u.requireLocked(t)
	})
	t.Run("missing key", func(t *testing.T) {
		out, err := u.ctl("", "password", "unlock", "--key", "--key-file", filepath.Join(dir, "absent.key"))
		require.Error(t, err, out)
		assert.Contains(t, out, "no such file or directory")
		u.requireLocked(t)
	})
	t.Run("right key", func(t *testing.T) {
		u.mustCtl(t, "", "password", "unlock", "--key", "--key-file", keyFile)
		u.requireUnlocked(t)
	})
}

// entry is an entry of "xkmsctl password list -o json".
type entry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Owner    string `json:"owner_id"`
	Shared   bool   `json:"shared"`
}

// list returns the entries the user sees in scope.
func (u *vaultUser) list(t *testing.T, scope string) map[string]entry {
	t.Helper()
	out := u.mustCtl(t, "", "password", "list", "--scope", scope, "-o", "json")
	var resp struct {
		Passwords []entry `json:"passwords"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &resp), out)
	byName := map[string]entry{}
	for _, e := range resp.Passwords {
		byName[e.Name] = e
	}
	return byName
}

// add stores an entry for the user and returns its ID.
func (u *vaultUser) add(t *testing.T, name, value string, shared bool) string {
	t.Helper()
	args := []string{"password", "add", name, "--password", "-", "-o", "json"}
	if shared {
		args = append(args, "--shared")
	}
	out := u.mustCtl(t, value, args...)
	var e entry
	require.NoError(t, json.Unmarshal([]byte(out), &e), out)
	require.NotEmpty(t, e.ID, out)
	return e.ID
}

// TestVault_SharedAndPersonalAcrossUsers proves a personal entry is its
// owner's alone -- another user neither lists nor reads it -- while a
// shared entry is the tenant's, readable by both, and that a locked vault
// hides its owner's personal entries but not the shared ones. Both are
// ordinary users: the password manager is a store for users.
func TestVault_SharedAndPersonalAcrossUsers(t *testing.T) {
	alice := newUser(t, "vault-alice")
	bob := newUser(t, "vault-bob")
	alice.enrollPassphrase(t)
	bob.enrollPassphrase(t)

	personal := alice.add(t, "alice-personal", "alice-only-secret", false)
	shared := alice.add(t, "team-shared", "team-secret", true)

	mine := alice.list(t, "all")
	require.Contains(t, mine, "alice-personal")
	require.Contains(t, mine, "team-shared")

	theirs := bob.list(t, "all")
	assert.NotContains(t, theirs, "alice-personal", "bob does not see alice's personal entry")
	require.Contains(t, theirs, "team-shared", "bob sees the shared entry")
	assert.True(t, theirs["team-shared"].Shared)

	out, err := bob.ctl("", "password", "get", personal, "-o", "json")
	require.Error(t, err, "bob cannot read alice's personal entry: %s", out)
	var got entry
	require.NoError(t, json.Unmarshal([]byte(bob.mustCtl(t, "", "password", "get", shared, "-o", "json")), &got))
	assert.Equal(t, "team-secret", got.Password)

	require.NoError(t, json.Unmarshal([]byte(alice.mustCtl(t, "", "password", "get", personal, "-o", "json")), &got))
	assert.Equal(t, "alice-only-secret", got.Password)

	// Locking alice's vault hides her personal entry from her too, and
	// leaves bob's session and the shared entry alone.
	alice.lock(t)
	locked := alice.list(t, "all")
	assert.NotContains(t, locked, "alice-personal")
	assert.Contains(t, locked, "team-shared")
	out, err = alice.ctl("", "password", "get", personal, "-o", "json")
	require.Error(t, err, "a locked vault does not open its personal entries: %s", out)
	bob.requireUnlocked(t)
}

// TestVault_SharedEntryIsItsOwners proves another user can read a shared
// entry but neither change nor delete it; its owner can.
func TestVault_SharedEntryIsItsOwners(t *testing.T) {
	alice := newUser(t, "vault-shared-owner")
	bob := newUser(t, "vault-shared-reader")
	alice.enrollPassphrase(t)
	bob.enrollPassphrase(t)
	shared := alice.add(t, "team-wifi", "original", true)

	out, err := bob.ctl("bob's value", "password", "update", shared, "--password", "-")
	require.Error(t, err, "another user cannot change the shared entry: %s", out)
	assert.Contains(t, out, "Not the owner")
	out, err = bob.ctl("", "password", "delete", shared)
	require.Error(t, err, "another user cannot delete the shared entry: %s", out)
	assert.Contains(t, out, "Not the owner")

	var got entry
	require.NoError(t, json.Unmarshal([]byte(bob.mustCtl(t, "", "password", "get", shared, "-o", "json")), &got))
	assert.Equal(t, "original", got.Password, "the entry is unchanged")

	alice.mustCtl(t, "rotated", "password", "update", shared, "--password", "-")
	require.NoError(t, json.Unmarshal([]byte(bob.mustCtl(t, "", "password", "get", shared, "-o", "json")), &got))
	assert.Equal(t, "rotated", got.Password, "its owner changes it")
	alice.mustCtl(t, "", "password", "delete", shared)
	assert.NotContains(t, bob.list(t, "all"), "team-wifi", "its owner deletes it")
}
