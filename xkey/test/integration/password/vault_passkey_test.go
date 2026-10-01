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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/test/integration/xkeytest"
	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// passkeyPIN is the PIN of the virtual authenticator.
const passkeyPIN = "123456"

// passkeyAuthenticatorArgv starts xkey's virtual CTAP2 authenticator with a
// PIN, which a vault passkey always requires, read from standard input, and
// without the post-PIN touch.
var passkeyAuthenticatorArgv = []string{"fido2", "--require-touch=false", "--pin", "--set-pin-stdin", "--unified-pin=false"}

// startAuthenticator attaches a fresh virtual security key: its credentials
// live in memory, so each one is a different key.
func startAuthenticator(t *testing.T) *xkeytest.Authenticator {
	t.Helper()
	return xkeytest.StartAuthenticator(t, vault.xkey, t.TempDir(), passkeyAuthenticatorArgv, passkeyPIN+"\n")
}

// TestVault_Passkey enrolls a passkey on a FIDO2 security key -- xkey's
// virtual authenticator, through /dev/uhid -- scoped to the server's relying
// party, and unlocks with it; another security key, a wrong PIN and no
// security key at all are refused.
func TestVault_Passkey(t *testing.T) {
	u := newUser(t, "vault-passkey")
	assert.Equal(t, xkmsdtest.RelyingParty, u.status(t).PasskeyRPID, "the vault's passkeys are the server's relying party's")

	key := startAuthenticator(t)
	out := u.mustCtl(t, passkeyPIN, "password", "vault", "enroll", "--passkey", "--pin-stdin", "--device", key.Device(), "--label", "security key")
	recoveryCodeOf(t, out)
	assert.Equal(t, 1, u.factors(t, "passkey"))
	u.lock(t)

	unlock := func(device, pin string) (string, error) {
		return u.ctl(pin, "password", "unlock", "--passkey", "--pin-stdin", "--device", device)
	}
	t.Run("wrong PIN", func(t *testing.T) {
		out, err := unlock(key.Device(), "654321")
		require.Error(t, err, out)
		assert.Contains(t, out, "invalid PIN")
		u.requireLocked(t)
	})
	t.Run("right key", func(t *testing.T) {
		out, err := unlock(key.Device(), passkeyPIN)
		require.NoError(t, err, out)
		u.requireUnlocked(t)
		u.lock(t)
	})
	key.Stop()
	t.Run("missing key", func(t *testing.T) {
		out, err := unlock(key.Device(), passkeyPIN)
		require.Error(t, err, out)
		assert.Contains(t, out, "no such device")
		u.requireLocked(t)
	})
	t.Run("wrong key", func(t *testing.T) {
		other := startAuthenticator(t)
		defer other.Stop()
		out, err := unlock(other.Device(), passkeyPIN)
		require.Error(t, err, out)
		assert.Contains(t, out, "none of the vault's passkeys is on this authenticator")
		u.requireLocked(t)
	})
}
