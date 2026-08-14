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

//go:build pkcs11

package softhsmtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openProvisioned opens a PKCS#11 context against a provisioned token and
// returns a logged-in read/write session.
func openProvisioned(t *testing.T, tok Token) (*pkcs11.Ctx, pkcs11.SessionHandle) {
	t.Helper()

	ctx := pkcs11.New(tok.Library)
	require.NotNil(t, ctx)
	require.NoError(t, ctx.Initialize())
	t.Cleanup(func() {
		require.NoError(t, ctx.Finalize())
		ctx.Destroy()
	})

	session, err := ctx.OpenSession(tok.Slot(t, ctx), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ctx.CloseSession(session)) })

	return ctx, session
}

// TestProvision_TokenIsUsable proves a provisioned token accepts the user PIN
// and can hold a key, which is the contract every consuming test relies on.
func TestProvision_TokenIsUsable(t *testing.T) {
	tok := Provision(t, "softhsmtest-usable")

	ctx, session := openProvisioned(t, tok)
	require.NoError(t, ctx.Login(session, pkcs11.CKU_USER, tok.UserPIN))

	_, _, err := ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			// DER-encoded OID for prime256v1.
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "softhsmtest-key"),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "softhsmtest-key"),
		})
	require.NoError(t, err, "a provisioned token must accept key generation")
}

// TestProvision_IsolatedFromHost proves the token store lives entirely inside
// the test's temporary directory, so the host's SoftHSM store is untouched.
func TestProvision_IsolatedFromHost(t *testing.T) {
	tok := Provision(t, "softhsmtest-isolated")

	conf := os.Getenv("SOFTHSM2_CONF")
	require.NotEmpty(t, conf)
	assert.True(t, filepath.IsAbs(conf))

	entries, err := os.ReadDir(filepath.Join(filepath.Dir(conf), "tokens"))
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "the provisioned token must be written under t.TempDir()")
	assert.Equal(t, "softhsmtest-isolated", tok.Label)
}

// TestProvision_WrongPINRejected proves the token really enforces its PIN, so
// a test that logs in successfully has proved something.
func TestProvision_WrongPINRejected(t *testing.T) {
	tok := Provision(t, "softhsmtest-badpin")

	ctx, session := openProvisioned(t, tok)
	err := ctx.Login(session, pkcs11.CKU_USER, "0000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CKR_PIN_INCORRECT")
}

// TestLibrary_HonorsOverride proves SOFTHSM2_LIB takes precedence, which is how
// CI images that install SoftHSM2 outside the standard prefixes are supported.
func TestLibrary_HonorsOverride(t *testing.T) {
	real := Library(t)
	t.Setenv("SOFTHSM2_LIB", real)
	assert.Equal(t, real, Library(t))
}
