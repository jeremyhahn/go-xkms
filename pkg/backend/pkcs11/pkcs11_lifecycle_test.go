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

package pkcs11

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyTokenStore points SOFTHSM2_CONF at a private, completely empty token
// directory and returns the SoftHSM2 library path.
//
// Unlike softhsmtest.Provision it deliberately does not run C_InitToken, so
// the only slot SoftHSM exposes holds an uninitialized token. That is the
// precondition Backend.Initialize is written for, and it is the only way to
// exercise the C_InitToken / C_InitPIN branch of initializeToken.
func emptyTokenStore(t *testing.T) string {
	t.Helper()

	lib := softhsmtest.Library(t)

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	require.NoError(t, os.Mkdir(tokenDir, 0o750))

	conf := filepath.Join(root, "softhsm2.conf")
	contents := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
		tokenDir)
	require.NoError(t, os.WriteFile(conf, []byte(contents), 0o600))

	// t.Setenv restores the host value when the test ends.
	t.Setenv("SOFTHSM2_CONF", conf)

	return lib
}

// uninitializedCtx returns a PKCS#11 context that has been loaded but never
// had C_Initialize called on it.
//
// Every Cryptoki entry point on such a context fails with
// CKR_CRYPTOKI_NOT_INITIALIZED (PKCS#11 v3.2 section 5.6), which makes it a
// faithful stand-in for a wedged device without touching global library
// state -- crucially, it never calls C_Finalize, so it cannot disturb another
// context that a concurrently running test holds open.
func uninitializedCtx(t *testing.T) *pkcs11.Ctx {
	t.Helper()

	ctx := pkcs11.New(softhsmtest.Library(t))
	require.NotNil(t, ctx, "the SoftHSM2 library must load")
	t.Cleanup(ctx.Destroy)

	return ctx
}

// TestBackend_GenerateRandom_FromToken proves GenerateRandom returns exactly
// the requested number of bytes from the token's RNG and that successive
// draws differ.
//
// The differing-draws assertion is the oracle that matters: a backend that
// silently returned a zeroed or cached buffer would still satisfy a
// length-only check, and callers use this entropy for key material.
func TestBackend_GenerateRandom_FromToken(t *testing.T) {
	b := newProvisionedBackend(t, "random-token")

	for _, length := range []int{1, 16, 32, 512} {
		t.Run(fmt.Sprintf("length-%d", length), func(t *testing.T) {
			first, err := b.GenerateRandom(length)
			require.NoError(t, err)
			require.Len(t, first, length, "C_GenerateRandom must fill the requested buffer exactly")

			second, err := b.GenerateRandom(length)
			require.NoError(t, err)
			require.Len(t, second, length)

			if length >= 16 {
				assert.NotEqual(t, first, second,
					"two draws of %d bytes must not be identical; the token RNG is not being consulted", length)
				assert.NotEqual(t, make([]byte, length), first,
					"an all-zero draw means the buffer was never written")
			}
		})
	}
}

// TestBackend_GenerateRandom_InvalidInput proves GenerateRandom rejects
// non-positive lengths and an uninitialized backend rather than returning an
// empty slice that a caller could mistake for entropy.
func TestBackend_GenerateRandom_InvalidInput(t *testing.T) {
	b := newProvisionedBackend(t, "random-invalid")

	for _, length := range []int{0, -1, -4096} {
		t.Run(fmt.Sprintf("length-%d", length), func(t *testing.T) {
			out, err := b.GenerateRandom(length)
			require.Error(t, err)
			assert.Nil(t, out, "no bytes may be returned alongside an error")

			var msg *errs.Message
			require.ErrorAs(t, err, &msg, "invalid length must surface as a typed errs.Message")
			assert.Equal(t, fmt.Sprintf("pkcs11: invalid length %d, must be > 0", length), msg.Msg)
		})
	}

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		out, err := fresh.GenerateRandom(32)
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Nil(t, out)
	})
}

// TestBackend_GenerateRandom_AfterClose proves a closed backend refuses to
// serve entropy instead of reaching into a drained session pool.
//
// It is a separate top-level test because a SoftHSM token can only be
// provisioned while no other PKCS#11 context in the process is initialized.
func TestBackend_GenerateRandom_AfterClose(t *testing.T) {
	b := newProvisionedBackend(t, "random-after-close")
	require.NoError(t, b.Close())

	out, err := b.GenerateRandom(32)
	require.ErrorIs(t, err, ErrNotInitialized)
	assert.Nil(t, out)
}

// TestBackend_Initialize_UninitializedToken drives Backend.Initialize against
// a SoftHSM store whose only slot holds an uninitialized token, which is the
// full C_InitToken + C_InitPIN + login path.
//
// The oracle is an independent PKCS#11 context: after Initialize returns, a
// second context must see a token carrying the configured label with
// CKF_TOKEN_INITIALIZED set and must accept the user PIN that was just
// installed.
func TestBackend_Initialize_UninitializedToken(t *testing.T) {
	lib := emptyTokenStore(t)

	const label = "freshly-initialized"
	config := testConfig(lib, label)

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	require.NoError(t, b.Initialize(softhsmtest.SOPIN, softhsmtest.UserPIN),
		"Initialize must provision an uninitialized SoftHSM token")

	require.NotNil(t, b.Pool(), "Initialize must leave a usable session pool behind")
	assert.Equal(t, softhsmtest.SOPIN, b.config.SOPIN, "Initialize records the SO PIN it was given")
	assert.Equal(t, softhsmtest.UserPIN, b.config.PIN, "Initialize records the user PIN it was given")

	random, err := b.GenerateRandom(16)
	require.NoError(t, err, "the pool created by Initialize must be logged in and usable")
	require.Len(t, random, 16)

	// Oracle: verify the token state through a context this backend does not own.
	slot, err := b.resolveSlot()
	require.NoError(t, err)

	info, err := b.p11ctx.GetTokenInfo(slot)
	require.NoError(t, err)
	assert.Equal(t, label, trimPKCS11Label(info.Label), "C_InitToken must have written the configured label")
	assert.NotZero(t, info.Flags&pkcs11.CKF_TOKEN_INITIALIZED,
		"the token must report CKF_TOKEN_INITIALIZED after Initialize")
	assert.NotZero(t, info.Flags&pkcs11.CKF_USER_PIN_INITIALIZED,
		"C_InitPIN must have installed a user PIN")
}

// TestBackend_Initialize_AlreadyInitializedToken proves Initialize tolerates a
// token that is already provisioned: initializeToken reports
// ErrAlreadyInitialized and Initialize must swallow that and proceed to log in
// rather than failing the caller.
func TestBackend_Initialize_AlreadyInitializedToken(t *testing.T) {
	token := softhsmtest.Provision(t, "already-initialized")

	config := testConfig(token.Library, token.Label)
	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	require.NoError(t, b.Initialize(token.SOPIN, token.UserPIN),
		"Initialize on an already-provisioned token must succeed by logging in")
	require.NotNil(t, b.Pool())

	random, err := b.GenerateRandom(8)
	require.NoError(t, err)
	require.Len(t, random, 8)
}

// TestBackend_Initialize_Rejected covers every input Initialize must refuse:
// short PINs (PKCS#11 tokens require at least four characters) and a second
// Initialize on a backend that already owns a pool.
func TestBackend_Initialize_Rejected(t *testing.T) {
	t.Run("short-so-pin", func(t *testing.T) {
		b := newProvisionedBackend(t, "init-short-so")
		require.ErrorIs(t, b.Initialize("123", softhsmtest.UserPIN), ErrInvalidSOPINLength)
	})

	t.Run("short-user-pin", func(t *testing.T) {
		b := newProvisionedBackend(t, "init-short-user")
		require.ErrorIs(t, b.Initialize(softhsmtest.SOPIN, "1"), ErrInvalidPINLength)
	})

	t.Run("pool-already-established", func(t *testing.T) {
		b := newProvisionedBackend(t, "init-twice")
		require.ErrorIs(t, b.Initialize(softhsmtest.SOPIN, softhsmtest.UserPIN), ErrAlreadyInitialized,
			"Initialize must not tear down or re-create a live session pool")
		require.NotNil(t, b.Pool(), "the existing pool must survive the rejected Initialize")
	})
}

// TestBackend_Login_WrongPIN proves a bad user PIN is reported as a session
// pool login failure and, critically, that no pool is published.
//
// A backend that kept a half-built pool after a failed C_Login would let
// subsequent operations run unauthenticated.
func TestBackend_Login_WrongPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "login-wrong-pin")

	config := testConfig(token.Library, token.Label)
	config.PIN = "0000" // valid length, wrong value
	require.NotEqual(t, token.UserPIN, config.PIN)

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	err = b.Login()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSessionPoolLogin, "a wrong PIN must surface as a pool login failure")
	assert.Nil(t, b.Pool(), "no session pool may be published after a failed login")

	// The token must not have been damaged: the correct PIN still works.
	// SoftHSM only locks the user PIN after three consecutive failures.
	b.config.PIN = token.UserPIN
	require.NoError(t, b.Login(), "the correct PIN must still be accepted after one failure")
	require.NotNil(t, b.Pool())
}

// TestBackend_Login_NoPIN proves Login refuses to run when no PIN is
// configured instead of silently opening an unauthenticated pool.
func TestBackend_Login_NoPIN(t *testing.T) {
	token := softhsmtest.Provision(t, "login-no-pin")

	b, err := NewBackend(testConfig(token.Library, token.Label))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	require.ErrorIs(t, b.Login(), ErrInvalidUserPIN)
	assert.Nil(t, b.Pool())
}

// TestBackend_Login_UnknownTokenLabel proves loginUser propagates a slot
// resolution failure instead of silently binding to whatever token happens to
// occupy slot 0 -- logging into the wrong token would put keys on the wrong
// device.
func TestBackend_Login_UnknownTokenLabel(t *testing.T) {
	token := softhsmtest.Provision(t, "login-label-present")

	config := testConfig(token.Library, "no-such-token")
	config.PIN = token.UserPIN

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	err = b.Login()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTokenNotFound)
	assert.Contains(t, err.Error(), `token label "no-such-token" not found`)
	assert.Nil(t, b.Pool())
}

// TestBackend_Login_BadLibrary proves a library path that is not a loadable
// PKCS#11 module is reported rather than dereferenced.
func TestBackend_Login_BadLibrary(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "libnotamodule.so")
	require.NoError(t, os.WriteFile(fake, []byte("this is not an ELF shared object"), 0o600))

	config := testConfig(fake, "irrelevant")
	config.PIN = "1234"

	b, err := NewBackend(config)
	require.NoError(t, err, "NewBackend only checks that the path exists")

	err = b.Login()
	require.Error(t, err)

	var msg *errs.Message
	require.ErrorAs(t, err, &msg)
	assert.Equal(t, "failed to load PKCS#11 library: "+fake, msg.Msg)
	assert.Nil(t, b.Pool())
	require.NoError(t, b.Close())
}

// TestBackend_ResolveSlot_ByLabel proves label-based slot resolution selects
// the slot whose token label matches, verified against an independent scan of
// the token list rather than against resolveSlot's own answer.
func TestBackend_ResolveSlot_ByLabel(t *testing.T) {
	const label = "resolve-by-label"
	b := newProvisionedBackend(t, label)

	got, err := b.resolveSlot()
	require.NoError(t, err)

	slots, err := b.p11ctx.GetSlotList(true)
	require.NoError(t, err)

	var want uint
	var found bool
	for _, slot := range slots {
		info, infoErr := b.p11ctx.GetTokenInfo(slot)
		if infoErr != nil {
			continue
		}
		if trimPKCS11Label(info.Label) == label {
			want, found = slot, true
			break
		}
	}
	require.True(t, found, "the provisioned token must appear in the slot list")
	assert.Equal(t, want, got, "resolveSlot must return the slot actually holding the labelled token")
}

// TestBackend_ResolveSlot_ExplicitSlot proves an explicitly configured slot
// short-circuits discovery. It is asserted with a nil context so the test
// fails loudly if the implementation ever starts querying the token first.
func TestBackend_ResolveSlot_ExplicitSlot(t *testing.T) {
	slot := 7
	b := &Backend{config: &Config{Slot: &slot, TokenLabel: "ignored"}}

	got, err := b.resolveSlot()
	require.NoError(t, err)
	assert.Equal(t, uint(7), got)
}

// TestBackend_ResolveSlot_NoLabelUsesFirstSlot proves an empty token label
// falls back to the first slot the token list reports.
func TestBackend_ResolveSlot_NoLabelUsesFirstSlot(t *testing.T) {
	b := newProvisionedBackend(t, "resolve-first-slot")

	probe := &Backend{config: &Config{}, p11ctx: b.p11ctx}
	got, err := probe.resolveSlot()
	require.NoError(t, err)

	slots, err := b.p11ctx.GetSlotList(true)
	require.NoError(t, err)
	require.NotEmpty(t, slots)
	assert.Equal(t, slots[0], got)
}

// TestBackend_ResolveSlot_Errors proves resolveSlot reports a failing device
// instead of returning slot 0, which would silently direct key material at
// the wrong token.
func TestBackend_ResolveSlot_Errors(t *testing.T) {
	t.Run("slot-list-fails", func(t *testing.T) {
		b := &Backend{config: &Config{TokenLabel: "anything"}, p11ctx: uninitializedCtx(t)}

		_, err := b.resolveSlot()
		require.Error(t, err)

		var wrapped *errs.Wrapped
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to get slot list", wrapped.Msg)
		require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED))
	})

	t.Run("label-not-present", func(t *testing.T) {
		b := newProvisionedBackend(t, "resolve-missing-label")

		probe := &Backend{config: &Config{TokenLabel: "absent-token"}, p11ctx: b.p11ctx}
		_, err := probe.resolveSlot()
		require.ErrorIs(t, err, ErrTokenNotFound)
		assert.Contains(t, err.Error(), `token label "absent-token" not found`)
	})
}

// TestBackend_SetSessionPool_BorrowsContext proves that a backend handed a
// pool it did not create treats the underlying PKCS#11 context as borrowed:
// Close must release the pool but must not call C_Finalize, because the
// owner is still using that context.
//
// Finalizing a borrowed context would invalidate every session the owner
// holds -- the exact failure mode SetSessionPool exists to avoid.
func TestBackend_SetSessionPool_BorrowsContext(t *testing.T) {
	owner := newProvisionedBackend(t, "borrowed-pool")

	slot, err := owner.resolveSlot()
	require.NoError(t, err)

	borrowedPool, err := NewSessionPool(owner.p11ctx, slot, owner.config.PIN, 2)
	require.NoError(t, err)

	borrower := &Backend{config: owner.config}
	borrower.SetSessionPool(borrowedPool)

	assert.Same(t, borrowedPool, borrower.Pool(), "the injected pool must be the one served by Pool()")
	assert.Same(t, owner.p11ctx, borrower.p11ctx, "SetSessionPool must adopt the pool's context")
	assert.False(t, borrower.ownsP11ctx, "an injected context is borrowed, never owned")

	random, err := borrower.GenerateRandom(16)
	require.NoError(t, err, "the borrower must be able to operate through the injected pool")
	require.Len(t, random, 16)

	require.NoError(t, borrower.Close())

	ownerRandom, err := owner.GenerateRandom(16)
	require.NoError(t, err, "closing a borrower must not finalize the owner's PKCS#11 context")
	require.Len(t, ownerRandom, 16)

	_, err = borrower.GenerateRandom(16)
	require.ErrorIs(t, err, ErrNotInitialized, "the borrower's own pool must be gone after Close")
}

// TestBackend_ProbeQuantumMechanisms_RealToken proves the probe reflects what
// the token actually advertises. SoftHSM2 exposes no PKCS#11 v3.2 ML-DSA or
// ML-KEM mechanism, so both quantum capabilities must stay false; claiming
// otherwise would route post-quantum key generation at a token that cannot
// perform it.
func TestBackend_ProbeQuantumMechanisms_RealToken(t *testing.T) {
	b := newProvisionedBackend(t, "probe-real-token")

	slot, err := b.resolveSlot()
	require.NoError(t, err)

	mechs, err := b.p11ctx.GetMechanismList(slot)
	require.NoError(t, err)

	var advertisesMLDSA, advertisesMLKEM bool
	for _, mech := range mechs {
		switch mech.Mechanism {
		case CKM_ML_DSA_KEY_PAIR_GEN:
			advertisesMLDSA = true
		case CKM_ML_KEM_KEY_PAIR_GEN:
			advertisesMLKEM = true
		}
	}

	caps := b.Capabilities()
	assert.Equal(t, advertisesMLDSA, caps.QuantumSigning,
		"QuantumSigning must mirror the token's ML-DSA mechanism list")
	// KeyEncapsulation is deliberately NOT mirrored from the token. This
	// asserted that it was, which pinned the defect: the capability feeds the
	// algorithms API and published ML-KEM-1024 as an offered algorithm, while
	// the backend implements no encapsulate or decapsulate operation, so such a
	// key could never be used. supportsMLKEM still records the token's own
	// support and is asserted separately below.
	assert.False(t, caps.KeyEncapsulation,
		"KeyEncapsulation must stay false until Encapsulate/Decapsulate exist, "+
			"even on a token that advertises ML-KEM")
	assert.Equal(t, advertisesMLKEM, b.supportsMLKEM,
		"the token's ML-KEM support must still be recorded for a future implementation")

	t.Run("explicit-slot", func(t *testing.T) {
		configured := int(slot)
		probe := &Backend{
			config: &Config{Slot: &configured, TokenLabel: b.config.TokenLabel},
			p11ctx: b.p11ctx,
		}
		probe.probeQuantumMechanisms()
		assert.Equal(t, advertisesMLDSA, probe.supportsMLDSA)
		assert.Equal(t, advertisesMLKEM, probe.supportsMLKEM)
	})
}

// TestBackend_ProbeQuantumMechanisms_DeviceErrors proves the probe fails
// closed. When the device cannot be queried the backend must report no
// quantum support rather than leaving the flags in an indeterminate state.
func TestBackend_ProbeQuantumMechanisms_DeviceErrors(t *testing.T) {
	t.Run("slot-list-fails", func(t *testing.T) {
		b := &Backend{config: &Config{}, p11ctx: uninitializedCtx(t)}
		b.probeQuantumMechanisms()
		assert.False(t, b.supportsMLDSA)
		assert.False(t, b.supportsMLKEM)
	})

	t.Run("mechanism-list-fails", func(t *testing.T) {
		real := newProvisionedBackend(t, "probe-bad-slot")

		bogus := 0x7fffffff
		probe := &Backend{config: &Config{Slot: &bogus}, p11ctx: real.p11ctx}
		probe.probeQuantumMechanisms()
		assert.False(t, probe.supportsMLDSA,
			"an unreadable mechanism list must not be treated as ML-DSA support")
		assert.False(t, probe.supportsMLKEM)
	})

	t.Run("no-context", func(t *testing.T) {
		b := &Backend{config: &Config{}}
		b.probeQuantumMechanisms()
		assert.False(t, b.supportsMLDSA)
		assert.False(t, b.supportsMLKEM)
	})
}

// TestBackend_Close_ReleasesOwnedContext proves Close on a backend that
// created its own context finalizes it and clears both the pool and the
// context, and that a second Close is a no-op rather than a double free.
func TestBackend_Close_ReleasesOwnedContext(t *testing.T) {
	token := softhsmtest.Provision(t, "close-owned-ctx")

	config := testConfig(token.Library, token.Label)
	config.PIN = token.UserPIN

	b, err := NewBackend(config)
	require.NoError(t, err)
	require.NoError(t, b.Login())
	require.True(t, b.ownsP11ctx, "a backend that loaded the library owns the context")

	require.NoError(t, b.Close())
	assert.Nil(t, b.pool, "Close must drop the pool")
	assert.Nil(t, b.p11ctx, "Close must drop an owned context")

	require.NoError(t, b.Close(), "Close is idempotent")
}

// TestBackend_SlotModel_GenericToken proves a generic (non-PIV) token reports
// no slot model. Callers branch on this to decide whether PIV slot semantics
// apply, so a non-nil answer here would make them address SoftHSM keys by PIV
// slot.
func TestBackend_SlotModel_GenericToken(t *testing.T) {
	b := newProvisionedBackend(t, "slotmodel-generic")

	assert.False(t, b.config.IsYubiKeyPIV(), "SoftHSM is not a PIV token")
	assert.Nil(t, b.SlotModel(), "a generic PKCS#11 token has no PIV slot model")
}

// trimPKCS11Label strips the space padding PKCS#11 applies to the fixed-width
// 32-byte token label field (PKCS#11 v3.2, CK_TOKEN_INFO).
func trimPKCS11Label(label string) string {
	return string(bytes.TrimRight([]byte(label), " "))
}

// TestBackend_Initialize_ExplicitSlot proves an explicitly configured slot is
// the slot token initialization inspects, rather than whichever slot the
// device happens to list first.
//
// Getting this wrong on a multi-token HSM would run C_InitToken against
// somebody else's token, destroying its contents.
func TestBackend_Initialize_ExplicitSlot(t *testing.T) {
	token := softhsmtest.Provision(t, "init-explicit-slot")

	// Resolve the slot with a throwaway context and release it again, so
	// Initialize is free to run C_Initialize itself.
	probe := pkcs11.New(token.Library)
	require.NotNil(t, probe)
	require.NoError(t, probe.Initialize())
	slot := int(token.Slot(t, probe))
	require.NoError(t, probe.Finalize())
	probe.Destroy()

	config := testConfig(token.Library, token.Label)
	config.Slot = &slot

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	require.NoError(t, b.Initialize(token.SOPIN, token.UserPIN),
		"the configured slot already holds an initialized token, so Initialize logs in")

	resolved, err := b.resolveSlot()
	require.NoError(t, err)
	assert.Equal(t, uint(slot), resolved, "the configured slot must be the one in use")

	random, err := b.GenerateRandom(8)
	require.NoError(t, err)
	require.Len(t, random, 8)
}

// TestBackend_Initialize_UnreadableSlot proves a slot the device cannot
// describe aborts initialization instead of proceeding to C_InitToken against
// an unknown slot.
func TestBackend_Initialize_UnreadableSlot(t *testing.T) {
	token := softhsmtest.Provision(t, "init-bad-slot")

	bogus := 0x7fffffff
	config := testConfig(token.Library, token.Label)
	config.Slot = &bogus

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	err = b.Initialize(token.SOPIN, token.UserPIN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token info")

	var wrapped *errs.Wrapped
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to initialize token", wrapped.Msg)
	assert.Nil(t, b.Pool(), "no session pool may be published after a failed initialization")
}

// TestBackend_Initialize_SecondBackendInProcess proves a second backend can
// initialize against the same library while the first still holds it open.
//
// PKCS#11 permits only one C_Initialize per process, so the second attempt
// receives CKR_CRYPTOKI_ALREADY_INITIALIZED. That is a normal condition, not a
// failure: xkms composes several backends over one module.
func TestBackend_Initialize_SecondBackendInProcess(t *testing.T) {
	first := newProvisionedBackend(t, "two-backends")

	second, err := NewBackend(testConfig(first.config.Library, first.config.TokenLabel))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.Close()) })

	require.NoError(t, second.Initialize(softhsmtest.SOPIN, softhsmtest.UserPIN),
		"an already-initialized Cryptoki library must not fail the second backend")

	firstRandom, err := first.GenerateRandom(8)
	require.NoError(t, err, "the first backend must keep working")
	require.Len(t, firstRandom, 8)

	secondRandom, err := second.GenerateRandom(8)
	require.NoError(t, err, "the second backend must have a usable pool")
	require.Len(t, secondRandom, 8)
}
