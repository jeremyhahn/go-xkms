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

//go:build pkcs11

package rand

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionedSlot provisions an isolated SoftHSM2 token and resolves the slot
// it landed on, without leaving a session open. Tests supply the returned
// library path and slot directly to newPKCS11Resolver so they exercise the
// production construction path exactly as a caller would, rather than a
// second, test-only entry point.
func provisionedSlot(t *testing.T, label string) (library string, slot uint, tok softhsmtest.Token) {
	t.Helper()

	tok = softhsmtest.Provision(t, label)

	ctx := pkcs11.New(tok.Library)
	require.NotNil(t, ctx, "SoftHSM2 library must load")
	require.NoError(t, ctx.Initialize())
	slot = tok.Slot(t, ctx)
	ctx.Finalize()
	ctx.Destroy()

	return tok.Library, slot, tok
}

// TestNewPKCS11Resolver_RejectsNilConfig verifies construction fails fast
// with a typed error rather than dereferencing a nil config.
func TestNewPKCS11Resolver_RejectsNilConfig(t *testing.T) {
	resolver, err := newPKCS11Resolver(nil)

	require.Error(t, err)
	assert.Nil(t, resolver)
	var typed *errs.Message
	assert.True(t, errors.As(err, &typed), "expected *errs.Message, got %T", err)
}

// TestNewPKCS11Resolver_RejectsEmptyModule verifies a config with no module
// path is rejected before any PKCS#11 call is attempted.
func TestNewPKCS11Resolver_RejectsEmptyModule(t *testing.T) {
	resolver, err := newPKCS11Resolver(&PKCS11Config{})

	require.Error(t, err)
	assert.Nil(t, resolver)
	var typed *errs.Message
	assert.True(t, errors.As(err, &typed), "expected *errs.Message, got %T", err)
}

// TestNewPKCS11Resolver_RejectsUnloadableModule verifies a module path that
// does not resolve to a loadable shared object surfaces a typed error rather
// than a nil-pointer panic later.
func TestNewPKCS11Resolver_RejectsUnloadableModule(t *testing.T) {
	resolver, err := newPKCS11Resolver(&PKCS11Config{Module: "/nonexistent/libsofthsm2.so"})

	require.Error(t, err)
	assert.Nil(t, resolver)
	var typed *errs.Message
	assert.True(t, errors.As(err, &typed), "expected *errs.Message, got %T", err)
}

// TestNewPKCS11Resolver_RejectsInvalidSlot verifies a slot ID that does not
// correspond to any token on a real, loadable module surfaces the wrapped
// PKCS#11 session error instead of succeeding silently.
func TestNewPKCS11Resolver_RejectsInvalidSlot(t *testing.T) {
	softhsmtest.Provision(t, "rand-invalid-slot") // redirects SOFTHSM2_CONF for this test
	lib := softhsmtest.Library(t)

	resolver, err := newPKCS11Resolver(&PKCS11Config{
		Module: lib,
		SlotID: 999999,
	})

	require.Error(t, err)
	assert.Nil(t, resolver)
	var typed *errs.Wrapped
	require.True(t, errors.As(err, &typed), "expected *errs.Wrapped, got %T", err)
	assert.Equal(t, "failed to open PKCS#11 session", typed.Msg)
}

// TestNewPKCS11Resolver_RejectsIncorrectPIN verifies a login failure closes
// the session/context it opened and surfaces the wrapped authentication
// error, rather than leaking a half-initialized resolver.
func TestNewPKCS11Resolver_RejectsIncorrectPIN(t *testing.T) {
	lib, slot, _ := provisionedSlot(t, "rand-bad-pin")

	resolver, err := newPKCS11Resolver(&PKCS11Config{
		Module:      lib,
		SlotID:      slot,
		PINRequired: true,
		PIN:         mustSecret(t, "0000-wrong-pin"),
	})

	require.Error(t, err)
	assert.Nil(t, resolver)
	var typed *errs.Wrapped
	require.True(t, errors.As(err, &typed), "expected *errs.Wrapped, got %T", err)
	assert.Equal(t, "failed to authenticate with PKCS#11", typed.Msg)
}

// TestPKCS11Resolver_FullLifecycleWithoutPIN exercises the resolver against a
// real, freshly provisioned SoftHSM2 token when no PIN is configured:
// construction, Rand, Read, the Source adapter, Available, and Close -- and
// that Close makes the resolver (and its Source) unavailable, and Rand after
// Close reports the typed "closed" error instead of touching a dangling
// context.
func TestPKCS11Resolver_FullLifecycleWithoutPIN(t *testing.T) {
	assert.True(t, pkcs11Available(), "the pkcs11 build tag must select the real implementation")

	lib, slot, _ := provisionedSlot(t, "rand-no-pin")

	r, err := newPKCS11Resolver(&PKCS11Config{Module: lib, SlotID: slot})
	require.NoError(t, err)
	require.True(t, r.Available())

	data, err := r.Rand(32)
	require.NoError(t, err)
	assert.Len(t, data, 32)

	buf := make([]byte, 16)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 16, n)

	src := r.Source()
	require.True(t, src.Available())
	srcData, err := src.Rand(8)
	require.NoError(t, err)
	assert.Len(t, srcData, 8)

	require.NoError(t, src.Close())
	assert.False(t, r.Available(), "closing the Source must close the underlying resolver")

	_, err = r.Rand(1)
	require.Error(t, err)
	var typed *errs.Message
	assert.True(t, errors.As(err, &typed), "expected *errs.Message, got %T", err)

	// Close is idempotent.
	require.NoError(t, r.Close())
}

// TestPKCS11Resolver_LoginWithCorrectPIN verifies the PIN login branch
// succeeds end-to-end against a real token and that Close logs out rather
// than leaving the session authenticated.
func TestPKCS11Resolver_LoginWithCorrectPIN(t *testing.T) {
	lib, slot, tok := provisionedSlot(t, "rand-good-pin")

	r, err := newPKCS11Resolver(&PKCS11Config{
		Module:      lib,
		SlotID:      slot,
		PINRequired: true,
		PIN:         mustSecret(t, tok.UserPIN),
	})
	require.NoError(t, err)

	data, err := r.Rand(24)
	require.NoError(t, err)
	assert.Len(t, data, 24)

	require.NoError(t, r.Close())
	assert.False(t, r.Available())
}

// TestPKCS11Resolver_CloseReportsUnderlyingFailures proves that a Logout or
// CloseSession failure inside Close is reported to the caller instead of
// being discarded (go-xkms#1347). Closing the session out from under the
// resolver, from the same package's test, guarantees Close's own Logout and
// CloseSession calls fail with CKR_SESSION_HANDLE_INVALID rather than racing
// against the resolver's own concurrent use of the session.
func TestPKCS11Resolver_CloseReportsUnderlyingFailures(t *testing.T) {
	lib, slot, tok := provisionedSlot(t, "rand-close-err")

	r, err := newPKCS11Resolver(&PKCS11Config{
		Module:      lib,
		SlotID:      slot,
		PINRequired: true,
		PIN:         mustSecret(t, tok.UserPIN),
	})
	require.NoError(t, err)

	pr, ok := r.(*pkcs11Resolver)
	require.True(t, ok, "expected the concrete *pkcs11Resolver")

	require.NoError(t, pr.ctx.CloseSession(pr.session),
		"closing the session directly must itself succeed to set up the failure")

	err = r.Close()
	require.Error(t, err, "Close must surface the Logout/CloseSession failures instead of discarding them")
}
