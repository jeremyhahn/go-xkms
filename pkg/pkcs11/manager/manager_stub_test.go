//go:build !pkcs11

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

package manager

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStubManager_IsAvailableIsFalse pins the single flag every caller uses to
// decide whether to offer PKCS#11 features. If a build without the pkcs11 tag
// ever reported true, the UI and CLI would advertise HSM support that cannot
// work and every subsequent call would fail at a much less obvious place.
func TestStubManager_IsAvailableIsFalse(t *testing.T) {
	mgr := New()

	assert.False(t, mgr.IsAvailable(),
		"a build without -tags pkcs11 must not advertise PKCS#11 support")
}

// TestStubManager_AllOperationsFailClosed verifies every fallible operation on
// the stub returns ErrPKCS11Disabled *and* a nil result. Returning a nil error
// or a non-nil zero value here would let a caller proceed into a nil
// dereference instead of surfacing the "rebuild with -tags pkcs11" message, so
// both halves of the contract matter.
func TestStubManager_AllOperationsFailClosed(t *testing.T) {
	mgr := New(WithLogger(slog.Default()))

	t.Run("RegisterModule", func(t *testing.T) {
		id, err := mgr.RegisterModule("/usr/lib/softhsm/libsofthsm2.so", "SoftHSM2")
		require.ErrorIs(t, err, ErrPKCS11Disabled)
		assert.Empty(t, id, "no module ID may be handed out when support is compiled out")
	})

	t.Run("UnregisterModule", func(t *testing.T) {
		require.ErrorIs(t, mgr.UnregisterModule("pkcs11-libsofthsm2"), ErrPKCS11Disabled)
	})

	t.Run("RefreshSlots", func(t *testing.T) {
		slots, err := mgr.RefreshSlots("pkcs11-libsofthsm2")
		require.ErrorIs(t, err, ErrPKCS11Disabled)
		assert.Nil(t, slots)
	})

	t.Run("GetModule", func(t *testing.T) {
		info, err := mgr.GetModule("pkcs11-libsofthsm2")
		require.ErrorIs(t, err, ErrPKCS11Disabled)
		assert.Nil(t, info)
	})

	t.Run("InitializeToken", func(t *testing.T) {
		err := mgr.InitializeToken("pkcs11-libsofthsm2", 0, "label", "12345678", "1234")
		require.ErrorIs(t, err, ErrPKCS11Disabled)
	})

	t.Run("TestLogin", func(t *testing.T) {
		require.ErrorIs(t, mgr.TestLogin("pkcs11-libsofthsm2", 0, "1234"), ErrPKCS11Disabled)
	})

	t.Run("Connect", func(t *testing.T) {
		backend, err := mgr.Connect("pkcs11-libsofthsm2", 0, "1234", "12345678")
		require.ErrorIs(t, err, ErrPKCS11Disabled)
		assert.Nil(t, backend, "a nil-error/non-nil-backend pair would crash the caller")
	})

	t.Run("Disconnect", func(t *testing.T) {
		require.ErrorIs(t, mgr.Disconnect("pkcs11-libsofthsm2", 0), ErrPKCS11Disabled)
	})

	t.Run("GetConnection", func(t *testing.T) {
		conn, err := mgr.GetConnection("pkcs11-libsofthsm2", 0)
		require.ErrorIs(t, err, ErrPKCS11Disabled)
		assert.Nil(t, conn)
	})
}

// TestStubManager_DisabledErrorTellsUserHowToFix checks the sentinel's message
// still names the build tag. This string is the only guidance an operator gets
// when an HSM-backed deployment is running a CLI-flavoured binary.
func TestStubManager_DisabledErrorTellsUserHowToFix(t *testing.T) {
	_, err := New().RegisterModule("/usr/lib/softhsm/libsofthsm2.so", "SoftHSM2")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkcs11",
		"the disabled error must name the build tag the operator needs")
}

// TestStubManager_CloseIsIdempotent verifies Close never errors and may be
// called repeatedly. Shutdown paths call Close from a defer and from an
// explicit teardown, so a second call must not fail.
func TestStubManager_CloseIsIdempotent(t *testing.T) {
	mgr := New()

	require.NoError(t, mgr.Close())
	require.NoError(t, mgr.Close())

	// Operations after Close still fail closed with the same sentinel rather
	// than switching to a different error or succeeding.
	_, err := mgr.RegisterModule("/usr/lib/softhsm/libsofthsm2.so", "SoftHSM2")
	assert.True(t, errors.Is(err, ErrPKCS11Disabled))
}
