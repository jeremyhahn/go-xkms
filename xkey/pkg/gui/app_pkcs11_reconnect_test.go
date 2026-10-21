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

//go:build !pkcs11

package gui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errCloseRefused is the close failure a stale PKCS#11 backend reports.
var errCloseRefused = errors.New("pkcs11 test backend: close refused")

// staleBackend is a registered backend whose Close fails, as a backend
// whose token was pulled mid-session does.
type staleBackend struct {
	xkmssdk.ServiceBackend
	closed bool
}

func (b *staleBackend) Close() error {
	b.closed = true
	return errCloseRefused
}

// TestApp_RegisterPKCS11XKMSBackend_ReconnectReplacesStaleBackend verifies a
// reconnect closes and unregisters the PKCS#11 backend already registered,
// even when its Close fails, before looking up the factory again.
func TestApp_RegisterPKCS11XKMSBackend_ReconnectReplacesStaleBackend(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	logs := captureLog(app)

	software, err := xkmssdk.GetBackend("software")
	require.NoError(t, err)
	stale := &staleBackend{ServiceBackend: software}
	require.NoError(t, xkmssdk.RegisterServiceBackend("pkcs11", stale))

	app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 0, "1234", "", "token")

	assert.True(t, stale.closed, "the stale backend must be closed before it is replaced")
	assert.True(t, logs.Contains("replacing existing PKCS#11 xkms backend"))
	assert.True(t, logs.Contains("failed to close existing PKCS#11 xkms backend"))
	_, err = xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "the stale backend must be unregistered when no factory can replace it")
}

// TestApp_RegisterPKCS11XKMSBackend_YubiKeyWithoutSOPinKeepsBackend verifies
// a YubiKey reconnect without the management key is refused before the
// registered backend is touched.
func TestApp_RegisterPKCS11XKMSBackend_YubiKeyWithoutSOPinKeepsBackend(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)

	software, err := xkmssdk.GetBackend("software")
	require.NoError(t, err)
	stale := &staleBackend{ServiceBackend: software}
	require.NoError(t, xkmssdk.RegisterServiceBackend("pkcs11", stale))

	app.registerPKCS11XKMSBackend("/usr/lib/libykcs11.so", 0, "123456", "", "YubiKey PIV")

	assert.False(t, stale.closed, "a refused registration must leave the existing backend open")
	_, err = xkmssdk.GetBackend("pkcs11")
	assert.NoError(t, err)
}
