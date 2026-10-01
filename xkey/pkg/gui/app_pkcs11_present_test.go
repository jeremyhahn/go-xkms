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

package gui

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestApp_RegisterPKCS11XKMSBackend_UnloadableLibrary verifies
// registerPKCS11XKMSBackend fails closed (no panic, no backend registered)
// when the pkcs11 backend factory is built in but the token's module cannot
// be loaded -- the case a binary built with the pkcs11 tag meets when the
// configured library is missing.
func TestApp_RegisterPKCS11XKMSBackend_UnloadableLibrary(t *testing.T) {
	app := newMinimalApp(t)

	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.True(t, xkmssdk.IsInitialized())

	_, ok := xkmssdk.GetBackendFactory(xkmssdk.BackendPKCS11)
	require.True(t, ok, "precondition: a pkcs11 build registers the pkcs11 backend factory")

	missing := filepath.Join(t.TempDir(), "no-such-pkcs11-module.so")
	assert.NotPanics(t, func() {
		app.registerPKCS11XKMSBackend(missing, 0, "1234", "", "token")
	})
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "no pkcs11 backend may be registered when its module cannot be loaded")
}
