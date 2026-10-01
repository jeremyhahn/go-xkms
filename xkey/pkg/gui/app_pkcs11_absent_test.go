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

// Whether the PKCS#11 backend factory exists is decided by the pkcs11 build
// tag (pkg/xkms/register_pkcs11.go), and xkey's Makefile builds its tests
// with that tag by default. Each build therefore gets the test of its own
// case: this file runs without the tag, app_pkcs11_present_test.go with it.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestApp_RegisterPKCS11XKMSBackend_FactoryNotRegistered verifies
// registerPKCS11XKMSBackend fails closed (no panic, no backend registered)
// when the xkms process was built without the pkcs11 backend factory, as a
// binary built without the pkcs11 tag is.
func TestApp_RegisterPKCS11XKMSBackend_FactoryNotRegistered(t *testing.T) {
	app := newMinimalApp(t)

	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.True(t, xkmssdk.IsInitialized())

	_, ok := xkmssdk.GetBackendFactory(xkmssdk.BackendPKCS11)
	require.False(t, ok, "precondition: this test binary must not have the pkcs11 backend factory registered")

	assert.NotPanics(t, func() {
		app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 0, "1234", "", "token")
	})
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "no pkcs11 backend may be registered when its factory is unavailable")
}
