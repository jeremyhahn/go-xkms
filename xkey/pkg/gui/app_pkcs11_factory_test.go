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

package gui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	errFactoryRefused = errors.New("pkcs11 test factory: refused")
	errLoginRefused   = errors.New("pkcs11 test token: login refused")
)

// loginKeyProvider is a software KeyProvider that also satisfies the
// Login seam registerPKCS11XKMSBackend calls on a PKCS#11 provider.
type loginKeyProvider struct {
	xkmssdk.KeyProvider
	loginErr error
	logins   int
}

func (p *loginKeyProvider) Login() error {
	p.logins++
	return p.loginErr
}

// usePKCS11Factory replaces the PKCS#11 factory lookup for one test. It
// records the configuration the app hands the factory and returns kp, or
// factoryErr when set.
func usePKCS11Factory(t *testing.T, kp xkmssdk.KeyProvider, factoryErr error) *map[string]interface{} {
	t.Helper()
	var got map[string]interface{}
	original := pkcs11BackendFactory
	pkcs11BackendFactory = func() (xkmssdk.ServiceBackendFactory, bool) {
		return func(cfg map[string]interface{}) (xkmssdk.KeyProvider, error) {
			got = cfg
			if factoryErr != nil {
				return nil, factoryErr
			}
			return kp, nil
		}, true
	}
	t.Cleanup(func() { pkcs11BackendFactory = original })
	return &got
}

// newPKCS11FactoryApp returns an initialized app, its log, and a software
// KeyProvider the stand-in factory can hand out as the token's provider.
func newPKCS11FactoryApp(t *testing.T) (*App, *logBuffer, *loginKeyProvider) {
	t.Helper()
	app := newMinimalApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	software, err := xkmssdk.GetBackend("software")
	require.NoError(t, err)
	return app, captureLog(app), &loginKeyProvider{KeyProvider: software.KeyProvider()}
}

func TestApp_RegisterPKCS11XKMSBackend_RegistersLoggedInBackend(t *testing.T) {
	app, logs, kp := newPKCS11FactoryApp(t)
	cfg := usePKCS11Factory(t, kp, nil)

	app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 3, "user-pin", "so-pin", "token")

	assert.Equal(t, map[string]interface{}{
		"library": "/usr/lib/softhsm/libsofthsm2.so",
		"slot":    3,
		"label":   "token",
		"pin":     "user-pin",
		"so_pin":  "so-pin",
	}, *cfg, "without a barrier the factory keeps its own session-only key storage")
	assert.Equal(t, 1, kp.logins, "the token must be logged in before it is registered")
	_, err := xkmssdk.GetBackend("pkcs11")
	require.NoError(t, err)
	assert.True(t, logs.Contains("dynamically registered PKCS#11 xkms backend"))
	assert.False(t, logs.Contains("user-pin"), "a PIN must never reach the log")
	assert.False(t, logs.Contains("so-pin"), "a PIN must never reach the log")
}

func TestApp_RegisterPKCS11XKMSBackend_BarrierRoutesKeyStorage(t *testing.T) {
	app, _, kp := newPKCS11FactoryApp(t)
	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))
	cfg := usePKCS11Factory(t, kp, nil)

	app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 0, "", "", "")

	assert.NotNil(t, (*cfg)["key_storage"], "an active barrier must back the PKCS#11 key datastore")
	for _, key := range []string{"label", "pin", "so_pin"} {
		assert.NotContains(t, *cfg, key, "an empty %s must not reach the factory", key)
	}
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.NoError(t, err)
}

func TestApp_RegisterPKCS11XKMSBackend_FactoryErrorRegistersNothing(t *testing.T) {
	app, logs, kp := newPKCS11FactoryApp(t)
	usePKCS11Factory(t, kp, errFactoryRefused)

	app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 0, "1234", "", "token")

	assert.True(t, logs.Contains("failed to create PKCS#11 key provider"))
	assert.True(t, logs.Contains(errFactoryRefused.Error()))
	assert.Zero(t, kp.logins)
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err)
}

func TestApp_RegisterPKCS11XKMSBackend_LoginErrorRegistersNothing(t *testing.T) {
	app, logs, kp := newPKCS11FactoryApp(t)
	kp.loginErr = errLoginRefused
	usePKCS11Factory(t, kp, nil)

	app.registerPKCS11XKMSBackend("/usr/lib/softhsm/libsofthsm2.so", 0, "1234", "", "token")

	assert.True(t, logs.Contains("failed to login to PKCS#11 token"))
	assert.True(t, logs.Contains(errLoginRefused.Error()))
	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "a token that refuses login must not be registered")
}
