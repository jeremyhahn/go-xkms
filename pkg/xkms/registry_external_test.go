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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// externalProvider stands in for a backend living in another module: it
// delegates the cryptography to the software backend and reports its own
// registered type, exactly as an out-of-tree backend reports its own.
type externalProvider struct {
	types.KeyProvider
	backendType types.BackendType
}

func (p *externalProvider) Type() types.BackendType { return p.backendType }

// newExternalFactory returns a factory for name that records the config it
// was constructed with.
func newExternalFactory(name BackendType, seen *atomic.Pointer[map[string]interface{}]) BackendFactory {
	return func(config map[string]interface{}) (types.KeyProvider, error) {
		seen.Store(&config)
		kp, err := newSoftwareKeyProvider(config)
		if err != nil {
			return nil, err
		}
		return &externalProvider{KeyProvider: kp, backendType: types.BackendType(name)}, nil
	}
}

// forgetBackendAfterTest removes name from this package's registries when
// the test ends, so later AutoInitialize tests see only the compiled-in set.
// The types-level name claim is permanent, so every test uses its own name.
func forgetBackendAfterTest(t *testing.T, name BackendType) {
	t.Helper()
	t.Cleanup(func() {
		Reset()
		deleteCopyOnWrite(&backendRegistry, name)
		deleteCopyOnWrite(&backendFactories, name)
	})
}

func deleteCopyOnWrite[V any](registry *atomic.Pointer[map[BackendType]V], name BackendType) {
	for {
		current := registry.Load()
		updated := make(map[BackendType]V)
		for k, v := range loadCopyOnWrite(registry) {
			if k != name {
				updated[k] = v
			}
		}
		if registry.CompareAndSwap(current, &updated) {
			return
		}
	}
}

// TestRegisterExternalBackend_EndToEnd registers an out-of-tree backend type
// through the hook and drives it through the same path the built-in backends
// use: validation, AutoInitialize with per-backend config, Key ID parsing,
// key generation and signing.
func TestRegisterExternalBackend_EndToEnd(t *testing.T) {
	name := BackendType("xkms-ext-e2e")
	forgetBackendAfterTest(t, name)
	require.False(t, name.IsValid())

	var seen atomic.Pointer[map[string]interface{}]
	require.NoError(t, RegisterExternalBackend(ExternalBackend{
		Type:    name,
		Factory: newExternalFactory(name, &seen),
	}))

	assert.True(t, name.IsValid())
	assert.True(t, IsBackendSupported(name))
	assert.Contains(t, SupportedBackends(), name)
	assert.True(t, types.StoreType(name).IsValid())
	assert.Equal(t, types.StoreType(name), types.ParseStoreType(string(name)))

	// Initialize is a no-op once the service is up; start from a clean one.
	Reset()
	require.NoError(t, AutoInitialize(&AutoConfig{
		DefaultBackend: string(name),
		BackendConfigs: map[BackendType]map[string]interface{}{
			name: {"device": "/dev/ttyACM0"},
		},
	}))
	require.NotNil(t, seen.Load(), "AutoInitialize did not construct the external backend")
	assert.Equal(t, "/dev/ttyACM0", (*seen.Load())["device"])
	b, err := GetBackend(string(name))
	require.NoError(t, err)
	assert.Equal(t, types.StoreType(name), b.Type())

	def, err := DefaultBackend()
	require.NoError(t, err)
	assert.Equal(t, types.StoreType(name), def.Type())

	kid := string(name) + ":signing:ecdsa-p256:fw-identity"
	attrs, err := ParseKeyIDToAttributes(kid)
	require.NoError(t, err)
	assert.Equal(t, types.StoreType(name), attrs.StoreType)
	assert.Equal(t, string(name), attrs.Backend)

	priv, err := GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	pub := priv.(crypto.Signer).Public().(*ecdsa.PublicKey)

	data := []byte("firmware attestation challenge")
	sig, err := Sign(context.Background(), kid, data, nil)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
}

// TestRegisterExternalBackend_Refusals proves duplicate, built-in, empty,
// malformed and factory-less registrations are refused with typed errors and
// register nothing.
func TestRegisterExternalBackend_Refusals(t *testing.T) {
	dup := BackendType("xkms-ext-dup")
	forgetBackendAfterTest(t, dup)
	var seen atomic.Pointer[map[string]interface{}]
	require.NoError(t, RegisterExternalBackend(ExternalBackend{Type: dup, Factory: newExternalFactory(dup, &seen)}))

	tests := []struct {
		name    string
		backend ExternalBackend
		want    error
	}{
		{"duplicate", ExternalBackend{Type: dup, Factory: newSoftwareKeyProvider}, types.ErrBackendTypeRegistered},
		{"xkms-only builtin", ExternalBackend{Type: BackendPKCS8, Factory: newSoftwareKeyProvider}, types.ErrBackendTypeRegistered},
		{"shared builtin", ExternalBackend{Type: BackendTPM2, Factory: newSoftwareKeyProvider}, types.ErrBackendTypeRegistered},
		{"empty", ExternalBackend{Type: "", Factory: newSoftwareKeyProvider}, types.ErrInvalidBackendTypeName},
		{"malformed", ExternalBackend{Type: "Fw:Backend", Factory: newSoftwareKeyProvider}, types.ErrInvalidBackendTypeName},
		{"nil factory", ExternalBackend{Type: "xkms-ext-nofactory"}, ErrNilBackendFactory},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterExternalBackend(tc.backend)
			require.ErrorIs(t, err, tc.want)
			var regErr *types.BackendTypeRegistrationError
			require.ErrorAs(t, err, &regErr)
			assert.Equal(t, types.BackendType(tc.backend.Type), regErr.Type)
		})
	}

	// The refused nil-factory name was not claimed: it registers once it
	// has a factory.
	assert.False(t, BackendType("xkms-ext-nofactory").IsValid())
	assert.False(t, IsBackendSupported("xkms-ext-nofactory"))

	// The duplicate kept its original factory.
	f, ok := GetBackendFactory(dup)
	require.True(t, ok)
	_, err := f(map[string]interface{}{"marker": "original"})
	require.NoError(t, err)
	assert.Equal(t, "original", (*seen.Load())["marker"])
}

// TestRegisterExternalBackend_UnknownTypeStaysInvalid proves a type nobody
// registered is refused on every path an external type opens.
func TestRegisterExternalBackend_UnknownTypeStaysInvalid(t *testing.T) {
	t.Cleanup(func() { Reset() })
	unknown := BackendType("xkms-ext-never-registered")

	assert.False(t, unknown.IsValid())
	assert.False(t, types.StoreType(unknown).IsValid())
	assert.Equal(t, types.StoreUnknown, types.ParseStoreType(string(unknown)))

	_, err := RequireBackend(unknown)
	require.ErrorIs(t, err, ErrFeatureNotCompiled)

	_, err = ParseKeyIDToAttributes(string(unknown) + ":signing:ecdsa-p256:k")
	require.ErrorIs(t, err, ErrInvalidBackendType)

	err = AutoInitialize(&AutoConfig{
		BackendConfigs: map[BackendType]map[string]interface{}{unknown: {}},
	})
	require.ErrorIs(t, err, ErrFeatureNotCompiled)
}

// TestRegisterBackendFactory_ConcurrentRegistrationsAllLand proves the
// copy-on-write registries lose no entry under concurrent registration.
func TestRegisterBackendFactory_ConcurrentRegistrationsAllLand(t *testing.T) {
	names := make([]BackendType, 16)
	for i := range names {
		names[i] = BackendType(fmt.Sprintf("xkms-cc-%d", i))
		forgetBackendAfterTest(t, names[i])
	}

	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterBackendFactory(n, newSoftwareKeyProvider)
			RegisterBackend(n)
		}()
	}
	wg.Wait()

	for _, n := range names {
		assert.True(t, IsBackendSupported(n), n)
		_, ok := GetBackendFactory(n)
		assert.True(t, ok, n)
	}
}
