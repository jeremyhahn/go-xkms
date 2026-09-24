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

//go:build frost

package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newSoftwareKeyProviderForTest builds a minimal in-memory software backend
// to stand in for backends.frost.secret_backend in tests.
func newSoftwareKeyProviderForTest(t *testing.T) types.KeyProvider {
	t.Helper()
	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	be, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	return be
}

// TestInitFrostBackend_Success verifies that a frost-tagged build registers
// the FROST backend under s.keyProviders["frost"] when backends.frost is
// enabled and its secret_backend is already initialized.
func TestInitFrostBackend_Success(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
		Backends: config.BackendsConfig{
			Frost: &config.FrostConfig{
				Enabled:          true,
				PublicPath:       "frost/public",
				SecretBackend:    "software",
				Algorithm:        "FROST-Ed25519-SHA512",
				DefaultThreshold: 2,
				DefaultTotal:     3,
			},
		},
	})
	s.keyProviders = map[string]types.KeyProvider{
		"software": newSoftwareKeyProviderForTest(t),
	}

	err := s.initFrostBackend()
	require.NoError(t, err)

	registered, ok := s.keyProviders["frost"]
	require.True(t, ok, "expected \"frost\" to be registered in s.keyProviders")
	assert.Equal(t, types.BackendTypeFrost, registered.Type())

	_, ok = registered.(*frost.FrostBackend)
	assert.True(t, ok, "expected s.keyProviders[\"frost\"] to be a *frost.FrostBackend, got %T", registered)
}

// TestInitFrostBackend_Disabled verifies that initFrostBackend is a no-op
// when backends.frost is nil or not enabled.
func TestInitFrostBackend_Disabled(t *testing.T) {
	tests := []struct {
		name  string
		frost *config.FrostConfig
	}{
		{name: "nil section", frost: nil},
		{name: "present but disabled", frost: &config.FrostConfig{Enabled: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMinimalServer(t, &config.Config{
				Storage:  config.StorageConfig{Backend: "memory"},
				Backends: config.BackendsConfig{Frost: tt.frost},
			})
			s.keyProviders = map[string]types.KeyProvider{}

			err := s.initFrostBackend()
			require.NoError(t, err)
			assert.Empty(t, s.keyProviders)
		})
	}
}

// TestInitFrostBackend_SecretBackendUnavailable verifies that
// initFrostBackend fails closed with *ErrFrostSecretBackendUnavailable
// when secret_backend names a backend that is not (yet) registered in
// s.keyProviders, rather than silently constructing a FROST backend with
// nowhere to keep the secret share.
func TestInitFrostBackend_SecretBackendUnavailable(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
		Backends: config.BackendsConfig{
			Frost: &config.FrostConfig{
				Enabled:       true,
				PublicPath:    "frost/public",
				SecretBackend: "tpm2",
			},
		},
	})
	s.keyProviders = map[string]types.KeyProvider{}

	err := s.initFrostBackend()
	require.Error(t, err)
	assert.NotContains(t, s.keyProviders, "frost")

	var unavailableErr *ErrFrostSecretBackendUnavailable
	require.True(t, errors.As(err, &unavailableErr), "error must unwrap to *ErrFrostSecretBackendUnavailable, got %v", err)
	assert.Equal(t, "tpm2", unavailableErr.Backend)
}
