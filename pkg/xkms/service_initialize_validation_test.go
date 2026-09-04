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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitialize_ValidatesBackendNames covers #174: Initialize assigned
// config.Backends verbatim and never validated its keys, while
// RegisterServiceBackend validated every name it was given. The
// single-registration path was guarded and the bulk entry point was not — and
// Initialize is exported as SDK surface (ServiceInitialize), so an embedder
// reached it directly.
//
// The names below are ones RegisterServiceBackend already refuses. Accepting
// them here meant the same service could hold a name no other entry point
// would have admitted.
func TestInitialize_ValidatesBackendNames(t *testing.T) {
	cases := []struct {
		name    string
		backend string
		why     string
	}{
		{"uppercase", "HSM-A", "the canonical validator is lowercase-only"},
		{"mixed case", "Software", "same"},
		{"leading space", " software", "whitespace is not part of a name"},
		{"trailing space", "software ", "same"},
		{"underscore", "hsm_a", "the charset is a-z, 0-9 and dash"},
		{"colon", "hsm:a", "the identifier separator must never appear in a name"},
		{"slash", "hsm/a", "path characters must not reach a storage identifier"},
		{"empty", "", "a nameless backend cannot be addressed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			Reset()
			t.Cleanup(Reset)

			err := Initialize(&ServiceConfig{
				Backends:       map[string]Backend{tc.backend: &mockXKMSBackend{}},
				DefaultBackend: tc.backend,
			})
			require.Error(t, err, "Initialize must refuse %q: %s", tc.backend, tc.why)
			assert.ErrorIs(t, err, ErrInvalidBackendName)
		})
	}
}

// TestInitialize_RefusesFoldCollidingBackendNames is the case #174 is named
// for: two backend names that differ only by case, registered at once.
//
// Downstream code compares backend names case-insensitively — pkg/api/mcp's
// import guard does exactly that — so with both registered a caller naming one
// passes the guard and reaches the other. Rejecting uppercase makes the
// collision unconstructible rather than merely unlikely.
func TestInitialize_RefusesFoldCollidingBackendNames(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	err := Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"hsm-a": &mockXKMSBackend{},
			"HSM-A": &mockXKMSBackend{},
		},
		DefaultBackend: "hsm-a",
	})
	require.Error(t, err, "two names differing only by case must not both register")
	assert.ErrorIs(t, err, ErrInvalidBackendName)
}

// TestInitialize_ValidatesKeyProviderNames covers the other map on the same
// config. A key provider is addressed by name too, so the same rule applies;
// validating only one map would leave the gap half open.
func TestInitialize_ValidatesKeyProviderNames(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	err := Initialize(&ServiceConfig{
		Backends:     map[string]Backend{"software": &mockXKMSBackend{}},
		KeyProviders: map[string]Backend{"PKCS8": &mockXKMSBackend{}},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidBackendName)
}

// TestInitialize_AcceptsValidNames is the companion: the change must not
// refuse a configuration that was always legal. Every name here is one
// RegisterServiceBackend accepts.
func TestInitialize_AcceptsValidNames(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	err := Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": &mockXKMSBackend{},
			"pkcs11":   &mockXKMSBackend{},
			"hsm-a":    &mockXKMSBackend{},
			"vault-2":  &mockXKMSBackend{},
		},
		KeyProviders:   map[string]Backend{"pkcs8": &mockXKMSBackend{}},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)
	assert.Equal(t, "software", svc.defaultBackend)
}

// TestInitialize_AcceptsNamesThatAreNotStoreTypes pins the distinction #297 is
// about, at the registration end. A backend name is a registry key, not a
// store-type keyword: "hsm-a" is a legal name that ParseStoreType maps to
// StoreUnknown. Initialize must validate it as a NAME, and must not start
// refusing names merely because they are not known store types.
func TestInitialize_AcceptsNamesThatAreNotStoreTypes(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	err := Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"token-a": &mockXKMSBackend{},
			"token-b": &mockXKMSBackend{},
		},
		DefaultBackend: "token-a",
	})
	require.NoError(t, err, "a registrable name that is not a store type must remain registrable")

	svc, err := Get()
	require.NoError(t, err)
	_, err = svc.LookupBackend("token-b")
	assert.NoError(t, err, "and must resolve through the canonical lookup")
}
