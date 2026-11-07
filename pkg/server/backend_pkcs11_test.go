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

package server

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServerForPKCS11 builds a minimal *Server for initPKCS11Backend,
// mirroring newTestServerForPhone: an in-memory storage backend needs no
// filesystem or SoftHSM setup, so these tests exercise config validation
// (including secret resolution) without depending on a real PKCS#11 module.
func newTestServerForPKCS11(t *testing.T, pkcs11Cfg *config.PKCS11Config) *Server {
	t.Helper()
	s := &Server{
		config: &config.Config{
			Datastore: config.DatastoreConfig{Engine: "memory"},
			Backends:  config.BackendsConfig{PKCS11: pkcs11Cfg},
		},
		backends:     make(map[string]xkms.Backend),
		keyProviders: make(map[string]types.KeyProvider),
		logger:       slog.Default(),
	}
	// The one shared datastore every createStorage call is a view over
	// (go-xkms#1345); Server.New would have opened it.
	s.setSharedStorage(storage.NewMemory())
	return s
}

// TestInitPKCS11Backend_UnresolvedCredentialReferenceFails proves the
// go-xkms#610 fix at the PKCS#11 backend specifically: a "credential://"
// Pin is refused with *types.SecretReferenceUnresolvedError during backend
// construction (pkcs11.Config.Validate, reached before the library is even
// loaded) instead of being used verbatim as the PIN, when nothing has
// resolved it first — exactly what this test's hand-built *Server does
// (initPKCS11Backend called directly, bypassing Server.New's ordering).
// Through the real Server.New path, go-xkms#653's approved item 2 moved
// resolveConfigSecrets before initializeBackends, so a "credential://" Pin
// DOES resolve there first; see TestBackendCredentials_ResolveViaCredentialReference
// (secret_wiring_test.go) for that path.
func TestInitPKCS11Backend_UnresolvedCredentialReferenceFails(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	require.NoError(t, os.WriteFile(tempLib, []byte("test"), 0o644))

	srv := newTestServerForPKCS11(t, &config.PKCS11Config{
		Enabled: true,
		Library: tempLib,
		Token:   "test-token",
		Pin:     &types.SecretValue{Raw: "credential://pkcs11-pin"},
	})

	err := srv.initPKCS11Backend()
	require.Error(t, err)

	var refErr *types.SecretReferenceUnresolvedError
	require.True(t, errors.As(err, &refErr),
		"error must unwrap to *types.SecretReferenceUnresolvedError, got %v", err)
	assert.Equal(t, "credential", refErr.Scheme)

	_, ok := srv.keyProviders["pkcs11"]
	assert.False(t, ok, "a failed resolution must not leave a pkcs11 backend registered")
}

// TestInitPKCS11Backend_EmptyPinMeansNotConfigured proves an empty Pin (the
// zero SecretValue -- no pin configured) is accepted by config validation:
// emptiness must stay distinguishable from an unresolved reference.
func TestInitPKCS11Backend_EmptyPinMeansNotConfigured(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	require.NoError(t, os.WriteFile(tempLib, []byte("test"), 0o644))

	srv := newTestServerForPKCS11(t, &config.PKCS11Config{
		Enabled: true,
		Library: tempLib,
		Token:   "test-token",
	})

	// With no PIN configured the backend looks for one in the pre-barrier
	// store, which this server cannot open, so construction still fails --
	// but NOT on secret resolution, which is what this test isolates.
	err := srv.initPKCS11Backend()
	require.Error(t, err)

	var refErr *types.SecretReferenceUnresolvedError
	assert.False(t, errors.As(err, &refErr),
		"an unconfigured PIN must never surface as an unresolved reference")
}
