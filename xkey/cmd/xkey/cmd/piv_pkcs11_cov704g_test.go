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

package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// pkcs11PIVConfig returns a PIV configuration bound to a fresh SoftHSM
// token, with the xkms process state reset before and after the test.
func pkcs11PIVConfig(t *testing.T, label string) *PIVConfig {
	t.Helper()
	newPIVProcess()
	t.Cleanup(newPIVProcess)
	token := softhsmtest.Provision(t, label)
	return &PIVConfig{
		Backend:       PIVBackendType("pkcs11"),
		PKCS11Library: token.Library,
		PKCS11Token:   token.Label,
		PKCS11PIN:     token.UserPIN,
		PKCS11SOPIN:   token.SOPIN,
	}
}

// openPKCS11PIVStorage opens the token's PIV certificate storage and closes
// it when the test ends, so the next test can initialize the library again.
func openPKCS11PIVStorage(t *testing.T, cfg *PIVConfig) xkms.PIVCertificateStorage {
	t.Helper()
	storage, err := createPKCS11PIVStorage(cfg, discardLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	return storage
}

// TestEnsurePKCS11Backend_InitializesOnceAndRewires proves the first call
// initializes and logs in to the token, and a second call in the same
// process reuses the initialized service instead of re-initializing it.
// The PIV manager is set up first, as `xkey piv generate` does.
func TestEnsurePKCS11Backend_InitializesOnceAndRewires(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-ensure")
	storage := openPKCS11PIVStorage(t, cfg)
	require.NoError(t, xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]xkms.PIVCertificateStorage{string(PIVBackendPKCS11): storage},
	}))

	require.NoError(t, ensurePKCS11Backend(cfg, discardLogger()))
	require.True(t, xkms.IsInitialized())
	_, err := xkms.GetBackend("pkcs11")
	require.NoError(t, err)

	require.NoError(t, ensurePKCS11Backend(cfg, discardLogger()))
}

// TestEnsurePKCS11Backend_RefusesAWrongPIN proves a token login failure is
// returned to the caller rather than leaving a half-usable backend wired.
func TestEnsurePKCS11Backend_RefusesAWrongPIN(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-wrong-pin")
	cfg.PKCS11PIN = "0000"

	require.ErrorIs(t, ensurePKCS11Backend(cfg, discardLogger()), pkcs11backend.ErrSessionPoolLogin)
}

// TestEnsurePKCS11Backend_RefusesAMissingLibrary proves a library path that
// does not exist leaves no PKCS#11 backend to log in to, and says so.
func TestEnsurePKCS11Backend_RefusesAMissingLibrary(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-no-lib")
	cfg.PKCS11Library = filepath.Join(t.TempDir(), "missing.so")

	require.ErrorIs(t, ensurePKCS11Backend(cfg, discardLogger()), xkms.ServiceErrBackendNotFound)
}

// TestEnsurePKCS11Backend_RequiresThePIVManager proves that a token login
// alone is not enough: without the PIV manager the resolver cannot be wired
// and the caller hears about it.
func TestEnsurePKCS11Backend_RequiresThePIVManager(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-no-manager")

	require.ErrorIs(t, ensurePKCS11Backend(cfg, discardLogger()), xkms.ServiceErrPIVNotInitialized)
	require.True(t, xkms.IsInitialized(), "the backend itself initialized")
}

// TestCreatePKCS11PIVStorage_OpensTheToken proves the PIV certificate
// storage opens a session on the configured token and round-trips a slot
// listing on it.
func TestCreatePKCS11PIVStorage_OpensTheToken(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-storage")

	storage := openPKCS11PIVStorage(t, cfg)
	slots, err := storage.List()
	require.NoError(t, err)
	require.Empty(t, slots, "a fresh token holds no PIV certificates")
}

// TestCreatePKCS11PIVStorage_RefusesAMissingLibrary proves a library path
// that does not exist is reported, not silently replaced by another store.
func TestCreatePKCS11PIVStorage_RefusesAMissingLibrary(t *testing.T) {
	cfg := pkcs11PIVConfig(t, "xkey-piv-storage-no-lib")
	cfg.PKCS11Library = filepath.Join(t.TempDir(), "missing.so")

	storage, err := createPKCS11PIVStorage(cfg, discardLogger())
	var storageErr *pivcert.PIVStorageError
	require.ErrorAs(t, err, &storageErr)
	require.Nil(t, storage)
}

// TestPIVPINSecret_SealsOnlyAPresentPIN proves an empty PIN means "no PIN"
// (nil) while a present PIN is sealed into protected memory.
func TestPIVPINSecret_SealsOnlyAPresentPIN(t *testing.T) {
	require.Nil(t, pivPINSecret(""))
	require.NotNil(t, pivPINSecret("123456"))
}
