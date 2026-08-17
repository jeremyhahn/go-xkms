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

package cmd

import (
	"context"
	"crypto/x509"
	"log/slog"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withPIVStoragePath points the "piv" command group's file storage at a
// temporary directory for the duration of the test, restoring the prior
// value on cleanup so other tests in this package keep their own storage
// path. It never touches the real ~/.xkey or ./data/piv locations a bare
// `go test` run must not write to.
func withPIVStoragePath(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	original := viper.GetString(viperKeyPIVStoragePath)
	viper.Set(viperKeyPIVStoragePath, tmpDir)
	t.Cleanup(func() { viper.Set(viperKeyPIVStoragePath, original) })
	return tmpDir
}

// storeTestPIVCertificate stores a self-signed test certificate in slot
// under the "software" file backend, using whatever storage path Viper
// currently resolves (see withPIVStoragePath). It returns the stored
// certificate.
func storeTestPIVCertificate(t *testing.T, slot xkms.PIVSlot) *x509.Certificate {
	t.Helper()
	cert := generateTestCertificate(t)

	cfg := &PIVConfig{
		Backend:     PIVBackendSoftware,
		StorageType: PIVStorageTypeFile,
		StoragePath: viper.GetString(viperKeyPIVStoragePath),
	}
	storage, err := createPIVStorage(cfg, slog.Default())
	require.NoError(t, err)
	defer func() { _ = storage.Close() }()

	require.NoError(t, storage.Store(slot, cert))
	return cert
}

// registerTestServer records serverURL in the server registry so
// runAuthLoginPIV's registry.Lookup succeeds, mirroring the manual
// registration pattern the existing auth tests use.
func registerTestServer(t *testing.T, serverURL string) {
	t.Helper()
	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer cleanup()

	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:      serverURL,
		Name:     serverURL,
		Protocol: serverregistry.ProtocolREST,
	}))
}

// authPIVCmd builds a bare *cobra.Command carrying the flags
// runAuthLoginPIV reads directly (slot, backend), mirroring how the
// existing auth tests exercise runAuthLogin without going through the real
// authLoginCmd instance.
func authPIVCmd(slot, backend string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("slot", slot, "")
	cmd.Flags().String("backend", backend, "")
	return cmd
}

func TestRunAuthLoginPIV_InvalidSlot(t *testing.T) {
	err := runAuthLoginPIV(authPIVCmd("zz", "software"), slog.Default(), "https://example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunAuthLoginPIV_NoCertificateInSlot(t *testing.T) {
	withPIVStoragePath(t)

	err := runAuthLoginPIV(authPIVCmd("9a", "software"), slog.Default(), "https://example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVCertificateNotFound)
}

func TestRunAuthLoginPIV_ServerNotRegistered(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	withPIVStoragePath(t)
	storeTestPIVCertificate(t, xkms.PIVSlot("9a"))

	err := runAuthLoginPIV(authPIVCmd("9a", "software"), slog.Default(), "https://nonexistent.example.com:8443")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthServerLookupFailed)
}

// TestRunAuthLoginPIV_ConnectionRefused proves the flow reaches the actual
// mTLS login attempt once the slot certificate and server registration are
// in place: a TCP connection refused by an unbound local port surfaces as
// ErrAuthPIVLoginFailed rather than failing earlier in cert/registry setup.
func TestRunAuthLoginPIV_ConnectionRefused(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	withPIVStoragePath(t)
	storeTestPIVCertificate(t, xkms.PIVSlot("9a"))

	const serverURL = "https://127.0.0.1:1"
	registerTestServer(t, serverURL)

	err := runAuthLoginPIV(authPIVCmd("9a", "software"), slog.Default(), serverURL)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthPIVLoginFailed)
}

func TestBuildAuthPIVConfig_DefaultsToSoftware(t *testing.T) {
	cmd := authPIVCmd("9a", "")
	cfg := buildAuthPIVConfig(cmd)
	assert.Equal(t, PIVBackendSoftware, cfg.Backend)
	assert.Equal(t, PIVStorageTypeFile, cfg.StorageType)
}

func TestBuildAuthPIVConfig_ExplicitBackend(t *testing.T) {
	cmd := authPIVCmd("9a", "pkcs11")
	cfg := buildAuthPIVConfig(cmd)
	assert.Equal(t, PIVBackendPKCS11, cfg.Backend)
	assert.Equal(t, PIVStorageTypePKCS11, cfg.StorageType)
}
