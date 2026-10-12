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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withPIVStoragePath points the "piv" command group's file storage at a
// temporary directory for the duration of the test by injecting it into
// loadedConfig.PIV.StoragePath -- the same package-level unified-config
// variable xkmsd_client_test.go and listen_config_test.go inject into,
// restoring the prior value on cleanup so other tests in this package keep
// their own configuration. It never touches the real ~/.xkey or ./data/piv
// locations a bare `go test` run must not write to.
func withPIVStoragePath(t *testing.T) string {
	t.Helper()
	withSoftwarePIVKeyStore(t)
	tmpDir := t.TempDir()
	previous := loadedConfig
	cfg := xkeyconfig.DefaultConfig()
	cfg.PIV.StoragePath = tmpDir
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
	return tmpDir
}

// storeTestPIVCertificate stores a self-signed test certificate in slot
// under the "software" file backend, using whatever storage path
// withPIVStoragePath configured. It returns the stored certificate.
func storeTestPIVCertificate(t *testing.T, slot xkms.PIVSlot) *x509.Certificate {
	t.Helper()
	cert := generateTestCertificate(t)

	cfg := &PIVConfig{
		Backend:     PIVBackendSoftware,
		StorageType: PIVStorageTypeFile,
		StoragePath: GetConfig().PIV.StoragePath,
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
	addBarrierPasswordFlags(cmd) // the software PIV backend's key store
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

// TestRunAuthLoginPIV_UnregisteredServerIsReachedByURL proves a PIV login
// needs no WebAuthn registration: an unregistered server is reached by the
// URL given (here an unbound port, so the login itself fails), rather than
// refused at the registry lookup.
func TestRunAuthLoginPIV_UnregisteredServerIsReachedByURL(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	withPIVStoragePath(t)
	storeTestPIVCertificate(t, xkms.PIVSlot("9a"))

	err := runAuthLoginPIV(authPIVCmd("9a", "software"), slog.Default(), "https://127.0.0.1:1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthPIVLoginFailed)
	assert.NotErrorIs(t, err, ErrAuthServerLookupFailed)
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

// TestRunAuthLoginPIV_StoresTheTokenPair drives a whole PIV login against a
// pinned mTLS server: the slot certificate is presented as the client
// certificate, the pair the server answers lands in the token store, and the
// registered server's last-connected time is recorded.
func TestRunAuthLoginPIV_StoresTheTokenPair(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateCertPIV(t)
	generateTestPIVKey(t)

	storage, err := createPIVStorage(&PIVConfig{
		Backend:     PIVBackendSoftware,
		StorageType: PIVStorageTypeFile,
		StoragePath: GetConfig().PIV.StoragePath,
	}, slog.Default())
	require.NoError(t, err)
	slotCert, err := storage.Retrieve(xkms.PIVSlot("9a"))
	require.NoError(t, err)
	require.NoError(t, storage.Close())

	var (
		mu        sync.Mutex
		presented []*x509.Certificate
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/login/piv" || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		presented = append(presented, r.TLS.PeerCertificates[0])
		mu.Unlock()
		writeTestJSON(t, w, http.StatusOK, map[string]any{
			"access_token":  "piv-access-token",
			"refresh_token": "piv-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    900,
		})
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:           srv.URL,
		Name:          "piv-login",
		Protocol:      serverregistry.ProtocolREST,
		CAFingerprint: tlsServerPin(t, srv),
	}))
	cleanup()

	cmd := authPIVCmd("9a", "software")
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runAuthLoginPIV(cmd, slog.Default(), srv.URL))
	assert.Contains(t, out.String(), "Authenticated to "+srv.URL+" with PIV slot 9a. Token pair stored.")

	mu.Lock()
	require.Len(t, presented, 1)
	assert.Equal(t, slotCert.Raw, presented[0].Raw)
	mu.Unlock()

	tokens, tokensCleanup, err := openTokenStore(slog.Default())
	require.NoError(t, err)
	defer tokensCleanup()
	entry, err := tokens.Load(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "piv-access-token", entry.Token)
	assert.Equal(t, "piv-refresh-token", entry.RefreshToken)
	assert.Equal(t, tokenstore.SourcePIV, entry.Source)

	registry, cleanup, err = openServerRegistry(slog.Default())
	require.NoError(t, err)
	defer cleanup()
	recorded, err := registry.Lookup(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.False(t, recorded.LastConnectedAt.IsZero())
}

func TestBuildAuthPIVConfig_DefaultsToSoftware(t *testing.T) {
	cmd := authPIVCmd("9a", "")
	cfg, err := buildAuthPIVConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, PIVBackendSoftware, cfg.Backend)
	assert.Equal(t, PIVStorageTypeFile, cfg.StorageType)
}

func TestBuildAuthPIVConfig_ExplicitBackend(t *testing.T) {
	cmd := authPIVCmd("9a", "pkcs11")
	cfg, err := buildAuthPIVConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, PIVBackendPKCS11, cfg.Backend)
	assert.Equal(t, PIVStorageTypePKCS11, cfg.StorageType)
}

// TestBuildAuthPIVConfig_PKCS11PINFromEnv proves the PKCS#11 PIN reaches
// "auth login --piv" through its dedicated environment variable even though
// the command declares no --pkcs11-pin-stdin flag of its own (go-xkms#871).
func TestBuildAuthPIVConfig_PKCS11PINFromEnv(t *testing.T) {
	t.Setenv("XKEY_PIV_PKCS11_PIN", "env-pin")
	t.Setenv("XKEY_PIV_PKCS11_SO_PIN", "env-so-pin")

	cfg, err := buildAuthPIVConfig(authPIVCmd("9a", "pkcs11"))
	require.NoError(t, err)
	assert.Equal(t, "env-pin", cfg.PKCS11PIN)
	assert.Equal(t, "env-so-pin", cfg.PKCS11SOPIN)
}
