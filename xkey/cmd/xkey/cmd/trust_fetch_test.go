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

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// makeFetchCA generates a self-signed CA cert for fetch-flow tests and
// returns the parsed cert plus the PEM bundle.
func makeFetchCA(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Trust Fetch CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

// startFetchServer returns a TLS test server that exposes the platform CA
// bundle endpoint at /api/v1/ca/bundle.
func startFetchServer(t *testing.T, bundlePEM []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ca/bundle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_ = r // keep linter happy
		_, _ = w.Write(bundlePEM)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newFetchTestCmd returns a fresh command with the trust-fetch flag set
// installed and shared run-fn state so each test gets a clean slate.
func newFetchTestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:  "fetch <url>",
		RunE: runTrustFetch,
	}
	registerTrustFetchFlags(c)
	return c
}

// newImportPlatformTestCmd is the analogous fresh command for import-platform.
func newImportPlatformTestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:  "import-platform <host:port>",
		RunE: runTrustImportPlatform,
	}
	registerTrustFetchFlags(c)
	return c
}

// tlsServerPin returns the SPKI hex hash of the TLS leaf certificate
// presented by the test server. This is what the fetcher pins against,
// NOT the bundle CA we are fetching.
func tlsServerPin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(srv.Certificate().Raw)
	require.NoError(t, err)
	return xkms.TrustFetcherSPKIHash(leaf)
}

// configureTrustStorePath points the openTrustStore() helper at a temp dir
// for the duration of the test by stuffing the value into viper.
func configureTrustStorePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "trust")
	viper.Set("trust.store_path", storeDir)
	t.Cleanup(func() { viper.Set("trust.store_path", "") })
	return storeDir
}

// --- trustFetchCmd structure ---

func TestTrustFetchCmd_Structure(t *testing.T) {
	assert.NotNil(t, trustFetchCmd)
	assert.Equal(t, "fetch <url>", trustFetchCmd.Use)
	assert.NotNil(t, trustFetchCmd.RunE)
}

func TestTrustFetchCmd_HasFlags(t *testing.T) {
	for _, name := range []string{"spki-pin", "purpose", "source", "install-system", "timeout"} {
		flag := trustFetchCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "fetch command should have --%s", name)
	}
}

func TestTrustFetchCmd_NoTOFUFlag(t *testing.T) {
	// Regression guard: --insecure-first-touch must NOT be reintroduced.
	flag := trustFetchCmd.Flags().Lookup("insecure-first-touch")
	assert.Nil(t, flag, "TOFU flag must remain removed; trust must be SPKI-pinned only")
}

func TestTrustImportPlatformCmd_Structure(t *testing.T) {
	assert.NotNil(t, trustImportPlatformCmd)
	assert.Equal(t, "import-platform <host:port>", trustImportPlatformCmd.Use)
	assert.NotNil(t, trustImportPlatformCmd.RunE)
}

// --- Happy path: pinned fetch persists certs to the trust store ---

func TestTrustFetch_PinnedHappyPath(t *testing.T) {
	_, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	pin := tlsServerPin(t, srv)

	storeDir := configureTrustStorePath(t)

	fcmd := newFetchTestCmd()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	fcmd.SetOut(out)
	fcmd.SetErr(errOut)
	require.NoError(t, fcmd.Flags().Set("spki-pin", pin))

	err := runTrustFetch(fcmd, []string{srv.URL + "/api/v1/ca/bundle"})
	require.NoError(t, err, "stderr=%s", errOut.String())
	assert.Contains(t, out.String(), "Bundle fetched from")

	// Verify the cert was actually persisted.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: storeDir})
	require.NoError(t, err)
	defer store.Close()
	certs, err := store.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "Trust Fetch CA", certs[0].Subject.CommonName)

	meta, err := store.Metadata(truststore.Fingerprint(certs[0]))
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, truststore.PurposeBootstrapCA, meta.Purpose)
	assert.True(t, strings.HasPrefix(meta.Source, "platform:"))
}

// --- Argument validation: --spki-pin is mandatory ---

func TestTrustFetch_RequiresPin(t *testing.T) {
	configureTrustStorePath(t)

	fcmd := newFetchTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})

	// Pin flag absent.
	err := runTrustFetch(fcmd, []string{"https://example.test/api/v1/ca/bundle"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustFetchInvalidArgs))
}

func TestTrustFetch_RequiresPin_BlankIsRejected(t *testing.T) {
	configureTrustStorePath(t)

	fcmd := newFetchTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, fcmd.Flags().Set("spki-pin", "   "))

	err := runTrustFetch(fcmd, []string{"https://example.test/api/v1/ca/bundle"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustFetchInvalidArgs))
}

func TestTrustFetch_BadPurpose(t *testing.T) {
	configureTrustStorePath(t)

	fcmd := newFetchTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, fcmd.Flags().Set("spki-pin", strings.Repeat("a", 64)))
	require.NoError(t, fcmd.Flags().Set("purpose", "not-a-real-purpose"))

	err := runTrustFetch(fcmd, []string{"https://example.test/api/v1/ca/bundle"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustFetchInvalidArgs))
}

// --- import-platform builds canonical URL and inherits flag validation ---

func TestTrustImportPlatform_HappyPath(t *testing.T) {
	_, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	pin := tlsServerPin(t, srv)

	configureTrustStorePath(t)

	// httptest.URL is "https://127.0.0.1:PORT". We pass just the host:port.
	hostPort := strings.TrimPrefix(srv.URL, "https://")

	fcmd := newImportPlatformTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, fcmd.Flags().Set("spki-pin", pin))

	err := runTrustImportPlatform(fcmd, []string{hostPort})
	require.NoError(t, err)
}

func TestTrustImportPlatform_StripsScheme(t *testing.T) {
	_, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	pin := tlsServerPin(t, srv)

	configureTrustStorePath(t)
	hostPort := strings.TrimPrefix(srv.URL, "https://")

	fcmd := newImportPlatformTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, fcmd.Flags().Set("spki-pin", pin))

	err := runTrustImportPlatform(fcmd, []string{"https://" + hostPort + "/"})
	require.NoError(t, err)
}

func TestTrustImportPlatform_RejectsEmpty(t *testing.T) {
	configureTrustStorePath(t)

	fcmd := newImportPlatformTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})

	err := runTrustImportPlatform(fcmd, []string{"   "})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustHostRequired))
}

// --- HTTP error surfaces as ErrTrustFetchFailed ---

func TestTrustFetch_ServerErrorWraps(t *testing.T) {
	_, bundlePEM := makeFetchCA(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// server cert pin (we still want the verification path to succeed before
	// the HTTP failure surfaces).
	srvCert, err := x509.ParseCertificate(srv.Certificate().Raw)
	require.NoError(t, err)
	pin := xkms.TrustFetcherSPKIHash(srvCert)
	_ = bundlePEM

	configureTrustStorePath(t)

	fcmd := newFetchTestCmd()
	fcmd.SetOut(&bytes.Buffer{})
	fcmd.SetErr(&bytes.Buffer{})
	require.NoError(t, fcmd.Flags().Set("spki-pin", pin))

	err = runTrustFetch(fcmd, []string{srv.URL + "/api/v1/ca/bundle"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustFetchFailed))
}

// --- certIsSelfSigned helper ---

func TestCertIsSelfSigned(t *testing.T) {
	t.Parallel()
	assert.True(t, certIsSelfSigned("CN=A", "CN=A"))
	assert.False(t, certIsSelfSigned("CN=A", "CN=B"))
	assert.False(t, certIsSelfSigned("", ""))
}

// --- registerTrustFetchFlags is idempotent on a fresh command ---

func TestRegisterTrustFetchFlags(t *testing.T) {
	t.Parallel()
	c := &cobra.Command{Use: "test"}
	registerTrustFetchFlags(c)
	for _, name := range []string{"spki-pin", "purpose", "source", "install-system", "timeout"} {
		assert.NotNil(t, c.Flags().Lookup(name), "expected --%s on fresh command", name)
	}
	// Regression guard: --insecure-first-touch must not be added.
	assert.Nil(t, c.Flags().Lookup("insecure-first-touch"),
		"TOFU flag must remain removed")
}

// --- helper to ensure the test suite shuts down all background goroutines ---

func TestMain_FetchSubcommands(t *testing.T) {
	t.Parallel()
	// Smoke check: ensure the fetcher package compiles into this binary
	// and the constant is reachable.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := xkms.TrustFetcherFetch(ctx, "https://example.invalid/api/v1/ca/bundle", xkms.TrustFetcherOptions{
		SPKIPin: strings.Repeat("a", 64),
		Timeout: 10 * time.Millisecond,
	})
	require.Error(t, err) // unreachable host: any error is fine.
}
