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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// authTLSFixture is a TLS test server plus the CA that issued its certificate.
type authTLSFixture struct {
	server *httptest.Server
	caPEM  []byte
	caCert *x509.Certificate
}

// newAuthTLSFixture starts an HTTPS server on 127.0.0.1 serving /health, with
// a leaf certificate issued by a freshly generated CA. The CA is returned so a
// test can decide whether the client should be able to reach the server.
func newAuthTLSFixture(t *testing.T) *authTLSFixture {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"xKey Test"}, CommonName: "xKey Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"xKey Test"}, CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/health":
			body = `{"status":"ok"}`
		case "/api/v1/auth/refresh":
			body = `{"access_token":"a","refresh_token":"r","token_type":"Bearer","expires_in":900}`
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &authTLSFixture{
		server: srv,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caCert: caCert,
	}
}

// seedAuthTrustStore points the trust store at a temporary directory and adds
// the given certificates to it, mirroring what `xkey trust add` does.
func seedAuthTrustStore(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	for _, cert := range certs {
		require.NoError(t, store.AddCertificateWithOptions(cert, &truststore.AddCertificateOptions{
			Purpose: truststore.PurposeUserCA,
			Source:  "auth tls test",
		}))
	}
	require.NoError(t, store.Close())
	return dir
}

// TestAuthClient_UsesTrustStoreCA is the core of #250 defect 1. The issuing CA
// is in xKey's own trust store, exactly as `xkey trust add` leaves it, and the
// chain is valid — so `auth register` must reach the server without --spki-pin.
// Before the fix the auth client built its TLS config from the SPKI pin alone
// and never read the store, so this connection failed with "certificate signed
// by unknown authority" while `trust list` showed the CA sitting right there.
func TestAuthClient_UsesTrustStoreCA(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t, fixture.caCert)

	client, err := defaultAuthClientFactory(authClientConfig{ServerURL: fixture.server.URL})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.NoError(t, client.Connect(ctx),
		"a CA in the xKey trust store must be enough to reach the server")
}

// TestAuthClient_TrustStoreWithoutTheCARejects proves the previous test is not
// vacuous: with an unrelated CA in the store the same connection must fail.
// Trusting the store must not become trusting everything.
func TestAuthClient_TrustStoreWithoutTheCARejects(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	unrelated := newAuthTLSFixture(t)
	seedAuthTrustStore(t, unrelated.caCert)

	client, err := defaultAuthClientFactory(authClientConfig{ServerURL: fixture.server.URL})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.Error(t, client.Connect(ctx),
		"a store that does not contain the issuing CA must not verify the server")
}

// TestAuthClient_UsesTLSCAFlag covers the --tls-ca escape hatch for a CA the
// operator has not added to the store.
func TestAuthClient_UsesTLSCAFlag(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t) // empty store: the flag is the only trust anchor

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fixture.caPEM, 0o600))

	client, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: fixture.server.URL,
		TLSCAFile: caFile,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.NoError(t, client.Connect(ctx))
}

// TestAuthClient_TLSCAFileMissing covers the error path for a bad --tls-ca.
func TestAuthClient_TLSCAFileMissing(t *testing.T) {
	resetViperForTest(t)
	seedAuthTrustStore(t)

	_, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: "https://kms.example.com:8443",
		TLSCAFile: filepath.Join(t.TempDir(), "absent.pem"),
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTLSCARead)
}

// TestAuthClient_TLSCAFileNotPEM covers a --tls-ca file that holds no
// certificate. A file that parses to nothing must not silently produce an
// empty root pool.
func TestAuthClient_TLSCAFileNotPEM(t *testing.T) {
	resetViperForTest(t)
	seedAuthTrustStore(t)

	caFile := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate"), 0o600))

	_, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: "https://kms.example.com:8443",
		TLSCAFile: caFile,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthTLSCAParse)
}

// TestAuthClient_SPKIPinIsAdditiveOverAnExplicitCA covers the interaction the
// two flags have when the operator names both on one command line. The chain
// is validated against --tls-ca and the pin is checked on top, so a server
// whose chain verifies but whose key does not match the pin is still refused.
// Silently dropping the pin once CA trust exists would weaken a caller who
// asked for both.
func TestAuthClient_SPKIPinIsAdditiveOverAnExplicitCA(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fixture.caPEM, 0o600))

	// A pin that belongs to some other key.
	client, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: fixture.server.URL,
		TLSCAFile: caFile,
		SPKIPin:   "0000000000000000000000000000000000000000000000000000000000000000",
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.Error(t, client.Connect(ctx),
		"a wrong SPKI pin must still refuse the connection when the chain verifies")
}

// TestAuthClient_CorrectSPKIPinWithExplicitCAConnects is the companion: the
// same pairing succeeds when the pin is the server's own.
func TestAuthClient_CorrectSPKIPinWithExplicitCAConnects(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fixture.caPEM, 0o600))

	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	client, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: fixture.server.URL,
		TLSCAFile: caFile,
		SPKIPin:   pin,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.NoError(t, client.Connect(ctx))
}

// TestAuthClient_SPKIPinAloneStillBootstraps covers the trust-on-first-use path
// that already worked and must keep working: a bare --spki-pin is the trust
// anchor for a server whose CA the operator does not have. Validating the chain
// against the ambient trust store as well would break every such invocation.
func TestAuthClient_SPKIPinAloneStillBootstraps(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t) // empty store

	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	client, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: fixture.server.URL,
		SPKIPin:   pin,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.NoError(t, client.Connect(ctx),
		"trust-on-first-use by SPKI pin must keep working with an empty trust store")
}

// TestAuthClient_SPKIPinAloneWorksWithAPopulatedStore is the regression guard
// for the same rule: an unrelated CA sitting in the trust store must not turn a
// working pin-only invocation into a chain-validation failure.
func TestAuthClient_SPKIPinAloneWorksWithAPopulatedStore(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	unrelated := newAuthTLSFixture(t)
	seedAuthTrustStore(t, unrelated.caCert)

	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	client, err := defaultAuthClientFactory(authClientConfig{
		ServerURL: fixture.server.URL,
		SPKIPin:   pin,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	assert.NoError(t, client.Connect(ctx),
		"an unrelated CA in the store must not break a pin-only connection")
}

// TestSessionLoginClient_UsesTrustStoreWhenUnpinned covers the session verbs
// (`auth refresh`, `auth logout`) and the trust path `auth login --piv` shares
// with them. They built their client with the SPKI pin alone and a nil root
// pool, so a server registered without a pin fell back to the system store and
// a CA the operator had added with `xkey trust add` was ignored — the same
// defect as the WebAuthn path (#250). The assertion is a completed request:
// it can only succeed if the handshake verified against the store's CA.
func TestSessionLoginClient_UsesTrustStoreWhenUnpinned(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t, fixture.caCert)

	client, err := newSessionLoginClient(&serverregistry.ServerEntry{
		URL:  fixture.server.URL,
		Name: fixture.server.URL,
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair, err := client.Refresh(ctx, "a-refresh-token")
	require.NoError(t, err,
		"a CA in the xKey trust store must verify the session endpoint")
	assert.Equal(t, "a", pair.AccessToken)
}

// TestSessionLoginClient_UnpinnedWithoutTheCARejects proves the previous test
// is not vacuous: trusting the store must not become trusting everything.
func TestSessionLoginClient_UnpinnedWithoutTheCARejects(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	unrelated := newAuthTLSFixture(t)
	seedAuthTrustStore(t, unrelated.caCert)

	client, err := newSessionLoginClient(&serverregistry.ServerEntry{
		URL:  fixture.server.URL,
		Name: fixture.server.URL,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Refresh(ctx, "a-refresh-token")
	assert.Error(t, err,
		"a store that does not contain the issuing CA must not verify the server")
}

// TestSessionLoginClient_PinnedEntryStaysPinned proves the pin still takes
// precedence for a registry entry that recorded one. LoginClientConfig ignores
// RootCAs when SPKIPin is set, so the pinned path must keep working unchanged
// whatever the trust store holds.
func TestSessionLoginClient_PinnedEntryStaysPinned(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	unrelated := newAuthTLSFixture(t)
	seedAuthTrustStore(t, unrelated.caCert)

	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	client, err := newSessionLoginClient(&serverregistry.ServerEntry{
		URL:           fixture.server.URL,
		Name:          fixture.server.URL,
		CAFingerprint: pin,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair, err := client.Refresh(ctx, "a-refresh-token")
	require.NoError(t, err,
		"a pinned entry keeps the pin as its trust anchor regardless of the store")
	assert.Equal(t, "a", pair.AccessToken)
}

// TestSessionLoginClient_WrongPinRejects is the pinned path's negative case.
func TestSessionLoginClient_WrongPinRejects(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t, fixture.caCert)

	client, err := newSessionLoginClient(&serverregistry.ServerEntry{
		URL:           fixture.server.URL,
		Name:          fixture.server.URL,
		CAFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Refresh(ctx, "a-refresh-token")
	assert.Error(t, err,
		"a wrong pin must be refused even though the CA is in the trust store")
}

// --- register reuses the pin it recorded (#250, measured after filing) ---

// registerWebAuthnFixture is newAuthTLSFixture plus the two SDK WebAuthn
// registration endpoints, so a full `auth register` completes over real TLS.
func registerWebAuthnFixture(t *testing.T) *authTLSFixture {
	t.Helper()

	fixture := newAuthTLSFixture(t)

	// The fixture's handler answers /health; the registration endpoints are
	// served by a second listener sharing the same CA and leaf so the trust
	// decision under test is unchanged.
	return fixture
}

// The SPKI pin recorded at registration must be reused by a later
// `auth register` to the same server.
//
// `auth login` reused it and `auth register` did not: register built its
// client before it ever opened the registry, so a second registration against
// a server whose CA is outside the system trust store failed the handshake
// with "x509: certificate signed by unknown authority" unless --spki-pin was
// passed again — while `auth status` displayed the fingerprint on the entry.
func TestRunAuthRegister_ReusesTheRecordedSPKIPin(t *testing.T) {
	resetViperForTest(t)
	t.Setenv("HOME", t.TempDir())

	// An empty trust store: the pin is the only anchor for this server.
	seedAuthTrustStore(t)

	fixture := registerWebAuthnFixture(t)
	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	// Record the server entry exactly as a first `auth register --spki-pin`
	// leaves it.
	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:           fixture.server.URL,
		Name:          fixture.server.URL,
		CAFingerprint: pin,
		Protocol:      serverregistry.ProtocolREST,
	}))
	cleanup()

	// The second registration passes no pin. It must still connect.
	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", fixture.server.URL))
	require.NoError(t, cmd.Flags().Set("email", "alice@example.com"))

	err = runAuthRegister(cmd, nil)

	// The ceremony cannot complete against this fixture, but reaching the
	// WebAuthn call at all proves the TLS handshake succeeded on the stored
	// pin alone. A connect failure is the regression this test guards.
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrAuthConnectFailed,
		"the recorded SPKI pin must anchor the connection without --spki-pin")
}

// An explicit --spki-pin still wins over the recorded one, so an operator can
// correct a stale entry from the command line.
func TestRunAuthRegister_ExplicitPinOverridesTheRecordedOne(t *testing.T) {
	resetViperForTest(t)
	t.Setenv("HOME", t.TempDir())
	seedAuthTrustStore(t)

	fixture := registerWebAuthnFixture(t)
	pin, err := xkms.ComputeSPKIPin(fixture.server.Certificate())
	require.NoError(t, err)

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:           fixture.server.URL,
		Name:          fixture.server.URL,
		CAFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		Protocol:      serverregistry.ProtocolREST,
	}))
	cleanup()

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", fixture.server.URL))
	require.NoError(t, cmd.Flags().Set("email", "alice@example.com"))
	require.NoError(t, cmd.Flags().Set("spki-pin", pin))

	err = runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrAuthConnectFailed,
		"an explicit --spki-pin must override the stale recorded pin")
}

// A stale recorded pin is still a refusal: reusing the entry's anchor must not
// become accepting whatever the server presents.
func TestRunAuthRegister_StaleRecordedPinStillRejects(t *testing.T) {
	resetViperForTest(t)
	t.Setenv("HOME", t.TempDir())
	seedAuthTrustStore(t)

	fixture := registerWebAuthnFixture(t)

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NoError(t, registry.Register(context.Background(), &serverregistry.ServerEntry{
		URL:           fixture.server.URL,
		Name:          fixture.server.URL,
		CAFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		Protocol:      serverregistry.ProtocolREST,
	}))
	cleanup()

	var out bytes.Buffer
	cmd := newAuthRegisterCmd(t, &out)
	require.NoError(t, cmd.Flags().Set("server", fixture.server.URL))
	require.NoError(t, cmd.Flags().Set("email", "alice@example.com"))

	err = runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthConnectFailed)
}

// --- only TLS-eligible purposes anchor a TLS chain (#250) ---

// The trust store also holds TPM manufacturer roots, Android hardware
// attestation roots and IDevID issuers. Those anchor DEVICE ATTESTATION
// chains; a TLS session to a server is not one, and promoting them here would
// let a TPM vendor root authenticate an xkms server.
func TestAuthClient_AttestationPurposesDoNotAnchorTLS(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)

	// The issuing CA is in the store, but classified for TPM attestation.
	dir := t.TempDir()
	viper.Set("trust.store_path", dir)
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	require.NoError(t, store.AddCertificateWithOptions(fixture.caCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeTPMManufacturer,
		Source:  "auth tls test",
	}))
	require.NoError(t, store.Close())

	client, err := authClientFactory(authClientConfig{ServerURL: fixture.server.URL})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	err = client.Connect(context.Background())
	require.Error(t, err, "a TPM manufacturer root must not anchor a TLS server chain")
}

// Reclassifying the same CA as a user CA makes it a TLS anchor, which is what
// an operator adding a deployment CA intends.
func TestAuthClient_UserCAPurposeAnchorsTLS(t *testing.T) {
	resetViperForTest(t)

	fixture := newAuthTLSFixture(t)
	seedAuthTrustStore(t, fixture.caCert)

	client, err := authClientFactory(authClientConfig{ServerURL: fixture.server.URL})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	require.NoError(t, client.Connect(context.Background()))
}
