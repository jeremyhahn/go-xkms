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

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// ceremonyAdminUsername is the user the fake identity store binds the
// init-style admin certificate to.
const ceremonyAdminUsername = "administrator"

// thumbprintUserStore is an in-memory auth.UserStore keyed by go-qrdb's SPKI
// thumbprint, the one binding the server's mTLS authenticator uses.
type thumbprintUserStore map[string]auth.MTLSUser

func (s thumbprintUserStore) GetByCertFingerprint(_ context.Context, thumbprint string) (auth.MTLSUser, error) {
	user, ok := s[thumbprint]
	if !ok {
		return auth.MTLSUser{}, &qrdbsdk.UserNotFoundError{Lookup: "cert_spki/" + thumbprint}
	}
	return user, nil
}

// issueClientCert issues a client-auth leaf signed by caCert/caKey and returns
// it as the tls.Certificate a client presents.
func issueClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// ceremonyServer is an xkmsd node whose data directory holds what
// `xkmsd init` leaves behind: the ceremony root in ca-bundle.pem.
type ceremonyServer struct {
	server   *Server
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	trust    *x509.CertPool // verifies the server's own TLS certificate
}

func newCeremonyServer(t *testing.T) *ceremonyServer {
	t.Helper()
	certFile, keyFile, caFile := createTestTLSFiles(t)
	dataDir := t.TempDir()
	rootKey, rootCert, rootPEM := generateCAKeyAndCert(t, "xkms Root CA")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, ceremonyRootBundleName), rootPEM, 0o600))

	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	trust := x509.NewCertPool()
	require.True(t, trust.AppendCertsFromPEM(caPEM))

	s := newTLSTestServer(t, &config.Config{
		TLS: config.TLSConfig{
			Enabled:    true,
			CertFile:   certFile,
			KeyFile:    keyFile,
			ClientAuth: "request",
		},
		Datastore: config.DatastoreConfig{Path: dataDir},
	})
	return &ceremonyServer{server: s, rootCert: rootCert, rootKey: rootKey, trust: trust}
}

// serveMTLS serves the unified TLS config on a loopback listener behind the
// production mTLS authenticator, answering 200 with the authenticated
// subject or 401 with the authenticator's error.
func serveMTLS(t *testing.T, cfg *tls.Config, store auth.UserStore) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	authenticator := auth.NewMTLSAuthenticator(&auth.MTLSConfig{UserStore: store})
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, authErr := authenticator.AuthenticateHTTP(r)
			if authErr != nil {
				http.Error(w, authErr.Error(), http.StatusUnauthorized)
				return
			}
			_, writeErr := io.WriteString(w, identity.Subject)
			if writeErr != nil {
				t.Errorf("write response: %v", writeErr)
			}
		}),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
		if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("serve: %v", serveErr)
		}
	})
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return "https://localhost:" + port + "/"
}

// serve serves the node the way `xkmsd run` does once its own CA composes:
// the unified TLS config with the client-CA pool upgraded to include the run
// CA's bundle, an issuer the init-issued admin certificate does not chain to.
func (n *ceremonyServer) serve(t *testing.T, store auth.UserStore) string {
	t.Helper()
	cfg, err := n.server.buildUnifiedTLSConfig()
	require.NoError(t, err)
	_, _, runPEM := generateCAKeyAndCert(t, "xkmsd run CA")
	pool, err := n.server.unifiedClientCAPool(&fakeBundleSource{pem: runPEM})
	require.NoError(t, err)
	n.server.unifiedTLS.clientCAs.Store(pool)
	return serveMTLS(t, cfg, store)
}

// mtlsGet issues one request with clientTLS and returns the status and body.
func mtlsGet(t *testing.T, url string, clientTLS *tls.Config) (int, string) {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: clientTLS,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	resp, err := client.Get(url)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(bytes.TrimSpace(body))
}

// TestUnifiedTLS_AdvertisesInitCeremonyRoot proves the CertificateRequest a
// client sees lists the ceremony root `xkmsd init` wrote to ca-bundle.pem
// (#794).
func TestUnifiedTLS_AdvertisesInitCeremonyRoot(t *testing.T) {
	node := newCeremonyServer(t)
	url := node.serve(t, thumbprintUserStore{})

	var acceptable [][]byte
	probe := &tls.Config{
		RootCAs:    node.trust,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			acceptable = cri.AcceptableCAs
			return &tls.Certificate{}, nil
		},
	}
	status, _ := mtlsGet(t, url, probe)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, acceptable, node.rootCert.RawSubject)
}

// TestUnifiedTLS_StaticCertificatesSendInitAdminCert proves a client holding
// the init-issued admin certificate in a static Certificates list, the way
// every SDK transport and xkmsctl configure it, now sends it and is
// authenticated as that admin by its SPKI thumbprint.
func TestUnifiedTLS_StaticCertificatesSendInitAdminCert(t *testing.T) {
	node := newCeremonyServer(t)
	admin := issueClientCert(t, node.rootCert, node.rootKey, ceremonyAdminUsername)
	store := thumbprintUserStore{
		qrdbsdk.ComputeSPKIThumbprint(admin.Leaf): {Username: ceremonyAdminUsername, Enabled: true},
	}
	url := node.serve(t, store)

	status, body := mtlsGet(t, url, &tls.Config{
		Certificates: []tls.Certificate{admin},
		RootCAs:      node.trust,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	assert.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, ceremonyAdminUsername, body)
}

// TestUnifiedTLS_AdvertisedRootGrantsNothing proves the advertised pool only
// steers which certificate a client offers: a certificate the ceremony root
// signed but bound to no user, and one from an unrelated CA sent
// unconditionally, are both refused by the SPKI binding.
func TestUnifiedTLS_AdvertisedRootGrantsNothing(t *testing.T) {
	node := newCeremonyServer(t)
	admin := issueClientCert(t, node.rootCert, node.rootKey, ceremonyAdminUsername)
	store := thumbprintUserStore{
		qrdbsdk.ComputeSPKIThumbprint(admin.Leaf): {Username: ceremonyAdminUsername, Enabled: true},
	}
	url := node.serve(t, store)

	sibling := issueClientCert(t, node.rootCert, node.rootKey, ceremonyAdminUsername)
	status, body := mtlsGet(t, url, &tls.Config{
		Certificates: []tls.Certificate{sibling},
		RootCAs:      node.trust,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, auth.ErrCertNotBound.Error(), body)

	otherKey, otherCA, _ := generateCAKeyAndCert(t, "unrelated CA")
	stranger := issueClientCert(t, otherCA, otherKey, ceremonyAdminUsername)
	status, body = mtlsGet(t, url, &tls.Config{
		RootCAs:    node.trust,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &stranger, nil
		},
	})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, auth.ErrCertNotBound.Error(), body)
}

// TestBuildTLSConfig_AdvertisesInitCeremonyRoot proves the per-protocol
// listeners' TLS config carries the ceremony root too.
func TestBuildTLSConfig_AdvertisesInitCeremonyRoot(t *testing.T) {
	node := newCeremonyServer(t)
	cfg, err := node.server.buildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.ClientCAs)
	assert.True(t, cfg.ClientCAs.Equal(poolOf(node.rootCert)))
}

// TestUnifiedClientCAPool_KeepsInitCeremonyRoot proves the pool installed
// once the run CA composes still lists the ceremony root beside the run
// CA's bundle.
func TestUnifiedClientCAPool_KeepsInitCeremonyRoot(t *testing.T) {
	node := newCeremonyServer(t)
	_, runCA, runPEM := generateCAKeyAndCert(t, "run CA")
	pool, err := node.server.unifiedClientCAPool(&fakeBundleSource{pem: runPEM})
	require.NoError(t, err)
	assert.True(t, pool.Equal(poolOf(node.rootCert, runCA)))
}

// TestConfiguredClientCAs_NoCeremonyBundle proves a node `xkmsd init` did not
// initialise has no ceremony root and that is not an error.
func TestConfiguredClientCAs_NoCeremonyBundle(t *testing.T) {
	s := newTLSTestServer(t, &config.Config{Datastore: config.DatastoreConfig{Path: t.TempDir()}})
	pool, err := s.configuredClientCAs()
	require.NoError(t, err)
	assert.Nil(t, pool)

	s = newTLSTestServer(t, &config.Config{})
	pool, err = s.configuredClientCAs()
	require.NoError(t, err)
	assert.Nil(t, pool)
}

// TestConfiguredClientCAs_UnparsableCeremonyBundle proves a present but
// unparsable ca-bundle.pem fails start-up with a typed error on both TLS
// paths instead of being skipped.
func TestConfiguredClientCAs_UnparsableCeremonyBundle(t *testing.T) {
	node := newCeremonyServer(t)
	bundle := filepath.Join(node.server.config.Datastore.Path, ceremonyRootBundleName)
	require.NoError(t, os.WriteFile(bundle, []byte("not a certificate"), 0o600))

	var parseErr *ErrCertParse
	_, err := node.server.buildUnifiedTLSConfig()
	require.ErrorAs(t, err, &parseErr)
	_, err = node.server.buildTLSConfig()
	require.ErrorAs(t, err, &parseErr)
}

// TestConfiguredClientCAs_UnreadableCeremonyBundle proves a ca-bundle.pem
// path that cannot be inspected is a typed *ErrFileRead, not "absent", while
// a data directory that is a file (an ephemeral node) holds no bundle.
func TestConfiguredClientCAs_UnreadableCeremonyBundle(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	s := newTLSTestServer(t, &config.Config{Datastore: config.DatastoreConfig{Path: notADir}})
	pool, err := s.configuredClientCAs()
	require.NoError(t, err)
	assert.Nil(t, pool)

	tooLong := filepath.Join(t.TempDir(), strings.Repeat("d", 300))
	s = newTLSTestServer(t, &config.Config{Datastore: config.DatastoreConfig{Path: tooLong}})
	var readErr *ErrFileRead
	_, err = s.configuredClientCAs()
	require.ErrorAs(t, err, &readErr)
}

// poolOf builds the pool the server is expected to advertise.
func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
