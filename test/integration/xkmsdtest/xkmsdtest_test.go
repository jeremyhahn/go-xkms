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

package xkmsdtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// issuedCert is a certificate with its key, PEM-encoded.
type issuedCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// issue creates a certificate from template, signed by parent, or
// self-signed when parent is nil.
func issue(t *testing.T, template *x509.Certificate, parent *issuedCert) *issuedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	signer, signerCert := key, template
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return &issuedCert{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// unsealedNode stands in for an unsealed xkmsd: it presents a certificate
// its CA issued, publishes that CA as its first-contact bundle, and answers
// barrier status only to a caller presenting admin's certificate. As xkmsd
// does, it persists its TLS anchors under data: its bootstrap certificate and
// the CA bundle that verifies the CA-issued one.
func unsealedNode(t *testing.T, admin *issuedCert, data string) *httptest.Server {
	t.Helper()
	ca := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkmsdtest Root CA"},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil)
	persistAnchors(t, data, servingCert(t, nil).certPEM, ca.certPEM)
	leaf := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca)
	serving, err := tls.X509KeyPair(leaf.certPEM, leaf.keyPEM)
	require.NoError(t, err)
	admins := x509.NewCertPool()
	admins.AddCert(admin.cert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/barrier/status" {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(ca.certPEM)
			return
		}
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(BarrierState{InitializedAt: "2026-10-25T00:00:00Z"})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serving},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    admins,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeAdminCredential writes admin where first boot writes it under data.
func writeAdminCredential(data string, admin *issuedCert) error {
	return errors.Join(
		os.WriteFile(filepath.Join(data, "admin-cert.pem"), admin.certPEM, 0o600),
		os.WriteFile(filepath.Join(data, "admin-key.pem"), admin.keyPEM, 0o600))
}

func newAdmin(t *testing.T) *issuedCert {
	t.Helper()
	return issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "admin"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, nil)
}

func TestAdminClient_ReadsBarrierStateOfUnsealedNode(t *testing.T) {
	admin := newAdmin(t)
	data := t.TempDir()
	srv := unsealedNode(t, admin, data)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First boot writes the credential while the client already waits.
	written := make(chan error, 1)
	go func() {
		time.Sleep(2 * retryInterval)
		written <- writeAdminCredential(data, admin)
	}()
	client, err := AdminClient(ctx, srv.URL, data)
	require.NoError(t, <-written)
	require.NoError(t, err)

	state, err := ReadBarrierState(ctx, client, srv.URL)
	require.NoError(t, err)
	require.True(t, state.Initialized())
	require.False(t, state.Sealed)
}

func TestAdminClient_UnauthenticatedCallerIsRefused(t *testing.T) {
	data := t.TempDir()
	srv := unsealedNode(t, newAdmin(t), data)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := os.ReadFile(filepath.Join(filepath.Dir(bootstrapCertPath(data)), unifiedCABundleFile))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(bundle))
	anonymous := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}

	_, err = ReadBarrierState(ctx, anonymous, srv.URL)
	var status *StatusError
	require.ErrorAs(t, err, &status)
	require.Equal(t, http.StatusUnauthorized, status.Code)
}

func TestAdminClient_NoCredentialFailsWhenContextEnds(t *testing.T) {
	srv := unsealedNode(t, newAdmin(t), t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3*retryInterval)
	defer cancel()

	_, err := AdminClient(ctx, srv.URL, t.TempDir())
	require.ErrorIs(t, err, ErrNoAdminCredential)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestAdminClient_NoBundleFailsWhenContextEnds(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	data := t.TempDir()
	persistAnchors(t, data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), nil)
	require.NoError(t, writeAdminCredential(data, newAdmin(t)))
	ctx, cancel := context.WithTimeout(context.Background(), 3*retryInterval)
	defer cancel()

	_, err := AdminClient(ctx, srv.URL, data)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "the client gives up only when ctx ends: %v", err)
	var status *StatusError
	require.ErrorAs(t, err, &status)
	require.Equal(t, http.StatusNotFound, status.Code)
}

// TestAdminClient_NodeTheAnchorsDoNotVerifyIsNeverTrusted proves the CA
// bundle is not trusted on first use (DS-3769): a server the persisted
// anchors do not verify never hands the client its trust anchor.
func TestAdminClient_NodeTheAnchorsDoNotVerifyIsNeverTrusted(t *testing.T) {
	admin := newAdmin(t)
	impostor := unsealedNode(t, admin, t.TempDir())
	data := t.TempDir()
	persistAnchors(t, data, servingCert(t, nil).certPEM, nil)
	require.NoError(t, writeAdminCredential(data, admin))
	ctx, cancel := context.WithTimeout(context.Background(), 4*retryInterval)
	defer cancel()

	_, err := AdminClient(ctx, impostor.URL, data)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	var unanswered *UnansweredError
	require.ErrorAs(t, err, &unanswered)
	var unverified x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unverified), "the error names the unverified server: %v", err)
}

func TestAdminClient_NoPersistedAnchorFailsWhenContextEnds(t *testing.T) {
	admin := newAdmin(t)
	srv := unsealedNode(t, admin, t.TempDir())
	data := t.TempDir()
	require.NoError(t, writeAdminCredential(data, admin))
	ctx, cancel := context.WithTimeout(context.Background(), 3*retryInterval)
	defer cancel()

	_, err := AdminClient(ctx, srv.URL, data)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrNoAnchor)
}

func TestAdminClient_UnreadableKeyIsRefused(t *testing.T) {
	data := t.TempDir()
	srv := unsealedNode(t, newAdmin(t), data)
	admin := newAdmin(t)
	admin.keyPEM = []byte("not a key")
	require.NoError(t, writeAdminCredential(data, admin))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := AdminClient(ctx, srv.URL, data)
	require.Error(t, err)
	require.False(t, errors.Is(err, context.DeadlineExceeded), "a bad key fails at once: %v", err)
}
