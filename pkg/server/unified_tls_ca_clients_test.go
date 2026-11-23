package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// issueTLSLeaf issues a leaf under caCert for the given extended key usage
// and returns it as a tls.Certificate (leaf only, as admin-cert.pem holds)
// plus its certificate and key PEM.
func issueTLSLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
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
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return pair, certPEM, keyPEM
}

// TestAdoptComposedCA_OperatorCertFile_AcceptsFirstBootAdminCert mirrors the
// bootstrap integration harness: the REST listener serves an operator
// cert_file under an operator ca_file, client_auth is "verify", and no
// server_cn is set. The first-boot administrator certificate is issued by
// the embedded CA once it composes; a client presenting it (leaf only, as
// admin-cert.pem holds it) must reach the handler with that certificate
// verified, not be refused with "no client certificate provided".
func TestAdoptComposedCA_OperatorCertFile_AcceptsFirstBootAdminCert(t *testing.T) {
	dir := t.TempDir()

	opKey, opCert, opPEM := generateCAKeyAndCert(t, "operator-ca")
	opCAPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(opCAPath, opPEM, 0o600))
	_, serverCertPEM, serverKeyPEM := issueTLSLeaf(t, opCert, opKey, "xkms-server", x509.ExtKeyUsageServerAuth)
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverKeyPEM, 0o600))

	embeddedKey, embeddedCert, embeddedPEM := generateCAKeyAndCert(t, "embedded-ca")
	adminPair, _, _ := issueTLSLeaf(t, embeddedCert, embeddedKey, "admin", x509.ExtKeyUsageClientAuth)

	cfg := buildRESTConfigTLSTestCfg()
	cfg.TLS.ServerCN = ""
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath
	cfg.TLS.CAFile = opCAPath
	cfg.TLS.ClientAuth = "verify"
	cfg.Datastore.Path = t.TempDir()

	s := newMinimalServer(t, cfg)
	tlsCfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)

	mock := &mockTrustedCA{initialized: true, caBundlePEM: embeddedPEM}
	s.ca = mock
	require.NoError(t, s.adoptComposedCA(mock, types.StoreSoftware))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "no client certificate provided", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(opCert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{adminPair},
		MinVersion:   tls.VersionTLS13,
	}}}
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the listener must request and verify the first-boot admin certificate the embedded CA issued")
}
