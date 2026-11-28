package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// writeStartupRootPEM writes a self-signed CA root to a PEM file.
func writeStartupRootPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), cn+".pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

// TestNew_StoreBackedAttestationVerifiersRegister: with the persisted trust
// root store wired, the TPM and Android verifiers anchor through the store
// (their config roots are imported, not copied), and server startup must
// accept them rather than refuse them as anchorless.
func TestNew_StoreBackedAttestationVerifiersRegister(t *testing.T) {
	cfg := pebbleMinimalConfig(t)
	cfg.Attestation = &config.AttestationConfig{Formats: map[string]*truststore.Config{
		"tpm2":            {ExternalRootPaths: []string{writeStartupRootPEM(t, "startup-tpm-root")}},
		"android-key":     {ExternalRootPaths: []string{writeStartupRootPEM(t, "startup-android-root")}},
		"apple-appattest": {ExternalRootPaths: []string{writeStartupRootPEM(t, "startup-apple-root")}},
	}}

	srv, err := newServerWithCleanup(t, cfg)
	require.NoError(t, err, "startup refused store-backed attestation verifiers")
	require.NotNil(t, srv)
	require.NotNil(t, srv.trustRoots, "the test must exercise the store-backed import path")
}
