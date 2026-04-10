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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCA creates a self-signed CA certificate for testing.
func generateTestCA(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	// Generate EC private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Parse the certificate for validation
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}

	// Encode to PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return pemData, cert
}

func TestNewTLSCABundler_ValidCertificate(t *testing.T) {
	pemData, expectedCert := generateTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, pemData, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	bundler, err := newTLSCABundler(caFile)
	require.NoError(t, err)
	require.NotNil(t, bundler)
	require.NotNil(t, bundler.certPEM)
	require.NotNil(t, bundler.cert)
	assert.True(t, bundler.cert.Equal(expectedCert))
}

func TestNewTLSCABundler_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "does-not-exist.pem")

	bundler, err := newTLSCABundler(nonExistentFile)
	assert.ErrorIs(t, err, ErrCAFileReadFailed)
	assert.Nil(t, bundler)
}

func TestNewTLSCABundler_InvalidPEMData(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "invalid.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("this is not valid PEM data"), 0600))

	bundler, err := newTLSCABundler(caFile)
	assert.ErrorIs(t, err, ErrCAParseFailed)
	assert.Nil(t, bundler)
}

func TestNewTLSCABundler_WrongPEMBlockType(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "wrong-type.pem")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	bundler, err := newTLSCABundler(caFile)
	assert.ErrorIs(t, err, ErrCAParseFailed)
	assert.Nil(t, bundler)
}

func TestNewTLSCABundler_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "empty.pem")
	require.NoError(t, os.WriteFile(caFile, []byte{}, 0600))

	bundler, err := newTLSCABundler(caFile)
	assert.ErrorIs(t, err, ErrCAParseFailed)
	assert.Nil(t, bundler)
}

func TestNewTLSCABundler_MalformedCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "malformed.pem")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{0x00, 0x01, 0x02, 0x03},
	})
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	bundler, err := newTLSCABundler(caFile)
	assert.ErrorIs(t, err, ErrCAParseFailed)
	assert.Nil(t, bundler)
}

func TestTLSCABundler_CABundle(t *testing.T) {
	pemData, _ := generateTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	bundler, err := newTLSCABundler(caFile)
	require.NoError(t, err)

	bundle, err := bundler.CABundle()
	require.NoError(t, err)
	assert.Equal(t, string(pemData), string(bundle))

	block, _ := pem.Decode(bundle)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestTLSCABundler_CACertificate(t *testing.T) {
	pemData, expectedCert := generateTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	bundler, err := newTLSCABundler(caFile)
	require.NoError(t, err)

	cert, err := bundler.CACertificate()
	require.NoError(t, err)
	assert.True(t, cert.Equal(expectedCert))
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestTLSCABundler_MultipleCalls(t *testing.T) {
	pemData, _ := generateTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	bundler, err := newTLSCABundler(caFile)
	require.NoError(t, err)

	bundle1, err1 := bundler.CABundle()
	bundle2, err2 := bundler.CABundle()
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, string(bundle1), string(bundle2))

	cert1, err1 := bundler.CACertificate()
	cert2, err2 := bundler.CACertificate()
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, cert1.Equal(cert2))
}

// =============================================================================
// newCAInstanceBundler Tests
// =============================================================================

// mockCAInstance implements caInstanceProvider for testing.
type mockCAInstance struct {
	bundlePEM []byte
	bundleErr error
	cert      *x509.Certificate
	certErr   error
}

func (m *mockCAInstance) CABundle() ([]byte, error)                  { return m.bundlePEM, m.bundleErr }
func (m *mockCAInstance) CACertificate() (*x509.Certificate, error) { return m.cert, m.certErr }

func TestNewCAInstanceBundler_Success(t *testing.T) {
	pemData, cert := generateTestCA(t)
	mock := &mockCAInstance{bundlePEM: pemData, cert: cert}

	bundler, err := newCAInstanceBundler(mock)
	require.NoError(t, err)
	require.NotNil(t, bundler)

	bundle, err := bundler.CABundle()
	require.NoError(t, err)
	assert.Equal(t, pemData, bundle)

	gotCert, err := bundler.CACertificate()
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, gotCert.Subject.CommonName)
}

func TestNewCAInstanceBundler_BundleError(t *testing.T) {
	mock := &mockCAInstance{bundleErr: errors.New("bundle error")}

	_, err := newCAInstanceBundler(mock)
	require.Error(t, err)

	var bundleErr *ErrCABundleGet
	assert.True(t, errors.As(err, &bundleErr))
}

func TestNewCAInstanceBundler_CertError(t *testing.T) {
	pemData, _ := generateTestCA(t)
	mock := &mockCAInstance{bundlePEM: pemData, certErr: errors.New("cert error")}

	_, err := newCAInstanceBundler(mock)
	require.Error(t, err)

	var bundleErr *ErrCABundleGet
	assert.True(t, errors.As(err, &bundleErr))
}
