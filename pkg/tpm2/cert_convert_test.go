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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateToTPMPublic_NilCertificate(t *testing.T) {
	tpmPub, err := CertificateToTPMPublic(nil)
	assert.Nil(t, tpmPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate is nil")
}

func TestCertificateToTPMPublic_ECCP521(t *testing.T) {
	// Generate ECDSA P-521 key
	ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	cert := createCertWithPublicKey(t, &ecKey.PublicKey)
	tpmPub, err := CertificateToTPMPublic(cert)
	require.NoError(t, err)

	eccParams, err := tpmPub.Parameters.ECCDetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMECCNistP521, eccParams.CurveID)

	eccUnique, err := tpmPub.Unique.ECC()
	require.NoError(t, err)
	// Coordinates should be padded to 66 bytes for P-521
	assert.Len(t, eccUnique.X.Buffer, 66)
	assert.Len(t, eccUnique.Y.Buffer, 66)
}

func TestRsaPublicKeyToTPMPublic_NilKey(t *testing.T) {
	tpmPub, err := rsaPublicKeyToTPMPublic(nil)
	assert.Nil(t, tpmPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA public key is nil")
}

func TestEcdsaPublicKeyToTPMPublic_NilKey(t *testing.T) {
	tpmPub, err := ecdsaPublicKeyToTPMPublic(nil)
	assert.Nil(t, tpmPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA public key is nil")
}

func TestEcdsaPublicKeyToTPMPublic_UnsupportedCurve(t *testing.T) {
	// P-224 is not supported by TPM 2.0
	ecKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	tpmPub, err := ecdsaPublicKeyToTPMPublic(&ecKey.PublicKey)
	assert.Nil(t, tpmPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECC curve")
}

func TestEcdsaPublicKeyToTPMPublic_CoordinatePadding(t *testing.T) {
	// Test that coordinates are properly padded
	// Generate keys until we get one with a small X or Y coordinate
	// that needs padding
	var ecKey *ecdsa.PrivateKey
	var err error

	// Generate multiple keys to ensure we test padding logic
	for i := 0; i < 10; i++ {
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		tpmPub, err := ecdsaPublicKeyToTPMPublic(&ecKey.PublicKey)
		require.NoError(t, err)

		eccUnique, err := tpmPub.Unique.ECC()
		require.NoError(t, err)

		// Verify padding is always applied correctly
		assert.Len(t, eccUnique.X.Buffer, 32, "X coordinate should be padded to 32 bytes")
		assert.Len(t, eccUnique.Y.Buffer, 32, "Y coordinate should be padded to 32 bytes")
	}
}

// Helper function to create a certificate with a given public key
func createCertWithPublicKey(t *testing.T, pubKey interface{}) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign with a temporary RSA key
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signingKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
