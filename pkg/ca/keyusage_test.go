package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignCSRDefaultKeyUsageFollowsKeyType checks that keyEncipherment is
// asserted for RSA subject keys only (RFC 5480 §3, RFC 8410 §5).
func TestSignCSRDefaultKeyUsageFollowsKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testCA := setupTestCA(t)
	for name, tt := range map[string]struct {
		key  crypto.Signer
		want x509.KeyUsage
	}{
		"rsa":     {rsaKey, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		"ecdsa":   {ecKey, x509.KeyUsageDigitalSignature},
		"ed25519": {edKey, x509.KeyUsageDigitalSignature},
	} {
		t.Run(name, func(t *testing.T) {
			cn := name + ".keyusage.example.com"
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
			}, tt.key)
			require.NoError(t, err)
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

			cert, err := testCA.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant})
			require.NoError(t, err)
			assert.Equal(t, tt.want, cert.KeyUsage)
		})
	}
}

func TestSignCSRKeyUsageOptionOverridesDefault(t *testing.T) {
	testCA := setupTestCA(t)

	cert, err := testCA.SignCSR(context.Background(), presignCSR(t, "override.keyusage.example.com"),
		&SignOptions{TenantID: testTenant, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement})
	require.NoError(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement, cert.KeyUsage)
}
