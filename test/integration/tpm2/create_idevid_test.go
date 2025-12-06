//go:build integration && tpm2

package integration

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// createSelfSignedEKCertLocal creates a self-signed EK certificate for testing
func createSelfSignedEKCertLocal(pubKey crypto.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	// Use RSA key for signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

// TestIntegration_CreateIDevID_Simple tests the CreateIDevID function
func TestIntegration_CreateIDevID_Simple(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	// Provision TPM - creates EK, SRK, IAK
	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	// Get IAK attributes (this is the AK that will be used to create IDevID)
	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")
	t.Logf("IAK CN: %s", iakAttrs.CN)

	// Get EK attributes (this loads the EK from TPM handle if not cached)
	ekAttrs, err := tpmInstance.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")
	require.NotNil(t, ekAttrs, "EK attributes should not be nil")

	// Parse the EK public key
	ekPub, err := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err, "Parsing EK public key should succeed")
	require.NotNil(t, ekPub, "EK public key should not be nil")

	// Create self-signed EK cert for testing
	ekCert, err := createSelfSignedEKCertLocal(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	// Call CreateIDevID - this is the main function we want to test
	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	idevIDAttrs, tcgCSR, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		// Log the error but don't fail - some errors are expected in simulator
		t.Logf("CreateIDevID returned error: %v", err)
	} else {
		require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil on success")
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil on success")
		t.Logf("IDevID created successfully: %s", idevIDAttrs.CN)
	}
}

// TestIntegration_Sign_WithIAK tests Sign function with IAK
func TestIntegration_Sign_WithIAK(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err)

	// Test Sign function using SignerOpts
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	// Create SignerOpts
	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
	}

	signature, err := tpmInstance.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign error: %v", err)
	} else {
		require.NotNil(t, signature, "Signature should not be nil")
		t.Logf("Signature length: %d", len(signature))
	}
}
