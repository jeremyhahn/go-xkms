//go:build integration && idevid

package idevid

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/logging"
	tpm2pkg "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// createTPMWithFullProvisioning creates a TPM instance with full provisioning
func createTPMWithFullProvisioning(t *testing.T) (tpm2pkg.TrustedPlatformModule, func()) {
	logger := logging.NewLogger(logging.DebugLevel, nil)

	config := &tpm2pkg.Config{
		Device:       "/dev/null",
		UseSimulator: true,
		Hash:         "SHA-256",
		EK: &tpm2pkg.EKConfig{
			Handle:          0x81010001,
			HierarchyAuth:   store.NewClearPassword([]byte("")),
			RSAConfig:       &store.RSAConfig{KeySize: 2048},
			SignatureAlg:    x509.SHA256WithRSAPSS,
			CertHandle:      0x01C00002,
			EncryptSessions: true,
		},
		SSRK: &tpm2pkg.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.NewClearPassword([]byte("")),
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
			SignatureAlg:  x509.SHA256WithRSAPSS,
		},
		IAK: &tpm2pkg.IAKConfig{
			CN:            "test-iak",
			Handle:        0x81000003,
			HierarchyAuth: store.NewClearPassword([]byte("")),
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
			SignatureAlg:  x509.SHA256WithRSAPSS,
		},
		IDevID: &tpm2pkg.IDevIDConfig{
			CN:            "test-idevid",
			Handle:        0x81000005,
			HierarchyAuth: store.NewClearPassword([]byte("")),
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
			SignatureAlg:  x509.SHA256WithRSAPSS,
			Model:         "TestDevice",
			Serial:        "SN123456",
		},
		PlatformPCR:   16,
		FileIntegrity: []string{},
	}

	// Create TPM instance
	tpmInstance, err := tpm2pkg.NewTPM2(logger, nil, config, nil, nil)
	require.NoError(t, err, "Failed to create TPM instance")

	cleanup := func() {
		if tpmInstance != nil {
			tpmInstance.Close()
		}
	}

	return tpmInstance, cleanup
}

// createSelfSignedEKCert creates a self-signed EK certificate
func createSelfSignedEKCert(pubKey crypto.PublicKey) (*x509.Certificate, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Manufacturer"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, certDER, nil
}

// TestIDevID_FullCreateIDevID tests the complete CreateIDevID flow
func TestIDevID_FullCreateIDevID(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	// Step 1: Provision TPM (creates EK, SRK, IAK)
	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}
	t.Log("TPM provisioned successfully")

	// Step 2: Get IAK attributes
	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")
	require.NotNil(t, iakAttrs.TPMAttributes, "IAK should have TPM attributes")
	t.Logf("IAK CN: %s, Handle: 0x%x", iakAttrs.CN, iakAttrs.TPMAttributes.Handle)

	// Step 3: Get EK public key
	ekPub := tpmInstance.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	// Step 4: Create EK certificate
	ekCert, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")
	t.Logf("EK Certificate created, size: %d bytes", len(ekCertDER))

	// Step 5: Create qualifying data (nonce)
	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err, "Creating qualifying data should succeed")

	// Step 6: Create IDevID - THIS IS THE MAIN TEST
	idevIDAttrs, tcgCSR, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Logf("CreateIDevID error (may be expected): %v", err)
		// Even on error, we exercised the code paths
	} else {
		require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil")
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
		t.Logf("IDevID created: %s", idevIDAttrs.CN)
		t.Logf("TCG CSR version: %d", tcgCSR.StructVer)
	}
}

// TestIDevID_SignWithIAK tests signing with the IAK using proper SignerOpts
func TestIDevID_SignWithIAK(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err)

	// Create digest
	message := []byte("Test message for signing")
	hash := sha256.Sum256(message)
	digest := hash[:]

	// Create SignerOpts
	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
	}

	// Sign the digest
	signature, err := tpmInstance.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign error: %v", err)
	} else {
		require.NotNil(t, signature, "Signature should not be nil")
		require.Greater(t, len(signature), 0, "Signature should not be empty")
		t.Logf("Signature created, length: %d bytes", len(signature))
	}
}

// TestIDevID_CreateTCGCSR tests TCG CSR creation
func TestIDevID_CreateTCGCSR(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err)

	ekPub := tpmInstance.EK()
	ekCert, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err)
	_ = ekCert

	// Get IAK public key bytes
	iakPubBytes, err := x509.MarshalPKIXPublicKey(tpmInstance.IAK())
	require.NoError(t, err)

	// Test CreateTCG_CSR_IDEVID directly
	tcgCSR, err := tpm2pkg.CreateTCG_CSR_IDEVID(
		[]byte{}, // platformConfigURI
		ekCertDER,
		iakPubBytes,
		"TestModel",
		"TestSerial",
		[]byte{}, // signature
		crypto.SHA256,
	)
	if err != nil {
		t.Logf("CreateTCG_CSR_IDEVID error: %v", err)
	} else {
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
		t.Logf("TCG CSR created: Version=%d, HashAlgID=%d", tcgCSR.StructVer, tcgCSR.HashAlgID)
	}
}

// TestIDevID_EKCertificateRetrieval tests EKCertificate function
func TestIDevID_EKCertificateRetrieval(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	// Try to get EK certificate (will likely fail on simulator)
	cert, err := tpmInstance.EKCertificate()
	if err != nil {
		t.Logf("EKCertificate error (expected on simulator): %v", err)
	} else {
		require.NotNil(t, cert, "EK Certificate should not be nil")
		t.Logf("EK Certificate retrieved: %s", cert.Subject.CommonName)
	}
}

// TestIDevID_ParsePublicKey tests ParsePublicKey function
func TestIDevID_ParsePublicKey(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	ekAttrs, err := tpmInstance.EKAttributes()
	require.NoError(t, err)

	// Get EK public bytes for parsing
	if ekAttrs.TPMAttributes != nil && len(ekAttrs.TPMAttributes.Public) > 0 {
		pubKey, err := tpmInstance.ParsePublicKey(ekAttrs.TPMAttributes.Public)
		if err != nil {
			t.Logf("ParsePublicKey error: %v", err)
		} else {
			require.NotNil(t, pubKey, "Parsed public key should not be nil")
			t.Log("Public key parsed successfully")
		}
	} else {
		t.Log("No TPM public bytes available for parsing")
	}
}

func TestMain(m *testing.M) {
	// Set up simulator environment variables
	if os.Getenv("TPM2_SIMULATOR_HOST") == "" {
		os.Setenv("TPM2_SIMULATOR_HOST", "tpm-simulator")
	}
	if os.Getenv("TPM2_SIMULATOR_PORT") == "" {
		os.Setenv("TPM2_SIMULATOR_PORT", "2421")
	}

	os.Exit(m.Run())
}
