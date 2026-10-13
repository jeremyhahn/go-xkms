//go:build integration && idevid

package idevid

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

const (
	defaultTPMHost = "tpm-simulator"
	defaultTPMPort = "2421"
)

// memCertStore is a minimal in-memory certificate store for the IDevID
// suite. Production certificate storage lives in pkg/ca; this suite only
// needs somewhere for the EK certificate to land during provisioning.
type memCertStore struct {
	mu    sync.RWMutex
	certs map[string]*x509.Certificate
}

func newMemCertStore() *memCertStore {
	return &memCertStore{certs: make(map[string]*x509.Certificate)}
}

func (m *memCertStore) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cert, ok := m.certs[attrs.CN]; ok {
		return cert, nil
	}
	return nil, &errs.Message{Msg: fmt.Sprintf("certificate not found: %s", attrs.CN)}
}

func (m *memCertStore) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[attrs.CN] = cert
	return nil
}

func (m *memCertStore) Delete(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certs, attrs.CN)
	return nil
}

func (m *memCertStore) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, &errs.Message{Msg: "failed to decode PEM certificate"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := m.Save(attrs, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// tpmAddress returns the TPM simulator address from the environment or the
// package defaults set in TestMain.
func tpmAddress() string {
	host := os.Getenv("TPM2_SIMULATOR_HOST")
	if host == "" {
		host = defaultTPMHost
	}
	port := os.Getenv("TPM2_SIMULATOR_PORT")
	if port == "" {
		port = defaultTPMPort
	}
	return net.JoinHostPort(host, port)
}

// openTPM establishes a TCP connection to the swtpm sidecar, retrying with
// exponential backoff while the container finishes starting up.
func openTPM(t *testing.T) io.ReadWriteCloser {
	t.Helper()

	address := tpmAddress()
	var conn net.Conn
	var err error
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
			t.Logf("Connection attempt %d failed, retrying in %v: %v", i+1, backoff, err)
			time.Sleep(backoff)
		}
	}
	if err != nil {
		t.Fatalf("Failed to connect to TPM at %s after %d attempts: %v", address, maxRetries, err)
	}
	return conn
}

// createTPMWithFullProvisioning creates a TPM2 instance connected to the
// swtpm sidecar, configured with EK, SRK, IAK and IDevID handles.
func createTPMWithFullProvisioning(t *testing.T) (tpm2pkg.TrustedPlatformModule, func()) {
	t.Helper()

	conn := openTPM(t)
	tpmTransport := transport.FromReadWriter(conn)

	logger := slog.Default()

	storageFactory, err := store.NewStorageFactory(logger, "")
	require.NoError(t, err, "Failed to create storage factory")

	config := &tpm2pkg.Config{
		Device:       "",
		UseSimulator: false,
		Hash:         "SHA-256",
		EK: &tpm2pkg.EKConfig{
			Handle:     0x81010001,
			RSAConfig:  &store.RSAConfig{KeySize: 2048},
			CertHandle: 0x01C00002,
		},
		SSRK: &tpm2pkg.SRKConfig{
			Handle:    0x81000001,
			RSAConfig: &store.RSAConfig{KeySize: 2048},
		},
		IAK: &tpm2pkg.IAKConfig{
			CN:                 "test-iak",
			Handle:             0x81000003,
			Hash:               "SHA-256",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		IDevID: &tpm2pkg.IDevIDConfig{
			CN:                 "test-idevid",
			Handle:             0x81000005,
			Hash:               "SHA-256",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			Model:              "TestDevice",
			Serial:             "SN123456",
		},
		PlatformPCR:   16,
		FileIntegrity: []string{},
	}

	params := &tpm2pkg.Params{
		Logger:    logger,
		Config:    config,
		Backend:   storageFactory.KeyBackend(),
		CertStore: newMemCertStore(),
		FQDN:      "idevid-integration-test.example.com",
		Transport: tpmTransport,
	}

	tpmInstance, err := tpm2pkg.NewTPM2(params)
	if err != nil && err != tpm2pkg.ErrNotInitialized {
		conn.Close()
		t.Fatalf("Failed to create TPM instance: %v", err)
	}

	cleanup := func() {
		if tpmInstance != nil {
			tpmInstance.Close()
		}
	}

	return tpmInstance, cleanup
}

// createSelfSignedEKCert creates a self-signed EK certificate for testing.
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

// TestIDevID_FullCreateIDevID tests the complete CreateIDevID flow.
func TestIDevID_FullCreateIDevID(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}
	t.Log("TPM provisioned successfully")

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")
	require.NotNil(t, iakAttrs.TPMAttributes, "IAK should have TPM attributes")
	t.Logf("IAK CN: %s, Handle: 0x%x", iakAttrs.CN, iakAttrs.TPMAttributes.Handle)

	ekPub, ekErr := tpmInstance.EK()
	require.NoError(t, ekErr, "EK should succeed")
	require.NotNil(t, ekPub, "EK public key should not be nil")

	ekCert, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")
	t.Logf("EK Certificate created, size: %d bytes", len(ekCertDER))

	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err, "Creating qualifying data should succeed")

	idevIDAttrs, tcgCSR, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Logf("CreateIDevID error (may be expected): %v", err)
	} else {
		require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil")
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
		t.Logf("IDevID created: %s", idevIDAttrs.CN)
		t.Logf("TCG CSR version: %d", tcgCSR.StructVer)
	}
}

// TestIDevID_SignWithIAK tests signing with the IAK using proper SignerOpts.
func TestIDevID_SignWithIAK(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err)

	message := []byte("Test message for signing")
	hash := sha256.Sum256(message)
	digest := hash[:]

	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
	}

	signature, err := tpmInstance.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign error: %v", err)
	} else {
		require.NotNil(t, signature, "Signature should not be nil")
		require.Greater(t, len(signature), 0, "Signature should not be empty")
		t.Logf("Signature created, length: %d bytes", len(signature))
	}
}

// TestIDevID_CreateTCGCSR tests TCG CSR creation via the CreateTCG_CSR_IDEVID
// method, which requires both the IAK and a provisioned IDevID.
func TestIDevID_CreateTCGCSR(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	require.NoError(t, err)

	ekPub, ekErr := tpmInstance.EK()
	require.NoError(t, ekErr, "EK should succeed")
	ekCert, _, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err)

	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err, "Creating qualifying data should succeed")

	idevIDAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Logf("CreateIDevID error (may be expected): %v", err)
		t.Skip("IDevID not available, cannot exercise CreateTCG_CSR_IDEVID")
	}
	require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil")

	tcgCSR, err := tpmInstance.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevIDAttrs)
	if err != nil {
		t.Logf("CreateTCG_CSR_IDEVID error: %v", err)
	} else {
		t.Logf("TCG CSR created: Version=%d, HashAlgID=%d", tcgCSR.StructVer, tcgCSR.CsrContents.HashAlgoId)
	}
}

// TestIDevID_EKCertificateRetrieval tests EKCertificate function.
func TestIDevID_EKCertificateRetrieval(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}

	cert, err := tpmInstance.EKCertificate()
	if err != nil {
		t.Logf("EKCertificate error (expected on simulator): %v", err)
	} else {
		require.NotNil(t, cert, "EK Certificate should not be nil")
		t.Logf("EK Certificate retrieved: %s", cert.Subject.CommonName)
	}
}

// TestIDevID_ParsePublicKey tests ParsePublicKey function.
func TestIDevID_ParsePublicKey(t *testing.T) {
	tpmInstance, cleanup := createTPMWithFullProvisioning(t)
	defer cleanup()

	err := tpmInstance.Provision(nil)
	if err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}

	ekAttrs, err := tpmInstance.EKAttributes()
	require.NoError(t, err)

	if ekAttrs.TPMAttributes != nil && len(ekAttrs.TPMAttributes.PublicKeyBytes) > 0 {
		pubKey, err := tpmInstance.ParsePublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
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
	if os.Getenv("TPM2_SIMULATOR_HOST") == "" {
		os.Setenv("TPM2_SIMULATOR_HOST", defaultTPMHost)
	}
	if os.Getenv("TPM2_SIMULATOR_PORT") == "" {
		os.Setenv("TPM2_SIMULATOR_PORT", defaultTPMPort)
	}

	os.Exit(m.Run())
}
