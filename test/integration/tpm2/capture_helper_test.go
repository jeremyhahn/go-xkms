//go:build integration && tpm2

package integration

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
)

// setupTPM2WithCapture creates a TPM2 instance with traffic capture enabled
func setupTPM2WithCapture(t *testing.T, encryptSession bool) (tpm2lib.TrustedPlatformModule, *TPMCapture, func()) {
	t.Helper()

	// Connect to TPM simulator
	host := getTPMAddress()
	t.Logf("Connecting to TPM at %s", host)

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to TPM: %v", err)
	}

	// Create base transport with closer
	baseTransport := &closableTransport{
		TPM:  transport.FromReadWriter(conn),
		conn: conn,
	}

	// Wrap with capture
	captureTransport := NewTPMCapture(baseTransport)

	// Create logger
	logger := logging.DefaultLogger()

	// Create go-objstore backed storage using the factory
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		t.Fatalf("Failed to create storage factory: %v", err)
	}

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	// Create TPM configuration with session encryption option
	config := &tpm2lib.Config{
		Device:          "", // Not using device, using custom transport
		UseSimulator:    false,
		EncryptSession:  encryptSession, // Control encryption for testing
		Hash:            "SHA-256",
		PlatformPCR:     16,
		PlatformPCRBank: "sha256",
		EK: &tpm2lib.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &tpm2lib.IAKConfig{
			Handle:       0x81010002,
			Hash:         "SHA-256",
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		SSRK: &tpm2lib.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	// Create TPM2 params with custom transport
	params := &tpm2lib.Params{
		Logger:       logger,
		DebugSecrets: false, // Disable to reduce noise in capture
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "capture-test.example.com",
		Transport:    captureTransport, // Use capture transport
	}

	// Create TPM2 instance (allow ErrNotInitialized for fresh TPM)
	tpmInstance, err := tpm2lib.NewTPM2(params)
	if err != nil && err != tpm2lib.ErrNotInitialized {
		captureTransport.Close()
		t.Fatalf("Failed to create TPM2 instance: %v", err)
	}

	// Provision if needed
	if err == tpm2lib.ErrNotInitialized {
		t.Log("TPM not initialized, provisioning...")
		if err := tpmInstance.Provision(nil); err != nil {
			captureTransport.Close()
			t.Fatalf("Failed to provision TPM: %v", err)
		}
	}

	// Cleanup function
	cleanup := func() {
		if tpmInstance != nil {
			tpmInstance.Close()
		}
		captureTransport.Close()
		storageFactory.Close()
	}

	return tpmInstance, captureTransport, cleanup
}

// getSensitivePatterns returns byte patterns that should never appear in plaintext
// These are example patterns - in real tests, use actual sensitive data markers
func getSensitivePatterns() [][]byte {
	return [][]byte{
		[]byte("SENSITIVE_TEST_PATTERN"),
		[]byte("SECRET_KEY_DATA"),
		// Add more patterns as needed for specific tests
	}
}

// closableTransport wraps transport.TPM to add Close functionality
type closableTransport struct {
	transport.TPM
	conn net.Conn
}

// Close closes the underlying connection
func (ct *closableTransport) Close() error {
	if ct.conn != nil {
		return ct.conn.Close()
	}
	return nil
}
