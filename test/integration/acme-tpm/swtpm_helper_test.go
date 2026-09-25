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

//go:build integration && tpm2

package tpm_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-objstore/pkg/common"
	"github.com/jeremyhahn/go-objstore/pkg/local"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"
)

// SwtpmConnection holds a connection to swtpm for integration testing
type SwtpmConnection struct {
	t           *testing.T
	conn        net.Conn
	transport   transport.TPM
	tpmModule   xkmssdk.TrustedPlatformModule
	deviceID    string
	ekCert      *x509.Certificate
	iakAttrs    *xkmssdk.KeyAttributes
	idevidAttrs *xkmssdk.KeyAttributes
	tcgCSR      *xkmssdk.TCG_CSR_IDEVID
	packedCSR   []byte
}

// NewSwtpmConnection creates a new connection to swtpm for testing
func NewSwtpmConnection(t *testing.T, deviceID string) *SwtpmConnection {
	// Get swtpm connection parameters from environment
	host := os.Getenv("TPM_SOCKET_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("TPM_SOCKET_PORT")
	if port == "" {
		port = "2321"
	}

	t.Logf("Connecting to swtpm at %s:%s", host, port)

	// Connect to swtpm via TCP
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), 5*time.Second)
	require.NoError(t, err, "Failed to connect to swtpm")

	// Wrap connection as TPM transport
	tpmTransport := transport.FromReadWriter(conn)

	// Initialize the TPM with TPM2_Startup
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpmTransport)
	if err != nil {
		// Ignore "already initialized" errors
		t.Logf("TPM2_Startup: %v (continuing)", err)
	}

	return &SwtpmConnection{
		t:         t,
		conn:      conn,
		transport: tpmTransport,
		deviceID:  deviceID,
	}
}

// InitializeTPM initializes the go-xkms TPM module
func (s *SwtpmConnection) InitializeTPM() error {
	// Create temporary directories for storage
	tempDir, err := os.MkdirTemp("", "tpm-test-*")
	if err != nil {
		return caerrors.StorageFailureError("failed to create temp dir: %v", err)
	}

	keysDir := filepath.Join(tempDir, "keys")
	blobsDir := filepath.Join(tempDir, "blobs")
	certsDir := filepath.Join(tempDir, "certs")

	for _, dir := range []string{keysDir, blobsDir, certsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return caerrors.StorageFailureError("failed to create dir %s: %v", dir, err)
		}
	}

	// Create local storage backends for testing
	keysStorage := local.New()
	if err := keysStorage.Configure(map[string]string{"path": keysDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure keys storage: %v", err)
	}
	blobsStorage := local.New()
	if err := blobsStorage.Configure(map[string]string{"path": blobsDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure blobs storage: %v", err)
	}
	certsStorage := local.New()
	if err := certsStorage.Configure(map[string]string{"path": certsDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure certs storage: %v", err)
	}

	// Create storage adapters
	backend := NewLocalBackendAdapter(s.t, keysStorage, keysDir)
	blobStore := NewLocalBlobStoreAdapter(s.t, blobsStorage, blobsDir)
	certStore := NewLocalCertStoreAdapter(s.t, certsStorage, certsDir)

	// Create TPM configuration
	config := xkmssdk.DefaultTPMConfig
	config.Device = "" // Not used when Transport is provided
	// Use cert store instead of TPM NVRAM
	config.EK.CertHandle = 0

	// Configure IDevID for enrollment
	config.IDevID = &xkmssdk.IDevIDConfig{
		CertHandle:         0, // Use cert store
		CN:                 "idevid-" + s.deviceID,
		Handle:             0x81010003,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Model:              "TEST-MODEL",
		Serial:             s.deviceID,
		SignatureAlgorithm: "SHA256-RSAPSS",
	}

	// Create TPM parameters
	params := &xkmssdk.TPMParams{
		Backend:      backend,
		BlobStore:    blobStore,
		CertStore:    certStore,
		Config:       &config,
		DebugSecrets: true,
		FQDN:         s.deviceID,
		Logger:       nil,
		Transport:    s.transport,
	}

	// Initialize TPM
	tpmModule, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return caerrors.TPMErr("failed to initialize TPM: %v", err)
	}

	s.tpmModule = tpmModule
	return nil
}

// InitializeTPMWithECDSA initializes the go-xkms TPM module with ECDSA keys for IDevID
func (s *SwtpmConnection) InitializeTPMWithECDSA() error {
	// Create temporary directories for storage
	tempDir, err := os.MkdirTemp("", "tpm-test-*")
	if err != nil {
		return caerrors.StorageFailureError("failed to create temp dir: %v", err)
	}

	keysDir := filepath.Join(tempDir, "keys")
	blobsDir := filepath.Join(tempDir, "blobs")
	certsDir := filepath.Join(tempDir, "certs")

	for _, dir := range []string{keysDir, blobsDir, certsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return caerrors.StorageFailureError("failed to create dir %s: %v", dir, err)
		}
	}

	// Create storage backends
	keysStorage := local.New()
	if err := keysStorage.Configure(map[string]string{"path": keysDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure keys storage: %v", err)
	}
	blobsStorage := local.New()
	if err := blobsStorage.Configure(map[string]string{"path": blobsDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure blobs storage: %v", err)
	}
	certsStorage := local.New()
	if err := certsStorage.Configure(map[string]string{"path": certsDir}); err != nil {
		return caerrors.StorageFailureError("failed to configure certs storage: %v", err)
	}

	// Create storage adapters
	backend := NewLocalBackendAdapter(s.t, keysStorage, keysDir)
	blobStore := NewLocalBlobStoreAdapter(s.t, blobsStorage, blobsDir)
	certStore := NewLocalCertStoreAdapter(s.t, certsStorage, certsDir)

	// Create TPM configuration with ECDSA for IDevID
	config := xkmssdk.DefaultTPMConfig
	config.Device = "" // Not used when Transport is provided
	// Use cert store instead of TPM NVRAM
	config.EK.CertHandle = 0

	// Configure IDevID for enrollment with ECDSA
	config.IDevID = &xkmssdk.IDevIDConfig{
		CertHandle:         0, // Use cert store
		CN:                 "idevid-" + s.deviceID,
		Handle:             0x81010003,
		Hash:               "SHA-256",
		KeyAlgorithm:       "ECDSA",
		Model:              "TEST-MODEL",
		Serial:             s.deviceID,
		SignatureAlgorithm: "ECDSA-SHA256",
	}

	// Create TPM parameters
	params := &xkmssdk.TPMParams{
		Backend:      backend,
		BlobStore:    blobStore,
		CertStore:    certStore,
		Config:       &config,
		DebugSecrets: true,
		FQDN:         s.deviceID,
		Logger:       nil,
		Transport:    s.transport,
	}

	// Initialize TPM
	tpmModule, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return caerrors.TPMErr("failed to initialize TPM: %v", err)
	}

	s.tpmModule = tpmModule
	return nil
}

// Provision provisions the TPM with EK, SRK, IAK keys
func (s *SwtpmConnection) Provision() error {
	if err := s.tpmModule.Provision(nil); err != nil {
		return caerrors.TPMErr("failed to provision TPM: %v", err)
	}

	// Get or generate EK certificate
	ekCert, err := s.tpmModule.EKCertificate()
	if err != nil {
		// Generate self-signed EK certificate for swtpm
		s.t.Logf("Generating self-signed EK certificate for swtpm")
		ekCertDER, err := s.generateEKCertificate()
		if err != nil {
			return caerrors.TPMErr("failed to generate EK certificate: %v", err)
		}

		if err := s.tpmModule.ProvisionEKCert(nil, ekCertDER); err != nil {
			return caerrors.TPMErr("failed to provision EK certificate: %v", err)
		}

		ekCert, err = x509.ParseCertificate(ekCertDER)
		if err != nil {
			return caerrors.MalformedError("failed to parse EK certificate: %v", err)
		}
	}
	s.ekCert = ekCert

	// Get IAK attributes
	iakAttrs, err := s.tpmModule.IAKAttributes()
	if err != nil {
		return caerrors.TPMErr("failed to get IAK attributes: %v", err)
	}
	s.iakAttrs = iakAttrs

	return nil
}

// CreateIDevID creates an IDevID and generates the TCG-CSR-IDEVID
func (s *SwtpmConnection) CreateIDevID(qualifyingData []byte) error {
	idevidAttrs, tcgCSR, err := s.tpmModule.CreateIDevID(s.iakAttrs, s.ekCert, qualifyingData)
	if err != nil {
		return caerrors.TPMErr("failed to create IDevID: %v", err)
	}

	s.idevidAttrs = idevidAttrs
	s.tcgCSR = tcgCSR

	// Pack the TCG-CSR for transmission
	packedCSR, err := xkmssdk.PackIDevIDCSR(tcgCSR)
	if err != nil {
		return caerrors.SerializationFailureError("failed to pack TCG-CSR: %v", err)
	}
	s.packedCSR = packedCSR

	return nil
}

// ActivateCredential performs TPM2_ActivateCredential
func (s *SwtpmConnection) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return s.tpmModule.ActivateCredential(credentialBlob, encryptedSecret)
}

// GetTCGCSR returns the unpacked TCG-CSR-IDEVID structure
func (s *SwtpmConnection) GetTCGCSR() *xkmssdk.TCG_CSR_IDEVID {
	return s.tcgCSR
}

// GetPackedCSR returns the packed TCG-CSR-IDEVID bytes
func (s *SwtpmConnection) GetPackedCSR() []byte {
	return s.packedCSR
}

// GetEKCertificate returns the EK certificate
func (s *SwtpmConnection) GetEKCertificate() *x509.Certificate {
	return s.ekCert
}

// GetTPMModule returns the underlying TPM module for direct access
func (s *SwtpmConnection) GetTPMModule() xkmssdk.TrustedPlatformModule {
	return s.tpmModule
}

// Close closes the swtpm connection
func (s *SwtpmConnection) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

// generateEKCertificate creates a self-signed EK certificate for swtpm testing
func (s *SwtpmConnection) generateEKCertificate() ([]byte, error) {
	// Get EK attributes to access the public key
	ekAttrs, err := s.tpmModule.EKAttributes()
	if err != nil {
		return nil, caerrors.TPMErr("failed to get EK attributes: %v", err)
	}

	// Parse the public key bytes from EK attributes
	ekPublicKey, err := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		return nil, caerrors.MalformedError("failed to parse EK public key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, caerrors.InternalServerError("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   s.deviceID,
			Organization: []string{"swtpm-test"},
		},
		Issuer: pkix.Name{
			CommonName:   "swtpm Test EK CA",
			Organization: []string{"swtpm-test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Generate a temporary signing key for the self-signed certificate
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, caerrors.KeyGenerationFailureError("failed to generate signing key: %v", err)
	}

	// Create the certificate with the EK public key
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, ekPublicKey, signingKey)
	if err != nil {
		return nil, caerrors.SigningFailureError("failed to create certificate: %v", err)
	}

	return certDER, nil
}

// LocalBackendAdapter implements KeyBackend using go-objstore local storage
type LocalBackendAdapter struct {
	t       *testing.T
	storage common.Storage
	dir     string
}

// NewLocalBackendAdapter creates a new local-storage-based key backend
func NewLocalBackendAdapter(t *testing.T, storage common.Storage, dir string) *LocalBackendAdapter {
	return &LocalBackendAdapter{
		t:       t,
		storage: storage,
		dir:     dir,
	}
}

// Get retrieves key data
func (l *LocalBackendAdapter) Get(attrs *xkmssdk.KeyAttributes, ext xkmssdk.FSExtension) ([]byte, error) {
	// Use just the filename - storage is already configured with base path
	key := attrs.CN + string(ext)
	reader, err := l.storage.Get(key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Save writes key data
func (l *LocalBackendAdapter) Save(attrs *xkmssdk.KeyAttributes, data []byte, ext xkmssdk.FSExtension, overwrite bool) error {
	// Use just the filename - storage is already configured with base path
	key := attrs.CN + string(ext)
	return l.storage.Put(key, bytes.NewReader(data))
}

// Delete removes key data
func (l *LocalBackendAdapter) Delete(attrs *xkmssdk.KeyAttributes) error {
	extensions := []xkmssdk.FSExtension{".blob", ".pub", ".ctx"}
	for _, ext := range extensions {
		// Use just the filename - storage is already configured with base path
		key := attrs.CN + string(ext)
		l.storage.Delete(key)
	}
	return nil
}

// LocalBlobStoreAdapter implements BlobStorer using go-objstore local storage
type LocalBlobStoreAdapter struct {
	t       *testing.T
	storage common.Storage
	dir     string
}

// NewLocalBlobStoreAdapter creates a new local-storage-based blob store
func NewLocalBlobStoreAdapter(t *testing.T, storage common.Storage, dir string) *LocalBlobStoreAdapter {
	return &LocalBlobStoreAdapter{
		t:       t,
		storage: storage,
		dir:     dir,
	}
}

// Read reads a blob
func (l *LocalBlobStoreAdapter) Read(name string) ([]byte, error) {
	// Use just the filename - storage is already configured with base path
	reader, err := l.storage.Get(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Write writes a blob
func (l *LocalBlobStoreAdapter) Write(name string, data []byte) error {
	// Use just the filename - storage is already configured with base path
	return l.storage.Put(name, bytes.NewReader(data))
}

// Delete deletes a blob
func (l *LocalBlobStoreAdapter) Delete(name string) error {
	// Use just the filename - storage is already configured with base path
	return l.storage.Delete(name)
}

// LocalCertStoreAdapter implements CertificateStorer using go-objstore local storage
type LocalCertStoreAdapter struct {
	t       *testing.T
	storage common.Storage
	dir     string
}

// NewLocalCertStoreAdapter creates a new local-storage-based cert store
func NewLocalCertStoreAdapter(t *testing.T, storage common.Storage, dir string) *LocalCertStoreAdapter {
	return &LocalCertStoreAdapter{
		t:       t,
		storage: storage,
		dir:     dir,
	}
}

// Get retrieves a certificate
func (l *LocalCertStoreAdapter) Get(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	// Use just the filename - storage is already configured with base path
	key := fmt.Sprintf("%s.pem", attrs.CN)
	reader, err := l.storage.Get(key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(data)
}

// Save saves a certificate
func (l *LocalCertStoreAdapter) Save(attrs *xkmssdk.KeyAttributes, cert *x509.Certificate) error {
	// Use just the filename - storage is already configured with base path
	key := fmt.Sprintf("%s.pem", attrs.CN)
	return l.storage.Put(key, bytes.NewReader(cert.Raw))
}

// Delete removes a certificate
func (l *LocalCertStoreAdapter) Delete(attrs *xkmssdk.KeyAttributes) error {
	// Use just the filename - storage is already configured with base path
	key := fmt.Sprintf("%s.pem", attrs.CN)
	return l.storage.Delete(key)
}

// ImportCertificate imports a certificate from PEM-encoded bytes
func (l *LocalCertStoreAdapter) ImportCertificate(attrs *xkmssdk.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	// Decode PEM to get DER bytes
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, caerrors.MalformedError("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := l.Save(attrs, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// IsSwtpmAvailable checks if swtpm is available for testing
func IsSwtpmAvailable() bool {
	host := os.Getenv("TPM_SOCKET_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("TPM_SOCKET_PORT")
	if port == "" {
		port = "2321"
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// RequireSwtpm fails the test if swtpm is not available.
// Use this instead of skip guards per project testing policy.
func RequireSwtpm(t *testing.T) {
	t.Helper()
	if !IsSwtpmAvailable() {
		host := os.Getenv("TPM_SOCKET_HOST")
		if host == "" {
			host = "localhost"
		}
		port := os.Getenv("TPM_SOCKET_PORT")
		if port == "" {
			port = "2321"
		}
		t.Fatalf("swtpm not available at %s:%s - integration tests require swtpm to be running", host, port)
	}
}
