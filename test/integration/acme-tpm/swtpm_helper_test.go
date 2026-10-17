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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"
	"github.com/stretchr/testify/require"
)

// SwtpmConnection holds a connection to swtpm for integration testing
type SwtpmConnection struct {
	t           *testing.T
	conn        net.Conn
	transport   transport.TPM
	tpmModule   xkmssdk.TrustedPlatformModule
	tpmConfig   *xkmssdk.TPMConfig
	keys        xkmssdk.TPMKeyBackend
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
	certsDir := filepath.Join(tempDir, "certs")

	for _, dir := range []string{keysDir, certsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return caerrors.StorageFailureError("failed to create dir %s: %v", dir, err)
		}
	}

	// Create local storage backends for testing
	keysStorage, err := xkmssdk.NewObjectStorage("local", map[string]string{"path": keysDir})
	if err != nil {
		return caerrors.StorageFailureError("failed to open keys storage: %v", err)
	}
	certsStorage, err := xkmssdk.NewObjectStorage("local", map[string]string{"path": certsDir})
	if err != nil {
		return caerrors.StorageFailureError("failed to open certs storage: %v", err)
	}

	// Create storage adapters
	backend := NewLocalBackendAdapter(s.t, keysStorage, keysDir)
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
		Backend:   backend,
		CertStore: certStore,
		Config:    &config,
		FQDN:      s.deviceID,
		Logger:    nil,
		Transport: s.transport,
	}

	// Initialize TPM
	tpmModule, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return caerrors.TPMErr("failed to initialize TPM: %v", err)
	}

	s.tpmModule = tpmModule
	s.tpmConfig = &config
	s.keys = backend
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
	certsDir := filepath.Join(tempDir, "certs")

	for _, dir := range []string{keysDir, certsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return caerrors.StorageFailureError("failed to create dir %s: %v", dir, err)
		}
	}

	// Create storage backends
	keysStorage, err := xkmssdk.NewObjectStorage("local", map[string]string{"path": keysDir})
	if err != nil {
		return caerrors.StorageFailureError("failed to open keys storage: %v", err)
	}
	certsStorage, err := xkmssdk.NewObjectStorage("local", map[string]string{"path": certsDir})
	if err != nil {
		return caerrors.StorageFailureError("failed to open certs storage: %v", err)
	}

	// Create storage adapters
	backend := NewLocalBackendAdapter(s.t, keysStorage, keysDir)
	certStore := NewLocalCertStoreAdapter(s.t, certsStorage, certsDir)

	// Create TPM configuration with ECDSA for IDevID
	config := xkmssdk.DefaultTPMConfig
	config.Device = "" // Not used when Transport is provided
	// Use cert store instead of TPM NVRAM
	config.EK.CertHandle = 0

	// Configure the IAK for ECDSA too: xkmssdk.DefaultTPMConfig.IAK is a
	// shared *IAKConfig (pkg/tpm2/config.go's package-level DefaultConfig),
	// so `config := xkmssdk.DefaultTPMConfig` only copies the outer struct --
	// config.IAK still points at that same shared RSA-default instance.
	// TestSignTCGCSRIDevID_ValidECDSAEnrollment asserts BOTH the IAK and the
	// IDevID public keys are ECDSA; leaving this unset left the IAK issued
	// as RSA (the shared default) while only IDevID actually became ECDSA.
	// Copying the struct before mutating it keeps the shared package default
	// untouched for every other test.
	iakConfig := *xkmssdk.DefaultTPMConfig.IAK
	iakConfig.KeyAlgorithm = "ECDSA"
	iakConfig.SignatureAlgorithm = "ECDSA-SHA256"
	iakConfig.RSAConfig = nil
	// ECCConfig must be set explicitly, not left nil: pkg/tpm2's own
	// TestVerifyTCG_CSR_IAK_Stateless_ECDSAKey_Succeeds (the one other place
	// in this repo that provisions an ECDSA IAK) sets exactly this, and
	// without it TPM2_Certify's signature over the IDevID key fails to
	// verify (ErrCertifySignature) even though key creation itself succeeds
	// silently -- the template's own "nil curve defaults to P-256" fallback
	// (pkg/tpm2/devid_template.go) is not enough on its own here.
	iakConfig.ECCConfig = &xkmssdk.ECCConfig{Curve: "P-256"}
	config.IAK = &iakConfig

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
		Backend:   backend,
		CertStore: certStore,
		Config:    &config,
		FQDN:      s.deviceID,
		Logger:    nil,
		Transport: s.transport,
	}

	// Initialize TPM
	tpmModule, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return caerrors.TPMErr("failed to initialize TPM: %v", err)
	}

	s.tpmModule = tpmModule
	s.tpmConfig = &config
	s.keys = backend
	return nil
}

// Provision provisions the TPM with EK, SRK, IAK keys, then enrolls the
// Platform SRK and installs a throwaway IAK certificate: TPM2.Provision is
// TCG-only (EK + Shared SRK + IAK) and never creates either. Both are
// required by the certify model device-attest-01 uses
// (client.XKMSTPMAdapter.CreateAttestedKey parents the certificate key under
// the Platform SRK; deviceattest01.Setup reads the IAK certificate for the
// statement's x5c[0]), the same way pkg/acme/client/service.openDeviceTPM
// provisions the in-process TPM simulator for the same challenge.
func (s *SwtpmConnection) Provision() error {
	if err := s.tpmModule.Provision(nil); err != nil {
		return caerrors.TPMErr("failed to provision TPM: %v", err)
	}

	if err := xkmstest.EnrollPlatformSRK(s.tpmModule, s.tpmConfig); err != nil {
		return caerrors.TPMErr("failed to enroll platform SRK: %v", err)
	}

	if err := service.ProvisionSimulatorIAKCertificate(s.tpmModule); err != nil {
		return caerrors.TPMErr("failed to provision IAK certificate: %v", err)
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

// GetKeyBackend returns the store the TPM's key blobs live in
func (s *SwtpmConnection) GetKeyBackend() xkmssdk.TPMKeyBackend {
	return s.keys
}

// Close closes the swtpm connection
func (s *SwtpmConnection) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

// swtpmTestEKIssuer is the shared, fixed signing key/certificate every
// generateEKCertificate call signs a test device's EK certificate with, so
// every EK certificate this test binary generates chains to ONE reusable
// root -- SwtpmTestEKRootPEM / writeSwtpmTestEKRootPEM expose it for
// newTestCA (handlers_tcgcsr_integration_test.go) to configure as a pkg/ca
// TCGConfig trust anchor. Lazily loaded once via swtpmTestEKIssuerOnce, from
// the fixed key/cert committed at testdata/swtpm-test-ek-root.{crt,key}.
//
// Before this, each call minted a fresh ECDSA key, signed with it, and then
// discarded it -- the certificate embedded the EK's own public key but was
// signed by a key nothing else ever saw again, so no caller could construct
// a matching root to verify it against. A shared, retrievable issuer is
// required for chain verification to be possible at all, not merely
// convenient.
//
// It must additionally be FIXED, not generated fresh per test-binary run
// (as an earlier version of this helper did): the acme-tpm lane's real ACME
// server (test/integration/acme-tpm/config.acme-tpm.yaml, a separate
// process in the acme-server container) verifies device EK certificates
// against its own configured trust anchors too, and can only be given a
// trust anchor that exists before it starts -- config.acme-tpm.yaml's
// `ca.tcg-config.trust-anchors` points at the same committed
// testdata/swtpm-test-ek-root.crt (bind-mounted read-only into that
// container by docker-compose.yml), so the two processes agree on the
// issuer without either needing to know anything about the other's runtime
// state.
var (
	swtpmTestEKIssuerOnce sync.Once
	swtpmTestEKIssuerKey  *ecdsa.PrivateKey
	swtpmTestEKIssuerCert *x509.Certificate
)

func swtpmTestEKIssuer() (*ecdsa.PrivateKey, *x509.Certificate) {
	swtpmTestEKIssuerOnce.Do(func() {
		certPEM, err := os.ReadFile("testdata/swtpm-test-ek-root.crt")
		if err != nil {
			panic(fmt.Sprintf("swtpmTestEKIssuer: failed to read issuer certificate: %v", err))
		}
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			panic("swtpmTestEKIssuer: testdata/swtpm-test-ek-root.crt has no PEM block")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			panic(fmt.Sprintf("swtpmTestEKIssuer: failed to parse issuer certificate: %v", err))
		}

		keyPEM, err := os.ReadFile("testdata/swtpm-test-ek-root.key")
		if err != nil {
			panic(fmt.Sprintf("swtpmTestEKIssuer: failed to read issuer key: %v", err))
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			panic("swtpmTestEKIssuer: testdata/swtpm-test-ek-root.key has no PEM block")
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			panic(fmt.Sprintf("swtpmTestEKIssuer: failed to parse issuer key: %v", err))
		}

		swtpmTestEKIssuerKey, swtpmTestEKIssuerCert = key, cert
	})
	return swtpmTestEKIssuerKey, swtpmTestEKIssuerCert
}

// SwtpmTestEKRootPEM returns the PEM encoding of the shared swtpm test EK
// issuer certificate (see swtpmTestEKIssuer).
func SwtpmTestEKRootPEM() []byte {
	_, cert := swtpmTestEKIssuer()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// writeSwtpmTestEKRootPEM writes SwtpmTestEKRootPEM to a file under t's
// temporary directory and returns its path, for
// truststore.Config.ExternalRootPaths (pkg/attestation/truststore has no
// inline-PEM option).
func writeSwtpmTestEKRootPEM(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "swtpm-test-ek-root.pem")
	require.NoError(t, os.WriteFile(path, SwtpmTestEKRootPEM(), 0o600))
	return path
}

// generateEKCertificate creates an EK certificate for swtpm testing, signed
// by the shared swtpmTestEKIssuer and carrying the tcg-kp-EKCertificate
// extended key usage (2.23.133.8.1) the TCG EK Credential Profile defines --
// pkg/ca/tcg_ek_trust.go's requireTCGEKCertificateEKU refuses any EK
// certificate without it, a real manufacturer certificate included.
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

	subject := pkix.Name{
		CommonName:   s.deviceID,
		Organization: []string{"swtpm-test"},
	}

	// TCG EK Credential Profile subjectAltName directoryName: tcg-at-
	// tpmManufacturer/tpmModel/tpmVersion (2.23.133.2.{1,2,3}). Without the
	// manufacturer attribute pkg/ca/tcg_devid_name.go's TCGTPMManufacturer
	// refuses the certificate outright (ErrTCGEKManufacturerUnknown) before
	// chain verification is even reached. Read from swtpm itself via
	// TPM2_GetCapability (FixedProperties) rather than hardcoding, the same
	// pattern service.ProvisionSimulatorIAKCertificate already uses for the
	// IAK certificate this same test binary provisions.
	props, err := s.tpmModule.FixedProperties()
	if err != nil {
		return nil, caerrors.TPMErr("failed to read TPM fixed properties: %v", err)
	}
	san, err := ca.BuildSubjectAltName(subject, nil, nil, nil, nil, nil, []pkix.Name{{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: props.ManufacturerCode},
			{Type: ca.OIDTCGAttributeTPMModel, Value: props.Model},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: fmt.Sprintf("id:%04X%04X", props.FwMajor, props.FwMinor)},
		},
	}})
	if err != nil {
		return nil, caerrors.MalformedError("failed to build EK certificate subject alt name: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		// tcg-kp-EKCertificate: see the function doc comment above.
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpEKCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{san},
	}

	issuerKey, issuerCert := swtpmTestEKIssuer()

	// Sign with the shared issuer (see swtpmTestEKIssuer's doc comment) --
	// the certificate's Issuer field is derived from issuerCert.Subject by
	// x509.CreateCertificate, not from this template.
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, ekPublicKey, issuerKey)
	if err != nil {
		return nil, caerrors.SigningFailureError("failed to create certificate: %v", err)
	}

	return certDER, nil
}

// LocalBackendAdapter implements KeyBackend using a go-qrdb objstore engine on the local provider
type LocalBackendAdapter struct {
	t       *testing.T
	storage xkmssdk.ObjectStorage
	dir     string
}

// NewLocalBackendAdapter creates a new local-storage-based key backend
func NewLocalBackendAdapter(t *testing.T, storage xkmssdk.ObjectStorage, dir string) *LocalBackendAdapter {
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
	data, err := l.storage.Get([]byte(key))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, store.ErrBlobNotFound
	}
	return data, nil
}

// Save writes key data
func (l *LocalBackendAdapter) Save(attrs *xkmssdk.KeyAttributes, data []byte, ext xkmssdk.FSExtension, overwrite bool) error {
	// Use just the filename - storage is already configured with base path
	key := attrs.CN + string(ext)
	return l.storage.Set([]byte(key), data)
}

// Delete removes key data
func (l *LocalBackendAdapter) Delete(attrs *xkmssdk.KeyAttributes) error {
	extensions := []xkmssdk.FSExtension{".blob", ".pub", ".ctx"}
	for _, ext := range extensions {
		// Use just the filename - storage is already configured with base path
		key := attrs.CN + string(ext)
		if err := l.storage.Delete([]byte(key)); err != nil {
			return err
		}
	}
	return nil
}

// LocalCertStoreAdapter implements CertificateStorer using a go-qrdb objstore engine on the local provider
type LocalCertStoreAdapter struct {
	t       *testing.T
	storage xkmssdk.ObjectStorage
	dir     string
}

// NewLocalCertStoreAdapter creates a new local-storage-based cert store
func NewLocalCertStoreAdapter(t *testing.T, storage xkmssdk.ObjectStorage, dir string) *LocalCertStoreAdapter {
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
	data, err := l.storage.Get([]byte(key))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, store.ErrBlobNotFound
	}
	return x509.ParseCertificate(data)
}

// Save saves a certificate
func (l *LocalCertStoreAdapter) Save(attrs *xkmssdk.KeyAttributes, cert *x509.Certificate) error {
	// Use just the filename - storage is already configured with base path
	key := fmt.Sprintf("%s.pem", attrs.CN)
	return l.storage.Set([]byte(key), cert.Raw)
}

// Delete removes a certificate
func (l *LocalCertStoreAdapter) Delete(attrs *xkmssdk.KeyAttributes) error {
	// Use just the filename - storage is already configured with base path
	key := fmt.Sprintf("%s.pem", attrs.CN)
	return l.storage.Delete([]byte(key))
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
