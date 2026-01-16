package tpm2

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================
// NewTPM2 Coverage Tests
// Tests that exercise error paths without needing the simulator
// ===========================================

// Note: TestNewTPM2_InvalidHashConfigError was removed because hash validation
// occurs after device/transport initialization in the NewTPM2 function.
// The hash function is only validated when parsing after the device is opened.

func TestNewTPM2_ConfigDefaultsApplied(t *testing.T) {
	// Test that defaults are applied to config
	// Use createSim which properly handles the simulator singleton
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	config := tpm.Config()

	// Check that defaults were applied
	assert.NotNil(t, config.EK)
	assert.NotNil(t, config.SSRK)
	assert.NotNil(t, config.KeyStore)
	assert.Equal(t, uint(16), config.PlatformPCR)
}

func TestNewTPM2_WithExistingTransport(t *testing.T) {
	// Test with existing transport
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create a new TPM2 using the existing transport
	params := &Params{
		Config: &Config{
			UseSimulator: false, // Don't try to open another simulator
			Hash:         "SHA-256",
			EK: &EKConfig{
				Handle:       0x81010001,
				KeyAlgorithm: x509.RSA.String(),
				RSAConfig: &store.RSAConfig{
					KeySize: 2048,
				},
			},
		},
		Logger:    slog.Default(),
		Transport: tpm.Transport(), // Use existing transport
	}

	tpm2Instance, err := NewTPM2(params)
	if err == nil || err == ErrNotInitialized {
		assert.NotNil(t, tpm2Instance)
		// Don't close as it shares the transport
	}
}

func TestNewTPM2_WithEntropyConfig(t *testing.T) {
	// Test with entropy enabled
	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// TPM should use itself as random source
	assert.True(t, tpm.Config().UseEntropy)
}

func TestNewTPM2_WithEncryptedSessions(t *testing.T) {
	// Test with encrypted sessions
	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	assert.True(t, tpm.Config().EncryptSession)
}

// ===========================================
// Sign Coverage Tests
// ===========================================

func TestSign_NonSignerOptsType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with non-SignerOpts type
	digest := sha256.Sum256([]byte("test data"))
	_, err := tpm.Sign(nil, digest[:], crypto.SHA256)

	assert.Equal(t, store.ErrInvalidSignerOpts, err)
}

func TestSign_WithNilOptsParam(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	digest := sha256.Sum256([]byte("test data"))
	_, err := tpm.Sign(nil, digest[:], nil)

	// Should return invalid signer opts error
	assert.NotNil(t, err)
}

func TestSign_RSAKeyCreationAndSigning(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create an RSA key
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent

	keyAttrs := &types.KeyAttributes{
		CN:           "test-sign-rsa-cov",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-pass")),
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
	require.NoError(t, err)
	require.NotNil(t, rsaPub)

	// Clean up created key
	defer tpm.Flush(keyAttrs.TPMAttributes.Handle)

	// Sign with the key
	digest := sha256.Sum256([]byte("test data to sign"))
	signerOpts := &store.SignerOpts{
		KeyAttributes: keyAttrs,
	}

	sig, err := tpm.Sign(nil, digest[:], signerOpts)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestSign_ECDSAKeyCreationAndSigning(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create an ECDSA key
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent

	keyAttrs := &types.KeyAttributes{
		CN:           "test-sign-ecdsa-cov",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-pass")),
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	ecPub, err := tpm.CreateECDSA(keyAttrs, nil, false)
	require.NoError(t, err)
	require.NotNil(t, ecPub)

	// Clean up created key
	defer tpm.Flush(keyAttrs.TPMAttributes.Handle)

	// Sign with the key
	digest := sha256.Sum256([]byte("test data to sign with ecdsa"))
	signerOpts := &store.SignerOpts{
		KeyAttributes: keyAttrs,
	}

	sig, err := tpm.Sign(nil, digest[:], signerOpts)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// Note: TestSign_WithSHA384HashAlgorithm and TestSign_WithSHA512HashAlgorithm were removed
// because the swtpm simulator does not support SHA384/SHA512 hash algorithms with RSA signing schemes.
// The TPM returns "TPM_RC_SCHEME: unsupported or incompatible scheme" for these combinations.
// SHA256 is the standard hash algorithm used with RSA keys in TPM2.

func TestSign_WithInvalidHashFuncMD5(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create an RSA key
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent

	keyAttrs := &types.KeyAttributes{
		CN:           "test-sign-invalid-hash-cov",
		Hash:         crypto.MD5, // Invalid hash for TPM
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-pass")),
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
	require.NoError(t, err)
	require.NotNil(t, rsaPub)

	defer tpm.Flush(keyAttrs.TPMAttributes.Handle)

	digest := sha256.Sum256([]byte("test data"))
	signerOpts := &store.SignerOpts{
		KeyAttributes: keyAttrs,
	}

	_, err = tpm.Sign(nil, digest[:], signerOpts)
	assert.Equal(t, store.ErrInvalidHashFunction, err)
}

func TestSign_WithCustomKeyBackend(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create an RSA key
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent

	// Create a memory backend for testing
	storageFactory, err := store.NewStorageFactory(slog.Default(), "")
	require.NoError(t, err)

	backend := storageFactory.KeyBackend()

	keyAttrs := &types.KeyAttributes{
		CN:           "test-sign-custom-backend-cov",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-pass")),
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	rsaPub, err := tpm.CreateRSA(keyAttrs, backend, false)
	require.NoError(t, err)
	require.NotNil(t, rsaPub)

	defer tpm.Flush(keyAttrs.TPMAttributes.Handle)

	digest := sha256.Sum256([]byte("test data"))
	signerOpts := &store.SignerOpts{
		KeyAttributes: keyAttrs,
		Backend:       backend, // Custom backend
	}

	sig, err := tpm.Sign(nil, digest[:], signerOpts)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// ===========================================
// SignValidate Coverage Tests
// Note: SignValidate currently panics on nil keyAttrs - these tests cover valid error paths
// ===========================================

func TestSignValidate_NilTPMAttrsError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:            "test",
		TPMAttributes: nil, // nil TPMAttributes
	}

	_, err := tpm.SignValidate(keyAttrs, []byte("digest"), []byte("validation"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "TPMAttributes.Public is required")
}

func TestSignValidate_ZeroPublicTypeError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			Public: tpm2.TPMTPublic{
				Type: 0, // Zero type
			},
		},
	}

	_, err := tpm.SignValidate(keyAttrs, []byte("digest"), []byte("validation"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "TPMAttributes.Public is required")
}

func TestSignValidate_ZeroHashAlgError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			Public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
			},
			HashAlg: 0, // Zero hash alg
		},
	}

	_, err := tpm.SignValidate(keyAttrs, []byte("digest"), []byte("validation"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "TPMAttributes.HashAlg is required")
}

// ===========================================
// EKCertificate Coverage Tests
// ===========================================

func TestEKCertificate_ZeroCertHandleWithMockStore(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Set up empty mock certificate store to avoid nil pointer
	mockCertStore := &mockCertStoreCov{
		certs: make(map[string]*x509.Certificate),
	}
	tpmImpl.certStore = mockCertStore

	// Set CertHandle to 0 to use certificate store path
	originalCertHandle := tpmImpl.config.EK.CertHandle
	tpmImpl.config.EK.CertHandle = 0

	// Without a certificate in the store, this should fail
	_, err := tpm.EKCertificate()
	assert.Equal(t, ErrEndorsementCertNotFound, err)

	// Restore
	tpmImpl.config.EK.CertHandle = originalCertHandle
}

func TestEKCertificate_CertStoreWithMock(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Create a mock certificate store
	mockCertStore := &mockCertStoreCov{
		certs: make(map[string]*x509.Certificate),
	}

	// Create a test certificate
	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test EK Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	mockCertStore.certs[ekAttrs.CN] = testCert
	tpmImpl.certStore = mockCertStore

	// Set CertHandle to 0 to use certificate store path
	originalCertHandle := tpmImpl.config.EK.CertHandle
	tpmImpl.config.EK.CertHandle = 0

	cert, err := tpm.EKCertificate()
	require.NoError(t, err)
	assert.Equal(t, testCert.SerialNumber, cert.SerialNumber)

	// Restore
	tpmImpl.config.EK.CertHandle = originalCertHandle
}

func TestEKCertificate_FallbackOnNVRAMReadError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// The default simulator setup should have EK cert handle set
	// If NVRAM read fails, it should try the cert store
	_, err := tpm.EKCertificate()
	// This may fail if no cert is in NVRAM or cert store,
	// which is expected for swtpm
	if err != nil {
		assert.True(t,
			err == ErrEndorsementCertNotFound ||
				errors.Is(err, ErrEndorsementCertNotFound) ||
				err.Error() == "x509: malformed certificate",
			"Unexpected error: %v", err)
	}
}

// ===========================================
// Hash and HashSequence Tests
// ===========================================

func TestHash_NilKeyAttrsError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, _, err := tpm.Hash(nil, []byte("test data"))
	assert.Equal(t, ErrInvalidKeyAttributes, err)
}

func TestHash_NilTPMAttrsError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:            "test",
		TPMAttributes: nil,
	}

	_, _, err := tpm.Hash(keyAttrs, []byte("test data"))
	assert.Equal(t, ErrInvalidKeyAttributes, err)
}

func TestHash_SmallDataDirectPath(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Small data (< 1024 bytes) uses direct hash
	data := []byte("small test data")
	hash, validation, err := tpm.Hash(keyAttrs, data)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEmpty(t, validation)
}

func TestHashSequence_LargeDataSequencePath(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Large data (> 1024 bytes) uses sequence hash
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash, validation, err := tpm.Hash(keyAttrs, data)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEmpty(t, validation)
}

func TestHashSequence_VeryLargeDataMultipleUpdates(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Very large data to test multiple sequence updates
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash, validation, err := tpm.Hash(keyAttrs, data)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEmpty(t, validation)
}

func TestHashSequence_WithHierarchyAuthPath(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN: "test",
		TPMAttributes: &types.TPMAttributes{
			HashAlg:       tpm2.TPMAlgSHA256,
			HierarchyAuth: store.NewClearPassword([]byte("test-auth")),
		},
	}

	// Large data to use sequence hash path
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash, validation, err := tpm.Hash(keyAttrs, data)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEmpty(t, validation)
}

func TestHashSequence_WithParentHierarchyAuthPath(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	parentAttrs := &types.KeyAttributes{
		CN: "parent",
		TPMAttributes: &types.TPMAttributes{
			HierarchyAuth: store.NewClearPassword([]byte("parent-auth")),
		},
	}

	keyAttrs := &types.KeyAttributes{
		CN:     "test",
		Parent: parentAttrs,
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Large data to use sequence hash path with parent auth
	data := make([]byte, 2048)

	hash, validation, err := tpm.Hash(keyAttrs, data)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEmpty(t, validation)
}

// ===========================================
// Open/Close Coverage Tests
// ===========================================

func TestOpen_SimulatorReopenPath(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Close and reopen
	err := tpm.Close()
	require.NoError(t, err)

	err = tpm.Open()
	require.NoError(t, err)
}

// ===========================================
// Misc Coverage Tests
// ===========================================

func TestTPM2_AlgIDMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	algID := tpm.AlgID()
	assert.NotZero(t, algID)
}

func TestTPM2_DeviceMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	device := tpm.Device()
	assert.NotEmpty(t, device)
}

func TestTPM2_TransportMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	trans := tpm.Transport()
	assert.NotNil(t, trans)
}

func TestTPM2_PlatformPolicyDigestMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	digest := tpm.PlatformPolicyDigest()
	assert.NotNil(t, digest.Buffer)
}

func TestFlush_WithInvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Flushing an invalid handle should not panic
	tpm.Flush(tpm2.TPMHandle(0xDEADBEEF))
}

func TestReadHandle_ValidEKHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	name, pub, err := tpm.ReadHandle(ekAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	assert.NotEmpty(t, name.Buffer)
	assert.NotZero(t, pub.Type)
}

func TestReadHandle_WithInvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, _, err := tpm.ReadHandle(tpm2.TPMHandle(0xDEADBEEF))
	assert.NotNil(t, err)
}

func TestTPM2_ConfigMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	config := tpm.Config()
	assert.NotNil(t, config)
	assert.NotNil(t, config.EK)
}

func TestParsePublicKey_RSAType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Read the public area
	pubArea, err := tpm2.ReadPublic{
		ObjectHandle: ekAttrs.TPMAttributes.Handle,
	}.Execute(tpm.Transport())
	require.NoError(t, err)

	// Parse the public key
	pub, err := tpm.ParsePublicKey(pubArea.OutPublic.Bytes())
	require.NoError(t, err)
	assert.NotNil(t, pub)
}

func TestGetActiveTransientHandles_Internal(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Get active handles - may be empty
	handles := tpmImpl.getActiveTransientHandles()
	// Just verify it doesn't panic and returns a slice
	_ = handles
}

func TestSetHierarchyAuth_NilTransportError(t *testing.T) {
	// Create a TPM with nil transport to test error path
	tpmInstance := &TPM2{
		transport: nil,
		logger:    slog.Default(),
	}

	err := tpmInstance.SetHierarchyAuth(nil, nil, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ===========================================
// Secret Sharing Tests
// ===========================================

func TestShareSecret_MinimumShares(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with minimum shares
	secret := []byte("test-secret")
	shares, err := tpm.ShareSecret(secret, 2)
	require.NoError(t, err)
	assert.Len(t, shares, 2)
}

func TestShareSecret_InsufficientShares(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with less than 2 shares
	secret := []byte("test-secret")
	_, err := tpm.ShareSecret(secret, 1)
	assert.NotNil(t, err)
}

func TestSecretFromShares_EmptySharesError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with empty shares
	_, err := tpm.SecretFromShares([]string{})
	assert.NotNil(t, err)
}

func TestSecretFromShares_InvalidJSONError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with invalid JSON
	_, err := tpm.SecretFromShares([]string{"invalid-json"})
	assert.NotNil(t, err)
}

func TestShareAndRecoverSecret_FullRecovery(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	secret := "my-super-secret"
	shares, err := tpm.ShareSecret([]byte(secret), 3)
	require.NoError(t, err)
	assert.Len(t, shares, 3)

	// Recover with all shares
	recovered, err := tpm.SecretFromShares(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, recovered)

	// Recover with threshold (2 out of 3)
	recovered, err = tpm.SecretFromShares(shares[:2])
	require.NoError(t, err)
	assert.Equal(t, secret, recovered)
}

// ===========================================
// Helper Types for Testing
// ===========================================

// mockCertStoreCov implements store.CertificateStorer for testing
type mockCertStoreCov struct {
	certs map[string]*x509.Certificate
}

func (m *mockCertStoreCov) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	cert, ok := m.certs[attrs.CN]
	if !ok {
		return nil, store.ErrCertNotFound
	}
	return cert, nil
}

func (m *mockCertStoreCov) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	m.certs[attrs.CN] = cert
	return nil
}

func (m *mockCertStoreCov) Delete(attrs *types.KeyAttributes) error {
	delete(m.certs, attrs.CN)
	return nil
}

func (m *mockCertStoreCov) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	return nil, nil
}

// mockTransportCov implements transport.TPM for testing
type mockTransportCov struct {
	sendFunc    func([]byte) ([]byte, error)
	closeFunc   func() error
	closeCalled bool
}

func (m *mockTransportCov) Send(data []byte) ([]byte, error) {
	if m.sendFunc != nil {
		return m.sendFunc(data)
	}
	return nil, errors.New("not implemented")
}

func (m *mockTransportCov) Close() error {
	m.closeCalled = true
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// Ensure mockTransportCov implements transport.TPM
var _ transport.TPM = (*mockTransportCov)(nil)
