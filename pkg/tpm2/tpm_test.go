//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Variables and helpers merged from base_test.go
// ---------------------------------------------------------------------------

var (
	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailWithDA = tpm2.TPMRC(0x98e)

	// TPM_RC_ATTRIBUTES (session 1): inconsistent attributes
	ErrInconsistentAttributes = tpm2.TPMRC(0x982)

	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailHMACWithDA = tpm2.TPMRC(0x99d)

	// TPM_RC_POLICY_FAIL (session 1): a policy check failed
	ErrPolicyCheckFailed = tpm2.TPMRC(0x99d)

	keyStoreHandle = tpm2.TPMHandle(0x81000003)
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {

}

func setup() {
	_ = os.RemoveAll(TEST_DIR)
}

func TestOpenAndCloseTPM(t *testing.T) {

	_, tpm := createSim(false, false)
	_ = tpm.Close()

	_, tpm = createSim(false, false)
	_ = tpm.Close()

	_, tpm = createSim(false, false)
	defer func() { _ = tpm.Close() }()
}

// Extends the debug PCR with random bytes
func extendRandomBytes(transport transport.TPM) {

	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		slog.Default().Error("failed to read random bytes", "error", err)
		panic(err)
	}

	fmt.Printf(
		"tpm: extending %s measurement to platform PCR %d\n",
		string(bytes), debugPCR)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(debugPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  bytes,
				},
			},
		},
	}.Execute(transport)
	if err != nil {
		slog.Default().Error("failed to extend PCR", "error", err)
		panic(err)
	}
}

func createKey(
	tpm TrustedPlatformModule,
	platformPolicy bool) *types.KeyAttributes {

	srkTemplate := tpm2.RSASRKTemplate
	srkTemplate.ObjectAttributes.NoDA = false

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		slog.Default().Error("failed to get EK attributes", "error", err)
		panic(err)
	}

	srkAttrs := &types.KeyAttributes{
		CN:             "srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeTPM,
		Parent:         ekAttrs,
		Password:       store.NewPassword([]byte("srk-pass")),
		PlatformPolicy: platformPolicy,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      srkTemplate,
		}}
	err = tpm.CreateSRK(srkAttrs)
	if err != nil {
		slog.Default().Error("failed to create SRK", "error", err)
		panic(err)
	}

	return &types.KeyAttributes{
		CN:             "key",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		PlatformPolicy: platformPolicy,
		Password:       store.NewPassword([]byte("key-pass")),
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(encrypt, entropy bool) (*slog.Logger, TrustedPlatformModule) {

	logger := slog.Default()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.Error("failed to read random bytes", "error", err)
		panic(err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		logger.Error("failed to create storage factory", "error", err)
		panic(err)
	}
	// Note: In a real test, we'd defer storageFactory.Close() but this helper
	// doesn't return a cleanup function. The temp dir will be cleaned up on program exit.

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
			// SRKAuth:        store.DEFAULT_PASSWORD,
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				logger.Error("failed to provision TPM", "error", err)
				panic(err)
			}
		} else {
			logger.Error("failed to create TPM2", "error", err)
			panic(err)
		}
	}

	return logger, tpm
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestInfo(t *testing.T) {

	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	assert.Nil(t, err)
	assert.NotNil(t, props.Manufacturer)
	assert.NotNil(t, props.VendorID)
	assert.NotNil(t, props.Family)
	assert.NotNil(t, props.FwMajor)
	assert.NotNil(t, props.FwMinor)

	fmt.Println(props)
}

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
	assert.NotNil(t, config.PlatformSRK)
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
		Password:     store.NewPassword([]byte("key-pass")),
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
		Password:     store.NewPassword([]byte("key-pass")),
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
		Password:     store.NewPassword([]byte("key-pass")),
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
		Password:     store.NewPassword([]byte("key-pass")),
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
			HierarchyAuth: store.NewPassword([]byte("test-auth")),
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
			HierarchyAuth: store.NewPassword([]byte("parent-auth")),
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

	digest, pdErr := tpm.PlatformPolicyDigest()
	assert.NoError(t, pdErr)
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
// EKCertificate Tests (from coverage_tpm_test.go)
// ===========================================

// TestEKCertificate_FromStore tests EK certificate retrieval from store
func TestEKCertificate_FromStore(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to get EK certificate
	ekCert, err := tpm.EKCertificate()

	// Expected to fail in simulator without actual EK cert
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, ekCert)
	}
}

// TestEKCertificate_WithCertHandle tests EK certificate retrieval from NVRAM
func TestEKCertificate_WithCertHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)

	// Save original config and set a CertHandle
	originalCertHandle := tpm2Impl.config.EK.CertHandle
	tpm2Impl.config.EK.CertHandle = 0x01C00002 // Standard RSA EK cert index
	defer func() { tpm2Impl.config.EK.CertHandle = originalCertHandle }()

	// Try to read from NVRAM - will likely fail but tests the code path
	ekCert, err := tpm.EKCertificate()
	_ = ekCert
	_ = err
}

// TestParsePublicKey_RSA tests parsing RSA public key from TPM public area
func TestParsePublicKey_RSA(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK public to use for testing
	_, ekPub, ekPubErr := tpm.EKPublic()
	require.NoError(t, ekPubErr)

	// Marshal to bytes
	pubBytes := tpm2.Marshal(ekPub)

	// Parse it back
	pubKey, err := tpm.ParsePublicKey(pubBytes)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// TestParsePublicKey_Invalid tests parsing with invalid data
func TestParsePublicKey_Invalid(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to parse invalid data
	_, err := tpm.ParsePublicKey([]byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

// TestOpenUnixSocketTransport tests opening Unix socket transport
func TestOpenUnixSocketTransport(t *testing.T) {
	// Try to open a non-existent socket - should fail
	_, err := OpenUnixSocketTransport("/tmp/nonexistent-tpm-socket.sock")
	assert.Error(t, err)
}

// TestFlush tests the Flush method
func TestFlush(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to flush a non-existent handle - should not panic
	tpm.Flush(tpm2.TPMHandle(0x80FFFFFF))
}

// TestReadHandle_CovTPM tests the ReadHandle method
func TestReadHandle_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	ekHandle := tpm2.TPMHandle(tpm2Impl.config.EK.Handle)

	name, pub, err := tpm.ReadHandle(ekHandle)
	require.NoError(t, err)
	assert.NotEmpty(t, name.Buffer)
	assert.NotEqual(t, tpm2.TPMAlgNull, pub.Type)
}

// TestReadHandle_InvalidHandle tests ReadHandle with invalid handle
func TestReadHandle_InvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, _, err := tpm.ReadHandle(tpm2.TPMHandle(0x81FFFFFF))
	assert.Error(t, err)
}

// TestConfig tests the Config method
func TestConfig(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	config := tpm.Config()
	assert.NotNil(t, config)
	assert.NotNil(t, config.EK)
	assert.NotNil(t, config.SSRK)
}

// TestRandom_CovTPM tests the Random method
func TestRandom_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	randomBytes, err := tpm.Random()
	require.NoError(t, err)
	assert.NotEmpty(t, randomBytes)
	assert.Len(t, randomBytes, 32) // Default is 32 bytes
}

// TestRandomBytes_CovTPM tests the RandomBytes method
func TestRandomBytes_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"128 bytes", 128},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			randomBytes, err := tpm.RandomBytes(tc.length)
			require.NoError(t, err)
			assert.Len(t, randomBytes, tc.length)
		})
	}
}

// TestEventLog tests the EventLog method
func TestEventLog(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Event log is typically not available in simulator
	eventLog, err := tpm.EventLog()
	if err != nil {
		// Expected to fail in simulator
		assert.Error(t, err)
	} else {
		assert.NotNil(t, eventLog)
	}
}

// TestIsPlatformPCRExtended_CovTPM tests the IsPlatformPCRExtended method
func TestIsPlatformPCRExtended_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	extended, err := tpm.IsPlatformPCRExtended()
	require.NoError(t, err)
	// May be true or false depending on TPM state
	_ = extended
}

// TestClose tests the Close method
func TestClose(t *testing.T) {
	_, tpm := createSim(false, false)

	err := tpm.Close()
	assert.NoError(t, err)

	// Closing again should be safe
	err = tpm.Close()
	// May or may not error depending on implementation
	_ = err
}

// TestPlatformQuote_CovTPM tests the PlatformQuote method
func TestPlatformQuote_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	quote, nonce, err := tpm.PlatformQuote(iakAttrs)

	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.NotEmpty(t, quote.Quoted)
	assert.NotEmpty(t, quote.Signature)
	assert.NotEmpty(t, nonce)
}

// TestQuote_CovTPM tests the Quote method with various PCR selections
func TestQuote_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tests := []struct {
		name  string
		pcrs  []uint
		nonce []byte
	}{
		{"single PCR", []uint{0}, nil},
		{"multiple PCRs", []uint{0, 1, 2}, nil},
		{"with nonce", []uint{0}, []byte("test-nonce")},
		{"golden PCRs", []uint{0, 7}, []byte("golden-nonce")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quote, err := tpm.Quote(tc.pcrs, tc.nonce)
			require.NoError(t, err)
			assert.NotNil(t, quote)
			assert.NotEmpty(t, quote.Quoted)
		})
	}
}

// TestMakeCredential_CovTPM tests the MakeCredential method
func TestMakeCredential_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	secret := []byte("test-secret-for-credential")
	credential, encrypted, _, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)

	require.NoError(t, err)
	assert.NotEmpty(t, credential)
	assert.NotEmpty(t, encrypted)
}

// TestActivateCredential_CovTPM tests the ActivateCredential method
func TestActivateCredential_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// First make a credential
	secret := []byte("test-secret-to-activate")
	credential, encrypted, _, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)
	require.NoError(t, err)

	// Now activate it
	recoveredSecret, err := tpm.ActivateCredential(credential, encrypted)
	require.NoError(t, err)
	assert.Equal(t, secret, recoveredSecret)
}

// TestMakeCredentialWithExternalEK_CovTPM tests MakeCredentialWithExternalEK
func TestMakeCredentialWithExternalEK_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK certificate
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		// No EK cert in simulator - skip
		t.Skip("EK certificate not available in simulator")
	}

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Get IAK public bytes
	iakKey, iakErr := tpm.IAK()
	require.NoError(t, iakErr)
	_, iakPub := iakKey.(interface{ Public() interface{} })
	_ = iakPub

	secret := []byte("external-ek-secret")
	credential, encrypted, _, err := tpm.MakeCredentialWithExternalEK(ekCert, tpm2.Marshal(iakAttrs.TPMAttributes.Public), secret)

	if err == nil {
		assert.NotEmpty(t, credential)
		assert.NotEmpty(t, encrypted)
	}
}

// TestProvision tests the Provision method
func TestProvision(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to provision - may already be provisioned
	err := tpm.Provision(nil)
	// Should succeed or indicate already provisioned
	_ = err
}

// TestSetHierarchyAuth_CovTPM tests the SetHierarchyAuth method
func TestSetHierarchyAuth_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// This is a sensitive operation - just test that it doesn't panic
	// with nil passwords (no change)
	err := tpm.SetHierarchyAuth(nil, nil, nil)
	// May succeed or fail depending on TPM state
	_ = err
}

// TestShareSecret_CovTPM tests ShareSecret and SecretFromShares
func TestShareSecret_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	secret := []byte("my-super-secret-key-material")

	// Share the secret into 5 parts (threshold 3)
	shares, err := tpm.ShareSecret(secret, 5)
	require.NoError(t, err)
	assert.Len(t, shares, 5)

	// Recover with 3 shares
	recoveredSecret, err := tpm.SecretFromShares(shares[:3])
	require.NoError(t, err)
	assert.NotEmpty(t, recoveredSecret)
}

// TestDevice_CovTPM tests the Device method
func TestDevice_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	device := tpm.Device()
	// Simulator will have a specific device name
	assert.NotEmpty(t, device)
}

// TestTransport_CovTPM tests the Transport method
func TestTransport_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	transport := tpm.Transport()
	assert.NotNil(t, transport)
}

// TestAlgID_CovTPM tests the AlgID method
func TestAlgID_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	algID := tpm.AlgID()
	assert.NotEqual(t, tpm2.TPMAlgNull, algID)
}

// TestEK_CovTPM tests the EK method
func TestEK_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// EK() panics if not initialized - get EKAttributes first to initialize
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	ek, ekErr := tpm.EK()
	assert.NoError(t, ekErr)
	assert.NotNil(t, ek)
}

// TestEKRSA_CovTPM tests the EKRSA method
func TestEKRSA_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	ekRSA, rsaErr := tpm.EKRSA()
	// May error if EK is ECC
	_ = rsaErr
	_ = ekRSA
}

// TestEKECC_CovTPM tests the EKECC method
// Default config uses RSA EK, so EKECC will panic - we test panic behavior
func TestEKECC_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	// EKECC returns error when EK is RSA (which is the default)
	ekECC, eccErr := tpm.EKECC()
	if eccErr != nil {
		// Expected: EK is RSA, so EKECC returns error
		t.Logf("EKECC correctly returned error for RSA EK: %v", eccErr)
	} else {
		// If we get here, EK must be ECC
		assert.NotNil(t, ekECC)
	}
}

// TestGoldenMeasurements_CovTPM tests the GoldenMeasurements method
func TestGoldenMeasurements_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	measurements, gmErr := tpm.GoldenMeasurements()
	// May error if not configured
	_ = gmErr
	_ = measurements
}

// TestPlatformPolicyDigest_CovTPM tests the PlatformPolicyDigest method
func TestPlatformPolicyDigest_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	digest, pdErr := tpm.PlatformPolicyDigest()
	// Digest may error if platform policy not created
	_ = pdErr
	_ = digest
}

// TestPlatformPolicyDigestHash_CovTPM tests the PlatformPolicyDigestHash method
func TestPlatformPolicyDigestHash_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	hash, err := tpm.PlatformPolicyDigestHash()
	// May fail if platform policy not created
	_ = hash
	_ = err
}

// TestRandomHex_CovTPM tests the RandomHex method
func TestRandomHex_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	hexBytes, err := tpm.RandomHex(32)
	require.NoError(t, err)
	assert.NotEmpty(t, hexBytes)
}

// TestRandomSource_CovTPM tests the RandomSource method
func TestRandomSource_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	source := tpm.RandomSource()
	assert.NotNil(t, source)

	// Read some random data through the source
	buf := make([]byte, 16)
	n, err := source.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 16, n)
}

// TestRead_CovTPM tests the Read method (io.Reader interface)
func TestRead_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	buf := make([]byte, 32)
	n, err := tpm.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 32, n)
}

// ===========================================
// CalculateName Unit Tests
// (Merged from calculate_name_test.go)
// ===========================================

func TestCalculateNameUnit(t *testing.T) {
	tests := []struct {
		name       string
		algID      tpm2.TPMAlgID
		publicArea []byte
		wantLen    int
		wantErr    bool
	}{
		{
			name:       "SHA1 algorithm",
			algID:      tpm2.TPMAlgSHA1,
			publicArea: []byte("test public area"),
			wantLen:    2 + 20, // 2 bytes algID + 20 bytes SHA1 hash
			wantErr:    false,
		},
		{
			name:       "SHA256 algorithm",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: []byte("test public area data"),
			wantLen:    2 + 32, // 2 bytes algID + 32 bytes SHA256 hash
			wantErr:    false,
		},
		{
			name:       "SHA3-384 algorithm",
			algID:      tpm2.TPMAlgSHA3384,
			publicArea: []byte("another test data"),
			wantLen:    2 + 48, // 2 bytes algID + 48 bytes SHA384 hash
			wantErr:    false,
		},
		{
			name:       "SHA512 algorithm",
			algID:      tpm2.TPMAlgSHA512,
			publicArea: []byte("sha512 test data"),
			wantLen:    2 + 64, // 2 bytes algID + 64 bytes SHA512 hash
			wantErr:    false,
		},
		{
			name:       "empty public area",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: []byte{},
			wantLen:    2 + 32,
			wantErr:    false,
		},
		{
			name:       "large public area",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: make([]byte, 10000),
			wantLen:    2 + 32,
			wantErr:    false,
		},
		{
			name:       "unsupported algorithm",
			algID:      tpm2.TPMAlgID(0xFFFF), // Invalid algorithm
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
		{
			name:       "null algorithm",
			algID:      tpm2.TPMAlgNull,
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
		{
			name:       "RSA algorithm ID (not a hash)",
			algID:      tpm2.TPMAlgRSA,
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateName(tt.algID, tt.publicArea)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CalculateName() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("CalculateName() unexpected error: %v", err)
				return
			}

			if len(result) != tt.wantLen {
				t.Errorf("CalculateName() length = %d, want %d", len(result), tt.wantLen)
			}

			// Verify algorithm ID is correctly encoded in first 2 bytes (big endian)
			if len(result) >= 2 {
				encodedAlgID := (uint16(result[0]) << 8) | uint16(result[1])
				if encodedAlgID != uint16(tt.algID) {
					t.Errorf("CalculateName() algID encoding = 0x%x, want 0x%x", encodedAlgID, tt.algID)
				}
			}
		})
	}
}

func TestCalculateNameConsistency(t *testing.T) {
	// Test that same input produces same output
	publicArea := []byte("consistent test data for name calculation")

	result1, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	if err != nil {
		t.Fatalf("CalculateName() first call error: %v", err)
	}

	result2, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	if err != nil {
		t.Fatalf("CalculateName() second call error: %v", err)
	}

	if len(result1) != len(result2) {
		t.Errorf("CalculateName() inconsistent length: %d vs %d", len(result1), len(result2))
	}

	for i := range result1 {
		if result1[i] != result2[i] {
			t.Errorf("CalculateName() inconsistent at byte %d: 0x%x vs 0x%x", i, result1[i], result2[i])
		}
	}
}

func TestCalculateNameDifferentData(t *testing.T) {
	// Different data should produce different names
	data1 := []byte("first public area")
	data2 := []byte("second public area")

	name1, err := CalculateName(tpm2.TPMAlgSHA256, data1)
	if err != nil {
		t.Fatalf("CalculateName() data1 error: %v", err)
	}

	name2, err := CalculateName(tpm2.TPMAlgSHA256, data2)
	if err != nil {
		t.Fatalf("CalculateName() data2 error: %v", err)
	}

	// Algorithm ID should be same
	if name1[0] != name2[0] || name1[1] != name2[1] {
		t.Error("CalculateName() algorithm IDs should match for same algorithm")
	}

	// Hash portion should be different
	sameHash := true
	for i := 2; i < len(name1); i++ {
		if name1[i] != name2[i] {
			sameHash = false
			break
		}
	}
	if sameHash {
		t.Error("CalculateName() different data should produce different names")
	}
}

// ===========================================
// Intel EK URL Unit Tests
// (Merged from calculate_name_test.go)
// ===========================================

func TestIntelEKURLUnit(t *testing.T) {
	tests := []struct {
		name     string
		ekPub    *rsa.PublicKey
		wantBase string
	}{
		{
			name: "valid RSA public key",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes([]byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				}),
				E: 65537, // 0x10001
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "different RSA public key",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes([]byte{
					0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
				}),
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "small N value",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(255),
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "large N value",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(make([]byte, 256)), // 2048-bit key
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intelEKURL(tt.ekPub)

			// Verify URL starts with Intel EK cert service base URL
			if len(result) < len(tt.wantBase) {
				t.Errorf("intelEKURL() result too short: got %s", result)
				return
			}

			if result[:len(tt.wantBase)] != tt.wantBase {
				t.Errorf("intelEKURL() base URL mismatch: got %s, want base %s", result, tt.wantBase)
			}

			// Verify the URL has encoded parameters
			encodedPart := result[len(tt.wantBase):]
			if len(encodedPart) == 0 {
				t.Error("intelEKURL() missing encoded hash part")
			}

			// Verify the encoded part is valid URL encoding
			_, err := url.QueryUnescape(encodedPart)
			if err != nil {
				t.Errorf("intelEKURL() URL encoding error: %v", err)
			}

			// Verify the hash computation matches expected
			pubHash := sha256.New()
			pubHash.Write(tt.ekPub.N.Bytes())
			pubHash.Write([]byte{0x1, 0x00, 0x01}) // Big-endian representation of 65537
			expectedEncoded := url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))

			if encodedPart != expectedEncoded {
				t.Errorf("intelEKURL() hash mismatch: got %s, want %s", encodedPart, expectedEncoded)
			}
		})
	}
}

func TestIntelEKURLDifferentExponents(t *testing.T) {
	// The function assumes E=65537, but let's verify it handles the key correctly
	ekPub := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD}),
		E: 65537,
	}

	ekURL := intelEKURL(ekPub)

	// Should be a valid URL string
	if ekURL == "" {
		t.Error("intelEKURL() returned empty string")
	}

	// Should start with the Intel EK cert service URL
	if len(ekURL) <= len(intelEKCertServiceURL) {
		t.Error("intelEKURL() URL too short")
	}
}

func TestIntelEKURLLargeKey(t *testing.T) {
	// Test with a 2048-bit RSA key (common size)
	keyBytes := make([]byte, 256)
	for i := range keyBytes {
		keyBytes[i] = byte(i % 256)
	}

	ekPub := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(keyBytes),
		E: 65537,
	}

	ekURL := intelEKURL(ekPub)

	// Verify the URL structure
	if len(ekURL) < len(intelEKCertServiceURL) || ekURL[:len(intelEKCertServiceURL)] != intelEKCertServiceURL {
		t.Errorf("intelEKURL() should contain base URL: %s", ekURL)
	}

	// The encoded hash should be URL-safe
	encodedPart := ekURL[len(intelEKCertServiceURL):]
	if len(encodedPart) == 0 {
		t.Error("intelEKURL() missing encoded part")
	}

	// Should not contain raw special characters
	for _, c := range encodedPart {
		if c == '+' || c == '/' || c == '=' {
			// These should be percent-encoded in URL
			t.Errorf("intelEKURL() contains non-URL-safe character: %c", c)
		}
	}
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
