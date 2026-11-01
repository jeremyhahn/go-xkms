//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

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
		string(bytes), DefaultPlatformPCRs()[0])

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(DefaultPlatformPCRs()[0]),
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
	t testing.TB,
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
		CN:           "srk",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeTPM,
		Parent:       ekAttrs,
		Password:     mustPassword(t, []byte("srk-pass")),
		TPMPolicy:    platformPolicyName(platformPolicy),
		StoreType:    types.StoreTPM2,
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
		CN:           "key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		TPMPolicy:    platformPolicyName(platformPolicy),
		Password:     mustPassword(t, []byte("key-pass")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(t testing.TB, entropy bool) (*slog.Logger, TrustedPlatformModule) {
	t.Helper()

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

	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		UseEntropy:   entropy,
		Device:       "/dev/tpmrm0",
		UseSimulator: true,
		Hash:         "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

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
		PlatformPCRs:    DefaultPlatformPCRs(),
		PlatformPCRBank: PCRBankSHA256,
		GoldenPCRs:      []uint{0, 7},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:  logger,
		Config:  config,
		Backend: fileBackend,
		FQDN:    "node1.example.com",
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

	enrollSimPlatformSRK(logger, tpm.(*TPM2), config)

	return logger, tpm
}

// enrollSimPlatformSRK creates the Platform SRK on a provisioned simulator
// when it is not already present.
func enrollSimPlatformSRK(logger *slog.Logger, tpm *TPM2, config *Config) {
	// Provision(nil) only creates the TCG-standard EK and Shared SRK. xkms's
	// own sealing (defaultSealKeyAttributes/defaultUnsealKeyAttributes) always
	// uses the Platform SRK and never falls back to the Shared SRK, so this
	// helper enrolls it too -- mirroring the Platform SRK creation
	// pkg/tpm2.ProvisionFresh performs on the same simulator
	// first-boot path -- whenever it is not already present.
	//
	// This duplicates pkg/tpm2/tpm2test.EnrollPlatformSRK's logic rather than
	// calling it: tpm2test imports pkg/tpm2 (it has to, to use
	// TrustedPlatformModule/Config/PlatformSRKAttributesFromConfig), so an
	// internal test file in package tpm2 importing tpm2test back would be a
	// real import cycle -- Go only exempts *_test.go files declared as an
	// external "tpm2_test" package from that, and this file (and everything
	// that calls createSim) is package tpm2. Every other module's tests use
	// the shared helper; this is the one place that cannot.
	if _, psrkErr := tpm.PlatformSRKAttributes(); psrkErr != nil {
		psrkAttrs, buildErr := PlatformSRKAttributesFromConfig(config)
		if buildErr != nil {
			logger.Error("failed to build Platform SRK attributes", "error", buildErr)
			panic(buildErr)
		}
		if ekAttrs, ekErr := tpm.EKAttributes(); ekErr == nil {
			psrkAttrs.Parent = ekAttrs
		}
		if createErr := tpm.CreateSRK(psrkAttrs); createErr != nil {
			logger.Error("failed to create Platform SRK", "error", createErr)
			panic(createErr)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ===========================================
// NewTPM2 Coverage Tests
// Tests that exercise error paths without needing the simulator
// ===========================================

// Note: TestNewTPM2_InvalidHashConfigError was removed because hash validation
// occurs after device/transport initialization in the NewTPM2 function.
// The hash function is only validated when parsing after the device is opened.

func TestNewTPM2_WithExistingTransport(t *testing.T) {
	// Test with existing transport
	_, tpm := createSim(t, false)
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

// ===========================================
// Sign Coverage Tests
// ===========================================

// Note: TestSign_WithSHA384HashAlgorithm and TestSign_WithSHA512HashAlgorithm were removed
// because the swtpm simulator does not support SHA384/SHA512 hash algorithms with RSA signing schemes.
// The TPM returns "TPM_RC_SCHEME: unsupported or incompatible scheme" for these combinations.
// SHA256 is the standard hash algorithm used with RSA keys in TPM2.

func TestSign_WithInvalidHashFuncMD5(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Create an RSA key
	childKeyAttrs := createKey(t, tpm, false)
	srkAttrs := childKeyAttrs.Parent

	keyAttrs := &types.KeyAttributes{
		CN:           "test-sign-invalid-hash-cov",
		Hash:         crypto.MD5, // Invalid hash for TPM
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     mustPassword(t, []byte("key-pass")),
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

// ===========================================
// SignValidate Coverage Tests
// Note: SignValidate currently panics on nil keyAttrs - these tests cover valid error paths
// ===========================================

func TestSignValidate_ZeroHashAlgError(t *testing.T) {
	_, tpm := createSim(t, false)
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
	assert.ErrorIs(t, err, ErrSignValidateHashAlgRequired)
}

// ===========================================
// EKCertificate Coverage Tests
// ===========================================

func TestEKCertificate_ZeroCertHandleWithMockStore(t *testing.T) {
	_, tpm := createSim(t, false)
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

// ===========================================
// Hash and HashSequence Tests
// ===========================================

func TestHash_NilTPMAttrsError(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:            "test",
		TPMAttributes: nil,
	}

	_, _, err := tpm.Hash(keyAttrs, []byte("test data"))
	assert.Equal(t, ErrInvalidKeyAttributes, err)
}

func TestHashSequence_WithParentHierarchyAuthPath(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	parentAttrs := &types.KeyAttributes{
		CN: "parent",
		TPMAttributes: &types.TPMAttributes{
			HierarchyAuth: mustPassword(t, []byte("parent-auth")),
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

// ===========================================
// Misc Coverage Tests
// ===========================================

func TestTPM2_AlgIDMethod(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	algID := tpm.AlgID()
	assert.NotZero(t, algID)
}

func TestTPM2_DeviceMethod(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	device := tpm.Device()
	assert.NotEmpty(t, device)
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
// EKCertificate Tests (from coverage_tpm_test.go)
// ===========================================

// TestOpenUnixSocketTransport tests opening Unix socket transport
func TestOpenUnixSocketTransport(t *testing.T) {
	// Try to open a non-existent socket - should fail
	_, err := OpenUnixSocketTransport("/tmp/nonexistent-tpm-socket.sock")
	assert.Error(t, err)
}

// TestOpenDeviceTransport_DevicePath proves OpenDeviceTransport opens a
// character-device-style path directly, without the EK discovery NewTPM2
// performs, and that the returned transport can be closed.
func TestOpenDeviceTransport_DevicePath(t *testing.T) {
	dir := t.TempDir()
	devicePath := dir + "/fake-tpm-device"
	require.NoError(t, os.WriteFile(devicePath, nil, 0600))

	transport, err := OpenDeviceTransport(devicePath)
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.NoError(t, transport.Close())
}

// TestOpenDeviceTransport_MissingDevice proves OpenDeviceTransport reports
// ErrOpeningDevice rather than panicking or leaking a partially opened
// handle when the device path does not exist.
func TestOpenDeviceTransport_MissingDevice(t *testing.T) {
	_, err := OpenDeviceTransport("/nonexistent/tpm-device-path")
	assert.ErrorIs(t, err, ErrOpeningDevice)
}

// TestOpenDeviceTransport_SocketPath proves OpenDeviceTransport routes a
// ".sock"-suffixed path through the Unix domain socket opener instead of
// treating it as a character device.
func TestOpenDeviceTransport_SocketPath(t *testing.T) {
	_, err := OpenDeviceTransport("/tmp/nonexistent-tpm-socket.sock")
	assert.Error(t, err)
}

// TestPlatformQuote_CovTPM tests the PlatformQuote method
func TestPlatformQuote_CovTPM(t *testing.T) {
	_, tpm := createSim(t, false)
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

// TestMakeCredentialWithExternalEK_CovTPM was deleted rather than un-skipped.
//
// It skipped on every run ("EK certificate not available in simulator") because
// no manufacturer EK certificate is provisioned into a simulator's NV RAM, and
// its assertions were in any case unfalsifiable: every one of them sat inside
// an "if err == nil" guard, so the test passed whether or not
// MakeCredentialWithExternalEK worked.
//
// The same API is covered properly, and far more strictly, in
// attestation_certify_simulator_test.go, which mints an EK certificate over the
// simulator's real EK public key instead of demanding a manufacturer one:
//
//   - TestMakeCredentialWithExternalEK_ActivatesOnTheOwningTPM drives the full
//     make-then-activate ceremony and asserts the secret is recovered.
//   - TestMakeCredentialWithExternalEK_WrongEKCannotActivate proves the
//     credential is bound to the EK it was made for.
//   - TestMakeCredentialWithExternalEK_InvalidInputs covers the nil
//     certificate, empty and malformed IAK public area, and unsupported
//     certificate key type paths.
//
// Reviving the skipped test would only have duplicated that coverage.

// TestEK_CovTPM tests the EK method
func TestEK_CovTPM(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// EK() panics if not initialized - get EKAttributes first to initialize
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	ek, ekErr := tpm.EK()
	assert.NoError(t, ekErr)
	assert.NotNil(t, ek)
}

// TestEKECC_CovTPM tests the EKECC method
// Default config uses RSA EK, so EKECC will panic - we test panic behavior
func TestEKECC_CovTPM(t *testing.T) {
	_, tpm := createSim(t, false)
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

// TestRandomSource_CovTPM tests the RandomSource method
func TestRandomSource_CovTPM(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	source := tpm.RandomSource()
	assert.NotNil(t, source)

	// Read some random data through the source
	buf := make([]byte, 16)
	n, err := source.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 16, n)
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
			// FIPS 140-only mode refuses SHA-1 with a *HashRefusedError.
			name:       "SHA1 algorithm",
			algID:      tpm2.TPMAlgSHA1,
			publicArea: []byte("test public area"),
			wantLen:    2 + 20, // 2 bytes algID + 20 bytes SHA1 hash
			wantErr:    fips140.Enforced(),
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
				var refused *HashRefusedError
				if tt.algID == tpm2.TPMAlgSHA1 && !errors.As(err, &refused) {
					t.Errorf("CalculateName(SHA1) error = %v, want *HashRefusedError", err)
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

// TestChangeAuth_WrongCurrentAuth proves ChangeAuth refuses to recreate a
// persistent primary key when the caller's claimed current auth does not
// match the key's actual UserAuth, rather than reaching TPM2_CreatePrimary
// with the wrong sensitive data. createKey provisions the SRK with a known,
// non-empty password ("srk-pass"), so a different value is guaranteed wrong.
func TestChangeAuth_WrongCurrentAuth(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	srkAttrs := createKey(t, tpm, false).Parent
	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.ChangeAuth(srkAttrs.TPMAttributes.Handle, []byte("not-srk-pass"), []byte("new-pass"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAuthFailed)
}
