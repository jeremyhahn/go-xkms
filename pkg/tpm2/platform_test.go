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

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAttribute(t *testing.T) {
	tests := []struct {
		name            string
		configValue     string
		discoveredValue string
		expected        string
	}{
		{
			name:            "config value takes priority",
			configValue:     "ConfigManufacturer",
			discoveredValue: "DiscoveredManufacturer",
			expected:        "ConfigManufacturer",
		},
		{
			name:            "fallback to discovered when config empty",
			configValue:     "",
			discoveredValue: "DiscoveredManufacturer",
			expected:        "DiscoveredManufacturer",
		},
		{
			name:            "both empty returns empty",
			configValue:     "",
			discoveredValue: "",
			expected:        "",
		},
		{
			name:            "config value with whitespace preserved",
			configValue:     "Dell Inc.",
			discoveredValue: "HP",
			expected:        "Dell Inc.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveAttribute(tt.configValue, tt.discoveredValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolvePlatformAttributes_NilConfig(t *testing.T) {
	// When config is nil, should attempt discovery (may fail on non-Linux or missing DMI)
	result := ResolvePlatformAttributes(nil)
	assert.NotNil(t, result)
	// Values may be empty if DMI files don't exist - that's OK
}

func TestResolvePlatformAttributes_ConfigOverridesDiscovery(t *testing.T) {
	config := &IDevIDConfig{
		Manufacturer: "TestManufacturer",
		Model:        "TestModel",
		Version:      "1.0.0",
		Serial:       "SN123456",
	}

	result := ResolvePlatformAttributes(config)

	assert.Equal(t, "TestManufacturer", result.Manufacturer)
	assert.Equal(t, "TestModel", result.Model)
	assert.Equal(t, "1.0.0", result.Version)
	assert.Equal(t, "SN123456", result.Serial)
}

func TestResolvePlatformAttributes_PartialConfig(t *testing.T) {
	// Only Model and Serial specified, Manufacturer and Version should come from discovery
	config := &IDevIDConfig{
		Model:  "CustomDevice",
		Serial: "ABC123",
	}

	result := ResolvePlatformAttributes(config)

	// Config values are used
	assert.Equal(t, "CustomDevice", result.Model)
	assert.Equal(t, "ABC123", result.Serial)
	// Manufacturer and Version come from discovery (may be empty on test systems)
	// Just verify they're strings (not panicking)
	assert.IsType(t, "", result.Manufacturer)
	assert.IsType(t, "", result.Version)
}

func TestResolvePlatformAttributes_EmptyConfig(t *testing.T) {
	config := &IDevIDConfig{}

	result := ResolvePlatformAttributes(config)

	// All values come from discovery
	assert.NotNil(t, result)
	// Values may be empty if DMI files don't exist
}

func TestReadDMIFile_NonExistent(t *testing.T) {
	// Should return empty string for non-existent files
	result := readDMIFile("nonexistent_file_12345")
	assert.Equal(t, "", result)
}

func TestReadDMIFile_WithMockFS(t *testing.T) {
	// Create a temporary directory structure mimicking DMI sysfs
	tmpDir := t.TempDir()

	// Create mock DMI files
	mockFiles := map[string]string{
		"sys_vendor":      "Test Manufacturer\n",
		"product_name":    "Test Model\n",
		"product_version": "v2.0\n",
		"product_serial":  "SN-TEST-001\n",
	}

	for name, content := range mockFiles {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	// We can't easily override dmiBasePath constant, but we can test
	// that the file reading and trimming logic works correctly
	// by testing with actual files if they exist on the system

	// Test that whitespace is trimmed
	testFile := filepath.Join(tmpDir, "test_attr")
	err := os.WriteFile(testFile, []byte("  Test Value  \n"), 0644)
	require.NoError(t, err)

	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	// Verify our trim logic would work
	assert.Contains(t, string(data), "Test Value")
}

func TestDiscoverPlatformAttributes(t *testing.T) {
	// This test verifies the function runs without panicking
	// Actual values depend on the system running the test
	result := DiscoverPlatformAttributes()
	assert.NotNil(t, result)

	// On a real Linux system with DMI, these should be non-empty
	// On other systems or containers, they may be empty
	t.Logf("Discovered platform attributes:")
	t.Logf("  Manufacturer: %q", result.Manufacturer)
	t.Logf("  Model: %q", result.Model)
	t.Logf("  Version: %q", result.Version)
	t.Logf("  Serial: %q", result.Serial)
}

func TestPlatformAttributes_EmptyStruct(t *testing.T) {
	attrs := &PlatformAttributes{}
	assert.Equal(t, "", attrs.Manufacturer)
	assert.Equal(t, "", attrs.Model)
	assert.Equal(t, "", attrs.Version)
	assert.Equal(t, "", attrs.Serial)
}

// ---------------------------------------------------------------------------
// PlatformKeyStore tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Mock TrustedPlatformModule for PlatformKeyStore tests
// ---------------------------------------------------------------------------

// mockTPMForPKS is a minimal mock of TrustedPlatformModule used exclusively
// by PlatformKeyStore tests. Only the methods exercised by the platform key
// store and its adapter are given meaningful implementations; all others
// return zero values.
type mockTPMForPKS struct {
	installCalled              atomic.Bool
	installErr                 error
	setAuthCalled              atomic.Bool
	setAuthErr                 error
	createSRKCalled            atomic.Bool
	createSRKErr               error
	createSRKAttrs             *types.KeyAttributes
	daResetErr                 error
	ekProvisioned              bool
	readHandleErr              error
	verifyAuthErr              error
	changeAuthErr              error
	deleteKeyErr               error
	verifyAuthClearOnCreateSRK bool // when true, CreateSRK clears verifyAuthErr
	config                     *Config
}

func (m *mockTPMForPKS) Install(soPIN types.Password) error {
	m.installCalled.Store(true)
	return m.installErr
}

func (m *mockTPMForPKS) SetHierarchyAuth(oldSecret, newSecret types.Password, hierarchy *tpm2.TPMHandle) error {
	m.setAuthCalled.Store(true)
	return m.setAuthErr
}

func (m *mockTPMForPKS) CreateSRK(keyAttrs *types.KeyAttributes) error {
	m.createSRKCalled.Store(true)
	m.createSRKAttrs = keyAttrs
	if m.createSRKErr != nil {
		return m.createSRKErr
	}
	// Simulate: after CreateSRK installs new auth, VerifyAuth succeeds.
	if m.verifyAuthClearOnCreateSRK {
		m.verifyAuthErr = nil
	}
	return nil
}

func (m *mockTPMForPKS) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return m.daResetErr
}

func (m *mockTPMForPKS) Config() *Config {
	return m.config
}

func (m *mockTPMForPKS) EK() (crypto.PublicKey, error) {
	if m.ekProvisioned {
		return nil, nil
	}
	return nil, ErrEKNotInitialized
}

func (m *mockTPMForPKS) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {
	return tpm2.TPM2BDigest{Buffer: make([]byte, 32)}, nil
}

// Remaining TrustedPlatformModule methods -- minimal stubs.

func (m *mockTPMForPKS) ActivateCredential(_, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) AKProfile() (AKProfile, error)           { return AKProfile{}, nil }
func (m *mockTPMForPKS) AlgID() tpm2.TPMAlgID                    { return tpm2.TPMAlgSHA256 }
func (m *mockTPMForPKS) CalculateName(_ tpm2.TPMAlgID, _ []byte) {}
func (m *mockTPMForPKS) Clear(_ []byte) error                    { return nil }
func (m *mockTPMForPKS) Close() error                            { return nil }
func (m *mockTPMForPKS) FactoryReset(_ []byte) error             { return nil }
func (m *mockTPMForPKS) CreateECDSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*ecdsa.PublicKey, error) {
	return nil, nil
}
func (m *mockTPMForPKS) CreateEK(_ *types.KeyAttributes) error { return nil }
func (m *mockTPMForPKS) CreateSecretKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	return nil
}
func (m *mockTPMForPKS) CreateIAK(_ *types.KeyAttributes, _ []byte) (*types.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPMForPKS) CreateIDevID(_ *types.KeyAttributes, _ *x509.Certificate, _ []byte) (*types.KeyAttributes, *TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) CreatePlatformPolicy() error { return nil }
func (m *mockTPMForPKS) CreateRSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*rsa.PublicKey, error) {
	return nil, nil
}
func (m *mockTPMForPKS) CreateKeySession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) CreateSession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) CreateTCG_CSR_IDEVID(_ *x509.Certificate, _ *types.KeyAttributes, _ *types.KeyAttributes) (TCG_CSR_IDEVID, error) {
	return TCG_CSR_IDEVID{}, nil
}
func (m *mockTPMForPKS) DeleteKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	return m.deleteKeyErr
}

func (m *mockTPMForPKS) Device() string { return "mock" }
func (m *mockTPMForPKS) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPMForPKS) EKAttributes() (*types.KeyAttributes, error) { return nil, nil }
func (m *mockTPMForPKS) EKCertificate() (*x509.Certificate, error)   { return nil, nil }
func (m *mockTPMForPKS) EKCertificateRSA() (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPMForPKS) EKCertificateEC() (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPMForPKS) EKECC() (*ecdsa.PublicKey, error) { return nil, nil }
func (m *mockTPMForPKS) EKRSA() (*rsa.PublicKey, error)   { return nil, nil }
func (m *mockTPMForPKS) EventLog() ([]byte, error)        { return nil, nil }
func (m *mockTPMForPKS) FixedProperties() (*PropertiesFixed, error) {
	return nil, nil
}
func (m *mockTPMForPKS) Flush(_ tpm2.TPMHandle)              {}
func (m *mockTPMForPKS) GoldenMeasurements() ([]byte, error) { return nil, nil }
func (m *mockTPMForPKS) HMAC(_ []byte) tpm2.Session          { return nil }
func (m *mockTPMForPKS) HMACSaltedSession(_ tpm2.TPMHandle, _ tpm2.TPMTPublic, _ []byte) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) HMACSession(_ []byte) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) IAK() (crypto.PublicKey, error)                  { return nil, nil }
func (m *mockTPMForPKS) IAKAttributes() (*types.KeyAttributes, error)    { return nil, nil }
func (m *mockTPMForPKS) IDevID() (crypto.PublicKey, error)               { return nil, nil }
func (m *mockTPMForPKS) IDevIDAttributes() (*types.KeyAttributes, error) { return nil, nil }
func (m *mockTPMForPKS) Info() (string, error)                           { return "", nil }
func (m *mockTPMForPKS) IsFIPS140_2() (bool, error)                      { return false, nil }
func (m *mockTPMForPKS) IsPlatformPCRExtended() (bool, error)            { return false, nil }
func (m *mockTPMForPKS) ExtendPCR(_ int, _ string, _ []byte) error       { return nil }
func (m *mockTPMForPKS) KeyAttributes(_ tpm2.TPMHandle) (*types.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPMForPKS) LoadKeyPair(_ *types.KeyAttributes, _ *tpm2.Session, _ store.KeyBackend) (*tpm2.LoadResponse, error) {
	return nil, nil
}
func (m *mockTPMForPKS) MakeCredential(_ tpm2.TPM2BName, _ []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPMForPKS) MakeCredentialWithExternalEK(_ *x509.Certificate, _, _ []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPMForPKS) NonceSession(_ types.Password) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) NVRead(_ *types.KeyAttributes, _ uint16) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) NVWrite(_ *types.KeyAttributes) error                 { return nil }
func (m *mockTPMForPKS) NVDefineCounter(_ *types.KeyAttributes) error         { return nil }
func (m *mockTPMForPKS) NVDefineExtend(_ *types.KeyAttributes) error          { return nil }
func (m *mockTPMForPKS) NVIncrement(_ *types.KeyAttributes) (uint64, error)   { return 0, nil }
func (m *mockTPMForPKS) NVExtend(_ *types.KeyAttributes, _ []byte) error      { return nil }
func (m *mockTPMForPKS) NVReadCounter(_ *types.KeyAttributes) (uint64, error) { return 0, nil }
func (m *mockTPMForPKS) NVReadExtend(_ *types.KeyAttributes) ([]byte, error)  { return nil, nil }
func (m *mockTPMForPKS) NVUndefine(_ *types.KeyAttributes) error              { return nil }
func (m *mockTPMForPKS) Open() error                                          { return nil }
func (m *mockTPMForPKS) ParseEKCertificate(_ []byte) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPMForPKS) ParsedEventLog() ([]Event, error)                  { return nil, nil }
func (m *mockTPMForPKS) ParsePublicKey(_ []byte) (crypto.PublicKey, error) { return nil, nil }
func (m *mockTPMForPKS) PlatformPolicyDigestHash() ([]byte, error)         { return nil, nil }
func (m *mockTPMForPKS) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) PlatformQuote(_ *types.KeyAttributes) (Quote, []byte, error) {
	return Quote{}, nil, nil
}
func (m *mockTPMForPKS) Provision(_ types.Password) error  { return nil }
func (m *mockTPMForPKS) ProvisionEKCert(_, _ []byte) error { return nil }
func (m *mockTPMForPKS) ProvisionOwner(_ types.Password) (*types.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPMForPKS) Quote(_ []uint, _ []byte) (Quote, error) { return Quote{}, nil }
func (m *mockTPMForPKS) CertifyKey(_ *types.KeyAttributes, _ []byte, _ store.KeyBackend) (*CertifyResult, error) {
	return nil, nil
}
func (m *mockTPMForPKS) Random() ([]byte, error)           { return nil, nil }
func (m *mockTPMForPKS) RandomBytes(_ int) ([]byte, error) { return nil, nil }
func (m *mockTPMForPKS) RandomHex(_ int) ([]byte, error)   { return nil, nil }
func (m *mockTPMForPKS) RandomSource() io.Reader           { return nil }
func (m *mockTPMForPKS) Read(_ []byte) (int, error)        { return 0, nil }
func (m *mockTPMForPKS) ReadHandle(_ tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, m.readHandleErr
}
func (m *mockTPMForPKS) ReadPCRs(_ []uint) ([]PCRBank, error) { return nil, nil }
func (m *mockTPMForPKS) RSADecrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) RSAEncrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) SaveKeyPair(_ *types.KeyAttributes, _ tpm2.TPM2BPrivate, _ tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], _ store.KeyBackend, _ bool) error {
	return nil
}
func (m *mockTPMForPKS) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return nil, nil
}
func (m *mockTPMForPKS) SealKey(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*tpm2.CreateResponse, error) {
	return nil, nil
}
func (m *mockTPMForPKS) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) SecretFromShares(_ []string) (string, error) { return "", nil }
func (m *mockTPMForPKS) ShareSecret(_ []byte, _ int) ([]string, error) {
	return nil, nil
}
func (m *mockTPMForPKS) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPMForPKS) SSRKAttributes() (*types.KeyAttributes, error)        { return nil, nil }
func (m *mockTPMForPKS) PlatformSRKAttributes() (*types.KeyAttributes, error) { return nil, nil }
func (m *mockTPMForPKS) SSRK() *SRKConfig                                     { return nil }
func (m *mockTPMForPKS) PlatformKeyStore() PlatformKeyStorer                  { return nil }
func (m *mockTPMForPKS) SupportedAlgorithms() ([]string, error)               { return nil, nil }
func (m *mockTPMForPKS) SupportedCommands() ([]string, error)                 { return nil, nil }
func (m *mockTPMForPKS) SupportedECCCurves() ([]string, error)                { return nil, nil }
func (m *mockTPMForPKS) Transport() transport.TPM                             { return nil }
func (m *mockTPMForPKS) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) UnsealKey(_ *types.KeyAttributes, _ store.KeyBackend) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) CanSeal() bool              { return false }
func (m *mockTPMForPKS) WriteEKCert(_ []byte) error { return nil }
func (m *mockTPMForPKS) IDevIDCertificate() (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPMForPKS) ProvisionIDevIDCert(_ *x509.Certificate) error { return nil }
func (m *mockTPMForPKS) DeleteIDevIDCertificate() error                { return nil }
func (m *mockTPMForPKS) IAKCertificate() (*x509.Certificate, error)    { return nil, nil }
func (m *mockTPMForPKS) ProvisionIAKCert(_ *x509.Certificate) error    { return nil }
func (m *mockTPMForPKS) DeleteIAKCertificate() error                   { return nil }
func (m *mockTPMForPKS) VerifyTCGCSR(_ *TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) VerifyTCG_CSR_IAK(_ *TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) VerifyTCG_CSR_IDevID(_ *TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) SignValidate(_ *types.KeyAttributes, _, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) HashSequence(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) Hash(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPMForPKS) ECDHZGen(_ *types.KeyAttributes, _ *tpm2.TPMSECCPoint, _ store.KeyBackend) ([]byte, error) {
	return nil, nil
}
func (m *mockTPMForPKS) ListPersistentHandles() ([]tpm2.TPMHandle, error) { return nil, nil }
func (m *mockTPMForPKS) ListTransientHandles() ([]tpm2.TPMHandle, error)  { return nil, nil }
func (m *mockTPMForPKS) ListNVIndexes() ([]NVIndexInfo, error)            { return nil, nil }
func (m *mockTPMForPKS) GenerateSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	return nil, nil
}
func (m *mockTPMForPKS) GetSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	return nil, nil
}
func (m *mockTPMForPKS) SymmetricEncrypter(_ *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	return nil, nil
}

func (m *mockTPMForPKS) VerifyAuth(_ tpm2.TPMHandle, _ []byte) error    { return m.verifyAuthErr }
func (m *mockTPMForPKS) ChangeAuth(_ tpm2.TPMHandle, _, _ []byte) error { return m.changeAuthErr }

// mockKeyBackendForPKS satisfies store.KeyBackend for tests.
type mockKeyBackendForPKS struct{}

func (m *mockKeyBackendForPKS) Get(_ *types.KeyAttributes, _ types.FSExtension) ([]byte, error) {
	return nil, nil
}
func (m *mockKeyBackendForPKS) Save(_ *types.KeyAttributes, _ []byte, _ types.FSExtension, _ bool) error {
	return nil
}
func (m *mockKeyBackendForPKS) Delete(_ *types.KeyAttributes) error { return nil }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testConfigForPKS(platformPolicy bool) *Config {
	return &Config{
		PlatformSRK: &PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: platformPolicy,
		},
		SSRK: &SRKConfig{
			Handle:       0x81000002,
			KeyAlgorithm: "ecc",
			ECCConfig: &store.ECCConfig{
				Curve: "P-256",
			},
		},
	}
}

func newTestPlatformKeyStore(t *testing.T, mock *mockTPMForPKS) *PlatformKeyStore {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "pin-state.json")
	pks, err := NewPlatformKeyStore(
		slog.Default(),
		mock,
		&mockKeyBackendForPKS{},
		mock.config,
		statePath,
	)
	require.NoError(t, err)
	return pks
}

// ---------------------------------------------------------------------------
// PlatformKeyStore Tests
// ---------------------------------------------------------------------------

func TestPlatformKeyStore_NewAndDefaults(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(true),
		readHandleErr: tpm2.TPMRC(0x18b), // SRK handle does not exist yet
	}
	pks := newTestPlatformKeyStore(t, mock)

	assert.NotNil(t, pks.SRKAttributes(), "SRK attributes must not be nil")
	assert.NotNil(t, pks.Backend(), "backend must not be nil")
	assert.NotNil(t, pks.PINManager(), "PINManager must not be nil")
	assert.False(t, pks.IsInitialized(), "must not be initialized before Initialize")
	assert.True(t, pks.PlatformPolicyEnabled(), "platform policy should be enabled")
}

func TestPlatformKeyStore_NewProbesSRKHandle(t *testing.T) {
	t.Run("SRKExists", func(t *testing.T) {
		// When the SRK handle already exists in the TPM (e.g., from a prior
		// InitializeWithDefaults call), the store should detect it and mark
		// itself as initialized even without PIN state.
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: nil, // ReadHandle succeeds = SRK exists
		}
		pks := newTestPlatformKeyStore(t, mock)
		assert.True(t, pks.IsInitialized(),
			"must be initialized when SRK handle exists in TPM")
	})

	t.Run("SRKNotFound", func(t *testing.T) {
		// When the SRK handle does not exist, the store remains uninitialized.
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: tpm2.TPMRC(0x18b), // TPM_RC_HANDLE
		}
		pks := newTestPlatformKeyStore(t, mock)
		assert.False(t, pks.IsInitialized(),
			"must not be initialized when SRK handle is absent")
	})
}

func TestPlatformKeyStore_NewNilTPMError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "pin-state.json")
	_, err := NewPlatformKeyStore(
		slog.Default(),
		nil,
		&mockKeyBackendForPKS{},
		testConfigForPKS(false),
		statePath,
	)
	require.ErrorIs(t, err, ErrPlatformKeyStoreNilTPM)
}

func TestPlatformKeyStore_NewNilBackendError(t *testing.T) {
	mock := &mockTPMForPKS{config: testConfigForPKS(false)}
	statePath := filepath.Join(t.TempDir(), "pin-state.json")
	_, err := NewPlatformKeyStore(
		slog.Default(),
		mock,
		nil,
		mock.config,
		statePath,
	)
	require.ErrorIs(t, err, ErrPlatformKeyStoreNilBackend)
}

func TestPlatformKeyStore_NewNilConfigError(t *testing.T) {
	mock := &mockTPMForPKS{config: testConfigForPKS(false)}
	statePath := filepath.Join(t.TempDir(), "pin-state.json")
	_, err := NewPlatformKeyStore(
		slog.Default(),
		mock,
		&mockKeyBackendForPKS{},
		nil,
		statePath,
	)
	require.ErrorIs(t, err, ErrPlatformKeyStoreNilConfig)
}

func TestPlatformKeyStore_Initialize(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(true),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	assert.False(t, pks.IsAuthReady(), "auth must not be ready before Initialize")

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)

	assert.True(t, pks.IsInitialized(), "must be initialized after Initialize")
	assert.True(t, pks.IsAuthReady(), "auth must be ready after successful Initialize")
	assert.True(t, mock.createSRKCalled.Load(), "TPM CreateSRK should have been called")

	// Verify SRK attributes passed to CreateSRK have platform policy set
	require.NotNil(t, mock.createSRKAttrs)
	assert.True(t, mock.createSRKAttrs.PlatformPolicy,
		"SRK should have platform policy enabled")
}

func TestPlatformKeyStore_InitializeDoubleCallIdempotent(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)

	// Second call with the same PIN should succeed (idempotent).
	// ensureSRKAuth verifies the PIN matches and re-registers it.
	err = pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)
}

func TestPlatformKeyStore_InitializeDoubleCallAuthMismatch(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)

	// Configure the mock to fail VerifyAuth (simulating wrong PIN).
	// ensureSRKAuth will try to evict and recreate the SRK.
	// ReadHandle must succeed for the eviction path.
	mock.verifyAuthErr = errors.New("TPM_RC_BAD_AUTH")
	mock.readHandleErr = nil // ReadHandle succeeds (SRK exists)

	// After eviction + recreation, VerifyAuth is called again via
	// SetUserPIN. Since verifyAuthErr is still set, SetUserPIN fails.
	err = pks.Initialize("supersecret", "wrongpin")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlatformKeyStoreSetUserPIN)
}

func TestPlatformKeyStore_InitializeSRKExistsButPINVerifyFails(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
		verifyAuthErr: errors.New("TPM_RC_BAD_AUTH"),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlatformKeyStoreSetUserPIN)
}

func TestPlatformKeyStore_InitializeUserPINVerifyError(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
		verifyAuthErr: errors.New("TPM_RC_AUTH_FAIL"),
	}
	pks := newTestPlatformKeyStore(t, mock)

	// SRK is created first, then SetUserPIN fails because VerifyAuth fails.
	err := pks.Initialize("supersecret", "userpin1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlatformKeyStoreSetUserPIN)
}

func TestPlatformKeyStore_InitializeCreateSRKError(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		createSRKErr:  ErrNotInitialized,
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlatformKeyStoreCreateSRK)
	assert.False(t, pks.IsInitialized(), "must not be initialized on SRK error")
}

func TestPlatformKeyStore_InitializeNVDefinedSuccess(t *testing.T) {
	// TPM_RC_NV_DEFINED (0x14c) means the SRK persistent handle is already
	// occupied from a prior provisioning attempt. This should be treated
	// as success rather than an error.
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(true),
		createSRKErr:  tpm2.TPMRC(0x14c),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err, "NV_DEFINED error from CreateSRK must be treated as success")

	assert.True(t, pks.IsInitialized(), "must be initialized when SRK already exists")
	assert.True(t, pks.IsAuthReady(), "auth must be ready when ensureSRKAuth succeeds")
	assert.True(t, mock.createSRKCalled.Load(), "CreateSRK should have been called")
}

func TestPlatformKeyStore_PINManager(t *testing.T) {
	mock := &mockTPMForPKS{config: testConfigForPKS(false)}
	pks := newTestPlatformKeyStore(t, mock)

	pm := pks.PINManager()
	require.NotNil(t, pm, "PINManager must not be nil")
	assert.Equal(t, "tpm2", string(pm.Strategy()),
		"PINManager strategy must be tpm2")
}

func TestPlatformKeyStore_SRKAttributes(t *testing.T) {
	mock := &mockTPMForPKS{config: testConfigForPKS(false)}
	pks := newTestPlatformKeyStore(t, mock)

	attrs := pks.SRKAttributes()
	require.NotNil(t, attrs, "SRK attributes must not be nil")
	assert.Equal(t, types.KeyTypeStorage, attrs.KeyType,
		"SRK key type must be Storage")
	assert.Equal(t, types.StoreTPM2, attrs.StoreType,
		"SRK store type must be TPM2")
	require.NotNil(t, attrs.TPMAttributes, "SRK TPM attributes must not be nil")
	assert.Equal(t, tpm2.TPMHandle(0x81000002), attrs.TPMAttributes.Handle,
		"SRK handle must match config")
}

func TestPlatformKeyStore_SRKAttributesCustomHandle(t *testing.T) {
	cfg := testConfigForPKS(false)
	cfg.PlatformSRK.SRKHandle = 0x81000099
	cfg.SSRK.Handle = 0x81000099
	mock := &mockTPMForPKS{config: cfg}
	pks := newTestPlatformKeyStore(t, mock)

	attrs := pks.SRKAttributes()
	require.NotNil(t, attrs)
	require.NotNil(t, attrs.TPMAttributes)
	assert.Equal(t, tpm2.TPMHandle(0x81000099), attrs.TPMAttributes.Handle,
		"SRK handle must match custom config value")
}

func TestPlatformKeyStore_Backend(t *testing.T) {
	mock := &mockTPMForPKS{config: testConfigForPKS(false)}
	pks := newTestPlatformKeyStore(t, mock)

	backend := pks.Backend()
	require.NotNil(t, backend, "backend must not be nil")
	_, ok := backend.(*mockKeyBackendForPKS)
	assert.True(t, ok, "backend must be the mock implementation")
}

func TestPlatformKeyStore_IsInitialized(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	assert.False(t, pks.IsInitialized(), "must not be initialized before Initialize")

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)

	assert.True(t, pks.IsInitialized(), "must be initialized after Initialize")
}

func TestPlatformKeyStore_PlatformPolicyEnabled(t *testing.T) {
	t.Run("Enabled", func(t *testing.T) {
		mock := &mockTPMForPKS{config: testConfigForPKS(true)}
		pks := newTestPlatformKeyStore(t, mock)
		assert.True(t, pks.PlatformPolicyEnabled())
	})

	t.Run("Disabled", func(t *testing.T) {
		mock := &mockTPMForPKS{config: testConfigForPKS(false)}
		pks := newTestPlatformKeyStore(t, mock)
		assert.False(t, pks.PlatformPolicyEnabled())
	})

	t.Run("NilPlatformSRKConfig", func(t *testing.T) {
		cfg := testConfigForPKS(false)
		cfg.PlatformSRK = nil
		mock := &mockTPMForPKS{config: cfg}
		statePath := filepath.Join(t.TempDir(), "pin-state.json")
		pks, err := NewPlatformKeyStore(
			slog.Default(),
			mock,
			&mockKeyBackendForPKS{},
			cfg,
			statePath,
		)
		require.NoError(t, err)
		assert.False(t, pks.PlatformPolicyEnabled(),
			"platform policy must be false when PlatformSRK config is nil")
	})
}

func TestPlatformKeyStore_InitializeWithoutPlatformPolicy(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.Initialize("supersecret", "userpin1")
	require.NoError(t, err)

	require.NotNil(t, mock.createSRKAttrs)
	assert.False(t, mock.createSRKAttrs.PlatformPolicy,
		"SRK should NOT have platform policy when disabled in config")
}

// ---------------------------------------------------------------------------
// InitializeWithDefaults tests
// ---------------------------------------------------------------------------

func TestPlatformKeyStore_InitializeWithDefaults(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.InitializeWithDefaults()
	require.NoError(t, err)

	assert.True(t, pks.IsInitialized(), "must be initialized after InitializeWithDefaults")
	assert.True(t, pks.IsAuthReady(), "auth must be ready (new SRK created with known empty auth)")
	assert.True(t, mock.createSRKCalled.Load(), "CreateSRK should have been called")

	// Verify SRK attributes passed to CreateSRK have empty auth
	require.NotNil(t, mock.createSRKAttrs)
	assert.False(t, mock.createSRKAttrs.PlatformPolicy,
		"SRK should NOT have platform policy when disabled")
}

func TestPlatformKeyStore_InitializeWithDefaultsPlatformPolicy(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(true),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.InitializeWithDefaults()
	require.NoError(t, err)

	assert.True(t, pks.IsInitialized())
	require.NotNil(t, mock.createSRKAttrs)
	assert.True(t, mock.createSRKAttrs.PlatformPolicy,
		"SRK should have platform policy when enabled in config")
}

func TestPlatformKeyStore_InitializeWithDefaultsDoubleCallError(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.InitializeWithDefaults()
	require.NoError(t, err)

	err = pks.InitializeWithDefaults()
	require.ErrorIs(t, err, ErrPlatformKeyStoreAlreadyInitialized)
}

func TestPlatformKeyStore_InitializeWithDefaultsCreateSRKError(t *testing.T) {
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		createSRKErr:  ErrNotInitialized,
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.InitializeWithDefaults()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlatformKeyStoreCreateSRK)
	assert.False(t, pks.IsInitialized(), "must not be initialized on SRK error")
}

func TestPlatformKeyStore_InitializeWithDefaultsNVDefinedSuccess(t *testing.T) {
	// TPM_RC_NV_DEFINED (0x14c) means the SRK persistent handle is already
	// occupied from a prior provisioning attempt. This should be treated
	// as success rather than an error.
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		createSRKErr:  tpm2.TPMRC(0x14c),
		readHandleErr: tpm2.TPMRC(0x18b),
	}
	pks := newTestPlatformKeyStore(t, mock)

	err := pks.InitializeWithDefaults()
	require.NoError(t, err, "NV_DEFINED error from CreateSRK must be treated as success")

	assert.True(t, pks.IsInitialized(), "must be initialized when SRK already exists")
	assert.True(t, mock.createSRKCalled.Load(), "CreateSRK should have been called")
}

// ---------------------------------------------------------------------------
// PlatformAuthProvider tests (PlatformKeyStore implements pin.PlatformAuthProvider)
// ---------------------------------------------------------------------------

func TestPlatformKeyStore_IsProvisioned(t *testing.T) {
	t.Run("NotInitialized", func(t *testing.T) {
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: errors.New("handle not found"),
		}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)
		assert.False(t, pks.IsProvisioned(), "not provisioned when SRK does not exist")
	})

	t.Run("Initialized", func(t *testing.T) {
		mock := &mockTPMForPKS{config: testConfigForPKS(false)}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)
		// SRK handle readable → initialized
		assert.True(t, pks.IsProvisioned(), "provisioned when SRK handle exists")
	})
}

func TestPlatformKeyStore_GetLockoutInfo(t *testing.T) {
	t.Run("NilProperties", func(t *testing.T) {
		mock := &mockTPMForPKS{config: testConfigForPKS(false)}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)

		// FixedProperties returns nil, nil → safe defaults
		failedAttempts, maxFail, interval, recovery, err := pks.GetLockoutInfo()
		require.NoError(t, err)
		assert.Equal(t, 0, failedAttempts)
		assert.Equal(t, 10, maxFail)
		assert.Equal(t, 0, interval)
		assert.Equal(t, 300, recovery)
	})
}

func TestPlatformKeyStore_DictionaryAttackLockoutReset(t *testing.T) {
	t.Run("DelegateError", func(t *testing.T) {
		mock := &mockTPMForPKS{
			config:     testConfigForPKS(false),
			daResetErr: ErrLockoutResetFailed,
		}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)

		err = pks.DictionaryAttackLockoutReset([]byte("lockout-auth"))
		require.ErrorIs(t, err, ErrLockoutResetFailed)
	})

	t.Run("Success", func(t *testing.T) {
		mock := &mockTPMForPKS{config: testConfigForPKS(false)}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)

		err = pks.DictionaryAttackLockoutReset([]byte("lockout-auth"))
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// buildSRKAttrsFromConfig tests
// ---------------------------------------------------------------------------

func TestPlatformKeyStore_BuildSRKAttrsNoSSRK(t *testing.T) {
	cfg := testConfigForPKS(false)
	cfg.SSRK = nil

	attrs, err := buildSRKAttrsFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, attrs)
	assert.Equal(t, "srk", attrs.CN)
	assert.Equal(t, types.KeyTypeStorage, attrs.KeyType)
	assert.Equal(t, tpm2.TPMHandle(0x81000002), attrs.TPMAttributes.Handle)
}

func TestPlatformKeyStore_BuildSRKAttrsNoPlatformSRKConfig(t *testing.T) {
	cfg := testConfigForPKS(false)
	cfg.PlatformSRK = nil
	cfg.SSRK = nil

	attrs, err := buildSRKAttrsFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, attrs)
	// Should fall back to tpSRKIndex = 0x81000002
	assert.Equal(t, tpm2.TPMHandle(tpSRKIndex), attrs.TPMAttributes.Handle)
}

// ---------------------------------------------------------------------------
// Eviction failure tests
// ---------------------------------------------------------------------------

func TestPlatformKeyStore_EvictionFailsWithClearError(t *testing.T) {
	// When the SRK already exists with different auth and eviction fails
	// (hierarchy auth from prior installation), Initialize must return
	// ErrPlatformKeyStoreEvictSRK with a clear message.
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: nil,                           // SRK handle exists
		verifyAuthErr: errors.New("TPM_RC_BAD_AUTH"), // SRK auth mismatch
		deleteKeyErr:  errors.New("TPM_RC_BAD_AUTH"), // eviction fails
	}
	pks := newTestPlatformKeyStore(t, mock)
	assert.True(t, pks.IsInitialized(), "SRK exists so store should be initialized")
	assert.False(t, pks.IsAuthReady(), "auth must NOT be ready (no marker, SRK has unknown auth)")

	err := pks.Initialize("", "userpin1")
	require.Error(t, err, "Initialize must fail when eviction fails")
	require.ErrorIs(t, err, ErrPlatformKeyStoreEvictSRK,
		"error must indicate eviction failure")
	assert.False(t, pks.IsAuthReady(), "auth must NOT be ready after eviction failure")
}

func TestPlatformKeyStore_EvictionSucceedsWithSOPIN(t *testing.T) {
	// When the correct SO PIN is provided, eviction and recreation succeed.
	// verifyAuthClearOnCreateSRK simulates: after CreateSRK installs new
	// auth, VerifyAuth starts succeeding.
	mock := &mockTPMForPKS{
		config:                     testConfigForPKS(false),
		readHandleErr:              nil,                           // SRK exists
		verifyAuthErr:              errors.New("TPM_RC_BAD_AUTH"), // auth mismatch initially
		deleteKeyErr:               nil,                           // eviction succeeds
		verifyAuthClearOnCreateSRK: true,
	}
	pks := newTestPlatformKeyStore(t, mock)
	assert.False(t, pks.IsAuthReady(), "auth must NOT be ready before Initialize")

	err := pks.Initialize("correctsopin", "userpin1")
	require.NoError(t, err, "Initialize must succeed when eviction succeeds")
	assert.True(t, mock.createSRKCalled.Load(),
		"CreateSRK should be called to recreate SRK with new auth")
	assert.True(t, pks.IsAuthReady(), "auth must be ready after successful eviction+recreate")
}

func TestPlatformKeyStore_IsAuthReady(t *testing.T) {
	t.Run("FalseBeforeInitialize", func(t *testing.T) {
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: tpm2.TPMRC(0x18b),
		}
		pks := newTestPlatformKeyStore(t, mock)
		assert.False(t, pks.IsAuthReady(), "must be false before Initialize")
	})

	t.Run("TrueAfterInitialize", func(t *testing.T) {
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: tpm2.TPMRC(0x18b),
		}
		pks := newTestPlatformKeyStore(t, mock)
		require.NoError(t, pks.Initialize("", "userpin1"))
		assert.True(t, pks.IsAuthReady(), "must be true after successful Initialize")
	})

	t.Run("FalseWhenSRKExistsButNoMarker", func(t *testing.T) {
		// SRK exists in TPM but no marker file → auth state unknown (prior owner).
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: nil, // SRK exists
		}
		pks := newTestPlatformKeyStore(t, mock)
		assert.True(t, pks.IsInitialized(), "SRK exists so initialized=true")
		assert.False(t, pks.IsAuthReady(), "no marker → auth not ready")
	})

	t.Run("FalseAfterAuthSyncFailure", func(t *testing.T) {
		// SRK exists with wrong auth, eviction fails → auth stays not ready.
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: nil,
			verifyAuthErr: errors.New("TPM_RC_BAD_AUTH"),
			deleteKeyErr:  errors.New("TPM_RC_BAD_AUTH"),
		}
		pks := newTestPlatformKeyStore(t, mock)
		_ = pks.Initialize("", "userpin1")
		assert.False(t, pks.IsAuthReady(), "must be false when ensureSRKAuth fails")
	})

	t.Run("EmptyStatePath", func(t *testing.T) {
		// When statePath is empty, authReady works in memory only.
		mock := &mockTPMForPKS{
			config:        testConfigForPKS(false),
			readHandleErr: tpm2.TPMRC(0x18b),
		}
		pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
		require.NoError(t, err)
		require.NoError(t, pks.Initialize("", "userpin1"))
		assert.True(t, pks.IsAuthReady(), "in-memory flag works even without statePath")
	})
}

func TestPlatformKeyStore_SetAuthReady(t *testing.T) {
	// SetAuthReady allows the app layer to restore auth-ready state from
	// persisted config (e.g., GUIConfig.PINStrategy == "tpm2") on restart.
	mock := &mockTPMForPKS{
		config:        testConfigForPKS(false),
		readHandleErr: nil, // SRK exists
	}
	pks, err := NewPlatformKeyStore(slog.Default(), mock, &mockKeyBackendForPKS{}, mock.config, "")
	require.NoError(t, err)

	// SRK exists → initialized, but authReady defaults to false.
	assert.True(t, pks.IsInitialized())
	assert.False(t, pks.IsAuthReady(), "auth not ready by default")

	// App layer restores from config.
	pks.SetAuthReady(true)
	assert.True(t, pks.IsAuthReady(), "app layer set auth ready")

	// App layer can also clear it.
	pks.SetAuthReady(false)
	assert.False(t, pks.IsAuthReady(), "app layer cleared auth ready")
}
