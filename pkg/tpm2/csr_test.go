package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test verifyTCGCSRSignature RSA PKCS1v15
func TestVerifyTCGCSRSignature_RSAPKCS1v15_ValidSignature(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Sign with RSA PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest[:])
	require.NoError(t, err)

	csr.Signature = signature

	// Create key attributes
	keyAttrs := createRSAKeyAttributes(rsaKey, x509.SHA256WithRSA)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.NoError(t, err, "valid RSA PKCS1v15 signature should verify")
}

func TestVerifyTCGCSRSignature_RSAPSS_ValidSignature(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Sign with RSA PSS
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}
	signature, err := rsa.SignPSS(rand.Reader, rsaKey, hash, digest[:], pssOpts)
	require.NoError(t, err)

	csr.Signature = signature

	// Create key attributes
	keyAttrs := createRSAKeyAttributes(rsaKey, x509.SHA256WithRSAPSS)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.NoError(t, err, "valid RSA PSS signature should verify")
}

func TestVerifyTCGCSRSignature_ECDSA_ValidSignature(t *testing.T) {
	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Sign with ECDSA
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest[:])
	require.NoError(t, err)

	csr.Signature = signature

	// Create key attributes
	keyAttrs := createECDSAKeyAttributes(ecdsaKey, x509.ECDSAWithSHA256)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.NoError(t, err, "valid ECDSA signature should verify")
}

func TestVerifyTCGCSRSignature_RSAPKCS1v15_InvalidSignature(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
		Signature:   []byte("invalid-signature"), // Invalid signature
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Create key attributes
	keyAttrs := createRSAKeyAttributes(rsaKey, x509.SHA256WithRSA)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature should fail
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.Error(t, err, "invalid RSA PKCS1v15 signature should fail verification")
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestVerifyTCGCSRSignature_RSAPSS_InvalidSignature(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
		Signature:   make([]byte, 256), // Wrong signature
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Create key attributes
	keyAttrs := createRSAKeyAttributes(rsaKey, x509.SHA256WithRSAPSS)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature should fail
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.Error(t, err, "invalid RSA PSS signature should fail verification")
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestVerifyTCGCSRSignature_ECDSA_InvalidSignature(t *testing.T) {
	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
		Signature:   []byte("invalid-ecdsa-signature"), // Invalid signature
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Create key attributes
	keyAttrs := createECDSAKeyAttributes(ecdsaKey, x509.ECDSAWithSHA256)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify signature should fail
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.Error(t, err, "invalid ECDSA signature should fail verification")
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestVerifyTCGCSRSignature_DifferentKey_InvalidSignature(t *testing.T) {
	// Generate two different RSA keys
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	verifyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create mock TPM instance
	tpm := createMockTPMForSignatureTests(t)

	// Create CSR content
	content := createTestCSRContent()
	csr := &TCG_CSR_IDEVID{
		CsrContents: content,
	}

	// Pack the content
	packedContents, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Create hash of packed content
	hash := crypto.SHA256
	digest := sha256.Sum256(packedContents)

	// Sign with one key
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, hash, digest[:])
	require.NoError(t, err)
	csr.Signature = signature

	// But verify with different key
	keyAttrs := createRSAKeyAttributes(verifyKey, x509.SHA256WithRSA)

	// Mock hash sequence to return the digest we computed
	tpm.mockHashSequenceResult = digest[:]

	// Verify should fail
	err = tpm.verifyTCGCSRSignature(csr, hash, keyAttrs)
	assert.Error(t, err, "signature from different key should fail verification")
	assert.Equal(t, ErrInvalidSignature, err)
}

// Test PackIDevIDCSR and UnpackIDevIDCSR
func TestPackUnpackIDevIDCSR_RoundTrip(t *testing.T) {
	// Create original CSR
	original := createTestTCGCSRIDevID()

	// Pack it
	packed, err := PackIDevIDCSR(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, packed)

	// Unmarshal it back
	unmarshaled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, original.StructVer, unmarshaled.StructVer)
	assert.Equal(t, original.Contents, unmarshaled.Contents)
	assert.Equal(t, original.SigSz, unmarshaled.SigSz)
	assert.Equal(t, original.Signature, unmarshaled.Signature)

	// Compare contents
	assert.Equal(t, original.CsrContents.StructVer, unmarshaled.CsrContents.StructVer)
	assert.Equal(t, original.CsrContents.HashAlgoId, unmarshaled.CsrContents.HashAlgoId)
	assert.Equal(t, original.CsrContents.ProdModel, unmarshaled.CsrContents.ProdModel)
	assert.Equal(t, original.CsrContents.ProdSerial, unmarshaled.CsrContents.ProdSerial)
}

func TestPackUnpackIDevIDCSR_EmptyContent(t *testing.T) {
	// Create CSR with minimal content
	csr := TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x00},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x01}, // 1 byte signature
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
			HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20}, // 32 bytes
		},
		Signature: []byte{0xFF}, // Minimal signature
	}

	packed, err := PackIDevIDCSR(&csr)
	require.NoError(t, err)
	assert.NotEmpty(t, packed)

	// Verify structure can be read back
	unmarshaled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)
	assert.Equal(t, csr.StructVer, unmarshaled.StructVer)
}

// Test UnpackIDevIDCSR
func TestUnpackIDevIDCSR_ValidCSR(t *testing.T) {
	// Create a CSR and then unpack it
	original := createTestTCGCSRIDevID()

	unpacked, err := UnpackIDevIDCSR(&original)
	require.NoError(t, err)
	assert.NotNil(t, unpacked)

	// Verify unpacked values
	assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	assert.Equal(t, uint32(256), unpacked.SigSz) // Based on test data
	assert.Equal(t, original.CsrContents.ProdModel, unpacked.CsrContents.ProdModel)
	assert.Equal(t, original.CsrContents.ProdSerial, unpacked.CsrContents.ProdSerial)
}

func TestUnpackIDevIDCSR_IncorrectSizes(t *testing.T) {
	// Create CSR with mismatched sizes
	csr := createTestTCGCSRIDevID()

	// Mismatch the size field
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 1000) // Wrong size

	_, err := UnpackIDevIDCSR(&csr)
	assert.Error(t, err, "mismatched size should cause error")
}

// Test CalculateName additional scenarios
func TestCalculateName_SHA384_Alt(t *testing.T) {
	publicArea := []byte("test public area data")

	name, err := CalculateName(tpm2.TPMAlgSHA3384, publicArea)
	require.NoError(t, err)

	// Name should start with algorithm ID (2 bytes) + hash (48 bytes for SHA384)
	assert.Len(t, name, 50) // 2 + 48
}

func TestCalculateName_UnsupportedAlgorithm(t *testing.T) {
	publicArea := []byte("test public area data")

	_, err := CalculateName(tpm2.TPMAlgID(0xFFFF), publicArea)
	assert.Error(t, err, "unsupported algorithm should return error")
}

func TestCalculateName_EmptyPublicArea(t *testing.T) {
	publicArea := []byte{}

	name, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	require.NoError(t, err)

	// Should still produce valid hash of empty data
	assert.Len(t, name, 34) // 2 + 32
}

func TestCalculateName_ConsistentResults(t *testing.T) {
	publicArea := []byte("same input data")

	name1, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	require.NoError(t, err)

	name2, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	require.NoError(t, err)

	// Same input should produce same output
	assert.Equal(t, name1, name2)
}

// Test TCGVendorID with unknown vendor
func TestTCGVendorID_UnknownVendor(t *testing.T) {
	unknownID := TCGVendorID(12345)
	result := unknownID.String()
	assert.Empty(t, result, "unknown vendor ID should return empty string")
}

// Test PackIDevIDContent
func TestPackIDevIDContent_Success(t *testing.T) {
	content := createTestCSRContent()

	packed, err := PackIDevIDContent(&content)
	require.NoError(t, err)
	assert.NotEmpty(t, packed)

	// Verify size is reasonable (all size fields + all data)
	expectedMinSize := 16*4 + // 16 size fields
		len(content.ProdModel) +
		len(content.ProdSerial) +
		len(content.EkCert) +
		len(content.AttestPub) +
		len(content.AtCreateTkt) +
		len(content.AtCertifyInfo) +
		len(content.AtCertifyInfoSig) +
		len(content.SigningPub) +
		len(content.SgnCertifyInfo) +
		len(content.SgnCertifyInfoSig)

	assert.GreaterOrEqual(t, len(packed), expectedMinSize)
}

func TestPackIDevIDContent_PreservesDataOrder(t *testing.T) {
	content := TCG_IDEVID_CONTENT{
		StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
		HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz: func() [4]byte {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], 4)
			return b
		}(),
		ProdSerial: []byte("1234"),
	}
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 4)
	content.ProdModel = []byte("TEST")

	packed, err := PackIDevIDContent(&content)
	require.NoError(t, err)

	// Verify structure version is at the start
	assert.Equal(t, content.StructVer[:], packed[0:4])

	// Verify hash algo ID follows
	assert.Equal(t, content.HashAlgoId[:], packed[4:8])

	// Verify hash size follows
	assert.Equal(t, content.HashSz[:], packed[8:12])
}

// Test Encode function
func TestEncode_HexEncoding(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "EmptyBytes",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "SingleByte",
			input:    []byte{0xFF},
			expected: "ff",
		},
		{
			name:     "MultipleBytesLowercase",
			input:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expected: "deadbeef",
		},
		{
			name:     "ZeroBytes",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: "00000000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := Encode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test AKProfile structure
func TestCSR_AKProfile_Structure(t *testing.T) {
	profile := AKProfile{
		EKPub:              []byte("ek-public-key-bytes"),
		AKPub:              []byte("ak-public-key-bytes"),
		AKName:             tpm2.TPM2BName{Buffer: []byte("ak-name")},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	assert.Equal(t, []byte("ek-public-key-bytes"), profile.EKPub)
	assert.Equal(t, []byte("ak-public-key-bytes"), profile.AKPub)
	assert.Equal(t, []byte("ak-name"), profile.AKName.Buffer)
	assert.Equal(t, x509.SHA256WithRSAPSS, profile.SignatureAlgorithm)
}

// Test Quote structure
func TestCSR_Quote_Structure(t *testing.T) {
	quote := Quote{
		Quoted:    []byte("quoted-data"),
		Signature: []byte("signature-bytes"),
		Nonce:     []byte("nonce-value"),
		PCRs:      []byte("pcr-data"),
		EventLog:  []byte("event-log-bytes"),
	}

	assert.Equal(t, []byte("quoted-data"), quote.Quoted)
	assert.Equal(t, []byte("signature-bytes"), quote.Signature)
	assert.Equal(t, []byte("nonce-value"), quote.Nonce)
	assert.Equal(t, []byte("pcr-data"), quote.PCRs)
	assert.Equal(t, []byte("event-log-bytes"), quote.EventLog)
}

// Test PCRBank structure
func TestCSR_PCRBank_Structure(t *testing.T) {
	bank := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte("pcr0-value")},
			{ID: 1, Value: []byte("pcr1-value")},
			{ID: 7, Value: []byte("pcr7-value")},
		},
	}

	assert.Equal(t, "SHA256", bank.Algorithm)
	assert.Len(t, bank.PCRs, 3)
	assert.Equal(t, int32(0), bank.PCRs[0].ID)
	assert.Equal(t, int32(1), bank.PCRs[1].ID)
	assert.Equal(t, int32(7), bank.PCRs[2].ID)
}

// Test error type definitions
func TestCSR_ErrorTypes(t *testing.T) {
	assert.NotNil(t, ErrInvalidSignature)
	assert.NotNil(t, ErrInvalidAKAttributes)
	assert.NotNil(t, ErrInvalidEKAttributes)
	assert.NotNil(t, ErrNotInitialized)
	assert.NotNil(t, ErrNotConfigured)
	assert.NotNil(t, ErrInvalidEnrollmentStrategy)
}

// Test template constants are properly defined
func TestCSR_TemplateConstants(t *testing.T) {
	// RSA SSA Template
	assert.Equal(t, tpm2.TPMAlgRSA, RSASSATemplate.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, RSASSATemplate.NameAlg)
	assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)

	// RSA PSS Template
	assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSTemplate.Type)
	assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)

	// ECC P256 Template
	assert.Equal(t, tpm2.TPMAlgECC, ECCP256Template.Type)
	assert.True(t, ECCP256Template.ObjectAttributes.SignEncrypt)

	// RSA SSA AK Template
	assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
	assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedTPM)
	assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedParent)

	// RSA PSS AK Template
	assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
	assert.True(t, RSAPSSAKTemplate.ObjectAttributes.FixedTPM)

	// ECC AK Template
	assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
	assert.True(t, ECCAKP256Template.ObjectAttributes.FixedTPM)

	// IDevID Templates (should NOT be restricted)
	assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
	assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.FixedTPM)

	assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
	assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
}

// Test AES templates
func TestCSR_AESTemplateConstants(t *testing.T) {
	// AES 128 CFB Template
	assert.Equal(t, tpm2.TPMAlgSymCipher, AES128CFBTemplate.Type)
	assert.True(t, AES128CFBTemplate.ObjectAttributes.Decrypt)
	assert.True(t, AES128CFBTemplate.ObjectAttributes.SignEncrypt)

	// AES 256 CFB Template
	assert.Equal(t, tpm2.TPMAlgSymCipher, AES256CFBTemplate.Type)
	assert.True(t, AES256CFBTemplate.ObjectAttributes.Decrypt)
	assert.True(t, AES256CFBTemplate.ObjectAttributes.SignEncrypt)

	// Keyed Hash Template
	assert.Equal(t, tpm2.TPMAlgKeyedHash, KeyedHashTemplate.Type)
}

// Test IDevIDConfig defaults
func TestCSR_IDevIDConfig_Structure(t *testing.T) {
	config := IDevIDConfig{
		CN:     "test-device-id",
		Model:  "TestModel",
		Serial: "SN123456",
		Pad:    true,
	}

	assert.Equal(t, "test-device-id", config.CN)
	assert.Equal(t, "TestModel", config.Model)
	assert.Equal(t, "SN123456", config.Serial)
	assert.True(t, config.Pad)
}

// Test enrollment strategy parsing
func TestCSR_ParseIdentityProvisioningStrategy(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK Strategy",
			input:    "IAK",
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IDevID Single Pass Strategy",
			input:    "IAK-IDevID-Single-Pass",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Default",
			input:    "unknown",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Helper functions for tests

func createTestLogger() *logging.Logger {
	return logging.DefaultLogger()
}

// mockTPMForSignatureTests wraps TPM2 for signature verification testing
type mockTPMForSignatureTests struct {
	*TPM2
	mockHashSequenceResult []byte
}

func createMockTPMForSignatureTests(t *testing.T) *mockTPMForSignatureTests {
	t.Helper()

	logger := createTestLogger()

	config := &Config{
		Hash:   "SHA-256",
		Device: "/dev/null",
		EK: &EKConfig{
			Handle:       0x81010001,
			KeyAlgorithm: "RSA",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	tpm := &TPM2{
		logger:       logger,
		config:       config,
		algID:        tpm2.TPMAlgSHA256,
		debugSecrets: false,
	}

	return &mockTPMForSignatureTests{
		TPM2: tpm,
	}
}

// Override HashSequence to use mocked result
func (m *mockTPMForSignatureTests) HashSequence(
	keyAttrs *types.KeyAttributes,
	data []byte) ([]byte, []byte, error) {

	if m.mockHashSequenceResult != nil {
		return m.mockHashSequenceResult, nil, nil
	}

	// Default behavior: compute SHA256
	digest := sha256.Sum256(data)
	return digest[:], nil, nil
}

// Override the real verifyTCGCSRSignature to use our mock
func (m *mockTPMForSignatureTests) verifyTCGCSRSignature(
	csr *TCG_CSR_IDEVID,
	hash crypto.Hash,
	keyAttrs *types.KeyAttributes) error {

	pub := keyAttrs.TPMAttributes.Public

	// Re-pack the CSR contents to get the digest
	packedContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return err
	}

	// Use mocked hash sequence
	digest, _, err := m.HashSequence(keyAttrs, packedContents)
	if err != nil {
		return err
	}

	// Verify the TCG-CSR-IDEVID signature
	if pub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return err
		}

		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return err
		}

		if store.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			err = rsa.VerifyPSS(rsaPub, hash, digest, csr.Signature, pssOpts)
			if err != nil {
				return ErrInvalidSignature
			}
		} else {
			err = rsa.VerifyPKCS1v15(rsaPub, hash, digest, csr.Signature)
			if err != nil {
				return ErrInvalidSignature
			}
		}

	} else if pub.Type == tpm2.TPMAlgECC {

		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return err
		}

		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return err
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return err
		}

		ecdsaPub := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		if !ecdsa.VerifyASN1(ecdsaPub, digest, csr.Signature) {
			return ErrInvalidSignature
		}
	}

	return nil
}

func createRSAKeyAttributes(key *rsa.PrivateKey, sigAlgo x509.SignatureAlgorithm) *types.KeyAttributes {
	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:   true,
			FixedTPM:     true,
			FixedParent:  true,
			SignEncrypt:  true,
			UserWithAuth: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: key.N.Bytes(),
			},
		),
	}

	return &types.KeyAttributes{
		CN:                 "test-rsa-key",
		KeyAlgorithm:       x509.RSA,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: sigAlgo,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
			Public:  pubArea,
		},
	}
}

func createECDSAKeyAttributes(key *ecdsa.PrivateKey, sigAlgo x509.SignatureAlgorithm) *types.KeyAttributes {
	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:   true,
			FixedTPM:     true,
			FixedParent:  true,
			SignEncrypt:  true,
			UserWithAuth: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: key.X.Bytes()},
				Y: tpm2.TPM2BECCParameter{Buffer: key.Y.Bytes()},
			},
		),
	}

	return &types.KeyAttributes{
		CN:                 "test-ecdsa-key",
		KeyAlgorithm:       x509.ECDSA,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: sigAlgo,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
			Public:  pubArea,
		},
	}
}

func createTestCSRContent() TCG_IDEVID_CONTENT {
	content := TCG_IDEVID_CONTENT{
		StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
		HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20}, // 32 bytes
	}

	// Set model
	model := []byte("TestModel")
	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(model)))
	content.ProdModel = model

	// Set serial
	serial := []byte("TestSerial123")
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(serial)))
	content.ProdSerial = serial

	// Set EK cert (dummy data)
	ekCert := []byte("dummy-ek-certificate-data")
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))
	content.EkCert = ekCert

	// Set AttestPub (dummy TPM2B_PUBLIC)
	attestPub := make([]byte, 64)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))
	content.AttestPub = attestPub

	// Set AtCreateTkt
	atCreateTkt := []byte("creation-ticket-digest")
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))
	content.AtCreateTkt = atCreateTkt

	// Set AtCertifyInfo
	atCertifyInfo := []byte("certify-info-data")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))
	content.AtCertifyInfo = atCertifyInfo

	// Set AtCertifyInfoSig
	atCertifyInfoSig := make([]byte, 256)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))
	content.AtCertifyInfoSig = atCertifyInfoSig

	// Set SigningPub
	signingPub := make([]byte, 64)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))
	content.SigningPub = signingPub

	// Set SgnCertifyInfo
	sgnCertifyInfo := []byte("signing-certify-info")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))
	content.SgnCertifyInfo = sgnCertifyInfo

	// Set SgnCertifyInfoSig
	sgnCertifyInfoSig := make([]byte, 256)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))
	content.SgnCertifyInfoSig = sgnCertifyInfoSig

	return content
}

func createTestTCGCSRIDevID() TCG_CSR_IDEVID {
	csr := TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x00},
	}

	// Create content
	content := createTestCSRContent()
	csr.CsrContents = content

	// Create signature
	signature := make([]byte, 256)
	for i := range signature {
		signature[i] = byte(i)
	}
	csr.Signature = signature
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))

	return csr
}
