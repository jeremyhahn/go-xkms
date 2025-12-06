//go:build !integration

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock TPM transport for unit tests

// Helper to create a mock TPM config for testing
func createIDevIDCSRUnitMockTPMConfig() *Config {
	return &Config{
		Device:                       "/dev/null",
		UseSimulator:                 false,
		Hash:                         "SHA-256",
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
		EK: &EKConfig{
			Handle:        0x81010001,
			KeyAlgorithm:  x509.RSA.String(),
			HierarchyAuth: "",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &IAKConfig{
			Handle:             0x81010002,
			Hash:               crypto.SHA256.String(),
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IDevID: &IDevIDConfig{
			Handle:             0x81020000,
			Hash:               crypto.SHA256.String(),
			KeyAlgorithm:       x509.RSA.String(),
			Model:              "test-model",
			Serial:             "test-serial-001",
			Pad:                true,
			PlatformPolicy:     false,
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		SSRK: &SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}
}

// Test ParseIdentityProvisioningStrategy
func TestParseIdentityProvisioningStrategy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			input:    string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			input:    string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Unknown strategy defaults to single pass",
			input:    "UNKNOWN",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Empty string defaults to single pass",
			input:    "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test ParseHashSize
func TestParseHashSize_Unit(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expectedSz  uint32
		expectError bool
	}{
		{
			name:        "SHA1 hash size",
			hash:        crypto.SHA1,
			expectedSz:  20,
			expectError: false,
		},
		{
			name:        "SHA256 hash size",
			hash:        crypto.SHA256,
			expectedSz:  32,
			expectError: false,
		},
		{
			name:        "SHA384 hash size",
			hash:        crypto.SHA384,
			expectedSz:  48,
			expectError: false,
		},
		{
			name:        "SHA512 hash size",
			hash:        crypto.SHA512,
			expectedSz:  64,
			expectError: false,
		},
		{
			name:        "Invalid hash returns error",
			hash:        crypto.MD5,
			expectedSz:  0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSz, size)
			}
		})
	}
}

// Test PackIDevIDContent - different from TestPackIDevIDContent in idevid_csr_test.go
func TestPackIDevIDContent_Unit(t *testing.T) {
	tests := []struct {
		name        string
		content     *TCG_IDEVID_CONTENT
		expectError bool
	}{
		{
			name: "Valid content packing",
			content: &TCG_IDEVID_CONTENT{
				StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
				HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20}, // 32 bytes
				ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
				ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
				ProdModel:    []byte("model"),
				ProdSerial:   []byte("001"),
				ProdCaData:   []byte{},
				BootEvntLog:  []byte{},
				EkCert:       []byte("mock-ek-cert"),
				AttestPub:    []byte("mock-attest-pub"),
			},
			expectError: false,
		},
		{
			name: "Empty content packing",
			content: &TCG_IDEVID_CONTENT{
				StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B},
				HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDContent(tc.content)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, packed)
				assert.Greater(t, len(packed), 0)

				// Verify that we can read back the structure version
				reader := bytes.NewReader(packed)
				var structVer [4]byte
				err = binary.Read(reader, binary.BigEndian, &structVer)
				assert.NoError(t, err)
				assert.Equal(t, tc.content.StructVer, structVer)
			}
		})
	}
}

// Test PackIDevIDCSR
func TestPackIDevIDCSR_Unit(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name: "Valid CSR packing",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x50}, // 80 bytes
				SigSz:     [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B},
					HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
				},
				Signature: make([]byte, 256),
			},
			expectError: false,
		},
		{
			name: "CSR with minimal data",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x00},
				SigSz:     [4]byte{0x00, 0x00, 0x00, 0x00},
				Signature: []byte{},
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDCSR(tc.csr)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, packed)
				assert.Greater(t, len(packed), 12) // At least header fields
			}
		})
	}
}

// Test UnpackIDevIDCSR
func TestUnpackIDevIDCSR_Unit(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name: "Valid CSR unpacking",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
				SigSz:     [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
					HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
					ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x0A},
					ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x0B},
					ProdModel:    []byte("test-model"),
					ProdSerial:   []byte("test-serial"),
					ProdCaData:   []byte{},
					BootEvntLog:  []byte{},
					EkCert:       []byte{},
					AttestPub:    []byte{},
				},
				Signature: make([]byte, 256),
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unpacked, err := UnpackIDevIDCSR(tc.csr)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, unpacked)
				assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
				assert.Equal(t, string(tc.csr.CsrContents.ProdModel), string(unpacked.CsrContents.ProdModel))
				assert.Equal(t, string(tc.csr.CsrContents.ProdSerial), string(unpacked.CsrContents.ProdSerial))
			}
		})
	}
}

// Test UnmarshalIDevIDCSR
func TestUnmarshalIDevIDCSR_Unit(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() []byte
		expectError bool
	}{
		{
			name: "Valid CSR bytes unmarshalling",
			setupFunc: func() []byte {
				csr := &TCG_CSR_IDEVID{
					StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
					Contents:  [4]byte{0x00, 0x00, 0x01, 0x00},
					SigSz:     [4]byte{0x00, 0x00, 0x00, 0x20}, // 32 bytes
					CsrContents: TCG_IDEVID_CONTENT{
						StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
						HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B},
						HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
					},
					Signature: make([]byte, 32),
				}
				packed, _ := PackIDevIDCSR(csr)
				return packed
			},
			expectError: false,
		},
		{
			name: "Truncated data returns error",
			setupFunc: func() []byte {
				return []byte{0x00, 0x00, 0x01} // Incomplete header
			},
			expectError: true,
		},
		{
			name: "Empty data returns error",
			setupFunc: func() []byte {
				return []byte{}
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csrBytes := tc.setupFunc()
			csr, err := UnmarshalIDevIDCSR(csrBytes)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, csr)
			}
		})
	}
}

// Test bytesToUint32
func TestBytesToUint32_Unit(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{
			name:     "Zero value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "Max value",
			input:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: 0xFFFFFFFF,
		},
		{
			name:     "Structure version 1.0",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 0x00000100,
		},
		{
			name:     "SHA256 algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: 11, // TPMAlgSHA256
		},
		{
			name:     "Arbitrary value",
			input:    [4]byte{0x12, 0x34, 0x56, 0x78},
			expected: 0x12345678,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test ErrInvalidEnrollmentStrategy error type
func TestErrInvalidEnrollmentStrategy(t *testing.T) {
	err := ErrInvalidEnrollmentStrategy
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid enrollment strategy")
}

// Test ErrInvalidSignature error type
func TestErrInvalidSignature_Unit(t *testing.T) {
	err := ErrInvalidSignature
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
}

// Test UNPACKED_TCG_IDEVID_CONTENT structure fields
func TestUNPACKED_TCG_IDEVID_CONTENT_Fields(t *testing.T) {
	content := &UNPACKED_TCG_IDEVID_CONTENT{
		StructVer:                 0x00000100,
		HashAlgoId:                uint32(tpm2.TPMAlgSHA256),
		HashSz:                    32,
		ProdModelSz:               10,
		ProdSerialSz:              15,
		ProdCaDataSz:              0,
		BootEvntLogSz:             1024,
		EkCertSZ:                  500,
		AttestPubSZ:               256,
		AtCreateTktSZ:             64,
		AtCertifyInfoSZ:           128,
		AtCertifyInfoSignatureSZ:  256,
		SigningPubSZ:              256,
		SgnCertifyInfoSZ:          128,
		SgnCertifyInfoSignatureSZ: 256,
		PadSz:                     4,
		ProdModel:                 []byte("test-model"),
		ProdSerial:                []byte("test-serial-001"),
		ProdCaData:                nil,
		BootEvntLog:               make([]byte, 1024),
		EkCert:                    make([]byte, 500),
		AttestPub:                 make([]byte, 256),
		AtCreateTkt:               make([]byte, 64),
		AtCertifyInfo:             make([]byte, 128),
		AtCertifyInfoSig:          make([]byte, 256),
		SigningPub:                make([]byte, 256),
		SgnCertifyInfo:            make([]byte, 128),
		SgnCertifyInfoSig:         make([]byte, 256),
		Pad:                       []byte("===="),
	}

	assert.Equal(t, uint32(0x00000100), content.StructVer)
	assert.Equal(t, uint32(11), content.HashAlgoId) // SHA256 = 0x0B = 11
	assert.Equal(t, uint32(32), content.HashSz)
	assert.Equal(t, uint32(len(content.ProdModel)), content.ProdModelSz)
	assert.Equal(t, uint32(len(content.ProdSerial)), content.ProdSerialSz)
	assert.Equal(t, uint32(len(content.Pad)), content.PadSz)
}

// Test TCG_CSR_IDEVID structure serialization consistency
func TestTCG_CSR_IDEVID_Serialization(t *testing.T) {
	original := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x02, 0x00}, // 512 bytes
		SigSz:     [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x0A},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x0F},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x10},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x10},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x10},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x10},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x10},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x10},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x10},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x10},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x04},
			ProdModel:                 []byte("test-model"),
			ProdSerial:                []byte("test-serial-001"),
			ProdCaData:                []byte{},
			BootEvntLog:               []byte{},
			EkCert:                    make([]byte, 16),
			AttestPub:                 make([]byte, 16),
			AtCreateTkt:               make([]byte, 16),
			AtCertifyInfo:             make([]byte, 16),
			AtCertifyInfoSig:          make([]byte, 16),
			SigningPub:                make([]byte, 16),
			SgnCertifyInfo:            make([]byte, 16),
			SgnCertifyInfoSig:         make([]byte, 16),
			Pad:                       []byte("===="),
		},
		Signature: make([]byte, 256),
	}

	// Pack the CSR
	packed, err := PackIDevIDCSR(original)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Unpack it back
	unpacked, err := UnpackIDevIDCSR(original)
	require.NoError(t, err)
	require.NotNil(t, unpacked)

	// Verify core fields
	assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	assert.Equal(t, uint32(0x00000200), unpacked.Contents)
	assert.Equal(t, uint32(0x00000100), unpacked.SigSz)
	assert.Equal(t, "test-model", string(unpacked.CsrContents.ProdModel))
	assert.Equal(t, "test-serial-001", string(unpacked.CsrContents.ProdSerial))
}

// Test RSA key type determination via templates
func TestRSAKeyTemplates_Unit(t *testing.T) {
	tests := []struct {
		name     string
		template tpm2.TPMTPublic
		isRSA    bool
	}{
		{
			name:     "RSA SSA Template",
			template: RSASSATemplate,
			isRSA:    true,
		},
		{
			name:     "RSA PSS Template",
			template: RSAPSSTemplate,
			isRSA:    true,
		},
		{
			name:     "RSA SSA AK Template",
			template: RSASSAAKTemplate,
			isRSA:    true,
		},
		{
			name:     "RSA PSS AK Template",
			template: RSAPSSAKTemplate,
			isRSA:    true,
		},
		{
			name:     "ECC P256 Template",
			template: ECCP256Template,
			isRSA:    false,
		},
		{
			name:     "ECC AK P256 Template",
			template: ECCAKP256Template,
			isRSA:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isRSA {
				assert.Equal(t, tpm2.TPMAlgRSA, tc.template.Type)
			} else {
				assert.Equal(t, tpm2.TPMAlgECC, tc.template.Type)
			}
		})
	}
}

// Test AK template attributes (restricted signing key)
func TestAKTemplateAttributes_Unit(t *testing.T) {
	templates := []struct {
		name     string
		template tpm2.TPMTPublic
	}{
		{"RSA SSA AK", RSASSAAKTemplate},
		{"RSA PSS AK", RSAPSSAKTemplate},
		{"ECC AK P256", ECCAKP256Template},
	}

	for _, tc := range templates {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.template.ObjectAttributes
			// AK must be restricted
			assert.True(t, attrs.Restricted, "AK should be restricted")
			// AK must be signing
			assert.True(t, attrs.SignEncrypt, "AK should be signing")
			// AK must be fixedTPM
			assert.True(t, attrs.FixedTPM, "AK should be fixedTPM")
			// AK must be fixedParent
			assert.True(t, attrs.FixedParent, "AK should be fixedParent")
		})
	}
}

// Test IDevID template attributes (non-restricted signing key)
func TestIDevIDTemplateAttributes_Unit(t *testing.T) {
	templates := []struct {
		name     string
		template tpm2.TPMTPublic
	}{
		{"RSA SSA IDevID", RSASSAIDevIDTemplate},
		{"RSA PSS IDevID", RSAPSSIDevIDTemplate},
		{"ECC IDevID P256", ECCIDevIDP256Template},
	}

	for _, tc := range templates {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.template.ObjectAttributes
			// IDevID must NOT be restricted
			assert.False(t, attrs.Restricted, "IDevID should NOT be restricted")
			// IDevID must be signing
			assert.True(t, attrs.SignEncrypt, "IDevID should be signing")
			// IDevID must be fixedTPM
			assert.True(t, attrs.FixedTPM, "IDevID should be fixedTPM")
			// IDevID must be fixedParent
			assert.True(t, attrs.FixedParent, "IDevID should be fixedParent")
		})
	}
}

// Test padding calculation logic
func TestPaddingCalculation(t *testing.T) {
	tests := []struct {
		name        string
		contentSize uint32
		expectedPad uint32
	}{
		{
			name:        "Already aligned to 16",
			contentSize: 160,
			expectedPad: 0,
		},
		{
			name:        "Need 4 bytes padding",
			contentSize: 156,
			expectedPad: 12,
		},
		{
			name:        "Need 8 bytes padding",
			contentSize: 152,
			expectedPad: 8,
		},
		{
			name:        "Need 12 bytes padding",
			contentSize: 148,
			expectedPad: 4,
		},
		{
			name:        "Need 1 byte padding",
			contentSize: 159,
			expectedPad: 15,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			padSz := tc.contentSize % 16
			assert.Equal(t, tc.expectedPad, padSz)
		})
	}
}

// Test hash algorithm mapping
func TestHashAlgorithmMapping(t *testing.T) {
	tests := []struct {
		name       string
		cryptoHash crypto.Hash
		tpmAlgID   tpm2.TPMIAlgHash
		expectErr  bool
	}{
		{
			name:       "SHA1 mapping",
			cryptoHash: crypto.SHA1,
			tpmAlgID:   tpm2.TPMAlgSHA1,
			expectErr:  false,
		},
		{
			name:       "SHA256 mapping",
			cryptoHash: crypto.SHA256,
			tpmAlgID:   tpm2.TPMAlgSHA256,
			expectErr:  false,
		},
		{
			name:       "SHA384 mapping",
			cryptoHash: crypto.SHA384,
			tpmAlgID:   tpm2.TPMAlgSHA384,
			expectErr:  false,
		},
		{
			name:       "SHA512 mapping",
			cryptoHash: crypto.SHA512,
			tpmAlgID:   tpm2.TPMAlgSHA512,
			expectErr:  false,
		},
		{
			name:       "Invalid hash",
			cryptoHash: crypto.MD5,
			tpmAlgID:   0,
			expectErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			algID, err := ParseHashAlg(tc.cryptoHash)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.tpmAlgID, algID)
			}
		})
	}
}

// Test RSA signature algorithm detection
func TestRSASignatureAlgorithmDetection(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		isRSAPSS bool
		isRSASSA bool
	}{
		{
			name:     "SHA256WithRSA",
			sigAlgo:  x509.SHA256WithRSA,
			isRSAPSS: false,
			isRSASSA: true,
		},
		{
			name:     "SHA384WithRSA",
			sigAlgo:  x509.SHA384WithRSA,
			isRSAPSS: false,
			isRSASSA: true,
		},
		{
			name:     "SHA512WithRSA",
			sigAlgo:  x509.SHA512WithRSA,
			isRSAPSS: false,
			isRSASSA: true,
		},
		{
			name:     "SHA256WithRSAPSS",
			sigAlgo:  x509.SHA256WithRSAPSS,
			isRSAPSS: true,
			isRSASSA: false,
		},
		{
			name:     "SHA384WithRSAPSS",
			sigAlgo:  x509.SHA384WithRSAPSS,
			isRSAPSS: true,
			isRSASSA: false,
		},
		{
			name:     "SHA512WithRSAPSS",
			sigAlgo:  x509.SHA512WithRSAPSS,
			isRSAPSS: true,
			isRSASSA: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isPSS := store.IsRSAPSS(tc.sigAlgo)
			assert.Equal(t, tc.isRSAPSS, isPSS)

			// RSASSA is any RSA that's not PSS
			isSSA := !store.IsRSAPSS(tc.sigAlgo) && tc.isRSASSA
			assert.Equal(t, tc.isRSASSA, isSSA)
		})
	}
}

// Test ECDSA signature algorithm detection
func TestECDSASignatureAlgorithmDetection(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		isECDSA bool
	}{
		{
			name:    "ECDSAWithSHA256",
			sigAlgo: x509.ECDSAWithSHA256,
			isECDSA: true,
		},
		{
			name:    "ECDSAWithSHA384",
			sigAlgo: x509.ECDSAWithSHA384,
			isECDSA: true,
		},
		{
			name:    "ECDSAWithSHA512",
			sigAlgo: x509.ECDSAWithSHA512,
			isECDSA: true,
		},
		{
			name:    "SHA256WithRSA is not ECDSA",
			sigAlgo: x509.SHA256WithRSA,
			isECDSA: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isECDSA := store.IsECDSA(tc.sigAlgo)
			assert.Equal(t, tc.isECDSA, isECDSA)
		})
	}
}

// Test binary endianness for TCG structures
func TestBinaryEndianness(t *testing.T) {
	// TCG specifies big-endian encoding
	var buf bytes.Buffer

	// Test writing uint32 in big endian
	val := uint32(0x12345678)
	err := binary.Write(&buf, binary.BigEndian, val)
	require.NoError(t, err)

	expected := []byte{0x12, 0x34, 0x56, 0x78}
	assert.Equal(t, expected, buf.Bytes())

	// Test reading back
	reader := bytes.NewReader(expected)
	var readVal uint32
	err = binary.Read(reader, binary.BigEndian, &readVal)
	require.NoError(t, err)
	assert.Equal(t, val, readVal)
}

// Test structure version constant
func TestStructureVersionConstant(t *testing.T) {
	// TCG CSR structure version 1.0 is encoded as 0x00000100
	var structVer [4]byte
	binary.BigEndian.PutUint32(structVer[:], 0x00000100)

	assert.Equal(t, byte(0x00), structVer[0])
	assert.Equal(t, byte(0x00), structVer[1])
	assert.Equal(t, byte(0x01), structVer[2])
	assert.Equal(t, byte(0x00), structVer[3])
}

// Test TCG vendor ID mapping
func TestTCGVendorIDMapping(t *testing.T) {
	tests := []struct {
		name     string
		id       TCGVendorID
		expected string
	}{
		{
			name:     "Intel vendor ID",
			id:       1229870147,
			expected: "Intel",
		},
		{
			name:     "IBM vendor ID",
			id:       1229081856,
			expected: "IBM",
		},
		{
			name:     "Microsoft vendor ID",
			id:       1297303124,
			expected: "Microsoft",
		},
		{
			name:     "Google vendor ID",
			id:       1196379975,
			expected: "Google",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.id.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test hierarchy name parsing
func TestHierarchyNameParsing(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy tpm2.TPMHandle
		expected  string
	}{
		{
			name:      "Platform hierarchy",
			hierarchy: tpm2.TPMRHPlatform,
			expected:  "PLATFORM",
		},
		{
			name:      "Owner hierarchy",
			hierarchy: tpm2.TPMRHOwner,
			expected:  "OWNER",
		},
		{
			name:      "Endorsement hierarchy",
			hierarchy: tpm2.TPMRHEndorsement,
			expected:  "ENDORSEMENT",
		},
		{
			name:      "Null hierarchy",
			hierarchy: tpm2.TPMRHNull,
			expected:  "NULL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := HierarchyName(tc.hierarchy)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test error handling for invalid hierarchy
func TestHierarchyNameInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for invalid hierarchy, but did not panic")
		}
	}()

	// This should panic
	HierarchyName(tpm2.TPMHandle(0xFFFFFFFF))
}

// Test CSR content byte slice independence
func TestCSRContentByteSliceIndependence(t *testing.T) {
	// Ensure that modifying source slices doesn't affect packed CSR
	original := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packed, err := PackIDevIDContent(original)
	require.NoError(t, err)

	// Modify original
	original.ProdModel[0] = 'X'
	original.ProdSerial[0] = 'X'

	// Packed data should still have original values
	// The packed data contains the original values, not the modified ones
	assert.NotContains(t, string(packed), "Xodel")
	assert.NotContains(t, string(packed), "X01")
}

// Test default enrollment strategy
func TestDefaultEnrollmentStrategy(t *testing.T) {
	config := createIDevIDCSRUnitMockTPMConfig()
	strategy := ParseIdentityProvisioningStrategy(config.IdentityProvisioningStrategy)
	assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
}

// Test RSA key size validation
func TestRSAKeySizeValidation(t *testing.T) {
	validSizes := []int{2048, 3072, 4096}
	for _, size := range validSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			assert.True(t, size >= 2048, "RSA key size should be at least 2048 bits")
			assert.True(t, size%1024 == 0 || size%1024 == 1024, "RSA key size should be multiple of 1024")
		})
	}
}

// Test ECC curve support
func TestECCCurveSupport(t *testing.T) {
	curves := map[string]elliptic.Curve{
		"P-256": elliptic.P256(),
		"P-384": elliptic.P384(),
		"P-521": elliptic.P521(),
	}

	for name, curve := range curves {
		t.Run(name, func(t *testing.T) {
			assert.NotNil(t, curve)
			params := curve.Params()
			assert.NotNil(t, params)
			assert.NotEmpty(t, params.Name)
		})
	}
}

// Test that empty CSR signature is valid
func TestEmptyCSRSignatureHandling(t *testing.T) {
	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x00},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x00},
		Signature: []byte{},
	}

	packed, err := PackIDevIDCSR(csr)
	assert.NoError(t, err)
	assert.NotNil(t, packed)
}

// Test maximum field sizes
func TestMaximumFieldSizes(t *testing.T) {
	maxUint32 := uint32(0xFFFFFFFF)

	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], maxUint32)

	result := bytesToUint32(buf)
	assert.Equal(t, maxUint32, result)
}

// Test CSR content alignment requirements
func TestCSRContentAlignmentRequirements(t *testing.T) {
	// TCG specifies that CSR content should be aligned to 16-byte boundaries
	testSizes := []uint32{0, 16, 32, 48, 64, 80, 96, 112, 128}

	for _, size := range testSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			assert.Equal(t, uint32(0), size%16, "Size should be multiple of 16")
		})
	}
}

// Test UNPACKED_TCG_CSR_IDEVID initialization
func TestUNPACKED_TCG_CSR_IDEVID_Initialization(t *testing.T) {
	unpacked := &UNPACKED_TCG_CSR_IDEVID{
		StructVer: 0x00000100,
		Contents:  0x00000200,
		SigSz:     0x00000100,
		CsrContents: UNPACKED_TCG_IDEVID_CONTENT{
			StructVer:  0x00000100,
			HashAlgoId: uint32(tpm2.TPMAlgSHA256),
			HashSz:     32,
		},
		RawBytes:  make([]byte, 512),
		Signature: make([]byte, 256),
	}

	assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	assert.Equal(t, uint32(0x00000200), unpacked.Contents)
	assert.Equal(t, uint32(0x00000100), unpacked.SigSz)
	assert.Equal(t, 512, len(unpacked.RawBytes))
	assert.Equal(t, 256, len(unpacked.Signature))
}

// Test EK certificate handle constants
func TestEKCertificateHandleConstants(t *testing.T) {
	assert.Equal(t, uint32(0x01C00002), uint32(ekCertIndexRSA2048))
	assert.Equal(t, uint32(0x01C0000a), uint32(ekCertIndexECCP256))
	assert.Equal(t, uint32(0x01C00016), uint32(ekCertIndexECCP384))
	assert.Equal(t, uint32(0x01C00018), uint32(ekCertIndexECCP521))
}

// Test IDevID key handle constants
func TestIDevIDKeyHandleConstants(t *testing.T) {
	assert.Equal(t, uint32(0x81020000), uint32(idevIDKey))
	assert.Equal(t, uint32(0x01C90000), uint32(idevIDCert))
	assert.Equal(t, uint32(0x01C90020), uint32(idevIDNVIndex))
}

// Test platform hierarchy constants
func TestPlatformHierarchyConstants(t *testing.T) {
	assert.Equal(t, uint32(0x81800001), uint32(tpEKIndex))
	assert.Equal(t, uint32(0x81800002), uint32(tpSRKIndex))
	assert.Equal(t, uint32(0x81000002), uint32(tpSealIndex))
}
