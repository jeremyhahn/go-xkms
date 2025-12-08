package tpm2

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test additional error paths and edge cases for pure functions

func TestParsePCRBankAlgIDAllCases(t *testing.T) {
	tests := []struct {
		name        string
		pcrBank     string
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"sha1", "sha1", tpm2.TPMAlgSHA1, false},
		{"sha256", "sha256", tpm2.TPMAlgSHA256, false},
		{"sha384", "sha384", tpm2.TPMAlgSHA384, false},
		{"sha512", "sha512", tpm2.TPMAlgSHA512, false},
		{"SHA1 uppercase", "SHA1", tpm2.TPMAlgSHA1, false},
		{"SHA256 uppercase", "SHA256", tpm2.TPMAlgSHA256, false},
		{"SHA384 uppercase", "SHA384", tpm2.TPMAlgSHA384, false},
		{"SHA512 uppercase", "SHA512", tpm2.TPMAlgSHA512, false},
		{"Sha1 mixed case", "Sha1", tpm2.TPMAlgSHA1, false},
		{"sHa256 weird case", "sHa256", tpm2.TPMAlgSHA256, false},
		{"invalid algorithm", "md5", 0, true},
		{"empty string", "", 0, true},
		{"whitespace", " ", 0, true},
		{"sha3-256 not supported", "sha3-256", 0, true},
		{"numeric", "256", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParsePCRBankAlgID(tc.pcrBank)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidPCRBankType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParsePCRBankCryptoHashAllCases(t *testing.T) {
	tests := []struct {
		name        string
		pcrBank     string
		expected    crypto.Hash
		expectError bool
	}{
		{"sha1", "sha1", crypto.SHA1, false},
		{"sha256", "sha256", crypto.SHA256, false},
		{"sha384", "sha384", crypto.SHA3_384, false},
		{"sha512", "sha512", crypto.SHA512, false},
		{"SHA1 uppercase", "SHA1", crypto.SHA1, false},
		{"SHA256 uppercase", "SHA256", crypto.SHA256, false},
		{"SHA384 uppercase", "SHA384", crypto.SHA3_384, false},
		{"SHA512 uppercase", "SHA512", crypto.SHA512, false},
		{"invalid", "invalid", 0, true},
		{"empty", "", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParsePCRBankCryptoHash(tc.pcrBank)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidPCRBankType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseCryptoHashAlgIDAllCases(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"SHA3-256", crypto.SHA3_256, tpm2.TPMAlgSHA3256, false},
		{"SHA3-384", crypto.SHA3_384, tpm2.TPMAlgSHA3384, false},
		{"SHA3-512", crypto.SHA3_512, tpm2.TPMAlgSHA3512, false},
		{"MD5 unsupported", crypto.MD5, 0, true},
		{"SHA224 unsupported", crypto.SHA224, 0, true},
		{"SHA512_224 unsupported", crypto.SHA512_224, 0, true},
		{"SHA512_256 unsupported", crypto.SHA512_256, 0, true},
		{"BLAKE2s_256 unsupported", crypto.BLAKE2s_256, 0, true},
		{"BLAKE2b_256 unsupported", crypto.BLAKE2b_256, 0, true},
		{"BLAKE2b_384 unsupported", crypto.BLAKE2b_384, 0, true},
		{"BLAKE2b_512 unsupported", crypto.BLAKE2b_512, 0, true},
		{"zero hash", crypto.Hash(0), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCryptoHashAlgID(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseHashAlgFromStringAllCases(t *testing.T) {
	tests := []struct {
		name        string
		hash        string
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA-1 uppercase", "SHA-1", tpm2.TPMAlgSHA1, false},
		{"SHA-256 uppercase", "SHA-256", tpm2.TPMAlgSHA256, false},
		{"SHA-384 uppercase", "SHA-384", tpm2.TPMAlgSHA384, false},
		{"SHA-512 uppercase", "SHA-512", tpm2.TPMAlgSHA512, false},
		{"sha-1 lowercase", "sha-1", tpm2.TPMAlgSHA1, false},
		{"sha-256 lowercase", "sha-256", tpm2.TPMAlgSHA256, false},
		{"sha-384 lowercase", "sha-384", tpm2.TPMAlgSHA384, false},
		{"sha-512 lowercase", "sha-512", tpm2.TPMAlgSHA512, false},
		{"ShA-256 mixed", "ShA-256", tpm2.TPMAlgSHA256, false},
		{"empty string", "", 0, true},
		{"MD5 unsupported", "MD5", 0, true},
		{"SHA3-256 unsupported string", "SHA3-256", 0, true},
		{"no dash", "SHA256", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHashAlgFromString(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseHashAlgAllCases(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"MD5", crypto.MD5, 0, true},
		{"SHA224", crypto.SHA224, 0, true},
		{"SHA3_256", crypto.SHA3_256, 0, true},
		{"SHA3_384", crypto.SHA3_384, 0, true},
		{"SHA3_512", crypto.SHA3_512, 0, true},
		{"BLAKE2b_256", crypto.BLAKE2b_256, 0, true},
		{"zero hash", crypto.Hash(0), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHashAlg(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseHashSizeAllCases(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    uint32
		expectError bool
	}{
		{"SHA1 is 20", crypto.SHA1, 20, false},
		{"SHA256 is 32", crypto.SHA256, 32, false},
		{"SHA384 is 48", crypto.SHA384, 48, false},
		{"SHA512 is 64", crypto.SHA512, 64, false},
		{"MD5 unsupported", crypto.MD5, 0, true},
		{"SHA224 unsupported", crypto.SHA224, 0, true},
		{"SHA3_256 unsupported", crypto.SHA3_256, 0, true},
		{"zero hash", crypto.Hash(0), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHashSize(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestUnpackIDevIDContentErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "too short for header",
			data:        make([]byte, 10), // Header is 64 bytes
			expectError: true,
		},
		{
			name:        "exactly header size with all zero sizes",
			data:        make([]byte, 64),
			expectError: true, // EOF when trying to read past header
		},
		{
			name: "header claims more data than available",
			data: func() []byte {
				header := make([]byte, 64)
				// Set ProdModelSz to a large value
				header[12] = 0x00
				header[13] = 0x00
				header[14] = 0x00
				header[15] = 0xFF // 255 bytes claimed but not available
				return header
			}(),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.data)
			_, err := UnpackIDevIDContent(reader)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPackIDevIDCSRNilContentFields(t *testing.T) {
	// Test with valid structure but nil byte slices
	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x01},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x00},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdModel:                 nil,
			ProdSerial:                nil,
			ProdCaData:                nil,
			BootEvntLog:               nil,
			EkCert:                    nil,
			AttestPub:                 nil,
			AtCreateTkt:               nil,
			AtCertifyInfo:             nil,
			AtCertifyInfoSig:          nil,
			SigningPub:                nil,
			SgnCertifyInfo:            nil,
			SgnCertifyInfoSig:         nil,
			Pad:                       nil,
		},
		Signature: nil,
	}

	packed, err := PackIDevIDCSR(csr)
	assert.NoError(t, err)
	assert.NotNil(t, packed)
	assert.Greater(t, len(packed), 0)
}

func TestPackIDevIDContentLargeData(t *testing.T) {
	// Test with large byte slices to ensure no buffer overflows
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x10, 0x00}, // 4096 bytes
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x10, 0x00},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x10, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x10, 0x00},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x10, 0x00},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x10, 0x00},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x10, 0x00},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x10, 0x00},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x10, 0x00},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x10, 0x00},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x10, 0x00},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x10, 0x00},
		PadSz:                     [4]byte{0x00, 0x00, 0x10, 0x00},
		ProdModel:                 make([]byte, 4096),
		ProdSerial:                make([]byte, 4096),
		ProdCaData:                make([]byte, 4096),
		BootEvntLog:               make([]byte, 4096),
		EkCert:                    make([]byte, 4096),
		AttestPub:                 make([]byte, 4096),
		AtCreateTkt:               make([]byte, 4096),
		AtCertifyInfo:             make([]byte, 4096),
		AtCertifyInfoSig:          make([]byte, 4096),
		SigningPub:                make([]byte, 4096),
		SgnCertifyInfo:            make([]byte, 4096),
		SgnCertifyInfoSig:         make([]byte, 4096),
		Pad:                       make([]byte, 4096),
	}

	packed, err := PackIDevIDContent(content)
	assert.NoError(t, err)
	assert.NotNil(t, packed)

	// Header is 64 bytes + 13 * 4096 bytes of data
	expectedSize := 64 + 13*4096
	assert.Equal(t, expectedSize, len(packed))
}

func TestUnmarshalIDevIDCSREdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "nil data",
			data:        nil,
			expectError: true,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "too small for header",
			data:        make([]byte, 75), // Need at least 76 bytes (12 + 64)
			expectError: true,
		},
		{
			name: "valid minimal structure",
			data: func() []byte {
				// 12 bytes for outer header + 64 bytes for content header
				header := make([]byte, 76)
				// StructVer
				header[0], header[1], header[2], header[3] = 0x00, 0x00, 0x01, 0x00
				// Contents
				header[4], header[5], header[6], header[7] = 0x00, 0x00, 0x00, 0x01
				// SigSz = 0
				header[8], header[9], header[10], header[11] = 0x00, 0x00, 0x00, 0x00
				// Content header starts at 12
				// StructVer
				header[12], header[13], header[14], header[15] = 0x00, 0x00, 0x01, 0x00
				// HashAlgoId = SHA256
				header[16], header[17], header[18], header[19] = 0x00, 0x00, 0x00, 0x0B
				// HashSz = 32
				header[20], header[21], header[22], header[23] = 0x00, 0x00, 0x00, 0x20
				// All size fields are 0
				return header
			}(),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalIDevIDCSR(tc.data)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTCGVendorIDStringComprehensive(t *testing.T) {
	tests := []struct {
		name   string
		id     TCGVendorID
		expect string
	}{
		{"AMD", TCGVendorID(1095582720), "AMD"},
		{"Atmel", TCGVendorID(1096043852), "Atmel"},
		{"Broadcom", TCGVendorID(1112687437), "Broadcom"},
		{"IBM", TCGVendorID(1229081856), "IBM"},
		{"HPE", TCGVendorID(1213220096), "HPE"},
		{"Microsoft", TCGVendorID(1297303124), "Microsoft"},
		{"Infineon", TCGVendorID(1229346816), "Infineon"},
		{"Intel", TCGVendorID(1229870147), "Intel"},
		{"Lenovo", TCGVendorID(1279610368), "Lenovo"},
		{"National Semiconductor", TCGVendorID(1314082080), "National Semiconductor"},
		{"Nationz", TCGVendorID(1314150912), "Nationz"},
		{"Nuvoton Technology", TCGVendorID(1314145024), "Nuvoton Technology"},
		{"Qualcomm", TCGVendorID(1363365709), "Qualcomm"},
		{"SMSC", TCGVendorID(1397576515), "SMSC"},
		{"ST Microelectronics", TCGVendorID(1398033696), "ST Microelectronics"},
		{"Samsung", TCGVendorID(1397576526), "Samsung"},
		{"Sinosun", TCGVendorID(1397641984), "Sinosun"},
		{"Texas Instruments", TCGVendorID(1415073280), "Texas Instruments"},
		{"Winbond", TCGVendorID(1464156928), "Winbond"},
		{"Fuzhou Rockchip", TCGVendorID(1380926275), "Fuzhou Rockchip"},
		{"Google", TCGVendorID(1196379975), "Google"},
		{"Unknown vendor", TCGVendorID(0), ""},
		{"Invalid vendor", TCGVendorID(123456789), ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.id.String()
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestEncodeDecodeSymmetry(t *testing.T) {
	// Test that Encode and Decode are symmetric operations
	testCases := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x00, 0xFF},
		{0xDE, 0xAD, 0xBE, 0xEF},
		make([]byte, 32),  // SHA-256 digest size
		make([]byte, 64),  // SHA-512 digest size
		make([]byte, 256), // RSA 2048 signature size
	}

	for i, data := range testCases {
		t.Run("case_"+string(rune('A'+i)), func(t *testing.T) {
			encoded := Encode(data)
			decoded, err := Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, data, decoded)
		})
	}
}

func TestQuoteStructEquality(t *testing.T) {
	q1 := Quote{
		Quoted:    []byte("quoted"),
		Signature: []byte("signature"),
		Nonce:     []byte("nonce"),
		PCRs:      []byte("pcrs"),
		EventLog:  []byte("eventlog"),
	}

	q2 := Quote{
		Quoted:    []byte("quoted"),
		Signature: []byte("signature"),
		Nonce:     []byte("nonce"),
		PCRs:      []byte("pcrs"),
		EventLog:  []byte("eventlog"),
	}

	assert.Equal(t, q1, q2)
}

func TestPCRBankStructEquality(t *testing.T) {
	b1 := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte{0x01}},
			{ID: 1, Value: []byte{0x02}},
		},
	}

	b2 := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte{0x01}},
			{ID: 1, Value: []byte{0x02}},
		},
	}

	assert.Equal(t, b1, b2)
}

func TestEnrollmentStrategyStringConversion(t *testing.T) {
	iakStrategy := EnrollmentStrategyIAK
	assert.Equal(t, "IAK", string(iakStrategy))

	singlePassStrategy := EnrollmentStrategyIAK_IDEVID_SINGLE_PASS
	assert.Equal(t, "IAK_IDEVID_SINGLE_PASS", string(singlePassStrategy))
}

func TestBytesToUint32EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{"all zeros", [4]byte{0x00, 0x00, 0x00, 0x00}, 0},
		{"all ones", [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFF},
		{"max value", [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, 4294967295},
		{"big endian 1", [4]byte{0x00, 0x00, 0x00, 0x01}, 1},
		{"big endian 256", [4]byte{0x00, 0x00, 0x01, 0x00}, 256},
		{"big endian 65536", [4]byte{0x00, 0x01, 0x00, 0x00}, 65536},
		{"big endian 16777216", [4]byte{0x01, 0x00, 0x00, 0x00}, 16777216},
		{"mixed bytes", [4]byte{0x12, 0x34, 0x56, 0x78}, 0x12345678},
		{"version number", [4]byte{0x00, 0x00, 0x01, 0x00}, 0x00000100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUnpackIDevIDCSRSignatureHandling(t *testing.T) {
	// Test that signature bytes are correctly extracted
	t.Run("CSR with signature", func(t *testing.T) {
		// Create a minimal CSR with signature
		header := make([]byte, 76)
		signature := []byte{0xDE, 0xAD, 0xBE, 0xEF}

		// StructVer
		header[0], header[1], header[2], header[3] = 0x00, 0x00, 0x01, 0x00
		// Contents
		header[4], header[5], header[6], header[7] = 0x00, 0x00, 0x00, 0x01
		// SigSz = 4
		header[8], header[9], header[10], header[11] = 0x00, 0x00, 0x00, 0x04
		// Content header
		header[12], header[13], header[14], header[15] = 0x00, 0x00, 0x01, 0x00

		csrBytes := append(header, signature...)

		csr, err := UnmarshalIDevIDCSR(csrBytes)
		assert.NoError(t, err)
		assert.Equal(t, signature, csr.Signature)
	})
}

func TestParseHierarchyEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		hierarchyType string
		expected      tpm2.TPMIRHHierarchy
		expectError   bool
	}{
		{"ENDORSEMENT", "ENDORSEMENT", tpm2.TPMRHEndorsement, false},
		{"OWNER", "OWNER", tpm2.TPMRHOwner, false},
		{"PLATFORM", "PLATFORM", tpm2.TPMRHPlatform, false},
		{"lowercase endorsement fails", "endorsement", 0, true},
		{"lowercase owner fails", "owner", 0, true},
		{"lowercase platform fails", "platform", 0, true},
		{"NULL not supported", "NULL", 0, true},
		{"empty string", "", 0, true},
		{"invalid hierarchy", "INVALID", 0, true},
		{"mixed case", "Endorsement", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHierarchy(tc.hierarchyType)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHierarchyType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		expected EnrollmentStrategy
	}{
		{"IAK", "IAK", EnrollmentStrategyIAK},
		{"IAK_IDEVID_SINGLE_PASS", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"empty defaults to single pass", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"unknown defaults to single pass", "UNKNOWN", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"lowercase iak defaults to single pass", "iak", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"mixed case defaults to single pass", "Iak_IDevID", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.strategy)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPCRBankAlgoStringCoverage(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRBankAlgo
		expected string
	}{
		{"sha1", PCRBankAlgo("sha1"), "sha1"},
		{"sha256", PCRBankAlgo("sha256"), "sha256"},
		{"sha384", PCRBankAlgo("sha384"), "sha384"},
		{"sha512", PCRBankAlgo("sha512"), "sha512"},
		{"empty", PCRBankAlgo(""), ""},
		{"custom", PCRBankAlgo("custom"), "custom"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.algo.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDefaultConfigValues(t *testing.T) {
	t.Run("verify all default config fields", func(t *testing.T) {
		assert.Equal(t, "/dev/tpmrm0", DefaultConfig.Device)
		assert.True(t, DefaultConfig.UseSimulator)
		assert.False(t, DefaultConfig.UseEntropy)
		assert.False(t, DefaultConfig.EncryptSession)
		assert.Equal(t, "SHA-256", DefaultConfig.Hash)
		assert.Equal(t, uint(16), DefaultConfig.PlatformPCR)
		assert.Equal(t, PCRBankSHA256, DefaultConfig.PlatformPCRBank)
	})

	t.Run("verify EK config defaults", func(t *testing.T) {
		assert.NotNil(t, DefaultConfig.EK)
		assert.Equal(t, uint32(0x01C00002), DefaultConfig.EK.CertHandle)
		assert.Equal(t, uint32(0x81010001), DefaultConfig.EK.Handle)
		assert.True(t, DefaultConfig.EK.Debug)
	})

	t.Run("verify SSRK config defaults", func(t *testing.T) {
		assert.NotNil(t, DefaultConfig.SSRK)
		assert.Equal(t, uint32(0x81000001), DefaultConfig.SSRK.Handle)
		assert.True(t, DefaultConfig.SSRK.PlatformPolicy)
	})

	t.Run("verify KeyStore config defaults", func(t *testing.T) {
		assert.NotNil(t, DefaultConfig.KeyStore)
		assert.Equal(t, "platform", DefaultConfig.KeyStore.SRKAuth)
		assert.Equal(t, uint32(0x81000002), DefaultConfig.KeyStore.SRKHandle)
		assert.True(t, DefaultConfig.KeyStore.PlatformPolicy)
	})
}
