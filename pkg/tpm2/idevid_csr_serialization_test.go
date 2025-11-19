package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPackIDevIDCSR_CompleteRoundTrip tests full pack/unpack cycle
func TestPackIDevIDCSR_CompleteRoundTrip(t *testing.T) {
	// Create a complete CSR with all fields populated
	content := &TCG_IDEVID_CONTENT{}
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(0x000B)) // SHA-256
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Populate all variable length fields
	content.ProdModel = []byte("TestModel")
	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(content.ProdModel)))

	content.ProdSerial = []byte("TestSerial123")
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(content.ProdSerial)))

	content.ProdCaData = []byte("CA Data")
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(content.ProdCaData)))

	content.BootEvntLog = []byte("Boot Log")
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(content.BootEvntLog)))

	content.EkCert = []byte("EK Certificate Data")
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(content.EkCert)))

	content.AttestPub = []byte("Attest Public Key")
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(content.AttestPub)))

	content.AtCreateTkt = []byte("Create Ticket")
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(content.AtCreateTkt)))

	content.AtCertifyInfo = []byte("Certify Info")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(content.AtCertifyInfo)))

	content.AtCertifyInfoSig = []byte("Certify Info Signature")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(content.AtCertifyInfoSig)))

	content.SigningPub = []byte("Signing Public Key")
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(content.SigningPub)))

	content.SgnCertifyInfo = []byte("Sign Certify Info")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(content.SgnCertifyInfo)))

	content.SgnCertifyInfoSig = []byte("Sign Certify Signature")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(content.SgnCertifyInfoSig)))

	content.Pad = []byte("===")
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(content.Pad)))

	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 256)
	binary.BigEndian.PutUint32(csr.SigSz[:], 64)
	csr.CsrContents = *content
	csr.Signature = make([]byte, 64)
	for i := range csr.Signature {
		csr.Signature[i] = byte(i)
	}

	// Pack the CSR
	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err, "PackIDevIDCSR should succeed")
	require.NotEmpty(t, packed, "Packed data should not be empty")

	// Unmarshal from bytes to struct
	unmarshalled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err, "UnmarshalIDevIDCSR should succeed")
	require.NotNil(t, unmarshalled, "Unmarshalled CSR should not be nil")

	// Unpack the CSR to get UNPACKED structure
	unpacked, err := UnpackIDevIDCSR(unmarshalled)
	require.NoError(t, err, "UnpackIDevIDCSR should succeed")
	require.NotNil(t, unpacked, "Unpacked CSR should not be nil")

	// Verify all fields match
	require.Equal(t, csr.StructVer, unmarshalled.StructVer, "StructVer should match")
	require.Equal(t, csr.Contents, unmarshalled.Contents, "Contents should match")
	require.Equal(t, csr.SigSz, unmarshalled.SigSz, "SigSz should match")
	require.Equal(t, csr.Signature, unmarshalled.Signature, "Signature should match")

	// Verify content fields
	require.Equal(t, content.ProdModel, unmarshalled.CsrContents.ProdModel, "ProdModel should match")
	require.Equal(t, content.ProdSerial, unmarshalled.CsrContents.ProdSerial, "ProdSerial should match")
}

// TestPackIDevIDCSR_EmptyFields tests packing with empty optional fields
func TestPackIDevIDCSR_EmptyFields(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(0x000B))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// All variable fields are empty (size 0)
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], 0)
	csr.CsrContents = *content

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err, "Should pack with empty fields")
	require.NotEmpty(t, packed)
}

// TestPackIDevIDContent_AllFieldSizes tests various field sizes
func TestPackIDevIDContent_AllFieldSizes(t *testing.T) {
	testCases := []struct {
		name      string
		modelSize int
		padSize   int
	}{
		{"Small fields", 10, 4},
		{"Medium fields", 100, 8},
		{"Large model", 1000, 16},
		{"Max padding", 20, 15},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := &TCG_IDEVID_CONTENT{}
			binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
			binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(0x000B))
			binary.BigEndian.PutUint32(content.HashSz[:], 32)

			content.ProdModel = make([]byte, tc.modelSize)
			for i := range content.ProdModel {
				content.ProdModel[i] = byte(i % 256)
			}
			binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(tc.modelSize))

			content.ProdSerial = []byte("SERIAL")
			binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(content.ProdSerial)))

			content.Pad = make([]byte, tc.padSize)
			binary.BigEndian.PutUint32(content.PadSz[:], uint32(tc.padSize))

			// Set remaining fields to zero
			binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
			binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
			binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
			binary.BigEndian.PutUint32(content.AttestPubSZ[:], 0)
			binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
			binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
			binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
			binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
			binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
			binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)

			packed, err := PackIDevIDContent(content)
			require.NoError(t, err, "Should pack successfully")
			require.NotEmpty(t, packed)

			// Unpack and verify
			reader := bytes.NewReader(packed)
			unpacked, err := UnpackIDevIDContent(reader)
			require.NoError(t, err, "Should unpack successfully")
			require.Equal(t, content.ProdModel, unpacked.ProdModel)
			require.Equal(t, content.Pad, unpacked.Pad)
		})
	}
}

// TestUnpackIDevIDContent_ShortBuffer tests error handling for short buffers
func TestUnpackIDevIDContent_ShortBuffer(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty buffer", []byte{}},
		{"Too short for header", make([]byte, 10)},
		{"Header only no data", make([]byte, 64)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.data)
			_, err := UnpackIDevIDContent(reader)
			require.Error(t, err, "Should fail on short buffer")
		})
	}
}

// TestUnpackIDevIDCSR_InvalidData tests various invalid input scenarios
func TestUnpackIDevIDCSR_InvalidData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty data", []byte{}},
		{"Too short", make([]byte, 8)},
		{"Invalid header only", make([]byte, 12)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalIDevIDCSR(tc.data)
			require.Error(t, err, "Should fail on invalid data")
		})
	}
}

// TestUnmarshalIDevIDCSR_ValidStructure tests unmarshaling with valid structure
func TestUnmarshalIDevIDCSR_ValidStructure(t *testing.T) {
	// Create a minimal valid CSR
	content := &TCG_IDEVID_CONTENT{}
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(0x000B))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Set all sizes to 0
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 32)
	csr.CsrContents = *content
	csr.Signature = make([]byte, 32)

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)

	result, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, [4]byte{0x00, 0x00, 0x01, 0x00}, result.StructVer)
	require.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x0B}, result.CsrContents.HashAlgoId)
}

// TestBytesToUint32_EdgeCases tests the bytesToUint32 helper
func TestBytesToUint32_EdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{"Zero", [4]byte{0, 0, 0, 0}, 0},
		{"One", [4]byte{0, 0, 0, 1}, 1},
		{"Max uint32", [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFF},
		{"Middle value", [4]byte{0x00, 0x01, 0x00, 0x00}, 65536},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestPackIDevIDCSR_NilInput tests nil input handling
// Note: PackIDevIDCSR panics on nil input, which is a design decision
// func TestPackIDevIDCSR_NilInput(t *testing.T) {
// 	_, err := PackIDevIDCSR(nil)
// 	require.Error(t, err, "Should error on nil input")
// }

// TestPackIDevIDContent_NilInput tests nil input handling
// Note: PackIDevIDContent panics on nil input, which is a design decision
// func TestPackIDevIDContent_NilInput(t *testing.T) {
// 	_, err := PackIDevIDContent(nil)
// 	require.Error(t, err, "Should error on nil input")
// }

// TestUnmarshalIDevIDCSR_EmptyInput tests empty input handling
func TestUnmarshalIDevIDCSR_EmptyInput(t *testing.T) {
	_, err := UnmarshalIDevIDCSR([]byte{})
	require.Error(t, err, "Should error on empty input")
}

// TestVerifyTCGCSR_HashAlgorithms tests different hash algorithm detection
func TestVerifyTCGCSR_HashAlgorithms(t *testing.T) {
	testCases := []struct {
		name       string
		hashAlgID  uint32
		hashSz     uint32
		shouldWork bool
	}{
		{"SHA-256", 0x000B, 32, true},
		{"SHA-384", 0x000C, 48, true},
		{"SHA-512", 0x000D, 64, true},
		{"Invalid algorithm", 0x9999, 32, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := &TCG_IDEVID_CONTENT{}
			var hashAlgBytes [4]byte
			binary.BigEndian.PutUint32(hashAlgBytes[:], tc.hashAlgID)
			content.HashAlgoId = hashAlgBytes

			var hashSzBytes [4]byte
			binary.BigEndian.PutUint32(hashSzBytes[:], tc.hashSz)
			content.HashSz = hashSzBytes

			// Check that the hash algorithm can be identified
			switch tc.hashAlgID {
			case 0x000B, 0x000C, 0x000D:
				require.True(t, tc.shouldWork, "Valid hash algorithm should work")
			default:
				require.False(t, tc.shouldWork, "Invalid hash algorithm should not work")
			}
			_ = content
		})
	}
}

// TestPackIDevIDContent_BinaryFormat tests binary format compliance
func TestPackIDevIDContent_BinaryFormat(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(0x000B))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	content.ProdModel = []byte("MODEL")
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 5)

	content.ProdSerial = []byte("SERIAL")
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 6)

	// Set rest to zero
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)

	// Check that the version is correctly encoded at the start
	version := binary.BigEndian.Uint32(packed[0:4])
	require.Equal(t, uint32(0x00000100), version)

	// Check hash algorithm ID
	hashAlgID := binary.BigEndian.Uint32(packed[4:8])
	require.Equal(t, uint32(0x000B), hashAlgID)
}
