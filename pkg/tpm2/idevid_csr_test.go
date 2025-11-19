package tpm2

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create a minimal valid TCG_IDEVID_CONTENT
// Note: Uses non-empty byte slices for all fields to avoid Go's Reader.Read EOF behavior
func createTestIDevIDContent() *TCG_IDEVID_CONTENT {
	content := &TCG_IDEVID_CONTENT{}

	// Set structure version to 1.0
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)

	// Use SHA-256 (0x000B = 11)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x0000000B)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Product info
	prodModel := []byte("TestModel")
	prodSerial := []byte("SN12345")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))

	// CA Data (non-empty)
	prodCaData := []byte("mock-ca-data")
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))

	// Boot event log (non-empty)
	bootEvntLog := []byte("mock-boot-log")
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))

	// EK Certificate (mock)
	ekCert := []byte("mock-ek-cert")
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))

	// Attestation public key (mock)
	attestPub := []byte("mock-attest-pub-key")
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))

	// Creation ticket
	atCreateTkt := []byte("mock-create-ticket")
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))

	// Certify info
	atCertifyInfo := []byte("mock-certify-info")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))

	// Certify info signature
	atCertifyInfoSig := []byte("mock-certify-sig")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))

	// Signing public key
	signingPub := []byte("mock-signing-pub")
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))

	// Signing certify info
	sgnCertifyInfo := []byte("mock-sgn-certify")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))

	// Signing certify info signature
	sgnCertifyInfoSig := []byte("mock-sgn-sig")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))

	// Padding (non-empty to avoid EOF)
	pad := []byte("==")
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

	// Set actual data
	content.ProdModel = prodModel
	content.ProdSerial = prodSerial
	content.ProdCaData = prodCaData
	content.BootEvntLog = bootEvntLog
	content.EkCert = ekCert
	content.AttestPub = attestPub
	content.AtCreateTkt = atCreateTkt
	content.AtCertifyInfo = atCertifyInfo
	content.AtCertifyInfoSig = atCertifyInfoSig
	content.SigningPub = signingPub
	content.SgnCertifyInfo = sgnCertifyInfo
	content.SgnCertifyInfoSig = sgnCertifyInfoSig
	content.Pad = pad

	return content
}

// Test helper to create a minimal valid TCG_CSR_IDEVID
func createTestCSRIDevID() *TCG_CSR_IDEVID {
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	signature := []byte("mock-signature-data")
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	csr.Signature = signature

	csr.CsrContents = *createTestIDevIDContent()

	return csr
}

func TestBytesToUint32(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{
			name:     "zero value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "max value",
			input:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: 4294967295,
		},
		{
			name:     "structure version 1.0",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 256,
		},
		{
			name:     "SHA-256 algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: 11,
		},
		{
			name:     "arbitrary value",
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

func TestPackIDevIDContent(t *testing.T) {
	t.Run("valid content packs successfully", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)
		require.NotNil(t, packed)

		// Verify it starts with the correct structure version
		structVer := binary.BigEndian.Uint32(packed[0:4])
		assert.Equal(t, uint32(0x00000100), structVer)

		// Verify hash algorithm ID
		hashAlgoId := binary.BigEndian.Uint32(packed[4:8])
		assert.Equal(t, uint32(0x0000000B), hashAlgoId)

		// Verify hash size
		hashSz := binary.BigEndian.Uint32(packed[8:12])
		assert.Equal(t, uint32(32), hashSz)
	})

	t.Run("content with padding packs correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		padding := []byte("========")
		content.Pad = padding
		binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(padding)))

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// Verify padding is at the end
		assert.Equal(t, padding, packed[len(packed)-len(padding):])
	})

	t.Run("content preserves field order", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// Check that product model appears after the header fields
		// Header: 16 fields * 4 bytes = 64 bytes
		headerSize := 64
		foundModel := bytes.Contains(packed[headerSize:], content.ProdModel)
		assert.True(t, foundModel, "Product model not found in packed content")
	})
}

func TestPackIDevIDCSR(t *testing.T) {
	t.Run("valid CSR packs successfully", func(t *testing.T) {
		csr := createTestCSRIDevID()

		packed, err := PackIDevIDCSR(csr)
		require.NoError(t, err)
		require.NotNil(t, packed)

		// Verify structure version at the beginning
		structVer := binary.BigEndian.Uint32(packed[0:4])
		assert.Equal(t, uint32(0x00000100), structVer)

		// Verify signature size
		sigSz := binary.BigEndian.Uint32(packed[8:12])
		assert.Equal(t, uint32(len(csr.Signature)), sigSz)

		// Verify signature is at the end
		assert.Equal(t, csr.Signature, packed[len(packed)-len(csr.Signature):])
	})

	t.Run("CSR with large signature", func(t *testing.T) {
		csr := createTestCSRIDevID()
		largeSignature := make([]byte, 512)
		for i := range largeSignature {
			largeSignature[i] = byte(i % 256)
		}
		csr.Signature = largeSignature
		binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(largeSignature)))

		packed, err := PackIDevIDCSR(csr)
		require.NoError(t, err)
		assert.Equal(t, largeSignature, packed[len(packed)-len(largeSignature):])
	})
}

func TestUnpackIDevIDContent(t *testing.T) {
	t.Run("valid packed content unpacks successfully", func(t *testing.T) {
		originalContent := createTestIDevIDContent()

		packed, err := PackIDevIDContent(originalContent)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpackedContent, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)
		require.NotNil(t, unpackedContent)

		// Verify all fields match
		assert.Equal(t, originalContent.StructVer, unpackedContent.StructVer)
		assert.Equal(t, originalContent.HashAlgoId, unpackedContent.HashAlgoId)
		assert.Equal(t, originalContent.HashSz, unpackedContent.HashSz)
		assert.Equal(t, originalContent.ProdModel, unpackedContent.ProdModel)
		assert.Equal(t, originalContent.ProdSerial, unpackedContent.ProdSerial)
		assert.Equal(t, originalContent.ProdCaData, unpackedContent.ProdCaData)
		assert.Equal(t, originalContent.BootEvntLog, unpackedContent.BootEvntLog)
		assert.Equal(t, originalContent.EkCert, unpackedContent.EkCert)
		assert.Equal(t, originalContent.AttestPub, unpackedContent.AttestPub)
		assert.Equal(t, originalContent.AtCreateTkt, unpackedContent.AtCreateTkt)
		assert.Equal(t, originalContent.AtCertifyInfo, unpackedContent.AtCertifyInfo)
		assert.Equal(t, originalContent.AtCertifyInfoSig, unpackedContent.AtCertifyInfoSig)
		assert.Equal(t, originalContent.SigningPub, unpackedContent.SigningPub)
		assert.Equal(t, originalContent.SgnCertifyInfo, unpackedContent.SgnCertifyInfo)
		assert.Equal(t, originalContent.SgnCertifyInfoSig, unpackedContent.SgnCertifyInfoSig)
		assert.Equal(t, originalContent.Pad, unpackedContent.Pad)
	})

	t.Run("truncated header returns error", func(t *testing.T) {
		truncatedData := []byte{0x00, 0x00, 0x01, 0x00, 0x00} // Only 5 bytes

		reader := bytes.NewReader(truncatedData)
		_, err := UnpackIDevIDContent(reader)
		require.Error(t, err)
	})

	t.Run("truncated payload returns error", func(t *testing.T) {
		// Create header with sizes but no actual payload
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
		_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x0B}) // HashAlgoId
		_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x20}) // HashSz
		_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x10}) // ProdModelSz = 16
		// ... rest of size fields would be 0
		for i := 0; i < 12; i++ {
			_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x00})
		}
		// No actual payload data for ProdModel

		reader := bytes.NewReader(buf.Bytes())
		_, err := UnpackIDevIDContent(reader)
		require.Error(t, err)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("empty reader returns error", func(t *testing.T) {
		reader := bytes.NewReader([]byte{})
		_, err := UnpackIDevIDContent(reader)
		require.Error(t, err)
	})
}

func TestUnmarshalIDevIDCSR(t *testing.T) {
	t.Run("valid CSR unmarshals successfully", func(t *testing.T) {
		originalCSR := createTestCSRIDevID()

		packed, err := PackIDevIDCSR(originalCSR)
		require.NoError(t, err)

		unmarshalledCSR, err := UnmarshalIDevIDCSR(packed)
		require.NoError(t, err)
		require.NotNil(t, unmarshalledCSR)

		// Verify header fields
		assert.Equal(t, originalCSR.StructVer, unmarshalledCSR.StructVer)
		assert.Equal(t, originalCSR.Contents, unmarshalledCSR.Contents)
		assert.Equal(t, originalCSR.SigSz, unmarshalledCSR.SigSz)

		// Verify signature
		assert.Equal(t, originalCSR.Signature, unmarshalledCSR.Signature)

		// Verify content fields
		assert.Equal(t, originalCSR.CsrContents.ProdModel, unmarshalledCSR.CsrContents.ProdModel)
		assert.Equal(t, originalCSR.CsrContents.ProdSerial, unmarshalledCSR.CsrContents.ProdSerial)
	})

	t.Run("truncated CSR returns error", func(t *testing.T) {
		truncatedData := []byte{0x00, 0x00, 0x01, 0x00}

		_, err := UnmarshalIDevIDCSR(truncatedData)
		require.Error(t, err)
	})

	t.Run("empty CSR returns error", func(t *testing.T) {
		_, err := UnmarshalIDevIDCSR([]byte{})
		require.Error(t, err)
	})
}

func TestUnpackIDevIDCSR(t *testing.T) {
	t.Run("valid CSR unpacks to native types", func(t *testing.T) {
		originalCSR := createTestCSRIDevID()

		unpacked, err := UnpackIDevIDCSR(originalCSR)
		require.NoError(t, err)
		require.NotNil(t, unpacked)

		// Verify native uint32 fields
		assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
		assert.Equal(t, uint32(0x00000100), unpacked.CsrContents.StructVer)
		assert.Equal(t, uint32(0x0000000B), unpacked.CsrContents.HashAlgoId)
		assert.Equal(t, uint32(32), unpacked.CsrContents.HashSz)

		// Verify signature
		assert.Equal(t, originalCSR.Signature, unpacked.Signature)
		assert.Equal(t, uint32(len(originalCSR.Signature)), unpacked.SigSz)

		// Verify payload data
		assert.Equal(t, originalCSR.CsrContents.ProdModel, unpacked.CsrContents.ProdModel)
		assert.Equal(t, originalCSR.CsrContents.ProdSerial, unpacked.CsrContents.ProdSerial)
		assert.Equal(t, originalCSR.CsrContents.EkCert, unpacked.CsrContents.EkCert)
	})

	t.Run("mismatched size fields return error", func(t *testing.T) {
		csr := createTestCSRIDevID()

		// Corrupt the size field to be larger than actual data
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 1000)
		// But actual ProdModel is smaller

		_, err := UnpackIDevIDCSR(csr)
		require.Error(t, err)
	})

	t.Run("all sizes match actual data lengths", func(t *testing.T) {
		csr := createTestCSRIDevID()

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		assert.Equal(t, uint32(len(unpacked.CsrContents.ProdModel)), unpacked.CsrContents.ProdModelSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.ProdSerial)), unpacked.CsrContents.ProdSerialSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.EkCert)), unpacked.CsrContents.EkCertSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.AttestPub)), unpacked.CsrContents.AttestPubSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.SigningPub)), unpacked.CsrContents.SigningPubSZ)
	})
}

func TestPackUnpackRoundTrip(t *testing.T) {
	t.Run("content round trip preserves data", func(t *testing.T) {
		original := createTestIDevIDContent()

		// Pack
		packed, err := PackIDevIDContent(original)
		require.NoError(t, err)

		// Unpack
		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		// Verify all fields match
		assert.Equal(t, original.StructVer, unpacked.StructVer)
		assert.Equal(t, original.HashAlgoId, unpacked.HashAlgoId)
		assert.Equal(t, original.ProdModel, unpacked.ProdModel)
		assert.Equal(t, original.ProdSerial, unpacked.ProdSerial)
		assert.Equal(t, original.ProdCaData, unpacked.ProdCaData)
		assert.Equal(t, original.BootEvntLog, unpacked.BootEvntLog)
		assert.Equal(t, original.EkCert, unpacked.EkCert)
		assert.Equal(t, original.AttestPub, unpacked.AttestPub)
		assert.Equal(t, original.AtCreateTkt, unpacked.AtCreateTkt)
		assert.Equal(t, original.AtCertifyInfo, unpacked.AtCertifyInfo)
		assert.Equal(t, original.AtCertifyInfoSig, unpacked.AtCertifyInfoSig)
		assert.Equal(t, original.SigningPub, unpacked.SigningPub)
		assert.Equal(t, original.SgnCertifyInfo, unpacked.SgnCertifyInfo)
		assert.Equal(t, original.SgnCertifyInfoSig, unpacked.SgnCertifyInfoSig)
	})

	t.Run("CSR round trip preserves data", func(t *testing.T) {
		original := createTestCSRIDevID()

		// Pack
		packed, err := PackIDevIDCSR(original)
		require.NoError(t, err)

		// Unmarshal
		unmarshalled, err := UnmarshalIDevIDCSR(packed)
		require.NoError(t, err)

		// Pack again
		packedAgain, err := PackIDevIDCSR(unmarshalled)
		require.NoError(t, err)

		// Should be identical
		assert.Equal(t, packed, packedAgain)
	})

	t.Run("large payload round trip", func(t *testing.T) {
		content := createTestIDevIDContent()

		// Create large boot event log
		bootLog := make([]byte, 10000)
		for i := range bootLog {
			bootLog[i] = byte(i % 256)
		}
		content.BootEvntLog = bootLog
		binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootLog)))

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		assert.Equal(t, bootLog, unpacked.BootEvntLog)
	})
}

func TestEncodingEdgeCases(t *testing.T) {
	t.Run("maximum size fields", func(t *testing.T) {
		content := createTestIDevIDContent()

		// Set a large but valid size
		largeData := make([]byte, 65535)
		content.EkCert = largeData
		binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(largeData)))

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		assert.Equal(t, len(largeData), len(unpacked.EkCert))
	})

	t.Run("binary encoding preserves byte order", func(t *testing.T) {
		content := createTestIDevIDContent()

		// Set a known value in big endian
		binary.BigEndian.PutUint32(content.StructVer[:], 0x12345678)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// First 4 bytes should be in big endian order
		assert.Equal(t, byte(0x12), packed[0])
		assert.Equal(t, byte(0x34), packed[1])
		assert.Equal(t, byte(0x56), packed[2])
		assert.Equal(t, byte(0x78), packed[3])
	})

	t.Run("special characters in model and serial", func(t *testing.T) {
		content := createTestIDevIDContent()

		specialModel := []byte("Model-123_!@#$%^&*()")
		specialSerial := []byte("SN\x00\xFF\n\t")

		content.ProdModel = specialModel
		binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(specialModel)))
		content.ProdSerial = specialSerial
		binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(specialSerial)))

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		assert.Equal(t, specialModel, unpacked.ProdModel)
		assert.Equal(t, specialSerial, unpacked.ProdSerial)
	})
}

func TestErrorConditions(t *testing.T) {
	t.Run("UnpackIDevIDContent with insufficient header bytes", func(t *testing.T) {
		// Create partial header (less than 64 bytes needed for all size fields)
		partialHeader := make([]byte, 60)

		reader := bytes.NewReader(partialHeader)
		_, err := UnpackIDevIDContent(reader)
		require.Error(t, err)
	})

	t.Run("UnpackIDevIDCSR detects corrupt copy", func(t *testing.T) {
		csr := createTestCSRIDevID()

		// Set size larger than actual data - should trigger corrupt copy error
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], uint32(len(csr.CsrContents.ProdModel)+100))

		_, err := UnpackIDevIDCSR(csr)
		require.Error(t, err)
	})
}

func TestHashAlgorithmEncoding(t *testing.T) {
	tests := []struct {
		name        string
		algoID      uint32
		expectedSz  uint32
		description string
	}{
		{
			name:        "SHA-1",
			algoID:      0x00000004,
			expectedSz:  20,
			description: "SHA-1 hash with 20 byte digest",
		},
		{
			name:        "SHA-256",
			algoID:      0x0000000B,
			expectedSz:  32,
			description: "SHA-256 hash with 32 byte digest",
		},
		{
			name:        "SHA-384",
			algoID:      0x0000000C,
			expectedSz:  48,
			description: "SHA-384 hash with 48 byte digest",
		},
		{
			name:        "SHA-512",
			algoID:      0x0000000D,
			expectedSz:  64,
			description: "SHA-512 hash with 64 byte digest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := createTestIDevIDContent()
			binary.BigEndian.PutUint32(content.HashAlgoId[:], tc.algoID)
			binary.BigEndian.PutUint32(content.HashSz[:], tc.expectedSz)

			packed, err := PackIDevIDContent(content)
			require.NoError(t, err)

			reader := bytes.NewReader(packed)
			unpacked, err := UnpackIDevIDContent(reader)
			require.NoError(t, err)

			unpackedAlgoID := bytesToUint32(unpacked.HashAlgoId)
			unpackedHashSz := bytesToUint32(unpacked.HashSz)

			assert.Equal(t, tc.algoID, unpackedAlgoID)
			assert.Equal(t, tc.expectedSz, unpackedHashSz)
		})
	}
}

func TestStructureVersionEncoding(t *testing.T) {
	tests := []struct {
		name    string
		version uint32
	}{
		{
			name:    "version 1.0",
			version: 0x00000100,
		},
		{
			name:    "version 1.1",
			version: 0x00000101,
		},
		{
			name:    "version 2.0",
			version: 0x00000200,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csr := createTestCSRIDevID()
			binary.BigEndian.PutUint32(csr.StructVer[:], tc.version)

			packed, err := PackIDevIDCSR(csr)
			require.NoError(t, err)

			unmarshalled, err := UnmarshalIDevIDCSR(packed)
			require.NoError(t, err)

			resultVersion := bytesToUint32(unmarshalled.StructVer)
			assert.Equal(t, tc.version, resultVersion)
		})
	}
}

func TestContentFieldBoundaries(t *testing.T) {
	t.Run("exactly aligned payload sizes", func(t *testing.T) {
		content := createTestIDevIDContent()

		// Create payloads that are exactly 16-byte aligned
		content.ProdModel = make([]byte, 16)
		binary.BigEndian.PutUint32(content.ProdModelSz[:], 16)
		content.ProdSerial = make([]byte, 32)
		binary.BigEndian.PutUint32(content.ProdSerialSz[:], 32)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		assert.Len(t, unpacked.ProdModel, 16)
		assert.Len(t, unpacked.ProdSerial, 32)
	})

	t.Run("single byte payloads", func(t *testing.T) {
		content := createTestIDevIDContent()

		content.ProdModel = []byte{0x41}
		binary.BigEndian.PutUint32(content.ProdModelSz[:], 1)
		content.ProdSerial = []byte{0x42}
		binary.BigEndian.PutUint32(content.ProdSerialSz[:], 1)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader := bytes.NewReader(packed)
		unpacked, err := UnpackIDevIDContent(reader)
		require.NoError(t, err)

		assert.Equal(t, []byte{0x41}, unpacked.ProdModel)
		assert.Equal(t, []byte{0x42}, unpacked.ProdSerial)
	})
}

func TestSignatureFieldHandling(t *testing.T) {
	t.Run("RSA 2048-bit signature", func(t *testing.T) {
		csr := createTestCSRIDevID()

		// RSA 2048 produces 256-byte signature
		sig := make([]byte, 256)
		for i := range sig {
			sig[i] = byte(i % 256)
		}
		csr.Signature = sig
		binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(sig)))

		packed, err := PackIDevIDCSR(csr)
		require.NoError(t, err)

		unmarshalled, err := UnmarshalIDevIDCSR(packed)
		require.NoError(t, err)

		assert.Equal(t, sig, unmarshalled.Signature)
		assert.Equal(t, uint32(256), bytesToUint32(unmarshalled.SigSz))
	})

	t.Run("ECDSA P-256 signature", func(t *testing.T) {
		csr := createTestCSRIDevID()

		// ECDSA P-256 typically produces ~70-72 byte signature
		sig := make([]byte, 71)
		for i := range sig {
			sig[i] = byte(i % 256)
		}
		csr.Signature = sig
		binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(sig)))

		packed, err := PackIDevIDCSR(csr)
		require.NoError(t, err)

		unmarshalled, err := UnmarshalIDevIDCSR(packed)
		require.NoError(t, err)

		assert.Equal(t, sig, unmarshalled.Signature)
	})
}

func TestErrInvalidSignature(t *testing.T) {
	t.Run("error variable is defined correctly", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSignature)
		assert.Equal(t, "tpm: invalid signature", ErrInvalidSignature.Error())
	})
}

func TestCSRContentSizeCalculations(t *testing.T) {
	t.Run("packed content size matches expectations", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// Calculate expected size
		headerSize := 16 * 4 // 16 uint32 fields
		payloadSize := len(content.ProdModel) +
			len(content.ProdSerial) +
			len(content.ProdCaData) +
			len(content.BootEvntLog) +
			len(content.EkCert) +
			len(content.AttestPub) +
			len(content.AtCreateTkt) +
			len(content.AtCertifyInfo) +
			len(content.AtCertifyInfoSig) +
			len(content.SigningPub) +
			len(content.SgnCertifyInfo) +
			len(content.SgnCertifyInfoSig) +
			len(content.Pad)

		expectedSize := headerSize + payloadSize
		assert.Equal(t, expectedSize, len(packed))
	})

	t.Run("CSR header size is correct", func(t *testing.T) {
		csr := createTestCSRIDevID()

		packed, err := PackIDevIDCSR(csr)
		require.NoError(t, err)

		// CSR header: StructVer (4) + Contents (4) + SigSz (4) = 12 bytes
		// Then CsrContents, then Signature
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		expectedSize := 12 + len(packedContent) + len(csr.Signature)
		assert.Equal(t, expectedSize, len(packed))
	})
}

func TestMultipleOperations(t *testing.T) {
	t.Run("multiple pack operations are idempotent", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed1, err := PackIDevIDContent(content)
		require.NoError(t, err)

		packed2, err := PackIDevIDContent(content)
		require.NoError(t, err)

		assert.Equal(t, packed1, packed2)
	})

	t.Run("multiple unpack operations produce same result", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)

		reader1 := bytes.NewReader(packed)
		unpacked1, err := UnpackIDevIDContent(reader1)
		require.NoError(t, err)

		reader2 := bytes.NewReader(packed)
		unpacked2, err := UnpackIDevIDContent(reader2)
		require.NoError(t, err)

		assert.Equal(t, unpacked1.ProdModel, unpacked2.ProdModel)
		assert.Equal(t, unpacked1.ProdSerial, unpacked2.ProdSerial)
	})
}
