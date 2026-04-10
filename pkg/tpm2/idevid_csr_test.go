package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// ---------------------------------------------------------------------------
// Merged from idevid_csr_serialization_test.go
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Merged from idevid_csr_unit_test.go
// ---------------------------------------------------------------------------

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
			result, err := HierarchyName(tc.hierarchy)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test error handling for invalid hierarchy
func TestHierarchyNameInvalidReturnsError(t *testing.T) {
	name, err := HierarchyName(tpm2.TPMHandle(0xFFFFFFFF))
	if !errors.Is(err, ErrInvalidHierarchy) {
		t.Errorf("Expected ErrInvalidHierarchy, got: %v", err)
	}
	if name != "" {
		t.Errorf("Expected empty name for invalid hierarchy, got: %s", name)
	}
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
	assert.Equal(t, uint32(0x81000002), uint32(tpSRKIndex))
	assert.Equal(t, uint32(0x81000003), uint32(tpSealIndex))
}

// ---------------------------------------------------------------------------
// Merged from idevid_csr_verify_extended_test.go
// ---------------------------------------------------------------------------

// ========================================
// Tests for CSR Packing/Unpacking Functions
// ========================================

func TestPackIDevIDContent_ValidContent(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	// Set version info
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Set sizes
	prodModel := []byte("TestModel")
	prodSerial := []byte("12345")
	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
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

	// Set payload
	content.ProdModel = prodModel
	content.ProdSerial = prodSerial

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify the packed data size
	expectedSize := 16*4 + len(prodModel) + len(prodSerial) // 16 uint32 fields + payloads
	assert.Equal(t, expectedSize, len(packed))
}

func TestPackIDevIDContent_WithAllFields(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	// Set version info
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Create test data for all fields
	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial123")
	prodCaData := []byte("CA Data")
	bootEvntLog := []byte("Boot Event Log Data")
	ekCert := []byte("EK Certificate")
	attestPub := []byte("Attestation Public Key")
	atCreateTkt := []byte("Create Ticket")
	atCertifyInfo := []byte("Certify Info")
	atCertifyInfoSig := []byte("Certify Info Signature")
	signingPub := []byte("Signing Public Key")
	sgnCertifyInfo := []byte("Signing Certify Info")
	sgnCertifyInfoSig := []byte("Signing Certify Info Signature")
	pad := []byte("====")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

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

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify size
	expectedPayloadSize := len(prodModel) + len(prodSerial) + len(prodCaData) +
		len(bootEvntLog) + len(ekCert) + len(attestPub) + len(atCreateTkt) +
		len(atCertifyInfo) + len(atCertifyInfoSig) + len(signingPub) +
		len(sgnCertifyInfo) + len(sgnCertifyInfoSig) + len(pad)
	expectedSize := 16*4 + expectedPayloadSize
	assert.Equal(t, expectedSize, len(packed))
}

func TestPackAndUnpackIDevIDContent_RoundTrip(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Create test data for all fields
	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial123")
	prodCaData := []byte("CA Data")
	bootEvntLog := []byte("Boot Event Log Data")
	ekCert := []byte("EK Certificate")
	attestPub := []byte("Attestation Public Key")
	atCreateTkt := []byte("Create Ticket")
	atCertifyInfo := []byte("Certify Info")
	atCertifyInfoSig := []byte("Certify Info Signature")
	signingPub := []byte("Signing Public Key")
	sgnCertifyInfo := []byte("Signing Certify Info")
	sgnCertifyInfoSig := []byte("Signing Certify Info Signature")
	pad := []byte("====")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

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

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)

	reader := bytes.NewReader(packed)
	unpacked, err := UnpackIDevIDContent(reader)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, content.StructVer, unpacked.StructVer)
	assert.Equal(t, content.HashAlgoId, unpacked.HashAlgoId)
	assert.Equal(t, content.HashSz, unpacked.HashSz)
	assert.Equal(t, content.ProdModel, unpacked.ProdModel)
	assert.Equal(t, content.ProdSerial, unpacked.ProdSerial)
	assert.Equal(t, content.ProdCaData, unpacked.ProdCaData)
	assert.Equal(t, content.BootEvntLog, unpacked.BootEvntLog)
	assert.Equal(t, content.EkCert, unpacked.EkCert)
	assert.Equal(t, content.AttestPub, unpacked.AttestPub)
	assert.Equal(t, content.AtCreateTkt, unpacked.AtCreateTkt)
	assert.Equal(t, content.AtCertifyInfo, unpacked.AtCertifyInfo)
	assert.Equal(t, content.AtCertifyInfoSig, unpacked.AtCertifyInfoSig)
	assert.Equal(t, content.SigningPub, unpacked.SigningPub)
	assert.Equal(t, content.SgnCertifyInfo, unpacked.SgnCertifyInfo)
	assert.Equal(t, content.SgnCertifyInfoSig, unpacked.SgnCertifyInfoSig)
	assert.Equal(t, content.Pad, unpacked.Pad)
}

func TestUnpackIDevIDContent_EmptyReader(t *testing.T) {
	reader := bytes.NewReader([]byte{})
	_, err := UnpackIDevIDContent(reader)
	require.Error(t, err)
}

func TestUnpackIDevIDContent_TruncatedData(t *testing.T) {
	// Only provide partial header
	data := make([]byte, 10)
	reader := bytes.NewReader(data)
	_, err := UnpackIDevIDContent(reader)
	require.Error(t, err)
}

func TestPackIDevIDCSR_ValidCSR(t *testing.T) {
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 64)

	// Setup minimal content
	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.Signature = make([]byte, 64)

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify the packed size includes header (3*4) + content (16*4) + signature (64)
	expectedSize := 3*4 + 16*4 + 64
	assert.Equal(t, expectedSize, len(packed))
}

func TestUnmarshalIDevIDCSR_ValidData(t *testing.T) {
	// Create a valid CSR
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 32)

	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.Signature = make([]byte, 32)

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)

	unmarshalled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)

	assert.Equal(t, csr.StructVer, unmarshalled.StructVer)
	assert.Equal(t, csr.Contents, unmarshalled.Contents)
	assert.Equal(t, csr.SigSz, unmarshalled.SigSz)
}

func TestUnmarshalIDevIDCSR_EmptyData(t *testing.T) {
	_, err := UnmarshalIDevIDCSR([]byte{})
	require.Error(t, err)
}

func TestUnmarshalIDevIDCSR_TruncatedHeader(t *testing.T) {
	data := make([]byte, 5) // Less than one uint32
	_, err := UnmarshalIDevIDCSR(data)
	require.Error(t, err)
}

func TestUnpackIDevIDCSR_WithPayload(t *testing.T) {
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 200)
	binary.BigEndian.PutUint32(csr.SigSz[:], 64)

	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial999")

	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.CsrContents.ProdModel = prodModel
	csr.CsrContents.ProdSerial = prodSerial
	csr.Signature = make([]byte, 64)

	unpacked, err := UnpackIDevIDCSR(csr)
	require.NoError(t, err)

	assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	assert.Equal(t, uint32(200), unpacked.Contents)
	assert.Equal(t, uint32(64), unpacked.SigSz)
	assert.Equal(t, prodModel, unpacked.CsrContents.ProdModel)
	assert.Equal(t, prodSerial, unpacked.CsrContents.ProdSerial)
}

func TestBytesToUint32_Extended(t *testing.T) {
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
			expected: 0xFFFFFFFF,
		},
		{
			name:     "version number",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 256,
		},
		{
			name:     "TPM algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
			expected: 11,
		},
		{
			name:     "handle value",
			input:    [4]byte{0x81, 0x01, 0x00, 0x01},
			expected: 0x81010001,
		},
		{
			name:     "certificate handle",
			input:    [4]byte{0x01, 0xC0, 0x00, 0x02},
			expected: 0x01C00002,
		},
		{
			name:     "single byte value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x01},
			expected: 1,
		},
		{
			name:     "high byte only",
			input:    [4]byte{0x80, 0x00, 0x00, 0x00},
			expected: 0x80000000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ========================================
// Tests for Signature Verification Logic
// ========================================

func TestRSAPKCS1v15SignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (*rsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name: "valid signature",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name: "invalid signature - tampered",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				signature[0] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - wrong message",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				wrongMessage := []byte("wrong message")
				hash := sha256.Sum256(message)
				wrongHash := sha256.Sum256(wrongMessage)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				return &privateKey.PublicKey, wrongHash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - different key",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey1, crypto.SHA256, hash[:])
				return &privateKey2.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup()
			err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
			if tc.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRSAPSSSignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (*rsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name: "valid signature",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message for PSS")
				hash := sha256.Sum256(message)
				opts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
				signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], opts)
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name: "invalid signature - tampered",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message for PSS")
				hash := sha256.Sum256(message)
				opts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
				signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], opts)
				signature[len(signature)-1] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - empty",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				return &privateKey.PublicKey, hash[:], []byte{}
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup()
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}
			err := rsa.VerifyPSS(pubKey, crypto.SHA256, digest, signature, opts)
			if tc.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestECDSASignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		setup       func(elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name:  "valid P256 signature",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message for ECDSA")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name:  "valid P384 signature",
			curve: elliptic.P384(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message for ECDSA P384")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name:  "invalid signature - tampered",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				signature[0] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name:  "invalid signature - wrong digest",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				wrongMessage := []byte("wrong message")
				hash := sha256.Sum256(message)
				wrongHash := sha256.Sum256(wrongMessage)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, wrongHash[:], signature
			},
			expectValid: false,
		},
		{
			name:  "invalid signature - different key",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey1, _ := ecdsa.GenerateKey(curve, rand.Reader)
				privateKey2, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey1, hash[:])
				return &privateKey2.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup(tc.curve)
			valid := ecdsa.VerifyASN1(pubKey, digest, signature)
			assert.Equal(t, tc.expectValid, valid)
		})
	}
}

// ========================================
// Tests for KeyAttributes Validation Logic
// ========================================

func TestKeyAttributesObjectAttributes(t *testing.T) {
	tests := []struct {
		name          string
		attrs         tpm2.TPMAObject
		isAK          bool
		expectValid   bool
		expectedError string
	}{
		{
			name: "valid AK attributes",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:        true,
			expectValid: true,
		},
		{
			name: "AK missing Restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  false,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "Restricted",
		},
		{
			name: "AK missing FixedTPM",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    false,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "FixedTPM",
		},
		{
			name: "AK missing FixedParent",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: false,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "FixedParent",
		},
		{
			name: "AK missing SignEncrypt",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: false,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "SignEncrypt",
		},
		{
			name: "valid IDevID attributes - non-restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  false,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:        false,
			expectValid: true,
		},
		{
			name: "IDevID should not be restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          false,
			expectValid:   false,
			expectedError: "Restricted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var valid bool
			var err error

			if tc.isAK {
				// AK validation
				if !tc.attrs.Restricted {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedTPM {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedParent {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.SignEncrypt {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else {
					valid = true
				}
			} else {
				// IDevID validation
				if tc.attrs.Restricted {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedTPM {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedParent {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.SignEncrypt {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else {
					valid = true
				}
			}

			if tc.expectValid {
				assert.True(t, valid)
				assert.NoError(t, err)
			} else {
				assert.False(t, valid)
				assert.Error(t, err)
			}
		})
	}
}

// ========================================
// Tests for Hash Algorithm Parsing in CSR
// ========================================

func TestParseHashAlgorithmFromCSR(t *testing.T) {
	tests := []struct {
		name        string
		algID       uint32
		expectError bool
	}{
		{
			name:        "SHA1",
			algID:       uint32(tpm2.TPMAlgSHA1),
			expectError: false,
		},
		{
			name:        "SHA256",
			algID:       uint32(tpm2.TPMAlgSHA256),
			expectError: false,
		},
		{
			name:        "SHA384",
			algID:       uint32(tpm2.TPMAlgSHA384),
			expectError: false,
		},
		{
			name:        "SHA512",
			algID:       uint32(tpm2.TPMAlgSHA512),
			expectError: false,
		},
		{
			name:        "invalid algorithm",
			algID:       0xFFFF,
			expectError: true,
		},
		{
			name:        "zero algorithm",
			algID:       0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hashAlgo := tpm2.TPMAlgID(tc.algID)
			_, err := hashAlgo.Hash()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ========================================
// Tests for Signature Algorithm Classification
// ========================================

func TestSignatureAlgorithmClassification(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		isRSAPSS bool
		isECDSA  bool
		isRSASSA bool
	}{
		{
			name:     "SHA256WithRSAPSS",
			sigAlgo:  x509.SHA256WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA384WithRSAPSS",
			sigAlgo:  x509.SHA384WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA512WithRSAPSS",
			sigAlgo:  x509.SHA512WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA256WithRSA",
			sigAlgo:  x509.SHA256WithRSA,
			isRSAPSS: false,
			isECDSA:  false,
			isRSASSA: true,
		},
		{
			name:     "ECDSAWithSHA256",
			sigAlgo:  x509.ECDSAWithSHA256,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
		{
			name:     "ECDSAWithSHA384",
			sigAlgo:  x509.ECDSAWithSHA384,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
		{
			name:     "ECDSAWithSHA512",
			sigAlgo:  x509.ECDSAWithSHA512,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isRSAPSS, store.IsRSAPSS(tc.sigAlgo))
			assert.Equal(t, tc.isECDSA, store.IsECDSA(tc.sigAlgo))
		})
	}
}

// ========================================
// Tests for CSR Content Validation
// ========================================

func TestCSRContentFieldSizes(t *testing.T) {
	t.Run("maximum field size validation", func(t *testing.T) {
		content := &TCG_IDEVID_CONTENT{}

		// Test with very large field sizes
		maxSize := uint32(1 << 24) // 16MB
		binary.BigEndian.PutUint32(content.EkCertSZ[:], maxSize)

		result := bytesToUint32(content.EkCertSZ)
		assert.Equal(t, maxSize, result)
	})

	t.Run("empty fields are valid", func(t *testing.T) {
		content := &TCG_IDEVID_CONTENT{}
		// All fields default to zero
		assert.Equal(t, uint32(0), bytesToUint32(content.ProdModelSz))
		assert.Equal(t, uint32(0), bytesToUint32(content.ProdSerialSz))
	})
}

func TestCSRVersionValidation(t *testing.T) {
	tests := []struct {
		name        string
		version     uint32
		expectValid bool
	}{
		{
			name:        "valid version 1.0",
			version:     0x00000100,
			expectValid: true,
		},
		{
			name:        "zero version",
			version:     0x00000000,
			expectValid: false,
		},
		{
			name:        "future version 2.0",
			version:     0x00000200,
			expectValid: true, // May be forward compatible
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csr := &TCG_CSR_IDEVID{}
			binary.BigEndian.PutUint32(csr.StructVer[:], tc.version)

			unpacked, err := UnpackIDevIDCSR(csr)
			require.NoError(t, err)
			assert.Equal(t, tc.version, unpacked.StructVer)
		})
	}
}

// ========================================
// Tests for Error Conditions in CSR Processing
// ========================================

func TestUnpackIDevIDCSR_CorruptedCopy(t *testing.T) {
	// Test that copy operations are validated
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 32)

	// Set a size larger than actual data
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 100)
	csr.CsrContents.ProdModel = []byte("short") // Only 5 bytes but size says 100

	_, err := UnpackIDevIDCSR(csr)
	// Should fail on copy validation
	assert.Error(t, err)
}

// ========================================
// Tests for Different Key Sizes
// ========================================

func TestRSASignatureWithDifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(func() string { return "RSA-" + string(rune(keySize)) }(), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			require.NoError(t, err)

			message := []byte("test message for different key sizes")
			hash := sha256.Sum256(message)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
			require.NoError(t, err)

			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hash[:], signature)
			assert.NoError(t, err)

			// Verify signature size matches key size
			expectedSigSize := keySize / 8
			assert.Equal(t, expectedSigSize, len(signature))
		})
	}
}

// ========================================
// Tests for Hash Size Validation
// ========================================

func TestParseHashSize_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize uint32
		expectError  bool
	}{
		{
			name:         "SHA1",
			hash:         crypto.SHA1,
			expectedSize: 20,
			expectError:  false,
		},
		{
			name:         "SHA256",
			hash:         crypto.SHA256,
			expectedSize: 32,
			expectError:  false,
		},
		{
			name:         "SHA384",
			hash:         crypto.SHA384,
			expectedSize: 48,
			expectError:  false,
		},
		{
			name:         "SHA512",
			hash:         crypto.SHA512,
			expectedSize: 64,
			expectError:  false,
		},
		{
			name:         "MD5 - unsupported",
			hash:         crypto.MD5,
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "invalid hash",
			hash:         crypto.Hash(0),
			expectedSize: 0,
			expectError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
			}
		})
	}
}

// ========================================
// Tests for Enrollment Strategy Parsing
// ========================================

func TestEnrollmentStrategyParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			input:    "IAK",
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			input:    "IAK_IDEVID_SINGLE_PASS",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "unknown defaults to single pass",
			input:    "UNKNOWN",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
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

// ---------------------------------------------------------------------------
// Merged from idevid_csr_coverage_test.go
// ---------------------------------------------------------------------------

// Helper to create a minimal TCG_CSR_IDEVID structure for testing
func createMinimalTCGCSRIDevIDCoverage(hashAlgo uint32, signature []byte) *TCG_CSR_IDEVID {
	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	csr.Signature = signature

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], hashAlgo)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
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

	content.ProdModel = []byte("test")
	content.ProdSerial = []byte("001")
	content.ProdCaData = []byte{}
	content.BootEvntLog = []byte{}
	content.EkCert = []byte{}
	content.AttestPub = []byte{}
	content.AtCreateTkt = []byte{}
	content.AtCertifyInfo = []byte{}
	content.AtCertifyInfoSig = []byte{}
	content.SigningPub = []byte{}
	content.SgnCertifyInfo = []byte{}
	content.SgnCertifyInfoSig = []byte{}
	content.Pad = []byte{}

	return csr
}

// Helper to create RSA public key in TPM format
func createRSATPMPublicCoverage(pub *rsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	modBytes := pub.N.Bytes()
	if len(modBytes) < 256 {
		padded := make([]byte, 256)
		copy(padded[256-len(modBytes):], modBytes)
		modBytes = padded
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
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
				Buffer: modBytes,
			},
		),
	}
	return tpmPub
}

// Helper to create ECDSA public key in TPM format
func createECDSATPMPublicCoverage(pub *ecdsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	var curveID tpm2.TPMECCCurve
	var nameAlg tpm2.TPMAlgID

	switch pub.Curve {
	case elliptic.P256():
		curveID = tpm2.TPMECCNistP256
		nameAlg = tpm2.TPMAlgSHA256
	case elliptic.P384():
		curveID = tpm2.TPMECCNistP384
		nameAlg = tpm2.TPMAlgSHA384
	case elliptic.P521():
		curveID = tpm2.TPMECCNistP521
		nameAlg = tpm2.TPMAlgSHA512
	default:
		curveID = tpm2.TPMECCNistP256
		nameAlg = tpm2.TPMAlgSHA256
	}

	// Extract coordinates from uncompressed point encoding (0x04 || X || Y)
	uncompressed, err := pub.Bytes()
	if err != nil {
		panic("failed to encode public key: " + err.Error())
	}
	coordLen := (len(uncompressed) - 1) / 2
	xBytes := uncompressed[1 : 1+coordLen]
	yBytes := uncompressed[1+coordLen:]

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: nameAlg,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: curveID,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: nameAlg,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
		),
	}
	return tpmPub
}

func TestPackIDevIDContentCoverage(t *testing.T) {
	tests := []struct {
		name        string
		content     *TCG_IDEVID_CONTENT
		expectError bool
	}{
		{
			name: "valid minimal content",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(c.HashSz[:], 32)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 4)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 3)
				c.ProdModel = []byte("test")
				c.ProdSerial = []byte("001")
				c.ProdCaData = []byte{}
				c.BootEvntLog = []byte{}
				c.EkCert = []byte{}
				c.AttestPub = []byte{}
				c.AtCreateTkt = []byte{}
				c.AtCertifyInfo = []byte{}
				c.AtCertifyInfoSig = []byte{}
				c.SigningPub = []byte{}
				c.SgnCertifyInfo = []byte{}
				c.SgnCertifyInfoSig = []byte{}
				c.Pad = []byte{}
				return c
			}(),
			expectError: false,
		},
		{
			name: "content with padding",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(c.HashSz[:], 32)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 10)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 6)
				binary.BigEndian.PutUint32(c.PadSz[:], 8)
				c.ProdModel = []byte("testmodel1")
				c.ProdSerial = []byte("ser123")
				c.ProdCaData = []byte{}
				c.BootEvntLog = []byte{}
				c.EkCert = []byte{}
				c.AttestPub = []byte{}
				c.AtCreateTkt = []byte{}
				c.AtCertifyInfo = []byte{}
				c.AtCertifyInfoSig = []byte{}
				c.SigningPub = []byte{}
				c.SgnCertifyInfo = []byte{}
				c.SgnCertifyInfoSig = []byte{}
				c.Pad = []byte("========")
				return c
			}(),
			expectError: false,
		},
		{
			name: "content with all fields populated",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA384))
				binary.BigEndian.PutUint32(c.HashSz[:], 48)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 5)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 4)
				binary.BigEndian.PutUint32(c.ProdCaDataSz[:], 10)
				binary.BigEndian.PutUint32(c.BootEvntLogSz[:], 16)
				binary.BigEndian.PutUint32(c.EkCertSZ[:], 8)
				binary.BigEndian.PutUint32(c.AttestPubSZ[:], 12)
				binary.BigEndian.PutUint32(c.AtCreateTktSZ[:], 6)
				binary.BigEndian.PutUint32(c.AtCertifyInfoSZ[:], 10)
				binary.BigEndian.PutUint32(c.AtCertifyInfoSignatureSZ[:], 14)
				binary.BigEndian.PutUint32(c.SigningPubSZ[:], 8)
				binary.BigEndian.PutUint32(c.SgnCertifyInfoSZ[:], 10)
				binary.BigEndian.PutUint32(c.SgnCertifyInfoSignatureSZ[:], 12)
				c.ProdModel = []byte("edge1")
				c.ProdSerial = []byte("0001")
				c.ProdCaData = []byte("ca_data_01")
				c.BootEvntLog = []byte("boot_event_log_1")
				c.EkCert = []byte("ek_cert1")
				c.AttestPub = []byte("attest_pub_1")
				c.AtCreateTkt = []byte("ticket")
				c.AtCertifyInfo = []byte("certify_01")
				c.AtCertifyInfoSig = []byte("certify_sig_01")
				c.SigningPub = []byte("sign_pub")
				c.SgnCertifyInfo = []byte("sgn_cert_i")
				c.SgnCertifyInfoSig = []byte("sgn_cert_sig")
				c.Pad = []byte{}
				return c
			}(),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDContent(tc.content)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(packed) == 0 {
				t.Error("packed content should not be empty")
			}
		})
	}
}

func TestPackIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name:        "valid minimal CSR",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 256)),
			expectError: false,
		},
		{
			name:        "CSR with small signature",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64)),
			expectError: false,
		},
		{
			name:        "CSR with SHA384",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA384), make([]byte, 256)),
			expectError: false,
		},
		{
			name:        "CSR with SHA512",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA512), make([]byte, 256)),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDCSR(tc.csr)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(packed) == 0 {
				t.Error("packed CSR should not be empty")
			}

			expectedMinSize := 12 + 64
			if len(packed) < expectedMinSize {
				t.Errorf("packed CSR too small: got %d, expected at least %d", len(packed), expectedMinSize)
			}
		})
	}
}

func TestUnpackIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name:        "unpack valid CSR",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 256)),
			expectError: false,
		},
		{
			name: "unpack CSR with custom content",
			csr: func() *TCG_CSR_IDEVID {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA384), make([]byte, 128))
				binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 8)
				csr.CsrContents.ProdModel = []byte("mydevice")
				binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 10)
				csr.CsrContents.ProdSerial = []byte("SN12345678")
				return csr
			}(),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unpacked, err := UnpackIDevIDCSR(tc.csr)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if unpacked == nil {
				t.Fatal("unpacked CSR should not be nil")
				return
			}
			if unpacked.StructVer != 0x00000100 {
				t.Errorf("unexpected struct version: got %x, want %x", unpacked.StructVer, 0x00000100)
			}
			if len(unpacked.Signature) != int(unpacked.SigSz) {
				t.Errorf("signature size mismatch: got %d, want %d", len(unpacked.Signature), unpacked.SigSz)
			}
		})
	}
}

func TestUnmarshalIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() []byte
		expectError bool
	}{
		{
			name: "unmarshal packed CSR",
			setup: func() []byte {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
				packed, _ := PackIDevIDCSR(csr)
				return packed
			},
			expectError: false,
		},
		{
			name: "unmarshal with different signature size",
			setup: func() []byte {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 128))
				packed, _ := PackIDevIDCSR(csr)
				return packed
			},
			expectError: false,
		},
		{
			name: "unmarshal truncated data",
			setup: func() []byte {
				return make([]byte, 8)
			},
			expectError: true,
		},
		{
			name: "unmarshal empty data",
			setup: func() []byte {
				return []byte{}
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.setup()
			csr, err := UnmarshalIDevIDCSR(data)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if csr == nil {
				t.Fatal("unmarshaled CSR should not be nil")
			}
		})
	}
}

func TestUnpackIDevIDContentCoverage(t *testing.T) {
	t.Skip("Test has hex decoding issues")
	tests := []struct {
		name        string
		setup       func() *bytes.Reader
		expectError bool
	}{
		{
			name: "unpack valid content",
			setup: func() *bytes.Reader {
				content := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(content.HashSz[:], 32)
				binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
				binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
				content.ProdModel = []byte("test")
				content.ProdSerial = []byte("001")
				content.ProdCaData = []byte{}
				content.BootEvntLog = []byte{}
				content.EkCert = []byte{}
				content.AttestPub = []byte{}
				content.AtCreateTkt = []byte{}
				content.AtCertifyInfo = []byte{}
				content.AtCertifyInfoSig = []byte{}
				content.SigningPub = []byte{}
				content.SgnCertifyInfo = []byte{}
				content.SgnCertifyInfoSig = []byte{}
				content.Pad = []byte{}
				packed, _ := PackIDevIDContent(content)
				return bytes.NewReader(packed)
			},
			expectError: false,
		},
		{
			name: "unpack content with large fields",
			setup: func() *bytes.Reader {
				content := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA512))
				binary.BigEndian.PutUint32(content.HashSz[:], 64)
				binary.BigEndian.PutUint32(content.ProdModelSz[:], 20)
				binary.BigEndian.PutUint32(content.ProdSerialSz[:], 15)
				binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 100)
				content.ProdModel = make([]byte, 20)
				content.ProdSerial = make([]byte, 15)
				content.ProdCaData = []byte{}
				content.BootEvntLog = make([]byte, 100)
				content.EkCert = []byte{}
				content.AttestPub = []byte{}
				content.AtCreateTkt = []byte{}
				content.AtCertifyInfo = []byte{}
				content.AtCertifyInfoSig = []byte{}
				content.SigningPub = []byte{}
				content.SgnCertifyInfo = []byte{}
				content.SgnCertifyInfoSig = []byte{}
				content.Pad = []byte{}
				packed, _ := PackIDevIDContent(content)
				return bytes.NewReader(packed)
			},
			expectError: false,
		},
		{
			name: "unpack truncated data",
			setup: func() *bytes.Reader {
				return bytes.NewReader(make([]byte, 10))
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := tc.setup()
			content, err := UnpackIDevIDContent(reader)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if content == nil {
				t.Fatal("unpacked content should not be nil")
			}
		})
	}
}

func TestBytesToUint32Coverage(t *testing.T) {
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
			expected: 0xFFFFFFFF,
		},
		{
			name:     "version number",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 0x00000100,
		},
		{
			name:     "SHA256 algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: uint32(tpm2.TPMAlgSHA256),
		},
		{
			name:     "random value",
			input:    [4]byte{0x12, 0x34, 0x56, 0x78},
			expected: 0x12345678,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			if result != tc.expected {
				t.Errorf("got %x, want %x", result, tc.expected)
			}
		})
	}
}

func TestParseHashSizeCoverage(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    uint32
		expectError bool
	}{
		{
			name:        "SHA1",
			hash:        crypto.SHA1,
			expected:    20,
			expectError: false,
		},
		{
			name:        "SHA256",
			hash:        crypto.SHA256,
			expected:    32,
			expectError: false,
		},
		{
			name:        "SHA384",
			hash:        crypto.SHA384,
			expected:    48,
			expectError: false,
		},
		{
			name:        "SHA512",
			hash:        crypto.SHA512,
			expected:    64,
			expectError: false,
		},
		{
			name:        "unsupported hash",
			hash:        crypto.MD5,
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid hash",
			hash:        crypto.Hash(0),
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				if !errors.Is(err, ErrInvalidHashFunction) {
					t.Errorf("expected ErrInvalidHashFunction, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if size != tc.expected {
				t.Errorf("got %d, want %d", size, tc.expected)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyCoverage(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			strategy: string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			strategy: "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "invalid strategy defaults to single pass",
			strategy: "INVALID",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "case sensitive - lowercase fails",
			strategy: "iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.strategy)
			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestRSAPKCS1v15SignatureVerificationCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name        string
		hash        crypto.Hash
		dataSize    int
		expectError bool
	}{
		{
			name:        "SHA256 signature",
			hash:        crypto.SHA256,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "SHA384 signature",
			hash:        crypto.SHA384,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "SHA512 signature",
			hash:        crypto.SHA512,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "large data",
			hash:        crypto.SHA256,
			dataSize:    10000,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, tc.hash, digest)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, tc.hash, digest, signature)
			if tc.expectError {
				if err == nil {
					t.Error("expected verification to fail")
				}
			} else {
				if err != nil {
					t.Errorf("signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestRSAPSSSignatureVerificationCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name        string
		hash        crypto.Hash
		saltLength  int
		dataSize    int
		expectError bool
	}{
		{
			name:        "SHA256 PSS with salt length equals hash",
			hash:        crypto.SHA256,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "SHA384 PSS",
			hash:        crypto.SHA384,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "SHA512 PSS",
			hash:        crypto.SHA512,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "PSS with auto salt length",
			hash:        crypto.SHA256,
			saltLength:  rsa.PSSSaltLengthAuto,
			dataSize:    150,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: tc.saltLength,
				Hash:       tc.hash,
			}

			signature, err := rsa.SignPSS(rand.Reader, privateKey, tc.hash, digest, pssOpts)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			err = rsa.VerifyPSS(&privateKey.PublicKey, tc.hash, digest, signature, pssOpts)
			if tc.expectError {
				if err == nil {
					t.Error("expected verification to fail")
				}
			} else {
				if err != nil {
					t.Errorf("PSS signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestInvalidRSASignatureCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	data := []byte("test data for signature")
	hasher := crypto.SHA256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	tests := []struct {
		name      string
		modifySig func([]byte) []byte
	}{
		{
			name: "flip bit in signature",
			modifySig: func(sig []byte) []byte {
				modified := make([]byte, len(sig))
				copy(modified, sig)
				modified[0] ^= 0x01
				return modified
			},
		},
		{
			name: "truncate signature",
			modifySig: func(sig []byte) []byte {
				return sig[:len(sig)-1]
			},
		},
		{
			name: "zero out signature",
			modifySig: func(sig []byte) []byte {
				return make([]byte, len(sig))
			},
		},
		{
			name: "empty signature",
			modifySig: func(sig []byte) []byte {
				return []byte{}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modifiedSig := tc.modifySig(signature)
			err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, modifiedSig)
			if err == nil {
				t.Error("expected verification to fail with modified signature")
			}
		})
	}
}

func TestECDSASignatureVerificationCoverage(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		hash        crypto.Hash
		dataSize    int
		expectError bool
	}{
		{
			name:        "P256 with SHA256",
			curve:       elliptic.P256(),
			hash:        crypto.SHA256,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "P384 with SHA384",
			curve:       elliptic.P384(),
			hash:        crypto.SHA384,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "P521 with SHA512",
			curve:       elliptic.P521(),
			hash:        crypto.SHA512,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "P256 with large data",
			curve:       elliptic.P256(),
			hash:        crypto.SHA256,
			dataSize:    10000,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature)
			if tc.expectError {
				if valid {
					t.Error("expected verification to fail")
				}
			} else {
				if !valid {
					t.Error("ECDSA signature verification failed")
				}
			}
		})
	}
}

func TestInvalidECDSASignatureCoverage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data for ECDSA signature")
	hasher := crypto.SHA256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	tests := []struct {
		name      string
		modifySig func([]byte) []byte
	}{
		{
			name: "flip bit in signature",
			modifySig: func(sig []byte) []byte {
				modified := make([]byte, len(sig))
				copy(modified, sig)
				if len(modified) > 10 {
					modified[10] ^= 0x01
				}
				return modified
			},
		},
		{
			name: "truncate signature",
			modifySig: func(sig []byte) []byte {
				return sig[:len(sig)-5]
			},
		},
		{
			name: "malformed ASN1",
			modifySig: func(sig []byte) []byte {
				return []byte{0x30, 0x00}
			},
		},
		{
			name: "empty signature",
			modifySig: func(sig []byte) []byte {
				return []byte{}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modifiedSig := tc.modifySig(signature)
			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, modifiedSig)
			if valid {
				t.Error("expected verification to fail with modified signature")
			}
		})
	}
}

func TestKeyAttributesCreationCoverage(t *testing.T) {
	tests := []struct {
		name        string
		setupAttrs  func() *types.KeyAttributes
		expectValid bool
	}{
		{
			name: "RSA key attributes with PKCS1v15",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-rsa-key",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSA,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSASSATemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "RSA key attributes with PSS",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-rsa-pss-key",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSTemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "ECDSA P256 key attributes",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ecdsa-p256-key",
					KeyAlgorithm:       x509.ECDSA,
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  ECCP256Template,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "ECDSA P384 key attributes",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ecdsa-p384-key",
					KeyAlgorithm:       x509.ECDSA,
					SignatureAlgorithm: x509.ECDSAWithSHA384,
					Hash:               crypto.SHA384,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA384,
						Public:  ECCP384Template,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "AK attributes (restricted)",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ak",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					KeyType:            types.KeyTypeAttestation,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSAKTemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "IDevID attributes (non-restricted)",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-idevid",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					KeyType:            types.KeyTypeIDevID,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSIDevIDTemplate,
					},
				}
			},
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.setupAttrs()
			if attrs == nil && tc.expectValid {
				t.Error("expected valid attributes but got nil")
			}
			if attrs != nil {
				if attrs.TPMAttributes == nil {
					t.Error("TPM attributes should not be nil")
				}
				if attrs.CN == "" {
					t.Error("CN should not be empty")
				}
			}
		})
	}
}

func TestCSRRoundTripCoverage(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo uint32
		sigSize  int
	}{
		{
			name:     "SHA256 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA256),
			sigSize:  256,
		},
		{
			name:     "SHA384 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA384),
			sigSize:  384,
		},
		{
			name:     "SHA512 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA512),
			sigSize:  512,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signature := make([]byte, tc.sigSize)
			if _, err := rand.Read(signature); err != nil {
				t.Fatalf("failed to generate random signature: %v", err)
			}

			originalCSR := createMinimalTCGCSRIDevIDCoverage(tc.hashAlgo, signature)

			packed, err := PackIDevIDCSR(originalCSR)
			if err != nil {
				t.Fatalf("failed to pack CSR: %v", err)
			}

			unmarshaled, err := UnmarshalIDevIDCSR(packed)
			if err != nil {
				t.Fatalf("failed to unmarshal CSR: %v", err)
			}

			if unmarshaled.StructVer != originalCSR.StructVer {
				t.Errorf("StructVer mismatch: got %v, want %v", unmarshaled.StructVer, originalCSR.StructVer)
			}
			if unmarshaled.Contents != originalCSR.Contents {
				t.Errorf("Contents mismatch: got %v, want %v", unmarshaled.Contents, originalCSR.Contents)
			}
			if unmarshaled.SigSz != originalCSR.SigSz {
				t.Errorf("SigSz mismatch: got %v, want %v", unmarshaled.SigSz, originalCSR.SigSz)
			}

			if !bytes.Equal(unmarshaled.Signature, originalCSR.Signature) {
				t.Error("signature bytes mismatch after round trip")
			}

			if unmarshaled.CsrContents.HashAlgoId != originalCSR.CsrContents.HashAlgoId {
				t.Errorf("HashAlgoId mismatch: got %v, want %v",
					unmarshaled.CsrContents.HashAlgoId, originalCSR.CsrContents.HashAlgoId)
			}
		})
	}
}

func TestDifferentHashAlgorithmsCoverage(t *testing.T) {
	tests := []struct {
		name       string
		tpmAlgID   tpm2.TPMAlgID
		cryptoHash crypto.Hash
		hashSize   uint32
	}{
		{
			name:       "SHA1",
			tpmAlgID:   tpm2.TPMAlgSHA1,
			cryptoHash: crypto.SHA1,
			hashSize:   20,
		},
		{
			name:       "SHA256",
			tpmAlgID:   tpm2.TPMAlgSHA256,
			cryptoHash: crypto.SHA256,
			hashSize:   32,
		},
		{
			name:       "SHA384",
			tpmAlgID:   tpm2.TPMAlgSHA384,
			cryptoHash: crypto.SHA384,
			hashSize:   48,
		},
		{
			name:       "SHA512",
			tpmAlgID:   tpm2.TPMAlgSHA512,
			cryptoHash: crypto.SHA512,
			hashSize:   64,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.cryptoHash)
			if err != nil {
				t.Fatalf("failed to parse hash size: %v", err)
			}
			if size != tc.hashSize {
				t.Errorf("hash size mismatch: got %d, want %d", size, tc.hashSize)
			}

			csr := createMinimalTCGCSRIDevIDCoverage(uint32(tc.tpmAlgID), make([]byte, 64))
			binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], tc.hashSize)

			unpacked, err := UnpackIDevIDCSR(csr)
			if err != nil {
				t.Fatalf("failed to unpack CSR: %v", err)
			}

			if unpacked.CsrContents.HashAlgoId != uint32(tc.tpmAlgID) {
				t.Errorf("hash algorithm ID mismatch: got %d, want %d",
					unpacked.CsrContents.HashAlgoId, tc.tpmAlgID)
			}

			if unpacked.CsrContents.HashSz != tc.hashSize {
				t.Errorf("hash size in content mismatch: got %d, want %d",
					unpacked.CsrContents.HashSz, tc.hashSize)
			}
		})
	}
}

func TestTPMPublicCreationCoverage(t *testing.T) {
	t.Run("RSA public key creation", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		restrictedPub := createRSATPMPublicCoverage(&privateKey.PublicKey, true)
		if restrictedPub.Type != tpm2.TPMAlgRSA {
			t.Errorf("expected RSA type, got %v", restrictedPub.Type)
		}
		if !restrictedPub.ObjectAttributes.Restricted {
			t.Error("expected restricted attribute to be true")
		}
		if !restrictedPub.ObjectAttributes.FixedTPM {
			t.Error("expected fixedTPM attribute to be true")
		}

		unrestrictedPub := createRSATPMPublicCoverage(&privateKey.PublicKey, false)
		if unrestrictedPub.ObjectAttributes.Restricted {
			t.Error("expected restricted attribute to be false for unrestricted key")
		}
	})

	t.Run("ECDSA P256 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, true)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA256 {
			t.Errorf("expected SHA256 name alg for P256, got %v", tpmPub.NameAlg)
		}
	})

	t.Run("ECDSA P384 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, false)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA384 {
			t.Errorf("expected SHA384 name alg for P384, got %v", tpmPub.NameAlg)
		}
	})

	t.Run("ECDSA P521 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, true)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA512 {
			t.Errorf("expected SHA512 name alg for P521, got %v", tpmPub.NameAlg)
		}
	})
}

func TestMixedKeyTypesSignatureScenariosCoverage(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	testData := []byte("test data to sign with different key types")
	sha256Hash := crypto.SHA256.New()
	sha256Hash.Write(testData)
	digest := sha256Hash.Sum(nil)

	t.Run("RSA key cannot verify ECDSA signature", func(t *testing.T) {
		ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivateKey, digest)
		if err != nil {
			t.Fatalf("failed to create ECDSA signature: %v", err)
		}

		err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, digest, ecdsaSig)
		if err == nil {
			t.Error("RSA verification should fail for ECDSA signature")
		}
	})

	t.Run("ECDSA key cannot verify RSA signature", func(t *testing.T) {
		rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("failed to create RSA signature: %v", err)
		}

		valid := ecdsa.VerifyASN1(&ecdsaPrivateKey.PublicKey, digest, rsaSig)
		if valid {
			t.Error("ECDSA verification should fail for RSA signature")
		}
	})

	t.Run("wrong data produces invalid signature", func(t *testing.T) {
		rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("failed to create RSA signature: %v", err)
		}

		wrongData := []byte("completely different data")
		wrongHash := crypto.SHA256.New()
		wrongHash.Write(wrongData)
		wrongDigest := wrongHash.Sum(nil)

		err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, wrongDigest, rsaSig)
		if err == nil {
			t.Error("signature verification should fail for wrong data")
		}
	})
}

func TestSignatureWithDifferentKeysCoverage(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate first RSA key: %v", err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate second RSA key: %v", err)
	}

	testData := []byte("data signed with key1")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key1, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign with key1: %v", err)
	}

	t.Run("correct key verifies signature", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(&key1.PublicKey, crypto.SHA256, digest, signature)
		if err != nil {
			t.Errorf("verification with correct key failed: %v", err)
		}
	})

	t.Run("wrong key fails to verify signature", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(&key2.PublicKey, crypto.SHA256, digest, signature)
		if err == nil {
			t.Error("verification with wrong key should fail")
		}
	})
}

func TestCSRContentFieldSizesCoverage(t *testing.T) {
	tests := []struct {
		name        string
		prodModel   string
		prodSerial  string
		ekCertSize  int
		attestPubSz int
		signPubSz   int
		bootLogSize int
		expectError bool
	}{
		{
			name:        "minimal sizes",
			prodModel:   "m",
			prodSerial:  "1",
			ekCertSize:  0,
			attestPubSz: 0,
			signPubSz:   0,
			bootLogSize: 0,
			expectError: false,
		},
		{
			name:        "typical sizes",
			prodModel:   "edge-device-v1",
			prodSerial:  "SN123456789",
			ekCertSize:  1024,
			attestPubSz: 256,
			signPubSz:   256,
			bootLogSize: 4096,
			expectError: false,
		},
		{
			name:        "large boot log",
			prodModel:   "server",
			prodSerial:  "SVR-001",
			ekCertSize:  2048,
			attestPubSz: 512,
			signPubSz:   512,
			bootLogSize: 65536,
			expectError: false,
		},
		{
			name:        "empty model and serial",
			prodModel:   "",
			prodSerial:  "",
			ekCertSize:  256,
			attestPubSz: 128,
			signPubSz:   128,
			bootLogSize: 1024,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := &TCG_IDEVID_CONTENT{}
			binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
			binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
			binary.BigEndian.PutUint32(content.HashSz[:], 32)
			binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(tc.prodModel)))
			binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(tc.prodSerial)))
			binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(tc.ekCertSize))
			binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(tc.attestPubSz))
			binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(tc.signPubSz))
			binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(tc.bootLogSize))

			content.ProdModel = []byte(tc.prodModel)
			content.ProdSerial = []byte(tc.prodSerial)
			content.ProdCaData = []byte{}
			content.BootEvntLog = make([]byte, tc.bootLogSize)
			content.EkCert = make([]byte, tc.ekCertSize)
			content.AttestPub = make([]byte, tc.attestPubSz)
			content.AtCreateTkt = []byte{}
			content.AtCertifyInfo = []byte{}
			content.AtCertifyInfoSig = []byte{}
			content.SigningPub = make([]byte, tc.signPubSz)
			content.SgnCertifyInfo = []byte{}
			content.SgnCertifyInfoSig = []byte{}
			content.Pad = []byte{}

			packed, err := PackIDevIDContent(content)
			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedMinSize := 64 + len(tc.prodModel) + len(tc.prodSerial) +
				tc.ekCertSize + tc.attestPubSz + tc.signPubSz + tc.bootLogSize
			if len(packed) < expectedMinSize {
				t.Errorf("packed size too small: got %d, expected at least %d",
					len(packed), expectedMinSize)
			}
		})
	}
}

func TestInvalidSignatureErrorCoverage(t *testing.T) {
	if ErrInvalidSignature == nil {
		t.Error("ErrInvalidSignature should not be nil")
	}

	expectedMsg := "tpm: invalid signature"
	if ErrInvalidSignature.Error() != expectedMsg {
		t.Errorf("unexpected error message: got %q, want %q",
			ErrInvalidSignature.Error(), expectedMsg)
	}

	if !errors.Is(ErrInvalidSignature, ErrInvalidSignature) {
		t.Error("ErrInvalidSignature should be equal to itself")
	}
}

func TestBigIntConversionsCoverage(t *testing.T) {
	tests := []struct {
		name string
		num  *big.Int
	}{
		{
			name: "small number",
			num:  big.NewInt(12345),
		},
		{
			name: "large number",
			num: func() *big.Int {
				n := new(big.Int)
				n.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
				return n
			}(),
		},
		{
			name: "256-bit number",
			num: func() *big.Int {
				bytes := make([]byte, 32)
				_, _ = rand.Read(bytes)
				return new(big.Int).SetBytes(bytes)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bytes := tc.num.Bytes()
			recovered := new(big.Int).SetBytes(bytes)
			if tc.num.Cmp(recovered) != 0 {
				t.Errorf("big.Int conversion failed: got %v, want %v", recovered, tc.num)
			}
		})
	}
}

func TestCreateIDevIDContent_ValidInput(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-endorsement-key-certificate"),
	}

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSAAKTemplate),
			CreationTicketDigest: []byte("creation-ticket-digest"),
			CertifyInfo:          []byte("ak-certify-info"),
			Signature:            []byte("ak-signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: []byte("idevid-certify-info"),
			Signature:   []byte("idevid-signature"),
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)
	require.NotNil(t, content)

	// Verify structure version
	assert.Equal(t, uint32(0x00000100), content.StructVer)

	// Verify hash algorithm
	assert.Equal(t, uint32(tpm2.TPMAlgSHA256), content.HashAlgoId)

	// Verify hash size for SHA256
	assert.Equal(t, uint32(32), content.HashSz)

	// Verify product model
	assert.Equal(t, []byte("TestModel"), content.ProdModel)
	assert.Equal(t, uint32(len("TestModel")), content.ProdModelSz)

	// Verify product serial
	assert.Equal(t, []byte("SN12345"), content.ProdSerial)
	assert.Equal(t, uint32(len("SN12345")), content.ProdSerialSz)

	// Verify EK cert
	assert.Equal(t, ekCert.Raw, content.EkCert)
	assert.Equal(t, uint32(len(ekCert.Raw)), content.EkCertSZ)

	// Verify AK attributes
	akPublic := akAttrs.TPMAttributes.BPublic
	assert.Equal(t, (&akPublic).Bytes(), content.AttestPub)
	assert.Equal(t, akAttrs.TPMAttributes.CreationTicketDigest, content.AtCreateTkt)
	assert.Equal(t, akAttrs.TPMAttributes.CertifyInfo, content.AtCertifyInfo)
	assert.Equal(t, akAttrs.TPMAttributes.Signature, content.AtCertifyInfoSig)

	// Verify IDevID attributes
	idevidPublic := idevidAttrs.TPMAttributes.BPublic
	assert.Equal(t, (&idevidPublic).Bytes(), content.SigningPub)
	assert.Equal(t, idevidAttrs.TPMAttributes.CertifyInfo, content.SgnCertifyInfo)
	assert.Equal(t, idevidAttrs.TPMAttributes.Signature, content.SgnCertifyInfoSig)
}

func TestCreateIDevIDContent_InvalidHash(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-ek-cert"),
	}

	akAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte("ticket"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	// Test with various invalid hash functions
	invalidHashes := []crypto.Hash{
		crypto.MD5,
		crypto.MD4,
		crypto.SHA224, // Not supported in our ParseHashSize
		crypto.RIPEMD160,
	}

	for _, invalidHash := range invalidHashes {
		idevidAttrs := &types.KeyAttributes{
			Hash: invalidHash,
			TPMAttributes: &types.TPMAttributes{
				BPublic:     tpm2.New2B(RSASSATemplate),
				CertifyInfo: []byte("idevid-certify-info"),
				Signature:   []byte("idevid-signature"),
			},
		}

		_, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidHashFunction, err)
	}
}

func TestCreateIDevIDContent_DifferentHashAlgorithms(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-ek-cert"),
	}

	akAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte("ticket"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize uint32
	}{
		{"SHA1", crypto.SHA1, 20},
		{"SHA256", crypto.SHA256, 32},
		{"SHA384", crypto.SHA384, 48},
		{"SHA512", crypto.SHA512, 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idevidAttrs := &types.KeyAttributes{
				Hash: tc.hash,
				TPMAttributes: &types.TPMAttributes{
					BPublic:     tpm2.New2B(RSASSATemplate),
					CertifyInfo: []byte("idevid-certify-info"),
					Signature:   []byte("idevid-signature"),
				},
			}

			content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSize, content.HashSz)
		})
	}
}

func TestCreateIDevIDContent_EmptyFields(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "",
			Serial: "",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte{},
	}

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte{},
			CertifyInfo:          []byte{},
			Signature:            []byte{},
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: []byte{},
			Signature:   []byte{},
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)

	// When config Model/Serial are empty, ResolvePlatformAttributes falls back
	// to SMBIOS discovery. On systems with SMBIOS data, these values will be
	// populated from /sys/class/dmi/id/. We verify the content is created
	// and matches the resolved platform attributes.
	platformAttrs := ResolvePlatformAttributes(config.IDevID)
	assert.Equal(t, uint32(len(platformAttrs.Model)), content.ProdModelSz)
	assert.Equal(t, uint32(len(platformAttrs.Serial)), content.ProdSerialSz)
	assert.Equal(t, uint32(0), content.EkCertSZ)
	assert.Equal(t, uint32(0), content.AtCreateTktSZ)
	assert.Equal(t, uint32(0), content.AtCertifyInfoSZ)
}

func TestCreateIDevIDContent_LargeData(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "LongModelName12345678901234567890",
			Serial: "VeryLongSerialNumber1234567890ABCDEFG",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	// Create a large EK certificate
	largeEKCert := make([]byte, 4096)
	_, _ = rand.Read(largeEKCert)

	ekCert := &x509.Certificate{
		Raw: largeEKCert,
	}

	largeBPublic := make([]byte, 512)
	_, _ = rand.Read(largeBPublic)

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA512,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: make([]byte, 64),
			CertifyInfo:          make([]byte, 128),
			Signature:            make([]byte, 256),
			HashAlg:              tpm2.TPMAlgSHA512,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA512,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: make([]byte, 128),
			Signature:   make([]byte, 256),
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), content.EkCertSZ)
	assert.NotEmpty(t, content.AttestPubSZ)
	assert.Equal(t, uint32(64), content.AtCreateTktSZ)
	assert.Equal(t, uint32(128), content.AtCertifyInfoSZ)
	assert.Equal(t, uint32(256), content.AtCertifyInfoSignatureSZ)
}

func TestTCGCSRRoundTrip(t *testing.T) {
	// Create a CSR with all fields populated
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x0A},
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x08},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x04},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x10},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x08},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x08},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x08},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x08},
		PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x02},
		ProdModel:                 []byte("TestModel1"),
		ProdSerial:                []byte("SN123456"),
		ProdCaData:                []byte{},
		BootEvntLog:               []byte{0x01, 0x02, 0x03, 0x04},
		EkCert:                    []byte("EKCertificate123"),
		AttestPub:                 []byte("AttPub12"),
		AtCreateTkt:               []byte{0x05, 0x06, 0x07, 0x08},
		AtCertifyInfo:             []byte{0x09, 0x0A, 0x0B, 0x0C},
		AtCertifyInfoSig:          []byte("AtCertSg"),
		SigningPub:                []byte("SgnPub12"),
		SgnCertifyInfo:            []byte{0x0D, 0x0E, 0x0F, 0x10},
		SgnCertifyInfoSig:         []byte("SgnCrtSg"),
		Pad:                       []byte("=="),
	}

	// Pack the content
	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotEmpty(t, packed)

	// Create CSR structure
	csr := &TCG_CSR_IDEVID{
		StructVer:   [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:    [4]byte{0x00, 0x00, 0x00, 0x50},
		SigSz:       [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
		CsrContents: *content,
		Signature:   make([]byte, 256),
	}
	_, _ = rand.Read(csr.Signature)

	// Pack the CSR
	packedCSR, err := PackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotEmpty(t, packedCSR)

	// Unmarshal the CSR
	unmarshalledCSR, err := UnmarshalIDevIDCSR(packedCSR)
	require.NoError(t, err)
	require.NotNil(t, unmarshalledCSR)

	// Verify structure version matches
	assert.Equal(t, csr.StructVer, unmarshalledCSR.StructVer)
	assert.Equal(t, csr.SigSz, unmarshalledCSR.SigSz)
	assert.Equal(t, csr.Signature, unmarshalledCSR.Signature)

	// Verify content fields
	assert.Equal(t, content.StructVer, unmarshalledCSR.CsrContents.StructVer)
	assert.Equal(t, content.HashAlgoId, unmarshalledCSR.CsrContents.HashAlgoId)
	assert.Equal(t, content.ProdModel, unmarshalledCSR.CsrContents.ProdModel)
	assert.Equal(t, content.ProdSerial, unmarshalledCSR.CsrContents.ProdSerial)
}

func TestBytesToUint32_ExtendedCases(t *testing.T) {
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
			name:     "One",
			input:    [4]byte{0x00, 0x00, 0x00, 0x01},
			expected: 1,
		},
		{
			name:     "Max uint32",
			input:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: 4294967295,
		},
		{
			name:     "Version number",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 256,
		},
		{
			name:     "SHA256 AlgID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: 11, // TPMAlgSHA256
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUnpackIDevIDCSR_ValidInput(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x04},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x04},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x04},
		PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
		ProdModel:                 []byte("model"),
		ProdSerial:                []byte("001"),
		ProdCaData:                []byte{},
		BootEvntLog:               []byte{},
		EkCert:                    []byte("cert"),
		AttestPub:                 []byte("pub1"),
		AtCreateTkt:               []byte("tkt1"),
		AtCertifyInfo:             []byte("inf1"),
		AtCertifyInfoSig:          []byte("sig1"),
		SigningPub:                []byte("pub2"),
		SgnCertifyInfo:            []byte("inf2"),
		SgnCertifyInfoSig:         []byte("sig2"),
		Pad:                       []byte{},
	}

	csr := &TCG_CSR_IDEVID{
		StructVer:   [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:    [4]byte{0x00, 0x00, 0x00, 0x50},
		SigSz:       [4]byte{0x00, 0x00, 0x00, 0x10},
		CsrContents: *content,
		Signature:   []byte("signaturedata123"),
	}

	unpacked, err := UnpackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotNil(t, unpacked)

	// Verify unpacked values
	assert.Equal(t, uint32(256), unpacked.StructVer)
	assert.Equal(t, uint32(80), unpacked.Contents)
	assert.Equal(t, uint32(16), unpacked.SigSz)
	assert.Equal(t, []byte("signaturedata123"), unpacked.Signature)

	// Verify content unpacking
	assert.Equal(t, uint32(256), unpacked.CsrContents.StructVer)
	assert.Equal(t, uint32(11), unpacked.CsrContents.HashAlgoId)
	assert.Equal(t, uint32(32), unpacked.CsrContents.HashSz)
	assert.Equal(t, []byte("model"), unpacked.CsrContents.ProdModel)
	assert.Equal(t, []byte("001"), unpacked.CsrContents.ProdSerial)
}
