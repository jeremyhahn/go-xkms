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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProdCaData tests the creation of ProdCaData from a Quote
func TestNewProdCaData(t *testing.T) {
	t.Run("creates ProdCaData from valid Quote", func(t *testing.T) {
		quote := &Quote{
			Quoted:    []byte("test-quoted-data"),
			Signature: []byte("test-signature"),
			Nonce:     []byte("test-nonce"),
			PCRs:      []byte("test-pcrs"),
			EventLog:  []byte("test-eventlog"), // EventLog is NOT included in ProdCaData
		}

		prodCaData, err := NewProdCaData(quote)
		require.NoError(t, err)
		require.NotNil(t, prodCaData)

		assert.Equal(t, ProdCaDataVersion, prodCaData.Version)
		assert.Equal(t, uint32(len(quote.Quoted)), prodCaData.QuotedSz)
		assert.Equal(t, uint32(len(quote.Signature)), prodCaData.SignatureSz)
		assert.Equal(t, uint32(len(quote.Nonce)), prodCaData.NonceSz)
		assert.Equal(t, uint32(len(quote.PCRs)), prodCaData.PCRsSz)
		assert.Equal(t, quote.Quoted, prodCaData.Quoted)
		assert.Equal(t, quote.Signature, prodCaData.Signature)
		assert.Equal(t, quote.Nonce, prodCaData.Nonce)
		assert.Equal(t, quote.PCRs, prodCaData.PCRs)
	})

	t.Run("returns nil for nil Quote", func(t *testing.T) {
		prodCaData, err := NewProdCaData(nil)
		require.NoError(t, err)
		assert.Nil(t, prodCaData)
	})

	t.Run("creates ProdCaData with empty fields", func(t *testing.T) {
		quote := &Quote{
			Quoted:    nil,
			Signature: nil,
			Nonce:     nil,
			PCRs:      nil,
		}

		prodCaData, err := NewProdCaData(quote)
		require.NoError(t, err)
		require.NotNil(t, prodCaData)

		assert.Equal(t, uint32(0), prodCaData.QuotedSz)
		assert.Equal(t, uint32(0), prodCaData.SignatureSz)
		assert.Equal(t, uint32(0), prodCaData.NonceSz)
		assert.Equal(t, uint32(0), prodCaData.PCRsSz)
	})
}

// TestPackProdCaData tests Pack function edge cases
func TestPackProdCaData(t *testing.T) {
	t.Run("returns nil for nil input", func(t *testing.T) {
		packed, err := PackProdCaData(nil)
		require.NoError(t, err)
		assert.Nil(t, packed)
	})

	t.Run("produces expected header size", func(t *testing.T) {
		prodCaData := &ProdCaData{
			Version:     ProdCaDataVersion,
			QuotedSz:    0,
			SignatureSz: 0,
			NonceSz:     0,
			PCRsSz:      0,
		}

		packed, err := PackProdCaData(prodCaData)
		require.NoError(t, err)

		// Header should be 5 * 4 = 20 bytes (version + 4 size fields)
		expectedHeaderSize := 20
		assert.Equal(t, expectedHeaderSize, len(packed))
	})

	t.Run("produces correct total size", func(t *testing.T) {
		dataSize := 100
		prodCaData := &ProdCaData{
			Version:     ProdCaDataVersion,
			QuotedSz:    uint32(dataSize),
			SignatureSz: uint32(dataSize),
			NonceSz:     uint32(dataSize),
			PCRsSz:      uint32(dataSize),
			Quoted:      bytes.Repeat([]byte{0x01}, dataSize),
			Signature:   bytes.Repeat([]byte{0x02}, dataSize),
			Nonce:       bytes.Repeat([]byte{0x03}, dataSize),
			PCRs:        bytes.Repeat([]byte{0x04}, dataSize),
		}

		packed, err := PackProdCaData(prodCaData)
		require.NoError(t, err)

		// Total size = header (20) + 4 * dataSize
		expectedSize := 20 + (4 * dataSize)
		assert.Equal(t, expectedSize, len(packed))
	})
}

// TestUnpackProdCaData tests Unpack function edge cases
func TestUnpackProdCaData(t *testing.T) {
	t.Run("returns nil for empty input", func(t *testing.T) {
		unpacked, err := UnpackProdCaData(nil)
		require.NoError(t, err)
		assert.Nil(t, unpacked)

		unpacked, err = UnpackProdCaData([]byte{})
		require.NoError(t, err)
		assert.Nil(t, unpacked)
	})

	t.Run("returns error for truncated header", func(t *testing.T) {
		// Less than 20 bytes (header size)
		truncated := []byte{0x00, 0x00, 0x00, 0x01}
		_, err := UnpackProdCaData(truncated)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})

	t.Run("returns error for invalid version", func(t *testing.T) {
		invalid := bytes.Repeat([]byte{0xFF}, 20)
		_, err := UnpackProdCaData(invalid)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})

	t.Run("returns error for truncated data", func(t *testing.T) {
		// Valid header claiming 100 bytes of data but only providing header
		prodCaData := &ProdCaData{
			Version:     ProdCaDataVersion,
			QuotedSz:    100,
			SignatureSz: 100,
			NonceSz:     100,
			PCRsSz:      100,
			Quoted:      bytes.Repeat([]byte{0x01}, 100),
			Signature:   bytes.Repeat([]byte{0x02}, 100),
			Nonce:       bytes.Repeat([]byte{0x03}, 100),
			PCRs:        bytes.Repeat([]byte{0x04}, 100),
		}

		packed, err := PackProdCaData(prodCaData)
		require.NoError(t, err)

		// Truncate the data after header
		truncated := packed[:21] // Just header + 1 byte
		_, err = UnpackProdCaData(truncated)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})
}

// TestProdCaDataLargeData tests handling of larger attestation data
func TestProdCaDataLargeData(t *testing.T) {
	t.Run("handles typical attestation data sizes", func(t *testing.T) {
		// Typical sizes from real TPM attestation
		quote := &Quote{
			Quoted:    bytes.Repeat([]byte{0x01}, 172), // Typical TPMS_ATTEST size
			Signature: bytes.Repeat([]byte{0x02}, 256), // RSA-2048 signature
			Nonce:     bytes.Repeat([]byte{0x03}, 32),  // SHA-256 nonce
			PCRs:      bytes.Repeat([]byte{0x04}, 768), // 24 PCRs * 32 bytes
		}

		prodCaData, err := NewProdCaData(quote)
		require.NoError(t, err)

		packed, err := PackProdCaData(prodCaData)
		require.NoError(t, err)

		unpacked, err := UnpackProdCaData(packed)
		require.NoError(t, err)

		resultQuote := unpacked.ToQuote()
		assert.Equal(t, quote.Quoted, resultQuote.Quoted)
		assert.Equal(t, quote.Signature, resultQuote.Signature)
		assert.Equal(t, quote.Nonce, resultQuote.Nonce)
		assert.Equal(t, quote.PCRs, resultQuote.PCRs)
	})

	t.Run("handles large PCR data (all banks)", func(t *testing.T) {
		// Simulate all PCR banks and values
		// SHA-1: 24 PCRs * 20 bytes = 480 bytes
		// SHA-256: 24 PCRs * 32 bytes = 768 bytes
		// SHA-384: 24 PCRs * 48 bytes = 1152 bytes
		// SHA-512: 24 PCRs * 64 bytes = 1536 bytes
		// Total: ~4KB for all banks
		largePCRs := bytes.Repeat([]byte{0x00}, 4*1024)

		quote := &Quote{
			Quoted:    bytes.Repeat([]byte{0x01}, 200),
			Signature: bytes.Repeat([]byte{0x02}, 512), // RSA-4096
			Nonce:     bytes.Repeat([]byte{0x03}, 64),  // SHA-512 nonce
			PCRs:      largePCRs,
		}

		prodCaData, err := NewProdCaData(quote)
		require.NoError(t, err)

		packed, err := PackProdCaData(prodCaData)
		require.NoError(t, err)

		unpacked, err := UnpackProdCaData(packed)
		require.NoError(t, err)

		assert.Equal(t, quote.PCRs, unpacked.PCRs)
	})
}

// TestUnpackProdCaData_HeaderTruncation tests all header truncation scenarios
func TestUnpackProdCaData_HeaderTruncation(t *testing.T) {
	// Build a valid packed structure first
	validData := &ProdCaData{
		Version:     ProdCaDataVersion,
		QuotedSz:    4,
		SignatureSz: 4,
		NonceSz:     4,
		PCRsSz:      4,
		Quoted:      []byte{1, 2, 3, 4},
		Signature:   []byte{5, 6, 7, 8},
		Nonce:       []byte{9, 10, 11, 12},
		PCRs:        []byte{13, 14, 15, 16},
	}
	packed, err := PackProdCaData(validData)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		length int // truncate at this length
	}{
		{"truncated before version complete", 3},
		{"truncated at quotedSz", 4},
		{"truncated before quotedSz complete", 7},
		{"truncated at signatureSz", 8},
		{"truncated before signatureSz complete", 11},
		{"truncated at nonceSz", 12},
		{"truncated before nonceSz complete", 15},
		{"truncated at pcrsSz", 16},
		{"truncated before pcrsSz complete", 19},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			truncated := packed[:tc.length]
			_, err := UnpackProdCaData(truncated)
			assert.Error(t, err)
			assert.Equal(t, ErrInvalidProdCaData, err)
		})
	}
}

// TestUnpackProdCaData_PayloadTruncation tests payload truncation at different fields
func TestUnpackProdCaData_PayloadTruncation(t *testing.T) {
	// Build a valid packed structure
	validData := &ProdCaData{
		Version:     ProdCaDataVersion,
		QuotedSz:    10,
		SignatureSz: 10,
		NonceSz:     10,
		PCRsSz:      10,
		Quoted:      bytes.Repeat([]byte{0x01}, 10),
		Signature:   bytes.Repeat([]byte{0x02}, 10),
		Nonce:       bytes.Repeat([]byte{0x03}, 10),
		PCRs:        bytes.Repeat([]byte{0x04}, 10),
	}
	packed, err := PackProdCaData(validData)
	require.NoError(t, err)

	// Total size should be 20 (header) + 40 (data) = 60 bytes
	assert.Equal(t, 60, len(packed))

	testCases := []struct {
		name        string
		length      int
		description string
	}{
		{"truncated during quoted read", 25, "header(20) + 5 bytes of quoted"},
		{"truncated during signature read", 35, "header(20) + quoted(10) + 5 bytes of signature"},
		{"truncated during nonce read", 45, "header(20) + quoted(10) + signature(10) + 5 bytes of nonce"},
		{"truncated during pcrs read", 55, "header(20) + quoted(10) + signature(10) + nonce(10) + 5 bytes of pcrs"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			truncated := packed[:tc.length]
			_, err := UnpackProdCaData(truncated)
			assert.Error(t, err, tc.description)
			assert.Equal(t, ErrInvalidProdCaData, err)
		})
	}
}

// TestUnpackProdCaData_SizeOverflowCheck tests the data size validation
func TestUnpackProdCaData_SizeOverflowCheck(t *testing.T) {
	// Create a header that claims more data than is present
	// This tests the expectedDataSize check at line 186-188

	t.Run("claimed size exceeds actual data - quoted", func(t *testing.T) {
		// Create packed data with header claiming 1000 bytes but only providing 10
		header := make([]byte, 20)
		// Version = 1
		header[0], header[1], header[2], header[3] = 0, 0, 0, 1
		// QuotedSz = 1000 (0x000003E8)
		header[4], header[5], header[6], header[7] = 0, 0, 0x03, 0xE8
		// SignatureSz = 0
		header[8], header[9], header[10], header[11] = 0, 0, 0, 0
		// NonceSz = 0
		header[12], header[13], header[14], header[15] = 0, 0, 0, 0
		// PCRsSz = 0
		header[16], header[17], header[18], header[19] = 0, 0, 0, 0

		// Only add 10 bytes of actual data
		data := append(header, bytes.Repeat([]byte{0x01}, 10)...)

		_, err := UnpackProdCaData(data)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})

	t.Run("claimed size exceeds actual data - signature", func(t *testing.T) {
		header := make([]byte, 20)
		header[0], header[1], header[2], header[3] = 0, 0, 0, 1         // Version
		header[4], header[5], header[6], header[7] = 0, 0, 0, 5         // QuotedSz = 5
		header[8], header[9], header[10], header[11] = 0, 0, 0x03, 0xE8 // SignatureSz = 1000
		header[12], header[13], header[14], header[15] = 0, 0, 0, 0
		header[16], header[17], header[18], header[19] = 0, 0, 0, 0

		// Add just enough for header + quoted, but not signature
		data := append(header, bytes.Repeat([]byte{0x01}, 5)...)

		_, err := UnpackProdCaData(data)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})

	t.Run("claimed size exceeds actual data - nonce", func(t *testing.T) {
		header := make([]byte, 20)
		header[0], header[1], header[2], header[3] = 0, 0, 0, 1
		header[4], header[5], header[6], header[7] = 0, 0, 0, 5           // QuotedSz = 5
		header[8], header[9], header[10], header[11] = 0, 0, 0, 5         // SignatureSz = 5
		header[12], header[13], header[14], header[15] = 0, 0, 0x03, 0xE8 // NonceSz = 1000
		header[16], header[17], header[18], header[19] = 0, 0, 0, 0

		// Add header + quoted + signature, but not enough for nonce
		data := append(header, bytes.Repeat([]byte{0x01}, 10)...)

		_, err := UnpackProdCaData(data)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})

	t.Run("claimed size exceeds actual data - pcrs", func(t *testing.T) {
		header := make([]byte, 20)
		header[0], header[1], header[2], header[3] = 0, 0, 0, 1
		header[4], header[5], header[6], header[7] = 0, 0, 0, 5           // QuotedSz = 5
		header[8], header[9], header[10], header[11] = 0, 0, 0, 5         // SignatureSz = 5
		header[12], header[13], header[14], header[15] = 0, 0, 0, 5       // NonceSz = 5
		header[16], header[17], header[18], header[19] = 0, 0, 0x03, 0xE8 // PCRsSz = 1000

		// Add header + quoted + signature + nonce, but not enough for pcrs
		data := append(header, bytes.Repeat([]byte{0x01}, 15)...)

		_, err := UnpackProdCaData(data)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidProdCaData, err)
	})
}

// BenchmarkProdCaDataPack benchmarks packing performance
func BenchmarkProdCaDataPack(b *testing.B) {
	prodCaData := &ProdCaData{
		Version:     ProdCaDataVersion,
		QuotedSz:    172,
		SignatureSz: 256,
		NonceSz:     32,
		PCRsSz:      768,
		Quoted:      bytes.Repeat([]byte{0x01}, 172),
		Signature:   bytes.Repeat([]byte{0x02}, 256),
		Nonce:       bytes.Repeat([]byte{0x03}, 32),
		PCRs:        bytes.Repeat([]byte{0x04}, 768),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PackProdCaData(prodCaData)
	}
}

// BenchmarkProdCaDataUnpack benchmarks unpacking performance
func BenchmarkProdCaDataUnpack(b *testing.B) {
	prodCaData := &ProdCaData{
		Version:     ProdCaDataVersion,
		QuotedSz:    172,
		SignatureSz: 256,
		NonceSz:     32,
		PCRsSz:      768,
		Quoted:      bytes.Repeat([]byte{0x01}, 172),
		Signature:   bytes.Repeat([]byte{0x02}, 256),
		Nonce:       bytes.Repeat([]byte{0x03}, 32),
		PCRs:        bytes.Repeat([]byte{0x04}, 768),
	}

	packed, _ := PackProdCaData(prodCaData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnpackProdCaData(packed)
	}
}
