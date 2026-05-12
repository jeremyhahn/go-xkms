// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ct

import (
	"bytes"
	"crypto/x509/pkix"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakePrecertPoisonExtension(t *testing.T) {
	ext := MakePrecertPoisonExtension()

	assert.True(t, ext.Id.Equal(OIDPrecertPoison), "OID should match precert poison OID")
	assert.True(t, ext.Critical, "extension should be critical")
	assert.Equal(t, []byte{0x05, 0x00}, ext.Value, "value should be ASN.1 NULL")
}

func TestMakeSCTListExtension(t *testing.T) {
	t.Run("single SCT", func(t *testing.T) {
		scts := []SignedCertificateTimestamp{
			createTestSCT(1),
		}

		ext, err := MakeSCTListExtension(scts)
		require.NoError(t, err)

		assert.True(t, ext.Id.Equal(OIDSCTList), "OID should match SCT list OID")
		assert.False(t, ext.Critical, "extension should not be critical")
		assert.NotEmpty(t, ext.Value, "value should not be empty")
	})

	t.Run("multiple SCTs", func(t *testing.T) {
		scts := []SignedCertificateTimestamp{
			createTestSCT(1),
			createTestSCT(2),
			createTestSCT(3),
		}

		ext, err := MakeSCTListExtension(scts)
		require.NoError(t, err)

		assert.True(t, ext.Id.Equal(OIDSCTList), "OID should match SCT list OID")
		assert.NotEmpty(t, ext.Value)
	})

	t.Run("empty SCT list", func(t *testing.T) {
		_, err := MakeSCTListExtension(nil)
		assert.ErrorIs(t, err, ErrNilInput)

		_, err = MakeSCTListExtension([]SignedCertificateTimestamp{})
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("SCT with extensions", func(t *testing.T) {
		sct := createTestSCT(1)
		sct.Extensions = []byte{0x01, 0x02, 0x03, 0x04}

		ext, err := MakeSCTListExtension([]SignedCertificateTimestamp{sct})
		require.NoError(t, err)
		assert.NotEmpty(t, ext.Value)

		// Round trip to verify extensions are preserved
		parsed, err := ParseSCTList(ext.Value)
		require.NoError(t, err)
		require.Len(t, parsed, 1)
		assert.Equal(t, sct.Extensions, parsed[0].Extensions)
	})
}

func TestSerializeSCT(t *testing.T) {
	t.Run("valid SCT", func(t *testing.T) {
		sct := createTestSCT(1)

		data, err := SerializeSCT(&sct)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Verify format:
		// 1 byte version + 32 bytes log ID + 8 bytes timestamp +
		// 2 bytes ext len + ext data + 1 byte hash alg + 1 byte sig alg +
		// 2 bytes sig len + sig data
		assert.GreaterOrEqual(t, len(data), 47)

		// Check version
		assert.Equal(t, byte(V1), data[0])

		// Check log ID
		assert.Equal(t, sct.LogID[:], data[1:33])
	})

	t.Run("nil SCT", func(t *testing.T) {
		_, err := SerializeSCT(nil)
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("SCT with extensions", func(t *testing.T) {
		sct := createTestSCT(1)
		sct.Extensions = []byte{0xDE, 0xAD, 0xBE, 0xEF}

		data, err := SerializeSCT(&sct)
		require.NoError(t, err)

		// Deserialize and verify extensions
		parsed, err := DeserializeSCT(data)
		require.NoError(t, err)
		assert.Equal(t, sct.Extensions, parsed.Extensions)
	})

	t.Run("SCT with large signature", func(t *testing.T) {
		sct := createTestSCT(1)
		sct.Signature.Signature = bytes.Repeat([]byte{0xAB}, 256)

		data, err := SerializeSCT(&sct)
		require.NoError(t, err)

		parsed, err := DeserializeSCT(data)
		require.NoError(t, err)
		assert.Equal(t, sct.Signature.Signature, parsed.Signature.Signature)
	})
}

func TestDeserializeSCT(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		original := createTestSCT(42)

		data, err := SerializeSCT(&original)
		require.NoError(t, err)

		parsed, err := DeserializeSCT(data)
		require.NoError(t, err)

		assert.Equal(t, original.Version, parsed.Version)
		assert.Equal(t, original.LogID, parsed.LogID)
		assert.Equal(t, original.Timestamp, parsed.Timestamp)
		assert.Equal(t, original.Extensions, parsed.Extensions)
		assert.Equal(t, original.Signature.HashAlgorithm, parsed.Signature.HashAlgorithm)
		assert.Equal(t, original.Signature.SigAlgorithm, parsed.Signature.SigAlgorithm)
		assert.Equal(t, original.Signature.Signature, parsed.Signature.Signature)
	})

	t.Run("too short", func(t *testing.T) {
		_, err := DeserializeSCT([]byte{0x00, 0x01, 0x02})
		assert.Error(t, err)
	})

	t.Run("empty", func(t *testing.T) {
		_, err := DeserializeSCT(nil)
		assert.Error(t, err)

		_, err = DeserializeSCT([]byte{})
		assert.Error(t, err)
	})

	t.Run("truncated at log ID", func(t *testing.T) {
		// Build valid prefix but truncate at log ID
		data := make([]byte, 20) // Only enough for version + partial log ID
		data[0] = byte(V1)
		_, err := DeserializeSCT(data)
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("truncated at timestamp", func(t *testing.T) {
		// Version + full log ID but no timestamp
		data := make([]byte, 37) // 1 + 32 + 4 (partial timestamp)
		data[0] = byte(V1)
		_, err := DeserializeSCT(data)
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("truncated at extensions length", func(t *testing.T) {
		// Version + log ID + timestamp but no extensions length
		data := make([]byte, 42) // 1 + 32 + 8 + 1 (partial ext len)
		data[0] = byte(V1)
		_, err := DeserializeSCT(data)
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("extensions length exceeds data", func(t *testing.T) {
		// Build a valid header with extension length claiming more data than available
		data := make([]byte, 47)
		data[0] = byte(V1) // version
		data[41] = 0x00    // ext len high byte
		data[42] = 0x10    // ext len low byte (claims 16 bytes)
		_, err := DeserializeSCT(data)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
	})

	t.Run("truncated at hash algorithm", func(t *testing.T) {
		// Build valid structure up to extensions, but truncate at hash algorithm
		sct := createTestSCT(1)
		data, err := SerializeSCT(&sct)
		require.NoError(t, err)

		// Truncate after extensions (version + logID + timestamp + extLen + ext = 43)
		_, err = DeserializeSCT(data[:43])
		assert.Error(t, err)
	})

	t.Run("truncated at signature algorithm", func(t *testing.T) {
		sct := createTestSCT(1)
		data, err := SerializeSCT(&sct)
		require.NoError(t, err)

		// Truncate after hash algorithm (43 + 1 = 44)
		_, err = DeserializeSCT(data[:44])
		assert.Error(t, err)
	})

	t.Run("truncated at signature length", func(t *testing.T) {
		sct := createTestSCT(1)
		data, err := SerializeSCT(&sct)
		require.NoError(t, err)

		// Truncate at signature length (43 + 1 + 1 + 1 = 46, partial sig len)
		_, err = DeserializeSCT(data[:46])
		assert.Error(t, err)
	})

	t.Run("with extensions round trip", func(t *testing.T) {
		original := createTestSCT(1)
		original.Extensions = []byte{0x01, 0x02, 0x03, 0x04, 0x05}

		data, err := SerializeSCT(&original)
		require.NoError(t, err)

		parsed, err := DeserializeSCT(data)
		require.NoError(t, err)
		assert.Equal(t, original.Extensions, parsed.Extensions)
	})
}

func TestParseSCTList(t *testing.T) {
	t.Run("round trip single", func(t *testing.T) {
		original := []SignedCertificateTimestamp{
			createTestSCT(1),
		}

		ext, err := MakeSCTListExtension(original)
		require.NoError(t, err)

		parsed, err := ParseSCTList(ext.Value)
		require.NoError(t, err)
		require.Len(t, parsed, 1)

		assert.Equal(t, original[0].Version, parsed[0].Version)
		assert.Equal(t, original[0].LogID, parsed[0].LogID)
		assert.Equal(t, original[0].Timestamp, parsed[0].Timestamp)
	})

	t.Run("round trip multiple", func(t *testing.T) {
		original := []SignedCertificateTimestamp{
			createTestSCT(1),
			createTestSCT(2),
			createTestSCT(3),
		}

		ext, err := MakeSCTListExtension(original)
		require.NoError(t, err)

		parsed, err := ParseSCTList(ext.Value)
		require.NoError(t, err)
		require.Len(t, parsed, 3)

		for i := range original {
			assert.Equal(t, original[i].LogID, parsed[i].LogID)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseSCTList(nil)
		assert.ErrorIs(t, err, ErrNilInput)

		_, err = ParseSCTList([]byte{})
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("invalid length", func(t *testing.T) {
		// Total length claims more than available
		data := []byte{0x04, 0x02, 0xff, 0xff}
		_, err := ParseSCTList(data)
		assert.Error(t, err)
	})

	t.Run("too short for header", func(t *testing.T) {
		// Single byte without OCTET STRING wrapper
		_, err := ParseSCTList([]byte{0x00})
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("invalid SCT in list", func(t *testing.T) {
		// Build a valid SCT list header but with invalid SCT data
		// Format: OCTET STRING wrapper + total length + SCT length + invalid SCT data
		invalidSCT := make([]byte, 10) // Too short to be valid SCT
		sctLen := len(invalidSCT)

		// Build list: 2 bytes total len + 2 bytes sct len + sct data
		listData := make([]byte, 0, 4+sctLen)
		listData = append(listData, byte((sctLen+2)>>8), byte((sctLen+2)&0xff)) // total len
		listData = append(listData, byte(sctLen>>8), byte(sctLen&0xff))         // sct len
		listData = append(listData, invalidSCT...)

		// Wrap in OCTET STRING
		wrapped := wrapInOctetString(listData)

		_, err := ParseSCTList(wrapped)
		assert.Error(t, err)
	})

	t.Run("truncated SCT length in list", func(t *testing.T) {
		// Build list with total length claiming SCTs but truncated at SCT length
		listData := []byte{
			0x00, 0x04, // total length claims 4 bytes
			0x00, // only 1 byte instead of 2 for SCT length
		}
		wrapped := wrapInOctetString(listData)

		_, err := ParseSCTList(wrapped)
		assert.Error(t, err)
	})

	t.Run("SCT data shorter than claimed", func(t *testing.T) {
		// Build list where SCT length claims more data than available
		listData := []byte{
			0x00, 0x04, // total length
			0x00, 0x10, // SCT length claims 16 bytes
			// But no actual SCT data follows
		}
		wrapped := wrapInOctetString(listData)

		_, err := ParseSCTList(wrapped)
		assert.Error(t, err)
	})

	t.Run("without OCTET STRING wrapper", func(t *testing.T) {
		// Valid SCT list without OCTET STRING wrapper (tag != 0x04)
		sct := createTestSCT(1)
		serialized, err := SerializeSCT(&sct)
		require.NoError(t, err)

		// Build raw list without OCTET STRING wrapper
		totalLen := 2 + len(serialized)
		listData := make([]byte, 0, 2+totalLen)
		listData = append(listData, byte(totalLen>>8), byte(totalLen&0xff))
		listData = append(listData, byte(len(serialized)>>8), byte(len(serialized)&0xff))
		listData = append(listData, serialized...)

		parsed, err := ParseSCTList(listData)
		require.NoError(t, err)
		require.Len(t, parsed, 1)
		assert.Equal(t, sct.LogID, parsed[0].LogID)
	})
}

func TestHasPrecertPoison(t *testing.T) {
	t.Run("with poison", func(t *testing.T) {
		extensions := []pkix.Extension{
			MakePrecertPoisonExtension(),
		}
		assert.True(t, HasPrecertPoison(extensions))
	})

	t.Run("without poison", func(t *testing.T) {
		extensions := []pkix.Extension{
			{Id: OIDSCTList, Value: []byte{0x01, 0x02}},
		}
		assert.False(t, HasPrecertPoison(extensions))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, HasPrecertPoison(nil))
		assert.False(t, HasPrecertPoison([]pkix.Extension{}))
	})

	t.Run("poison among multiple extensions", func(t *testing.T) {
		extensions := []pkix.Extension{
			{Id: OIDSCTList, Value: []byte{0x01, 0x02}},
			MakePrecertPoisonExtension(),
			{Id: OIDSCTList, Value: []byte{0x03, 0x04}},
		}
		assert.True(t, HasPrecertPoison(extensions))
	})
}

func TestValidatePrecertPoison(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		extensions := []pkix.Extension{
			MakePrecertPoisonExtension(),
		}
		err := ValidatePrecertPoison(extensions)
		assert.NoError(t, err)
	})

	t.Run("missing", func(t *testing.T) {
		extensions := []pkix.Extension{}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonMissing)
	})

	t.Run("not critical", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: false,
				Value:    []byte{0x05, 0x00},
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})

	t.Run("invalid value", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: true,
				Value:    []byte{0x01, 0x02, 0x03},
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})

	t.Run("empty value", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: true,
				Value:    []byte{},
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})

	t.Run("single byte value", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: true,
				Value:    []byte{0x05},
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})

	t.Run("wrong tag byte", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: true,
				Value:    []byte{0x04, 0x00}, // Should be 0x05 0x00
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})

	t.Run("wrong length byte", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       OIDPrecertPoison,
				Critical: true,
				Value:    []byte{0x05, 0x01}, // Should be 0x05 0x00
			},
		}
		err := ValidatePrecertPoison(extensions)
		assert.ErrorIs(t, err, ErrPrecertPoisonInvalid)
	})
}

func TestHasSCTList(t *testing.T) {
	t.Run("with SCT list", func(t *testing.T) {
		extensions := []pkix.Extension{
			{Id: OIDSCTList, Value: []byte{0x01, 0x02}},
		}
		assert.True(t, HasSCTList(extensions))
	})

	t.Run("without SCT list", func(t *testing.T) {
		extensions := []pkix.Extension{
			MakePrecertPoisonExtension(),
		}
		assert.False(t, HasSCTList(extensions))
	})

	t.Run("empty extensions", func(t *testing.T) {
		assert.False(t, HasSCTList(nil))
		assert.False(t, HasSCTList([]pkix.Extension{}))
	})
}

func TestGetSCTListExtension(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		sctExt := pkix.Extension{Id: OIDSCTList, Value: []byte{0x01, 0x02}}
		extensions := []pkix.Extension{
			MakePrecertPoisonExtension(),
			sctExt,
		}

		result := GetSCTListExtension(extensions)
		require.NotNil(t, result)
		assert.True(t, result.Id.Equal(OIDSCTList))
	})

	t.Run("not found", func(t *testing.T) {
		extensions := []pkix.Extension{
			MakePrecertPoisonExtension(),
		}

		result := GetSCTListExtension(extensions)
		assert.Nil(t, result)
	})

	t.Run("empty extensions", func(t *testing.T) {
		result := GetSCTListExtension(nil)
		assert.Nil(t, result)

		result = GetSCTListExtension([]pkix.Extension{})
		assert.Nil(t, result)
	})
}

func TestWrapUnwrapOctetString(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte{0x01, 0x02, 0x03}},
		{"medium", bytes.Repeat([]byte{0xAB}, 100)},
		{"large", bytes.Repeat([]byte{0xCD}, 300)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := wrapInOctetString(tc.data)
			assert.Equal(t, byte(0x04), wrapped[0], "should start with OCTET STRING tag")

			unwrapped, err := unwrapOctetString(wrapped)
			require.NoError(t, err)
			assert.Equal(t, tc.data, unwrapped)
		})
	}
}

func TestWrapInOctetString(t *testing.T) {
	t.Run("short form length (< 128)", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xAB}, 50)
		wrapped := wrapInOctetString(data)

		assert.Equal(t, byte(0x04), wrapped[0])
		assert.Equal(t, byte(50), wrapped[1])
		assert.Equal(t, data, wrapped[2:])
	})

	t.Run("one byte long form (128-255)", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xAB}, 200)
		wrapped := wrapInOctetString(data)

		assert.Equal(t, byte(0x04), wrapped[0])
		assert.Equal(t, byte(0x81), wrapped[1]) // Long form indicator
		assert.Equal(t, byte(200), wrapped[2])
		assert.Equal(t, data, wrapped[3:])
	})

	t.Run("two byte long form (256-65535)", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xAB}, 1000)
		wrapped := wrapInOctetString(data)

		assert.Equal(t, byte(0x04), wrapped[0])
		assert.Equal(t, byte(0x82), wrapped[1]) // Long form indicator for 2 bytes
		assert.Equal(t, byte(0x03), wrapped[2]) // 1000 >> 8 = 3
		assert.Equal(t, byte(0xE8), wrapped[3]) // 1000 & 0xFF = 232
		assert.Equal(t, data, wrapped[4:])
	})

	t.Run("three byte long form (> 65535)", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xAB}, 70000)
		wrapped := wrapInOctetString(data)

		assert.Equal(t, byte(0x04), wrapped[0])
		assert.Equal(t, byte(0x83), wrapped[1])            // Long form indicator for 3 bytes
		assert.Equal(t, byte(70000>>16), wrapped[2])       // High byte
		assert.Equal(t, byte((70000>>8)&0xff), wrapped[3]) // Middle byte
		assert.Equal(t, byte(70000&0xff), wrapped[4])      // Low byte
		assert.Equal(t, data, wrapped[5:])
	})
}

func TestUnwrapOctetString(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := unwrapOctetString([]byte{0x04})
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("wrong tag", func(t *testing.T) {
		_, err := unwrapOctetString([]byte{0x05, 0x02, 0x01, 0x02})
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.Malformed, caErr.Type)
	})

	t.Run("short form valid", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03}
		wrapped := []byte{0x04, 0x03, 0x01, 0x02, 0x03}

		unwrapped, err := unwrapOctetString(wrapped)
		require.NoError(t, err)
		assert.Equal(t, data, unwrapped)
	})

	t.Run("multi-byte length insufficient bytes", func(t *testing.T) {
		// Claims 2-byte length but only has 1 byte
		data := []byte{0x04, 0x82, 0x01}
		_, err := unwrapOctetString(data)
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("length exceeds available data", func(t *testing.T) {
		// Short form: claims 10 bytes but only 2 available
		data := []byte{0x04, 0x0A, 0x01, 0x02}
		_, err := unwrapOctetString(data)
		assert.ErrorIs(t, err, ErrInvalidSCT)
	})

	t.Run("one byte long form", func(t *testing.T) {
		// 0x81 means 1 byte of length follows
		content := bytes.Repeat([]byte{0xAB}, 200)
		wrapped := []byte{0x04, 0x81, 200}
		wrapped = append(wrapped, content...)

		unwrapped, err := unwrapOctetString(wrapped)
		require.NoError(t, err)
		assert.Equal(t, content, unwrapped)
	})

	t.Run("two byte long form", func(t *testing.T) {
		// 0x82 means 2 bytes of length follow
		content := bytes.Repeat([]byte{0xAB}, 1000)
		wrapped := []byte{0x04, 0x82, 0x03, 0xE8} // 0x03E8 = 1000
		wrapped = append(wrapped, content...)

		unwrapped, err := unwrapOctetString(wrapped)
		require.NoError(t, err)
		assert.Equal(t, content, unwrapped)
	})

	t.Run("three byte long form", func(t *testing.T) {
		// 0x83 means 3 bytes of length follow
		content := bytes.Repeat([]byte{0xAB}, 70000)
		wrapped := []byte{0x04, 0x83, byte(70000 >> 16), byte((70000 >> 8) & 0xff), byte(70000 & 0xff)}
		wrapped = append(wrapped, content...)

		unwrapped, err := unwrapOctetString(wrapped)
		require.NoError(t, err)
		assert.Equal(t, content, unwrapped)
	})

	t.Run("empty content with long form length", func(t *testing.T) {
		// Using long form 0x81 0x00 for zero length (unusual but valid)
		wrapped := []byte{0x04, 0x81, 0x00}
		unwrapped, err := unwrapOctetString(wrapped)
		require.NoError(t, err)
		assert.Empty(t, unwrapped)
	})
}

func TestSCTTime(t *testing.T) {
	now := time.Now()
	sct := SignedCertificateTimestamp{
		Timestamp: uint64(now.UnixMilli()),
	}

	result := sct.Time()
	assert.Equal(t, now.UnixMilli(), result.UnixMilli())
}

func TestSCTWithDifferentAlgorithms(t *testing.T) {
	testCases := []struct {
		name    string
		hashAlg HashAlgorithm
		sigAlg  SignatureAlgorithm
	}{
		{"SHA256/ECDSA", HashAlgorithmSHA256, SignatureAlgorithmECDSA},
		{"SHA256/RSA", HashAlgorithmSHA256, SignatureAlgorithmRSA},
		{"SHA384/ECDSA", HashAlgorithmSHA384, SignatureAlgorithmECDSA},
		{"SHA512/ECDSA", HashAlgorithmSHA512, SignatureAlgorithmECDSA},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sct := createTestSCT(1)
			sct.Signature.HashAlgorithm = tc.hashAlg
			sct.Signature.SigAlgorithm = tc.sigAlg

			data, err := SerializeSCT(&sct)
			require.NoError(t, err)

			parsed, err := DeserializeSCT(data)
			require.NoError(t, err)
			assert.Equal(t, tc.hashAlg, parsed.Signature.HashAlgorithm)
			assert.Equal(t, tc.sigAlg, parsed.Signature.SigAlgorithm)
		})
	}
}

// createTestSCT creates a test SCT with a unique log ID based on seed.
func createTestSCT(seed int) SignedCertificateTimestamp {
	var logID [32]byte
	for i := range logID {
		logID[i] = byte(seed + i)
	}

	return SignedCertificateTimestamp{
		Version:   V1,
		LogID:     logID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Signature: DigitallySigned{
			HashAlgorithm: HashAlgorithmSHA256,
			SigAlgorithm:  SignatureAlgorithmECDSA,
			Signature:     []byte("test-signature-data"),
		},
	}
}
