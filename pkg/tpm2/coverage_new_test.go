// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
// Additional coverage tests for the tpm2 package.

package tpm2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test ParseHash function for all supported hash algorithms and edge cases
func TestParseHashAllHashAlgEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected crypto.Hash
	}{
		{"SHA1 uppercase", "SHA-1", crypto.SHA1},
		{"SHA256 uppercase", "SHA-256", crypto.SHA256},
		{"SHA384 uppercase", "SHA-384", crypto.SHA384},
		{"SHA512 uppercase", "SHA-512", crypto.SHA512},
		{"sha1 lowercase", "sha-1", crypto.SHA1},
		{"sha256 lowercase", "sha-256", crypto.SHA256},
		{"sha384 lowercase", "sha-384", crypto.SHA384},
		{"sha512 lowercase", "sha-512", crypto.SHA512},
		{"empty string returns 0", "", crypto.Hash(0)},
		{"invalid algorithm returns 0", "MD5", crypto.Hash(0)},
		{"unknown algorithm returns 0", "UNKNOWN", crypto.Hash(0)},
		{"partial match returns 0", "SHA", crypto.Hash(0)},
		{"sha3-256 returns 0", "SHA3-256", crypto.Hash(0)},
		{"whitespace returns 0", " ", crypto.Hash(0)},
		{"numbers only returns 0", "256", crypto.Hash(0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseHash(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test TCG_CSR_IDEVID.Marshal method with different scenarios
func TestTCGCSRIDevIDMarshalEdgeCases(t *testing.T) {
	t.Run("Marshal empty CSR produces valid output", func(t *testing.T) {
		csr := TCG_CSR_IDEVID{}
		result, err := csr.Marshal()
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("Marshal CSR with signature produces valid output", func(t *testing.T) {
		csr := TCG_CSR_IDEVID{
			StructVer: [4]byte{0x00, 0x00, 0x00, 0x01},
			Contents:  [4]byte{0x00, 0x00, 0x00, 0x10},
			SigSz:     [4]byte{0x00, 0x00, 0x00, 0x08},
			Signature: []byte("testsig!"),
		}
		result, err := csr.Marshal()
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result) > 12)
	})

	t.Run("Marshal CSR with large signature", func(t *testing.T) {
		largeSig := bytes.Repeat([]byte{0xAB}, 512)
		csr := TCG_CSR_IDEVID{
			StructVer: [4]byte{0x00, 0x00, 0x00, 0x01},
			Contents:  [4]byte{0x00, 0x00, 0x02, 0x00},
			SigSz:     [4]byte{0x00, 0x00, 0x02, 0x00},
			Signature: largeSig,
		}
		result, err := csr.Marshal()
		require.NoError(t, err)
		assert.True(t, len(result) >= len(largeSig))
	})
}

// Test ProdCaData ToQuote method with edge cases
func TestProdCaDataToQuoteExtended(t *testing.T) {
	t.Run("ToQuote with all fields populated returns complete quote", func(t *testing.T) {
		prodCaData := &ProdCaData{
			Version:     ProdCaDataVersion,
			QuotedSz:    8,
			SignatureSz: 8,
			NonceSz:     16,
			PCRsSz:      32,
			Quoted:      []byte("quotedda"),
			Signature:   []byte("sigdata!"),
			Nonce:       []byte("nonce-value-here"),
			PCRs:        bytes.Repeat([]byte{0xAB}, 32),
		}

		quote := prodCaData.ToQuote()
		require.NotNil(t, quote)
		assert.Equal(t, prodCaData.Quoted, quote.Quoted)
		assert.Equal(t, prodCaData.Signature, quote.Signature)
		assert.Equal(t, prodCaData.Nonce, quote.Nonce)
		assert.Equal(t, prodCaData.PCRs, quote.PCRs)
		assert.Nil(t, quote.EventLog)
	})

	t.Run("ToQuote with nil fields returns quote with nil slices", func(t *testing.T) {
		prodCaData := &ProdCaData{
			Version: ProdCaDataVersion,
		}

		quote := prodCaData.ToQuote()
		require.NotNil(t, quote)
		assert.Nil(t, quote.Quoted)
		assert.Nil(t, quote.Signature)
		assert.Nil(t, quote.Nonce)
		assert.Nil(t, quote.PCRs)
	})
}

// Test NewProdCaData with boundary conditions
func TestNewProdCaDataBoundaryConditions(t *testing.T) {
	t.Run("quote with zero-length slices", func(t *testing.T) {
		quote := &Quote{
			Quoted:    []byte{},
			Signature: []byte{},
			Nonce:     []byte{},
			PCRs:      []byte{},
		}
		result, err := NewProdCaData(quote)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, uint32(0), result.QuotedSz)
	})
}

// Test tpm2SymmetricKey interface implementation
func TestTPM2SymmetricKeyInterface(t *testing.T) {
	t.Run("Algorithm returns correct algorithm string", func(t *testing.T) {
		key := &tpm2SymmetricKey{
			algorithm: "AES-256-GCM",
			keySize:   256,
		}
		assert.Equal(t, "AES-256-GCM", key.Algorithm())
	})

	t.Run("KeySize returns correct key size", func(t *testing.T) {
		key := &tpm2SymmetricKey{
			algorithm: "AES-128-GCM",
			keySize:   128,
		}
		assert.Equal(t, 128, key.KeySize())
	})

	t.Run("Raw returns error for TPM keys", func(t *testing.T) {
		key := &tpm2SymmetricKey{
			algorithm: "AES-GCM",
			keySize:   256,
		}
		raw, err := key.Raw()
		require.Error(t, err)
		assert.Nil(t, raw)
		assert.Contains(t, err.Error(), "TPM2 symmetric keys do not expose raw key material")
	})
}

// Test Quote struct fields
func TestQuoteStructFieldAccess(t *testing.T) {
	t.Run("Quote fields are accessible", func(t *testing.T) {
		quote := Quote{
			Quoted:    []byte("quoted-data"),
			Signature: []byte("signature-data"),
			Nonce:     []byte("nonce-data"),
			PCRs:      []byte("pcr-data"),
			EventLog:  []byte("eventlog-data"),
		}

		assert.Equal(t, []byte("quoted-data"), quote.Quoted)
		assert.Equal(t, []byte("signature-data"), quote.Signature)
		assert.Equal(t, []byte("nonce-data"), quote.Nonce)
		assert.Equal(t, []byte("pcr-data"), quote.PCRs)
		assert.Equal(t, []byte("eventlog-data"), quote.EventLog)
	})

	t.Run("Quote with nil fields", func(t *testing.T) {
		quote := Quote{}
		assert.Nil(t, quote.Quoted)
		assert.Nil(t, quote.Signature)
		assert.Nil(t, quote.Nonce)
		assert.Nil(t, quote.PCRs)
		assert.Nil(t, quote.EventLog)
	})
}

// Test PCR struct fields
func TestPCRStructFieldAccess(t *testing.T) {
	t.Run("PCR fields are accessible", func(t *testing.T) {
		pcr := PCR{
			ID:    16,
			Value: bytes.Repeat([]byte{0xAB}, 32),
		}

		assert.Equal(t, int32(16), pcr.ID)
		assert.Equal(t, 32, len(pcr.Value))
		assert.Equal(t, byte(0xAB), pcr.Value[0])
	})

	t.Run("PCR with ID 0", func(t *testing.T) {
		pcr := PCR{
			ID:    0,
			Value: bytes.Repeat([]byte{0x00}, 20),
		}
		assert.Equal(t, int32(0), pcr.ID)
		assert.Equal(t, 20, len(pcr.Value))
	})
}

// Test AKProfile struct
func TestAKProfileStructFieldAccess(t *testing.T) {
	t.Run("AKProfile fields are accessible", func(t *testing.T) {
		profile := AKProfile{
			EKPub:              []byte("ek-public-key"),
			AKPub:              []byte("ak-public-key"),
			AKName:             tpm2.TPM2BName{Buffer: []byte("ak-name-buffer")},
			SignatureAlgorithm: 0,
		}

		assert.Equal(t, []byte("ek-public-key"), profile.EKPub)
		assert.Equal(t, []byte("ak-public-key"), profile.AKPub)
		assert.Equal(t, []byte("ak-name-buffer"), profile.AKName.Buffer)
	})
}

// Test TCGVendorID string conversion for all vendors
func TestTCGVendorIDStringConversionAllVendors(t *testing.T) {
	vendorTests := []struct {
		id       TCGVendorID
		expected string
	}{
		{1095582720, "AMD"},
		{1096043852, "Atmel"},
		{1112687437, "Broadcom"},
		{1229081856, "IBM"},
		{1213220096, "HPE"},
		{1297303124, "Microsoft"},
		{1229346816, "Infineon"},
		{1229870147, "Intel"},
		{1279610368, "Lenovo"},
		{1314082080, "National Semiconductor"},
		{1314150912, "Nationz"},
		{1314145024, "Nuvoton Technology"},
		{1363365709, "Qualcomm"},
		{1397576515, "SMSC"},
		{1398033696, "ST Microelectronics"},
		{1397576526, "Samsung"},
		{1397641984, "Sinosun"},
		{1415073280, "Texas Instruments"},
		{1464156928, "Winbond"},
		{1380926275, "Fuzhou Rockchip"},
		{1196379975, "Google"},
	}

	for _, tc := range vendorTests {
		t.Run(tc.expected, func(t *testing.T) {
			result := tc.id.String()
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("unknown vendor returns empty", func(t *testing.T) {
		unknownID := TCGVendorID(12345)
		result := unknownID.String()
		assert.Equal(t, "", result)
	})

	t.Run("zero vendor ID returns empty", func(t *testing.T) {
		zeroID := TCGVendorID(0)
		result := zeroID.String()
		assert.Equal(t, "", result)
	})
}

// Test UNPACKED_TCG_CSR_IDEVID struct fields
func TestUnpackedTCGCSRIDevIDStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		csr := UNPACKED_TCG_CSR_IDEVID{
			StructVer: 1,
			Contents:  100,
			SigSz:     64,
			Signature: []byte("test-signature"),
			RawBytes:  []byte("raw-csr-bytes"),
		}

		assert.Equal(t, uint32(1), csr.StructVer)
		assert.Equal(t, uint32(100), csr.Contents)
		assert.Equal(t, uint32(64), csr.SigSz)
		assert.Equal(t, []byte("test-signature"), csr.Signature)
		assert.Equal(t, []byte("raw-csr-bytes"), csr.RawBytes)
	})
}

// Test UNPACKED_TCG_IDEVID_CONTENT struct fields
func TestUnpackedTCGIDevIDContentStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		content := UNPACKED_TCG_IDEVID_CONTENT{
			StructVer:    1,
			HashAlgoId:   11,
			HashSz:       32,
			ProdModelSz:  10,
			ProdSerialSz: 20,
			ProdModel:    []byte("TestModel!"),
			ProdSerial:   []byte("12345678901234567890"),
			EkCert:       []byte("ek-cert"),
			AttestPub:    []byte("attest-pub"),
		}

		assert.Equal(t, uint32(1), content.StructVer)
		assert.Equal(t, uint32(11), content.HashAlgoId)
		assert.Equal(t, uint32(32), content.HashSz)
		assert.Equal(t, []byte("TestModel!"), content.ProdModel)
		assert.Equal(t, []byte("12345678901234567890"), content.ProdSerial)
	})
}

// Test TCG_CSR_LDEVID struct fields
func TestTCGCSRLDevIDStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		csr := TCG_CSR_LDEVID{
			StructVer: [4]byte{0x00, 0x00, 0x00, 0x01},
			Contents:  [4]byte{0x00, 0x00, 0x00, 0x50},
			SigSz:     [4]byte{0x00, 0x00, 0x00, 0x40},
			Signature: []byte("signature-data"),
		}

		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x01}, csr.StructVer)
		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x50}, csr.Contents)
		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x40}, csr.SigSz)
		assert.Equal(t, []byte("signature-data"), csr.Signature)
	})
}

// Test TCG_LDEVID_CONTENT struct fields
func TestTCGLDevIDContentStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		content := TCG_LDEVID_CONTENT{
			StructVer:  [4]byte{0x00, 0x00, 0x00, 0x01},
			HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
			EkCert:     []byte("ek-certificate"),
			IakCert:    []byte("iak-certificate"),
			PlatCert:   []byte("platform-certificate"),
		}

		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x01}, content.StructVer)
		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x0B}, content.HashAlgoId)
		assert.Equal(t, []byte("ek-certificate"), content.EkCert)
		assert.Equal(t, []byte("iak-certificate"), content.IakCert)
	})
}

// Test UNPACKED_TCG_CSR_LDEVID struct fields
func TestUnpackedTCGCSRLDevIDStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		csr := UNPACKED_TCG_CSR_LDEVID{
			StructVer: 1,
			Contents:  80,
			SigSz:     64,
			Signature: []byte("signature"),
		}

		assert.Equal(t, uint32(1), csr.StructVer)
		assert.Equal(t, uint32(80), csr.Contents)
		assert.Equal(t, uint32(64), csr.SigSz)
		assert.Equal(t, []byte("signature"), csr.Signature)
	})
}

// Test UNPACKED_TCG_LDEVID_CONTENT struct fields
func TestUnpackedTCGLDevIDContentStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		content := UNPACKED_TCG_LDEVID_CONTENT{
			StructVer:     1,
			HashAlgoId:    11,
			HashSz:        32,
			EkCertSZ:      100,
			IakCertSZ:     200,
			PlatCertSZ:    300,
			PubkeySZ:      256,
			EkCert:        []byte("ek-cert"),
			IakCert:       []byte("iak-cert"),
			PlatCert:      []byte("plat-cert"),
			Pubkey:        []byte("public-key"),
			AtCertifyInfo: []byte("certify-info"),
		}

		assert.Equal(t, uint32(1), content.StructVer)
		assert.Equal(t, uint32(11), content.HashAlgoId)
		assert.Equal(t, uint32(100), content.EkCertSZ)
		assert.Equal(t, []byte("ek-cert"), content.EkCert)
		assert.Equal(t, []byte("iak-cert"), content.IakCert)
	})
}

// Test TCG_IDEVID_CONTENT struct fields
func TestTCGIDevIDContentStructFields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		content := TCG_IDEVID_CONTENT{
			StructVer:  [4]byte{0x00, 0x00, 0x00, 0x01},
			HashAlgoId: [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:     [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModel:  []byte("Device-Model"),
			ProdSerial: []byte("Serial-12345"),
			EkCert:     []byte("ek-certificate-data"),
			AttestPub:  []byte("attest-public-key"),
			SigningPub: []byte("signing-public-key"),
		}

		assert.Equal(t, [4]byte{0x00, 0x00, 0x00, 0x01}, content.StructVer)
		assert.Equal(t, []byte("Device-Model"), content.ProdModel)
		assert.Equal(t, []byte("Serial-12345"), content.ProdSerial)
		assert.Equal(t, []byte("ek-certificate-data"), content.EkCert)
	})
}

// Test all defined errors
func TestAllDefinedErrorsAreValid(t *testing.T) {
	errorList := []struct {
		name string
		err  error
	}{
		{"ErrInvalidAKAttributes", ErrInvalidAKAttributes},
		{"ErrInvalidEKCertFormat", ErrInvalidEKCertFormat},
		{"ErrInvalidEKAttributes", ErrInvalidEKAttributes},
		{"ErrInvalidEKCert", ErrInvalidEKCert},
		{"ErrDeviceAlreadyOpen", ErrDeviceAlreadyOpen},
		{"ErrOpeningDevice", ErrOpeningDevice},
		{"ErrInvalidSessionType", ErrInvalidSessionType},
		{"ErrInvalidSRKAuth", ErrInvalidSRKAuth},
		{"ErrInvalidActivationCredential", ErrInvalidActivationCredential},
		{"ErrHashAlgorithmNotSupported", ErrHashAlgorithmNotSupported},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes},
		{"ErrInvalidPolicyDigest", ErrInvalidPolicyDigest},
		{"ErrInvalidHandle", ErrInvalidHandle},
		{"ErrUnexpectedRandomBytes", ErrUnexpectedRandomBytes},
		{"ErrInvalidRandomBytesLength", ErrInvalidRandomBytesLength},
		{"ErrInvalidPCRIndex", ErrInvalidPCRIndex},
		{"ErrInvalidNonce", ErrInvalidNonce},
		{"ErrNotInitialized", ErrNotInitialized},
		{"ErrNotConfigured", ErrNotConfigured},
		{"ErrEndorsementCertNotFound", ErrEndorsementCertNotFound},
		{"ErrInvalidKeyStoreConfiguration", ErrInvalidKeyStoreConfiguration},
		{"ErrInvalidHashFunction", ErrInvalidHashFunction},
		{"ErrInvalidSessionAuthorization", ErrInvalidSessionAuthorization},
		{"ErrMissingMeasurementLog", ErrMissingMeasurementLog},
		{"ErrRSAPSSNotSupported", ErrRSAPSSNotSupported},
		{"ErrInvalidEnrollmentStrategy", ErrInvalidEnrollmentStrategy},
		{"ErrInvalidCryptoHashAlgID", ErrInvalidCryptoHashAlgID},
		{"ErrCurveNotSupported", ErrCurveNotSupported},
		{"ErrInvalidKeySize", ErrInvalidKeySize},
		{"ErrInvalidNVExtendData", ErrInvalidNVExtendData},
	}

	for _, tc := range errorList {
		t.Run(tc.name+"_is_not_nil", func(t *testing.T) {
			assert.NotNil(t, tc.err)
		})
		t.Run(tc.name+"_has_message", func(t *testing.T) {
			assert.NotEmpty(t, tc.err.Error())
		})
	}
}

// Test TPM template constants validity
func TestTPMTemplateConstantsValidity(t *testing.T) {
	t.Run("RSASSATemplate_type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSATemplate.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, RSASSATemplate.NameAlg)
		assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("RSAPSSTemplate_type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSTemplate.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, RSAPSSTemplate.NameAlg)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("ECCP256Template_type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP256Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, ECCP256Template.NameAlg)
	})

	t.Run("ECCP384Template_type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP384Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA384, ECCP384Template.NameAlg)
	})

	t.Run("ECCP521Template_type", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP521Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA512, ECCP521Template.NameAlg)
	})

	t.Run("RSASSAAKTemplate_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAAKTemplate.Type)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("RSAPSSAKTemplate_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSAKTemplate.Type)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
	})

	t.Run("ECCAKP256Template_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCAKP256Template.Type)
		assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
	})

	t.Run("RSASSAIDevIDTemplate_not_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAIDevIDTemplate.Type)
		assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("RSAPSSIDevIDTemplate_not_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSIDevIDTemplate.Type)
		assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
	})

	t.Run("ECCIDevIDP256Template_not_restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCIDevIDP256Template.Type)
		assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
	})

	t.Run("AES128CFBTemplate_symmetric", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES128CFBTemplate.Type)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.Decrypt)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("AES256CFBTemplate_symmetric", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES256CFBTemplate.Type)
		assert.True(t, AES256CFBTemplate.ObjectAttributes.Decrypt)
	})

	t.Run("KeyedHashTemplate_keyed_hash", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgKeyedHash, KeyedHashTemplate.Type)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedTPM)
	})
}

// Test ProdCaData error types
func TestProdCaDataErrorTypes(t *testing.T) {
	t.Run("ErrInvalidProdCaData_contains_ProdCaData", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidProdCaData)
		assert.Contains(t, ErrInvalidProdCaData.Error(), "ProdCaData")
	})

	t.Run("ErrProdCaDataTooLarge_contains_ProdCaData", func(t *testing.T) {
		assert.NotNil(t, ErrProdCaDataTooLarge)
		assert.Contains(t, ErrProdCaDataTooLarge.Error(), "ProdCaData")
	})
}

// Test ProdCaDataVersion constant value
func TestProdCaDataVersionValue(t *testing.T) {
	assert.Equal(t, uint32(0x00000001), ProdCaDataVersion)
}

// Test maxRandomBytesPerRequest constant value
func TestMaxRandomBytesPerRequestValue(t *testing.T) {
	assert.Equal(t, 48, maxRandomBytesPerRequest)
}

// Test ErrCommandNotSupported constant value
func TestErrCommandNotSupportedValue(t *testing.T) {
	assert.Equal(t, tpm2.TPMRC(0xb0143), ErrCommandNotSupported)
}

// Test EnrollmentStrategy string values
func TestEnrollmentStrategyStringValues(t *testing.T) {
	t.Run("IAK_strategy_string", func(t *testing.T) {
		assert.Equal(t, EnrollmentStrategy("IAK"), EnrollmentStrategyIAK)
		assert.Equal(t, "IAK", string(EnrollmentStrategyIAK))
	})

	t.Run("IAK_IDEVID_SINGLE_PASS_strategy_string", func(t *testing.T) {
		assert.Equal(t, EnrollmentStrategy("IAK_IDEVID_SINGLE_PASS"), EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		assert.Equal(t, "IAK_IDEVID_SINGLE_PASS", string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
	})
}

// Test Encode function edge cases
func TestEncodeEdgeCases(t *testing.T) {
	t.Run("Encode_nil_slice", func(t *testing.T) {
		result := Encode(nil)
		assert.Equal(t, "", result)
	})

	t.Run("Encode_empty_slice", func(t *testing.T) {
		result := Encode([]byte{})
		assert.Equal(t, "", result)
	})

	t.Run("Encode_single_byte_zero", func(t *testing.T) {
		result := Encode([]byte{0x00})
		assert.Equal(t, "00", result)
	})

	t.Run("Encode_single_byte_max", func(t *testing.T) {
		result := Encode([]byte{0xFF})
		assert.Equal(t, "ff", result)
	})

	t.Run("Encode_multiple_bytes", func(t *testing.T) {
		result := Encode([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		assert.Equal(t, "deadbeef", result)
	})
}

// Test Decode function edge cases
func TestDecodeEdgeCases(t *testing.T) {
	t.Run("Decode_empty_string", func(t *testing.T) {
		result, err := Decode("")
		require.NoError(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("Decode_valid_hex", func(t *testing.T) {
		result, err := Decode("deadbeef")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
	})

	t.Run("Decode_uppercase_hex", func(t *testing.T) {
		result, err := Decode("DEADBEEF")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
	})

	t.Run("Decode_mixed_case_hex", func(t *testing.T) {
		result, err := Decode("DeAdBeEf")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, result)
	})

	t.Run("Decode_invalid_hex_odd_length", func(t *testing.T) {
		_, err := Decode("abc")
		require.Error(t, err)
	})

	t.Run("Decode_invalid_hex_chars", func(t *testing.T) {
		_, err := Decode("ghijkl")
		require.Error(t, err)
	})

	t.Run("Decode_invalid_with_spaces", func(t *testing.T) {
		_, err := Decode("de ad")
		require.Error(t, err)
	})
}

// Test Encode/Decode round trip
func TestEncodeDecodeRoundTripComplete(t *testing.T) {
	testData := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		bytes.Repeat([]byte{0xAA}, 100),
	}

	for i, original := range testData {
		t.Run("round_trip_"+string(rune('0'+i)), func(t *testing.T) {
			encoded := Encode(original)
			decoded, err := Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, original, decoded)
		})
	}
}

// Test PCRBank with multiple PCRs
func TestPCRBankWithMultiplePCRs(t *testing.T) {
	t.Run("SHA256_bank_with_multiple_PCRs", func(t *testing.T) {
		bank := PCRBank{
			Algorithm: "sha256",
			PCRs: []PCR{
				{ID: 0, Value: bytes.Repeat([]byte{0x00}, 32)},
				{ID: 1, Value: bytes.Repeat([]byte{0x11}, 32)},
				{ID: 7, Value: bytes.Repeat([]byte{0x77}, 32)},
				{ID: 16, Value: bytes.Repeat([]byte{0xAA}, 32)},
			},
		}

		assert.Equal(t, "sha256", bank.Algorithm)
		assert.Equal(t, 4, len(bank.PCRs))
		assert.Equal(t, int32(0), bank.PCRs[0].ID)
		assert.Equal(t, int32(7), bank.PCRs[2].ID)
		assert.Equal(t, int32(16), bank.PCRs[3].ID)
	})

	t.Run("SHA1_bank_with_20_byte_values", func(t *testing.T) {
		bank := PCRBank{
			Algorithm: "sha1",
			PCRs: []PCR{
				{ID: 0, Value: bytes.Repeat([]byte{0x00}, 20)},
			},
		}

		assert.Equal(t, "sha1", bank.Algorithm)
		assert.Equal(t, 20, len(bank.PCRs[0].Value))
	})
}

// Test EncodeQuote with various quote structures
func TestEncodeQuoteVariousStructures(t *testing.T) {
	t.Run("empty_quote_encodes", func(t *testing.T) {
		quote := Quote{}
		encoded, err := EncodeQuote(quote)
		require.NoError(t, err)
		assert.NotNil(t, encoded)
	})

	t.Run("populated_quote_encodes", func(t *testing.T) {
		quote := Quote{
			Quoted:    bytes.Repeat([]byte{0x01}, 100),
			Signature: bytes.Repeat([]byte{0x02}, 256),
			Nonce:     bytes.Repeat([]byte{0x03}, 32),
			PCRs:      bytes.Repeat([]byte{0x04}, 64),
			EventLog:  bytes.Repeat([]byte{0x05}, 1024),
		}
		encoded, err := EncodeQuote(quote)
		require.NoError(t, err)
		assert.NotNil(t, encoded)

		decoded, err := DecodeQuote(encoded)
		require.NoError(t, err)
		assert.Equal(t, quote.Quoted, decoded.Quoted)
		assert.Equal(t, quote.Signature, decoded.Signature)
		assert.Equal(t, quote.Nonce, decoded.Nonce)
		assert.Equal(t, quote.PCRs, decoded.PCRs)
		assert.Equal(t, quote.EventLog, decoded.EventLog)
	})
}

// Test DecodeQuote error handling
func TestDecodeQuoteErrorHandling(t *testing.T) {
	t.Run("invalid_data_returns_error", func(t *testing.T) {
		_, err := DecodeQuote([]byte("not valid gob data"))
		require.Error(t, err)
	})

	t.Run("truncated_data_returns_error", func(t *testing.T) {
		quote := Quote{Quoted: []byte("test")}
		encoded, err := EncodeQuote(quote)
		require.NoError(t, err)

		// Truncate the data
		truncated := encoded[:len(encoded)/2]
		_, err = DecodeQuote(truncated)
		require.Error(t, err)
	})
}

// Test EncodePCRs with various structures
func TestEncodePCRsVariousStructures(t *testing.T) {
	t.Run("empty_banks_encodes", func(t *testing.T) {
		banks := []PCRBank{}
		encoded, err := EncodePCRs(banks)
		require.NoError(t, err)
		assert.NotNil(t, encoded)
	})

	t.Run("single_bank_encodes", func(t *testing.T) {
		banks := []PCRBank{
			{
				Algorithm: "sha256",
				PCRs: []PCR{
					{ID: 0, Value: bytes.Repeat([]byte{0x00}, 32)},
				},
			},
		}
		encoded, err := EncodePCRs(banks)
		require.NoError(t, err)
		assert.NotNil(t, encoded)

		decoded, err := DecodePCRs(encoded)
		require.NoError(t, err)
		assert.Equal(t, 1, len(decoded))
		assert.Equal(t, "sha256", decoded[0].Algorithm)
	})

	t.Run("multiple_banks_encodes", func(t *testing.T) {
		banks := []PCRBank{
			{Algorithm: "sha256", PCRs: []PCR{{ID: 0, Value: bytes.Repeat([]byte{0x00}, 32)}}},
			{Algorithm: "sha384", PCRs: []PCR{{ID: 0, Value: bytes.Repeat([]byte{0x00}, 48)}}},
			{Algorithm: "sha1", PCRs: []PCR{{ID: 0, Value: bytes.Repeat([]byte{0x00}, 20)}}},
		}
		encoded, err := EncodePCRs(banks)
		require.NoError(t, err)

		decoded, err := DecodePCRs(encoded)
		require.NoError(t, err)
		assert.Equal(t, 3, len(decoded))
	})
}

// Test DecodePCRs error handling
func TestDecodePCRsErrorHandling(t *testing.T) {
	t.Run("invalid_data_returns_error", func(t *testing.T) {
		_, err := DecodePCRs([]byte("not valid gob data"))
		require.Error(t, err)
	})

	t.Run("truncated_data_returns_error", func(t *testing.T) {
		banks := []PCRBank{{Algorithm: "sha256", PCRs: []PCR{{ID: 0, Value: bytes.Repeat([]byte{0x00}, 32)}}}}
		encoded, err := EncodePCRs(banks)
		require.NoError(t, err)

		truncated := encoded[:len(encoded)/2]
		_, err = DecodePCRs(truncated)
		require.Error(t, err)
	})
}

// Test TPM Device and Config methods
func TestTPMDeviceAndConfigMethods(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	t.Run("Device returns device path", func(t *testing.T) {
		device := tpm2Instance.Device()
		assert.NotEmpty(t, device)
	})

	t.Run("Config returns non-nil config", func(t *testing.T) {
		cfg := tpm2Instance.Config()
		assert.NotNil(t, cfg)
	})

	t.Run("Transport returns non-nil transport", func(t *testing.T) {
		transport := tpm2Instance.Transport()
		assert.NotNil(t, transport)
	})

	t.Run("AlgID returns valid algorithm ID", func(t *testing.T) {
		algID := tpm2Instance.AlgID()
		assert.NotEqual(t, tpm2.TPMAlgID(0), algID)
	})

	t.Run("RandomSource returns non-nil reader", func(t *testing.T) {
		reader := tpm2Instance.RandomSource()
		assert.NotNil(t, reader)
	})
}

// Test EK methods
func TestEKMethods(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("EKAttributes returns valid attributes", func(t *testing.T) {
		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err)
		assert.NotNil(t, ekAttrs)
		assert.NotNil(t, ekAttrs.TPMAttributes)
	})

	t.Run("EK returns public key", func(t *testing.T) {
		ek := tpm.EK()
		assert.NotNil(t, ek)
	})

	t.Run("EKPublic returns name and public", func(t *testing.T) {
		name, pub := tpm.EKPublic()
		assert.NotNil(t, name.Buffer)
		assert.NotEqual(t, tpm2.TPMAlgID(0), pub.Type)
	})

	t.Run("EKRSA returns RSA public key", func(t *testing.T) {
		rsaPub := tpm.EKRSA()
		assert.NotNil(t, rsaPub)
	})
}

// Test SSRKAttributes returns valid attributes
func TestSSRKAttributesCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	srkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, srkAttrs)
}

// Test IAK methods
func TestIAKMethods(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("IAK returns public key", func(t *testing.T) {
		iak := tpm.IAK()
		assert.NotNil(t, iak)
	})

	t.Run("IAKAttributes returns valid attributes", func(t *testing.T) {
		iakAttrs, err := tpm.IAKAttributes()
		require.NoError(t, err)
		assert.NotNil(t, iakAttrs)
	})
}

// Test Hash functions
func TestHashFunctions(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	t.Run("Hash with small data", func(t *testing.T) {
		data := []byte("test data for hashing")
		digest, validation, err := tpm2Instance.Hash(iakAttrs, data)
		require.NoError(t, err)
		assert.NotNil(t, digest)
		assert.NotNil(t, validation)
		assert.Equal(t, 32, len(digest)) // SHA-256 produces 32 bytes
	})

	t.Run("HashSequence with large data", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xAB}, 2048) // Large data requiring sequence
		digest, validation, err := tpm2Instance.HashSequence(iakAttrs, data)
		require.NoError(t, err)
		assert.NotNil(t, digest)
		assert.NotNil(t, validation)
	})

	t.Run("Hash with nil key attributes returns error", func(t *testing.T) {
		_, _, err := tpm2Instance.Hash(nil, []byte("test"))
		assert.Error(t, err)
	})

	t.Run("Hash with nil TPMAttributes returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "test"}
		_, _, err := tpm2Instance.Hash(attrs, []byte("test"))
		assert.Error(t, err)
	})
}

// Test ReadHandle
func TestReadHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	t.Run("ReadHandle with valid handle", func(t *testing.T) {
		name, pub, err := tpm.ReadHandle(ekAttrs.TPMAttributes.Handle)
		require.NoError(t, err)
		assert.NotNil(t, name.Buffer)
		assert.NotEqual(t, tpm2.TPMAlgID(0), pub.Type)
	})

	t.Run("ReadHandle with invalid handle returns error", func(t *testing.T) {
		_, _, err := tpm.ReadHandle(tpm2.TPMHandle(0x12345678))
		assert.Error(t, err)
	})
}

// Test ReadPCRs
func TestReadPCRs(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("ReadPCRs with valid PCR list", func(t *testing.T) {
		pcrList := []uint{0, 7, 16}
		banks, err := tpm.ReadPCRs(pcrList)
		require.NoError(t, err)
		assert.NotNil(t, banks)
		assert.True(t, len(banks) > 0)
	})

	t.Run("ReadPCRs with empty list", func(t *testing.T) {
		pcrList := []uint{}
		banks, err := tpm.ReadPCRs(pcrList)
		require.NoError(t, err)
		assert.NotNil(t, banks)
	})
}

// Test Seal with nil data generates random key
func TestSealWithNilData(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-seal-nil-data",
			Parent:   ssrkAttrs,
			Password: store.NewClearPassword([]byte("test-pass")),
		},
	}

	sealed, err := tpm2Instance.Seal(ctx, nil, opts)
	require.NoError(t, err)
	assert.NotNil(t, sealed)
}

// Test Unseal with provided blobs path (covers unsealFromBlobs)
func TestUnsealWithProvidedBlobs(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	// First seal some data
	ctx := context.Background()
	data := []byte("data for blob unseal test")
	sealOpts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-unseal-blobs",
			Parent:   ssrkAttrs,
			Password: store.NewClearPassword([]byte("test-pass")),
		},
	}

	sealed, err := tpm2Instance.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	// Now unseal using the blobs directly
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-unseal-blobs",
			Parent:   ssrkAttrs,
			Password: store.NewClearPassword([]byte("test-pass")),
		},
	}

	unsealed, err := tpm2Instance.Unseal(ctx, sealed, unsealOpts)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed)
}

// Test CreateRSA with different key types
func TestCreateRSAKeyTypes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	t.Run("CreateRSA encryption key", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:           "test-rsa-encrypt",
			Parent:       ssrkAttrs,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeEncryption,
			Password:     store.NewClearPassword([]byte("test-pass")),
		}

		pub, err := tpm2Instance.CreateRSA(keyAttrs, nil, true)
		require.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("CreateRSA signing key", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:                 "test-rsa-sign",
			Parent:             ssrkAttrs,
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeCA,
			SignatureAlgorithm: x509.SHA256WithRSA,
			Password:           store.NewClearPassword([]byte("test-pass")),
		}

		pub, err := tpm2Instance.CreateRSA(keyAttrs, nil, true)
		require.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("CreateRSA with nil parent returns error", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:           "test-rsa-no-parent",
			KeyAlgorithm: x509.RSA,
		}

		_, err := tpm2Instance.CreateRSA(keyAttrs, nil, true)
		assert.Error(t, err)
	})
}

// Test CreateECDSA key creation
func TestCreateECDSAKeys(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	t.Run("CreateECDSA P256 key", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:           "test-ecdsa-p256",
			Parent:       ssrkAttrs,
			KeyAlgorithm: x509.ECDSA,
			Password:     store.NewClearPassword([]byte("test-pass")),
		}

		pub, err := tpm2Instance.CreateECDSA(keyAttrs, nil, true)
		require.NoError(t, err)
		assert.NotNil(t, pub)
	})

	t.Run("CreateECDSA with nil parent returns error", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:           "test-ecdsa-no-parent",
			KeyAlgorithm: x509.ECDSA,
		}

		_, err := tpm2Instance.CreateECDSA(keyAttrs, nil, true)
		assert.Error(t, err)
	})
}

// Test HMACSession methods
func TestHMACSessionMethods(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	t.Run("HMACSession with auth", func(t *testing.T) {
		session, closer, err := tpm2Instance.HMACSession([]byte("test-auth"))
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotNil(t, closer)
		err = closer()
		assert.NoError(t, err)
	})

	t.Run("HMACSession with nil auth", func(t *testing.T) {
		session, closer, err := tpm2Instance.HMACSession(nil)
		require.NoError(t, err)
		assert.NotNil(t, session)
		err = closer()
		assert.NoError(t, err)
	})
}

// Test HMACSaltedSession
func TestHMACSaltedSession(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	t.Run("HMACSaltedSession with EK", func(t *testing.T) {
		session, closer, err := tpm2Instance.HMACSaltedSession(
			ekAttrs.TPMAttributes.Handle,
			ekAttrs.TPMAttributes.Public,
			nil,
		)
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotNil(t, closer)
		err = closer()
		assert.NoError(t, err)
	})
}

// Test CreateSession with various configurations
func TestCreateSessionConfigurations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	t.Run("CreateSession with password auth", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:             "test-session",
			Parent:         ssrkAttrs,
			Password:       store.NewClearPassword([]byte("test-pass")),
			PlatformPolicy: false,
		}

		session, closer, err := tpm2Instance.CreateSession(keyAttrs)
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotNil(t, closer)
		err = closer()
		assert.NoError(t, err)
	})

	t.Run("CreateSession with platform policy", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:             "test-session-policy",
			Parent:         ssrkAttrs,
			PlatformPolicy: true,
		}

		session, closer, err := tpm2Instance.CreateSession(keyAttrs)
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotNil(t, closer)
		err = closer()
		assert.NoError(t, err)
	})
}

// Test IsPlatformPCRExtended
func TestIsPlatformPCRExtendedCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("IsPlatformPCRExtended returns valid result", func(t *testing.T) {
		extended, err := tpm.IsPlatformPCRExtended()
		require.NoError(t, err)
		// After provisioning, the PCR should be extended
		assert.True(t, extended)
	})
}

// Test FixedProperties
func TestFixedPropertiesCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("FixedProperties returns valid properties", func(t *testing.T) {
		props, err := tpm.FixedProperties()
		require.NoError(t, err)
		assert.NotNil(t, props)
		assert.NotEmpty(t, props.Manufacturer)
	})
}

// Test IsFIPS140_2
func TestIsFIPS140_2Coverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("IsFIPS140_2 returns valid result", func(t *testing.T) {
		fips, err := tpm.IsFIPS140_2()
		require.NoError(t, err)
		// Simulator is typically not FIPS certified
		_ = fips
	})
}

// Test Info
func TestTPMInfoCoverage(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("Info returns valid string", func(t *testing.T) {
		info, err := tpm.Info()
		require.NoError(t, err)
		assert.NotEmpty(t, info)
	})
}

// Test AKProfile error handling when not initialized
func TestAKProfileMethod(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("AKProfile returns error when IAK not initialized", func(t *testing.T) {
		// When using basic createSim, IAK is not initialized
		// so AKProfile should return ErrNotInitialized
		_, err := tpm.AKProfile()
		assert.Error(t, err)
		assert.Equal(t, ErrNotInitialized, err)
	})
}

// Test MakeCredential
func TestMakeCredential(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	t.Run("MakeCredential with valid parameters", func(t *testing.T) {
		secret := []byte("test-secret-data-32bytes-long!!")
		credBlob, encSecret, tpmPub, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)
		require.NoError(t, err)
		assert.NotNil(t, credBlob)
		assert.NotNil(t, encSecret)
		assert.NotNil(t, tpmPub)
	})
}

// Test ActivateCredential
func TestActivateCredential(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// First make a credential
	secret := []byte("test-secret-data-32bytes-long!!")
	credBlob, encSecret, _, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)
	require.NoError(t, err)

	t.Run("ActivateCredential with valid parameters", func(t *testing.T) {
		recoveredSecret, err := tpm.ActivateCredential(credBlob, encSecret)
		require.NoError(t, err)
		assert.Equal(t, secret, recoveredSecret)
	})
}
