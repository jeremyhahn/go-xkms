// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestTCGVendorID_StringComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		vendorID TCGVendorID
		expected string
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
		{"Unknown vendor 2", TCGVendorID(9999999), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vendorID.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHierarchyName_PanicOnInvalid(t *testing.T) {
	// Test that an invalid hierarchy causes a panic
	assert.Panics(t, func() {
		HierarchyName(tpm2.TPMHandle(0x12345678))
	})

	// Test with specific invalid handle values
	assert.Panics(t, func() {
		HierarchyName(tpm2.TPMHandle(0x00000000))
	})
}

func TestParseHash_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected crypto.Hash
	}{
		{"SHA-1 uppercase", "SHA-1", crypto.SHA1},
		{"SHA-1 lowercase", "sha-1", crypto.SHA1},
		{"SHA-1 mixed", "Sha-1", crypto.SHA1},
		{"SHA-256 uppercase", "SHA-256", crypto.SHA256},
		{"SHA-256 lowercase", "sha-256", crypto.SHA256},
		{"SHA-256 mixed", "Sha-256", crypto.SHA256},
		{"SHA-384 uppercase", "SHA-384", crypto.SHA384},
		{"SHA-384 lowercase", "sha-384", crypto.SHA384},
		{"SHA-512 uppercase", "SHA-512", crypto.SHA512},
		{"SHA-512 lowercase", "sha-512", crypto.SHA512},
		{"Invalid hash", "invalid", crypto.Hash(0)},
		{"Empty string", "", crypto.Hash(0)},
		{"MD5 unsupported", "MD5", crypto.Hash(0)},
		{"SHA3 not supported", "SHA3-256", crypto.Hash(0)},
		{"Partial match SHA", "SHA", crypto.Hash(0)},
		{"Partial match 256", "256", crypto.Hash(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseHash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseHashAlgFromString_Extended(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA-1 uppercase", "SHA-1", tpm2.TPMAlgSHA1, false},
		{"SHA-1 lowercase", "sha-1", tpm2.TPMAlgSHA1, false},
		{"SHA-256 uppercase", "SHA-256", tpm2.TPMAlgSHA256, false},
		{"SHA-256 lowercase", "sha-256", tpm2.TPMAlgSHA256, false},
		{"SHA-384 uppercase", "SHA-384", tpm2.TPMAlgSHA384, false},
		{"SHA-384 lowercase", "sha-384", tpm2.TPMAlgSHA384, false},
		{"SHA-512 uppercase", "SHA-512", tpm2.TPMAlgSHA512, false},
		{"SHA-512 lowercase", "sha-512", tpm2.TPMAlgSHA512, false},
		{"Invalid hash", "invalid", 0, true},
		{"Empty string", "", 0, true},
		{"MD5 unsupported", "MD5", 0, true},
		{"Whitespace", " SHA-256", 0, true},
		{"Trailing whitespace", "SHA-256 ", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlgFromString(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidHashFunction)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseHashAlg_Extended(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"MD5 unsupported", crypto.MD5, 0, true},
		{"MD4 unsupported", crypto.MD4, 0, true},
		{"SHA224 unsupported", crypto.SHA224, 0, true},
		{"Invalid hash 999", crypto.Hash(999), 0, true},
		{"Zero hash", crypto.Hash(0), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlg(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidHashFunction)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseHashSize_Extended(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    uint32
		expectError bool
	}{
		{"SHA1", crypto.SHA1, 20, false},
		{"SHA256", crypto.SHA256, 32, false},
		{"SHA384", crypto.SHA384, 48, false},
		{"SHA512", crypto.SHA512, 64, false},
		{"MD5 unsupported", crypto.MD5, 0, true},
		{"SHA224 unsupported", crypto.SHA224, 0, true},
		{"SHA512_224 unsupported", crypto.SHA512_224, 0, true},
		{"SHA512_256 unsupported", crypto.SHA512_256, 0, true},
		{"Invalid hash", crypto.Hash(999), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashSize(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidHashFunction)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTCG_CSR_IDEVID_MarshalBasic(t *testing.T) {
	// Create a simple CSR structure
	csr := TCG_CSR_IDEVID{
		StructVer: [4]byte{0, 0, 0, 1},
		Contents:  [4]byte{0, 0, 0, 64},
		SigSz:     [4]byte{0, 0, 0, 32},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:  [4]byte{0, 0, 0, 1},
			HashAlgoId: [4]byte{0, 0, 0, 11}, // SHA-256
			HashSz:     [4]byte{0, 0, 0, 32},
		},
		Signature: make([]byte, 32),
	}

	// Marshal should not panic and produce some output
	data, err := csr.Marshal()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
}

// Test error type constants are properly defined
func TestErrorTypesDefinitions(t *testing.T) {
	// Verify error messages are correct
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidAKAttributes", ErrInvalidAKAttributes, "tpm: invalid AK attributes"},
		{"ErrInvalidEKCertFormat", ErrInvalidEKCertFormat, "tpm: invalid endorsement certificate format"},
		{"ErrInvalidEKAttributes", ErrInvalidEKAttributes, "tpm: invalid EK attributes"},
		{"ErrInvalidEKCert", ErrInvalidEKCert, "tpm: failed to verify endorsement key certificate"},
		{"ErrDeviceAlreadyOpen", ErrDeviceAlreadyOpen, "tpm: device already open"},
		{"ErrOpeningDevice", ErrOpeningDevice, "tpm: error opening device"},
		{"ErrInvalidSessionType", ErrInvalidSessionType, "tpm: invalid session type"},
		{"ErrInvalidSRKAuth", ErrInvalidSRKAuth, "tpm: invalid storage root key auth"},
		{"ErrInvalidActivationCredential", ErrInvalidActivationCredential, "tpm: invalid activation credential"},
		{"ErrHashAlgorithmNotSupported", ErrHashAlgorithmNotSupported, "tpm: hash algorithm not supported"},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes, "tpm: invalid key attributes"},
		{"ErrInvalidPolicyDigest", ErrInvalidPolicyDigest, "tpm: invalid policy digest"},
		{"ErrInvalidHandle", ErrInvalidHandle, "tpm: invalid entity handle"},
		{"ErrUnexpectedRandomBytes", ErrUnexpectedRandomBytes, "tpm: unexpected number of random bytes read"},
		{"ErrInvalidRandomBytesLength", ErrInvalidRandomBytesLength, "tpm: invalid random bytes length"},
		{"ErrInvalidPCRIndex", ErrInvalidPCRIndex, "tpm: invalid PCR index"},
		{"ErrInvalidNonce", ErrInvalidNonce, "tpm: invalid nonce"},
		{"ErrNotInitialized", ErrNotInitialized, "tpm: not initialized"},
		{"ErrNotConfigured", ErrNotConfigured, "tpm: IDevID not configured"},
		{"ErrEndorsementCertNotFound", ErrEndorsementCertNotFound, "tpm: endorsement certificate not found"},
		{"ErrInvalidKeyStoreConfiguration", ErrInvalidKeyStoreConfiguration, "tpm: invalid key store configuration"},
		{"ErrInvalidHashFunction", ErrInvalidHashFunction, "tpm: invalid hash function"},
		{"ErrInvalidSessionAuthorization", ErrInvalidSessionAuthorization, "tpm: invalid session authorization"},
		{"ErrMissingMeasurementLog", ErrMissingMeasurementLog, "tpm: binary measurement log not found"},
		{"ErrRSAPSSNotSupported", ErrRSAPSSNotSupported, "tpm: RSA-PSS / FIPS 140-2 not supported by this TPM"},
		{"ErrInvalidEnrollmentStrategy", ErrInvalidEnrollmentStrategy, "tpm: invalid enrollment strategy"},
		{"ErrInvalidCryptoHashAlgID", ErrInvalidCryptoHashAlgID, "tpm: crypto.Hash doesn't map to a supported TPMAlgID"},
		{"ErrCurveNotSupported", ErrCurveNotSupported, "tpm: ECC curve not supported by TPM"},
		{"ErrInvalidKeySize", ErrInvalidKeySize, "tpm: invalid key size"},
		{"ErrInvalidNVExtendData", ErrInvalidNVExtendData, "tpm: invalid NV extend data - data cannot be nil or empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.EqualError(t, tt.err, tt.expected)
		})
	}
}

// Test TPM templates have correct values
func TestTPMTemplatesComprehensive(t *testing.T) {
	// Verify RSA SSA template
	t.Run("RSASSATemplate_SignEncrypt", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSATemplate.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, RSASSATemplate.NameAlg)
		assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedTPM)
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedParent)
		assert.True(t, RSASSATemplate.ObjectAttributes.SensitiveDataOrigin)
		assert.True(t, RSASSATemplate.ObjectAttributes.UserWithAuth)
		assert.False(t, RSASSATemplate.ObjectAttributes.Restricted)
	})

	// Verify RSA PSS template
	t.Run("RSAPSSTemplate_SignEncrypt", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSTemplate.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, RSAPSSTemplate.NameAlg)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)
		assert.False(t, RSAPSSTemplate.ObjectAttributes.Restricted)
	})

	// Verify ECC P256 template
	t.Run("ECCP256Template_Attributes", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP256Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, ECCP256Template.NameAlg)
		assert.True(t, ECCP256Template.ObjectAttributes.SignEncrypt)
		assert.False(t, ECCP256Template.ObjectAttributes.Restricted)
	})

	// Verify ECC P384 template
	t.Run("ECCP384Template_Attributes", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP384Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA384, ECCP384Template.NameAlg)
	})

	// Verify ECC P521 template
	t.Run("ECCP521Template_Attributes", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCP521Template.Type)
		assert.Equal(t, tpm2.TPMAlgSHA512, ECCP521Template.NameAlg)
	})

	// Verify AK templates are restricted
	t.Run("RSASSAAKTemplate_Restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAAKTemplate.Type)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedTPM)
		assert.False(t, RSASSAAKTemplate.ObjectAttributes.Decrypt)
	})

	t.Run("RSAPSSAKTemplate_Restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSAKTemplate.Type)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.SignEncrypt)
	})

	t.Run("ECCAKP256Template_Restricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCAKP256Template.Type)
		assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
		assert.True(t, ECCAKP256Template.ObjectAttributes.SignEncrypt)
	})

	// Verify IDevID templates are NOT restricted
	t.Run("RSASSAIDevIDTemplate_NotRestricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSASSAIDevIDTemplate.Type)
		assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("RSAPSSIDevIDTemplate_NotRestricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgRSA, RSAPSSIDevIDTemplate.Type)
		assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
	})

	t.Run("ECCIDevIDP256Template_NotRestricted", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgECC, ECCIDevIDP256Template.Type)
		assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
	})

	// Verify AES templates
	t.Run("AES128CFBTemplate_SymCipher", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES128CFBTemplate.Type)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.Decrypt)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.NoDA)
		assert.False(t, AES128CFBTemplate.ObjectAttributes.Restricted)
	})

	t.Run("AES256CFBTemplate_SymCipher", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgSymCipher, AES256CFBTemplate.Type)
		assert.True(t, AES256CFBTemplate.ObjectAttributes.Decrypt)
		assert.True(t, AES256CFBTemplate.ObjectAttributes.SignEncrypt)
	})

	// Verify KeyedHash template
	t.Run("KeyedHashTemplate_Attributes", func(t *testing.T) {
		assert.Equal(t, tpm2.TPMAlgKeyedHash, KeyedHashTemplate.Type)
		assert.Equal(t, tpm2.TPMAlgSHA256, KeyedHashTemplate.NameAlg)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedParent)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.UserWithAuth)
	})
}

// Test Quote and PCRBank structures
func TestQuoteStructureFields(t *testing.T) {
	quote := Quote{
		Quoted:    []byte("test-quoted"),
		Signature: []byte("test-sig"),
		Nonce:     []byte("test-nonce"),
		PCRs:      []byte("test-pcrs"),
		EventLog:  []byte("test-eventlog"),
	}

	assert.Equal(t, []byte("test-quoted"), quote.Quoted)
	assert.Equal(t, []byte("test-sig"), quote.Signature)
	assert.Equal(t, []byte("test-nonce"), quote.Nonce)
	assert.Equal(t, []byte("test-pcrs"), quote.PCRs)
	assert.Equal(t, []byte("test-eventlog"), quote.EventLog)
}

func TestPCRBankStructureFields(t *testing.T) {
	bank := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte("pcr0")},
			{ID: 7, Value: []byte("pcr7")},
		},
	}

	assert.Equal(t, "SHA256", bank.Algorithm)
	assert.Len(t, bank.PCRs, 2)
	assert.Equal(t, int32(0), bank.PCRs[0].ID)
	assert.Equal(t, int32(7), bank.PCRs[1].ID)
}

// Test AKProfile structure
func TestAKProfileStructureFields(t *testing.T) {
	profile := AKProfile{
		EKPub:  []byte("ek-public"),
		AKPub:  []byte("ak-public"),
		AKName: tpm2.TPM2BName{Buffer: []byte("ak-name")},
	}

	assert.Equal(t, []byte("ek-public"), profile.EKPub)
	assert.Equal(t, []byte("ak-public"), profile.AKPub)
	assert.Equal(t, []byte("ak-name"), profile.AKName.Buffer)
}

// Test EnrollmentStrategy constants
func TestEnrollmentStrategyConstantsValues(t *testing.T) {
	assert.Equal(t, EnrollmentStrategy("IAK"), EnrollmentStrategyIAK)
	assert.Equal(t, EnrollmentStrategy("IAK_IDEVID_SINGLE_PASS"), EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
}

// Test TCG CSR structures
func TestTCG_IDEVID_CONTENT_Structure(t *testing.T) {
	content := TCG_IDEVID_CONTENT{
		StructVer:  [4]byte{0, 0, 0, 1},
		HashAlgoId: [4]byte{0, 0, 0, 11},
		HashSz:     [4]byte{0, 0, 0, 32},
		ProdModel:  []byte("test-model"),
		ProdSerial: []byte("test-serial"),
		EkCert:     []byte("test-cert"),
	}

	assert.Equal(t, [4]byte{0, 0, 0, 1}, content.StructVer)
	assert.Equal(t, [4]byte{0, 0, 0, 11}, content.HashAlgoId)
	assert.Equal(t, []byte("test-model"), content.ProdModel)
	assert.Equal(t, []byte("test-serial"), content.ProdSerial)
	assert.Equal(t, []byte("test-cert"), content.EkCert)
}

func TestUNPACKED_TCG_IDEVID_CONTENT_Structure(t *testing.T) {
	content := UNPACKED_TCG_IDEVID_CONTENT{
		StructVer:    1,
		HashAlgoId:   11,
		HashSz:       32,
		ProdModelSz:  10,
		ProdSerialSz: 11,
		ProdModel:    []byte("test-model"),
		ProdSerial:   []byte("test-serial"),
	}

	assert.Equal(t, uint32(1), content.StructVer)
	assert.Equal(t, uint32(11), content.HashAlgoId)
	assert.Equal(t, uint32(32), content.HashSz)
	assert.Equal(t, uint32(10), content.ProdModelSz)
	assert.Equal(t, []byte("test-model"), content.ProdModel)
	assert.Equal(t, []byte("test-serial"), content.ProdSerial)
}

func TestUNPACKED_TCG_CSR_IDEVID_Structure(t *testing.T) {
	csr := UNPACKED_TCG_CSR_IDEVID{
		StructVer: 1,
		Contents:  64,
		SigSz:     256,
		Signature: make([]byte, 256),
		RawBytes:  []byte("raw"),
	}

	assert.Equal(t, uint32(1), csr.StructVer)
	assert.Equal(t, uint32(64), csr.Contents)
	assert.Equal(t, uint32(256), csr.SigSz)
	assert.Len(t, csr.Signature, 256)
}
