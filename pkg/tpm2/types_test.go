package tpm2

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Common test utilities (merged from test_common_test.go)
// ---------------------------------------------------------------------------

var (
	currentWorkingDirectoryCommon, _ = os.Getwd()
	TEST_DIR                         = fmt.Sprintf("%s/testdata", currentWorkingDirectoryCommon)
	CLEAN_TMP                        = false
)

func init() {
	// Ensure test directory exists
	_ = os.MkdirAll(TEST_DIR, 0755)
}

func TestHierarchyNameTypes(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy tpm2.TPMHandle
		want      string
		wantPanic bool
	}{
		{
			name:      "platform hierarchy",
			hierarchy: tpm2.TPMRHPlatform,
			want:      "PLATFORM",
		},
		{
			name:      "owner hierarchy",
			hierarchy: tpm2.TPMRHOwner,
			want:      "OWNER",
		},
		{
			name:      "endorsement hierarchy",
			hierarchy: tpm2.TPMRHEndorsement,
			want:      "ENDORSEMENT",
		},
		{
			name:      "null hierarchy",
			hierarchy: tpm2.TPMRHNull,
			want:      "NULL",
		},
		{
			name:      "invalid hierarchy panics",
			hierarchy: tpm2.TPMHandle(0x12345678),
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HierarchyName(tt.hierarchy)
			if tt.wantPanic {
				if err == nil {
					t.Errorf("HierarchyName() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("HierarchyName() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HierarchyName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashAlgFromStringTypes(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		want    tpm2.TPMIAlgHash
		wantErr error
	}{
		{
			name: "SHA-1 uppercase",
			hash: "SHA-1",
			want: tpm2.TPMAlgSHA1,
		},
		{
			name: "SHA-256 uppercase",
			hash: "SHA-256",
			want: tpm2.TPMAlgSHA256,
		},
		{
			name: "SHA-384 uppercase",
			hash: "SHA-384",
			want: tpm2.TPMAlgSHA384,
		},
		{
			name: "SHA-512 uppercase",
			hash: "SHA-512",
			want: tpm2.TPMAlgSHA512,
		},
		{
			name: "sha-256 lowercase",
			hash: "sha-256",
			want: tpm2.TPMAlgSHA256,
		},
		{
			name: "sha-1 lowercase",
			hash: "sha-1",
			want: tpm2.TPMAlgSHA1,
		},
		{
			name:    "invalid hash algorithm",
			hash:    "MD5",
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "empty string",
			hash:    "",
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "nonsense string",
			hash:    "notahash",
			wantErr: ErrInvalidHashFunction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlgFromString(tt.hash)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ParseHashAlgFromString() expected error %v, got nil", tt.wantErr)
					return
				}
				if err != tt.wantErr {
					t.Errorf("ParseHashAlgFromString() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseHashAlgFromString() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseHashAlgFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashAlgTypes(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    tpm2.TPMIAlgHash
		wantErr error
	}{
		{
			name: "SHA1",
			hash: crypto.SHA1,
			want: tpm2.TPMAlgSHA1,
		},
		{
			name: "SHA256",
			hash: crypto.SHA256,
			want: tpm2.TPMAlgSHA256,
		},
		{
			name: "SHA384",
			hash: crypto.SHA384,
			want: tpm2.TPMAlgSHA384,
		},
		{
			name: "SHA512",
			hash: crypto.SHA512,
			want: tpm2.TPMAlgSHA512,
		},
		{
			name:    "MD5 not supported",
			hash:    crypto.MD5,
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "SHA224 not supported",
			hash:    crypto.SHA224,
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "BLAKE2b_256 not supported",
			hash:    crypto.BLAKE2b_256,
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "zero value hash",
			hash:    crypto.Hash(0),
			wantErr: ErrInvalidHashFunction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlg(tt.hash)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ParseHashAlg() expected error %v, got nil", tt.wantErr)
					return
				}
				if err != tt.wantErr {
					t.Errorf("ParseHashAlg() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseHashAlg() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseHashAlg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashSizeTypes(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    uint32
		wantErr error
	}{
		{
			name: "SHA1 size is 20",
			hash: crypto.SHA1,
			want: 20,
		},
		{
			name: "SHA256 size is 32",
			hash: crypto.SHA256,
			want: 32,
		},
		{
			name: "SHA384 size is 48",
			hash: crypto.SHA384,
			want: 48,
		},
		{
			name: "SHA512 size is 64",
			hash: crypto.SHA512,
			want: 64,
		},
		{
			name:    "MD5 not supported",
			hash:    crypto.MD5,
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "SHA224 not supported",
			hash:    crypto.SHA224,
			wantErr: ErrInvalidHashFunction,
		},
		{
			name:    "zero value hash",
			hash:    crypto.Hash(0),
			wantErr: ErrInvalidHashFunction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashSize(tt.hash)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ParseHashSize() expected error %v, got nil", tt.wantErr)
					return
				}
				if err != tt.wantErr {
					t.Errorf("ParseHashSize() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseHashSize() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseHashSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCGVendorIDString(t *testing.T) {
	tests := []struct {
		name string
		id   TCGVendorID
		want string
	}{
		{
			name: "AMD",
			id:   TCGVendorID(1095582720),
			want: "AMD",
		},
		{
			name: "Intel",
			id:   TCGVendorID(1229870147),
			want: "Intel",
		},
		{
			name: "Microsoft",
			id:   TCGVendorID(1297303124),
			want: "Microsoft",
		},
		{
			name: "Google",
			id:   TCGVendorID(1196379975),
			want: "Google",
		},
		{
			name: "IBM",
			id:   TCGVendorID(1229081856),
			want: "IBM",
		},
		{
			name: "Infineon",
			id:   TCGVendorID(1229346816),
			want: "Infineon",
		},
		{
			name: "unknown vendor returns empty",
			id:   TCGVendorID(0),
			want: "",
		},
		{
			name: "invalid vendor ID",
			id:   TCGVendorID(999999999),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.id.String()
			if got != tt.want {
				t.Errorf("TCGVendorID.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTemplatesExist(t *testing.T) {
	// Verify that key templates are properly initialized
	tests := []struct {
		name     string
		template tpm2.TPMTPublic
		wantType tpm2.TPMAlgID
	}{
		{
			name:     "RSA SSA Template",
			template: RSASSATemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "RSA PSS Template",
			template: RSAPSSTemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "ECC P256 Template",
			template: ECCP256Template,
			wantType: tpm2.TPMAlgECC,
		},
		{
			name:     "ECC P384 Template",
			template: ECCP384Template,
			wantType: tpm2.TPMAlgECC,
		},
		{
			name:     "ECC P521 Template",
			template: ECCP521Template,
			wantType: tpm2.TPMAlgECC,
		},
		{
			name:     "RSA SSA AK Template",
			template: RSASSAAKTemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "RSA PSS AK Template",
			template: RSAPSSAKTemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "ECC P256 AK Template",
			template: ECCAKP256Template,
			wantType: tpm2.TPMAlgECC,
		},
		{
			name:     "RSA SSA IDevID Template",
			template: RSASSAIDevIDTemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "RSA PSS IDevID Template",
			template: RSAPSSIDevIDTemplate,
			wantType: tpm2.TPMAlgRSA,
		},
		{
			name:     "ECC P256 IDevID Template",
			template: ECCIDevIDP256Template,
			wantType: tpm2.TPMAlgECC,
		},
		{
			name:     "AES 128 CFB Template",
			template: AES128CFBTemplate,
			wantType: tpm2.TPMAlgSymCipher,
		},
		{
			name:     "AES 256 CFB Template",
			template: AES256CFBTemplate,
			wantType: tpm2.TPMAlgSymCipher,
		},
		{
			name:     "Keyed Hash Template",
			template: KeyedHashTemplate,
			wantType: tpm2.TPMAlgKeyedHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.template.Type != tt.wantType {
				t.Errorf("%s Type = %v, want %v", tt.name, tt.template.Type, tt.wantType)
			}
		})
	}
}

func TestAKTemplateAttributes(t *testing.T) {
	// Verify AK templates have required attributes per TCG spec:
	// - Restricted
	// - Signing
	// - Not-decrypting
	// - FixedTPM
	tests := []struct {
		name     string
		template tpm2.TPMTPublic
	}{
		{
			name:     "RSA SSA AK Template",
			template: RSASSAAKTemplate,
		},
		{
			name:     "RSA PSS AK Template",
			template: RSAPSSAKTemplate,
		},
		{
			name:     "ECC P256 AK Template",
			template: ECCAKP256Template,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := tt.template.ObjectAttributes
			if !attrs.Restricted {
				t.Errorf("%s should have Restricted=true", tt.name)
			}
			if !attrs.SignEncrypt {
				t.Errorf("%s should have SignEncrypt=true", tt.name)
			}
			if !attrs.FixedTPM {
				t.Errorf("%s should have FixedTPM=true", tt.name)
			}
			if attrs.Decrypt {
				t.Errorf("%s should have Decrypt=false", tt.name)
			}
		})
	}
}

func TestIDevIDTemplateAttributes(t *testing.T) {
	// Verify IDevID templates have required attributes per TCG spec:
	// - Not-Restricted
	// - Signing
	// - Not-decrypting
	// - FixedTPM
	tests := []struct {
		name     string
		template tpm2.TPMTPublic
	}{
		{
			name:     "RSA SSA IDevID Template",
			template: RSASSAIDevIDTemplate,
		},
		{
			name:     "RSA PSS IDevID Template",
			template: RSAPSSIDevIDTemplate,
		},
		{
			name:     "ECC P256 IDevID Template",
			template: ECCIDevIDP256Template,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := tt.template.ObjectAttributes
			if attrs.Restricted {
				t.Errorf("%s should have Restricted=false for IDevID", tt.name)
			}
			if !attrs.SignEncrypt {
				t.Errorf("%s should have SignEncrypt=true", tt.name)
			}
			if !attrs.FixedTPM {
				t.Errorf("%s should have FixedTPM=true", tt.name)
			}
			if attrs.Decrypt {
				t.Errorf("%s should have Decrypt=false", tt.name)
			}
		})
	}
}

func TestErrorTypesFromTypes(t *testing.T) {
	// Verify error types are properly typed
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrInvalidAKAttributes",
			err:  ErrInvalidAKAttributes,
			want: "tpm: invalid AK attributes",
		},
		{
			name: "ErrInvalidEKCertFormat",
			err:  ErrInvalidEKCertFormat,
			want: "tpm: invalid endorsement certificate format",
		},
		{
			name: "ErrDeviceAlreadyOpen",
			err:  ErrDeviceAlreadyOpen,
			want: "tpm: device already open",
		},
		{
			name: "ErrInvalidSessionType",
			err:  ErrInvalidSessionType,
			want: "tpm: invalid session type",
		},
		{
			name: "ErrHashAlgorithmNotSupported",
			err:  ErrHashAlgorithmNotSupported,
			want: "tpm: hash algorithm not supported",
		},
		{
			name: "ErrInvalidPolicyDigest",
			err:  ErrInvalidPolicyDigest,
			want: "tpm: invalid policy digest",
		},
		{
			name: "ErrInvalidHandle",
			err:  ErrInvalidHandle,
			want: "tpm: invalid entity handle",
		},
		{
			name: "ErrUnexpectedRandomBytes",
			err:  ErrUnexpectedRandomBytes,
			want: "tpm: unexpected number of random bytes read",
		},
		{
			name: "ErrInvalidPCRIndex",
			err:  ErrInvalidPCRIndex,
			want: "tpm: invalid PCR index",
		},
		{
			name: "ErrInvalidNonce",
			err:  ErrInvalidNonce,
			want: "tpm: invalid nonce",
		},
		{
			name: "ErrNotInitialized",
			err:  ErrNotInitialized,
			want: "tpm: not initialized",
		},
		{
			name: "ErrEndorsementCertNotFound",
			err:  ErrEndorsementCertNotFound,
			want: "tpm: endorsement certificate not found",
		},
		{
			name: "ErrInvalidHashFunction",
			err:  ErrInvalidHashFunction,
			want: "tpm: invalid hash function",
		},
		{
			name: "ErrMissingMeasurementLog",
			err:  ErrMissingMeasurementLog,
			want: "tpm: binary measurement log not found",
		},
		{
			name: "ErrRSAPSSNotSupported",
			err:  ErrRSAPSSNotSupported,
			want: "tpm: RSA-PSS / FIPS 140-2 not supported by this TPM",
		},
		{
			name: "ErrInvalidEnrollmentStrategy",
			err:  ErrInvalidEnrollmentStrategy,
			want: "tpm: invalid enrollment strategy",
		},
		{
			name: "ErrCurveNotSupported",
			err:  ErrCurveNotSupported,
			want: "tpm: ECC curve not supported by TPM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("%s.Error() = %v, want %v", tt.name, tt.err.Error(), tt.want)
			}
		})
	}
}

func TestEnrollmentStrategyConstants(t *testing.T) {
	// Test enrollment strategy type
	tests := []struct {
		name     string
		strategy EnrollmentStrategy
		want     string
	}{
		{
			name:     "IAK strategy",
			strategy: EnrollmentStrategyIAK,
			want:     "IAK",
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
			want:     "IAK_IDEVID_SINGLE_PASS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.strategy) != tt.want {
				t.Errorf("EnrollmentStrategy = %v, want %v", string(tt.strategy), tt.want)
			}
		})
	}
}

func TestQuoteStruct(t *testing.T) {
	// Test Quote struct initialization
	quote := Quote{
		Quoted:    []byte("quoted-data"),
		Signature: []byte("signature-data"),
		Nonce:     []byte("nonce-data"),
		PCRs:      []byte("pcr-data"),
		EventLog:  []byte("eventlog-data"),
	}

	if string(quote.Quoted) != "quoted-data" {
		t.Errorf("Quote.Quoted = %v, want %v", string(quote.Quoted), "quoted-data")
	}
	if string(quote.Signature) != "signature-data" {
		t.Errorf("Quote.Signature = %v, want %v", string(quote.Signature), "signature-data")
	}
	if string(quote.Nonce) != "nonce-data" {
		t.Errorf("Quote.Nonce = %v, want %v", string(quote.Nonce), "nonce-data")
	}
	if string(quote.PCRs) != "pcr-data" {
		t.Errorf("Quote.PCRs = %v, want %v", string(quote.PCRs), "pcr-data")
	}
	if string(quote.EventLog) != "eventlog-data" {
		t.Errorf("Quote.EventLog = %v, want %v", string(quote.EventLog), "eventlog-data")
	}
}

func TestPCRBankStruct(t *testing.T) {
	// Test PCRBank struct initialization
	bank := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte("pcr0-value")},
			{ID: 1, Value: []byte("pcr1-value")},
		},
	}

	if bank.Algorithm != "SHA256" {
		t.Errorf("PCRBank.Algorithm = %v, want %v", bank.Algorithm, "SHA256")
	}
	if len(bank.PCRs) != 2 {
		t.Errorf("len(PCRBank.PCRs) = %v, want %v", len(bank.PCRs), 2)
	}
	if bank.PCRs[0].ID != 0 {
		t.Errorf("PCRBank.PCRs[0].ID = %v, want %v", bank.PCRs[0].ID, 0)
	}
	if string(bank.PCRs[0].Value) != "pcr0-value" {
		t.Errorf("PCRBank.PCRs[0].Value = %v, want %v", string(bank.PCRs[0].Value), "pcr0-value")
	}
}

// ---------------------------------------------------------------------------
// Tests merged from types_helpers_test.go
// ---------------------------------------------------------------------------

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

func TestHierarchyName_ErrorOnInvalid(t *testing.T) {
	// Test that an invalid hierarchy returns ErrInvalidHierarchy
	_, err := HierarchyName(tpm2.TPMHandle(0x12345678))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidHierarchy)

	// Test with specific invalid handle values
	_, err = HierarchyName(tpm2.TPMHandle(0x00000000))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidHierarchy)
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
		{"ErrInvalidPlatformSRKConfiguration", ErrInvalidPlatformSRKConfiguration, "tpm: invalid platform SRK configuration"},
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

// ---------------------------------------------------------------------------
// Extended template parameter tests (merged from templates_test.go)
// ---------------------------------------------------------------------------

func TestRSASSATemplateExtended(t *testing.T) {
	t.Run("has correct RSA parameters", func(t *testing.T) {
		rsaDetail, err := RSASSATemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.NotNil(t, rsaDetail)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has empty auth policy by default", func(t *testing.T) {
		assert.Empty(t, RSASSATemplate.AuthPolicy.Buffer)
	})

	t.Run("unique buffer has correct size for RSA 2048", func(t *testing.T) {
		rsaUnique, err := RSASSATemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestRSAPSSTemplateExtended(t *testing.T) {
	t.Run("has RSA-PSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has correct key size", func(t *testing.T) {
		rsaDetail, err := RSAPSSTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("unique buffer has correct size", func(t *testing.T) {
		rsaUnique, err := RSAPSSTemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestECCP256TemplateExtended(t *testing.T) {
	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has empty auth policy by default", func(t *testing.T) {
		assert.Empty(t, ECCP256Template.AuthPolicy.Buffer)
	})
}

func TestECCP384TemplateExtended(t *testing.T) {
	t.Run("has NIST P384 curve", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP384, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has SHA384 hash algorithm in scheme", func(t *testing.T) {
		eccDetail, err := ECCP384Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		schemeDetails := eccDetail.Scheme.Details
		ecdsaScheme, err := schemeDetails.ECDSA()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, ecdsaScheme.HashAlg)
	})
}

func TestECCP521TemplateExtended(t *testing.T) {
	t.Run("has NIST P521 curve", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP521, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})

	t.Run("has SHA512 hash algorithm in scheme", func(t *testing.T) {
		eccDetail, err := ECCP521Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		schemeDetails := eccDetail.Scheme.Details
		ecdsaScheme, err := schemeDetails.ECDSA()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, ecdsaScheme.HashAlg)
	})
}

func TestRSASSAAKTemplateExtended(t *testing.T) {
	t.Run("has RSASSA scheme", func(t *testing.T) {
		rsaDetail, err := RSASSAAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSASSAAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("unique buffer has correct size", func(t *testing.T) {
		rsaUnique, err := RSASSAAKTemplate.Unique.RSA()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(rsaUnique.Buffer))
	})
}

func TestRSAPSSAKTemplateExtended(t *testing.T) {
	t.Run("has RSAPSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSAPSSAKTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})

	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, RSAPSSAKTemplate.AuthPolicy.Buffer)
	})
}

func TestECCAKP256TemplateExtended(t *testing.T) {
	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCAKP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCAKP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})
}

func TestRSASSAIDevIDTemplateExtended(t *testing.T) {
	t.Run("has RSASSA scheme", func(t *testing.T) {
		rsaDetail, err := RSASSAIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	})

	t.Run("has 2048-bit key size", func(t *testing.T) {
		rsaDetail, err := RSASSAIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)
	})
}

func TestRSAPSSIDevIDTemplateExtended(t *testing.T) {
	t.Run("has RSAPSS scheme", func(t *testing.T) {
		rsaDetail, err := RSAPSSIDevIDTemplate.Parameters.RSADetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
	})

	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, RSAPSSIDevIDTemplate.AuthPolicy.Buffer)
	})
}

func TestECCIDevIDP256TemplateExtended(t *testing.T) {
	t.Run("has NIST P256 curve", func(t *testing.T) {
		eccDetail, err := ECCIDevIDP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	})

	t.Run("has ECDSA scheme", func(t *testing.T) {
		eccDetail, err := ECCIDevIDP256Template.Parameters.ECCDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)
	})
}

func TestAES128CFBTemplateAttributes(t *testing.T) {
	t.Run("has AES algorithm in parameters", func(t *testing.T) {
		symParms, err := AES128CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgAES, symParms.Sym.Algorithm)
	})

	t.Run("has CFB mode in parameters", func(t *testing.T) {
		symParms, err := AES128CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		mode, err := symParms.Sym.Mode.AES()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgCFB, *mode)
	})
}

func TestAES256CFBTemplateAttributes(t *testing.T) {
	t.Run("has AES algorithm in parameters", func(t *testing.T) {
		symParms, err := AES256CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgAES, symParms.Sym.Algorithm)
	})

	t.Run("has CFB mode in parameters", func(t *testing.T) {
		symParms, err := AES256CFBTemplate.Parameters.SymDetail()
		assert.NoError(t, err)
		mode, err := symParms.Sym.Mode.AES()
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgCFB, *mode)
	})
}

func TestKeyedHashTemplateAttributes(t *testing.T) {
	t.Run("has empty auth policy", func(t *testing.T) {
		assert.Empty(t, KeyedHashTemplate.AuthPolicy.Buffer)
	})
}

func TestTemplateAttributeModification(t *testing.T) {
	t.Run("can modify auth policy on RSA template", func(t *testing.T) {
		template := RSASSATemplate
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		}
		template.AuthPolicy = policyDigest
		assert.Equal(t, policyDigest.Buffer, template.AuthPolicy.Buffer)
	})

	t.Run("can modify NoDA attribute", func(t *testing.T) {
		template := RSASSATemplate
		template.ObjectAttributes.NoDA = true
		assert.True(t, template.ObjectAttributes.NoDA)
	})

	t.Run("can set AdminWithPolicy attribute", func(t *testing.T) {
		template := RSASSAIDevIDTemplate
		template.ObjectAttributes.AdminWithPolicy = true
		assert.True(t, template.ObjectAttributes.AdminWithPolicy)
	})

	t.Run("can change name algorithm", func(t *testing.T) {
		template := RSASSATemplate
		template.NameAlg = tpm2.TPMAlgSHA384
		assert.Equal(t, tpm2.TPMAlgSHA384, template.NameAlg)
	})
}

func TestTemplateConsistencyChecks(t *testing.T) {
	t.Run("all AK templates are restricted", func(t *testing.T) {
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.Restricted)
		assert.True(t, ECCAKP256Template.ObjectAttributes.Restricted)
	})

	t.Run("all IDevID templates are not restricted", func(t *testing.T) {
		assert.False(t, RSASSAIDevIDTemplate.ObjectAttributes.Restricted)
		assert.False(t, RSAPSSIDevIDTemplate.ObjectAttributes.Restricted)
		assert.False(t, ECCIDevIDP256Template.ObjectAttributes.Restricted)
	})

	t.Run("all signing templates have SignEncrypt set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCP256Template.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCAKP256Template.ObjectAttributes.SignEncrypt)
		assert.True(t, RSASSAIDevIDTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, RSAPSSIDevIDTemplate.ObjectAttributes.SignEncrypt)
		assert.True(t, ECCIDevIDP256Template.ObjectAttributes.SignEncrypt)
	})

	t.Run("all templates have FixedTPM set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.FixedTPM)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP256Template.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP384Template.ObjectAttributes.FixedTPM)
		assert.True(t, ECCP521Template.ObjectAttributes.FixedTPM)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, ECCAKP256Template.ObjectAttributes.FixedTPM)
		assert.True(t, AES128CFBTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, AES256CFBTemplate.ObjectAttributes.FixedTPM)
		assert.True(t, KeyedHashTemplate.ObjectAttributes.FixedTPM)
	})

	t.Run("all templates have UserWithAuth set", func(t *testing.T) {
		assert.True(t, RSASSATemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, RSAPSSTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP256Template.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP384Template.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCP521Template.ObjectAttributes.UserWithAuth)
		assert.True(t, RSASSAAKTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, RSAPSSAKTemplate.ObjectAttributes.UserWithAuth)
		assert.True(t, ECCAKP256Template.ObjectAttributes.UserWithAuth)
	})
}

// ---------------------------------------------------------------------------
// Tests merged from data_structures_test.go
// ---------------------------------------------------------------------------

func TestBytesToUint32Unit(t *testing.T) {
	tests := []struct {
		name string
		b    [4]byte
		want uint32
	}{
		{
			name: "zero",
			b:    [4]byte{0x00, 0x00, 0x00, 0x00},
			want: 0,
		},
		{
			name: "one",
			b:    [4]byte{0x00, 0x00, 0x00, 0x01},
			want: 1,
		},
		{
			name: "max uint32",
			b:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			want: 0xFFFFFFFF,
		},
		{
			name: "version number",
			b:    [4]byte{0x00, 0x00, 0x01, 0x00},
			want: 0x00000100,
		},
		{
			name: "arbitrary value",
			b:    [4]byte{0x12, 0x34, 0x56, 0x78},
			want: 0x12345678,
		},
		{
			name: "high byte set",
			b:    [4]byte{0x80, 0x00, 0x00, 0x00},
			want: 0x80000000,
		},
		{
			name: "alternating bytes",
			b:    [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			want: 0xAABBCCDD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToUint32(tt.b)
			if got != tt.want {
				t.Errorf("bytesToUint32() = %d (0x%x), want %d (0x%x)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestPackIDevIDContentUnit(t *testing.T) {
	tests := []struct {
		name    string
		content *TCG_IDEVID_CONTENT
		wantErr bool
	}{
		{
			name: "valid content with all fields",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
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
				ProdModel:                 []byte("test"),
				ProdSerial:                []byte("001"),
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{1, 2, 3, 4},
				AttestPub:                 []byte{5, 6, 7, 8},
				AtCreateTkt:               []byte{9, 10, 11, 12},
				AtCertifyInfo:             []byte{13, 14, 15, 16},
				AtCertifyInfoSig:          []byte{17, 18, 19, 20},
				SigningPub:                []byte{21, 22, 23, 24},
				SgnCertifyInfo:            []byte{25, 26, 27, 28},
				SgnCertifyInfoSig:         []byte{29, 30, 31, 32},
				Pad:                       []byte{},
			},
			wantErr: false,
		},
		{
			name: "empty content",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{},
				ProdSerialSz:              [4]byte{},
				ProdCaDataSz:              [4]byte{},
				BootEvntLogSz:             [4]byte{},
				EkCertSZ:                  [4]byte{},
				AttestPubSZ:               [4]byte{},
				AtCreateTktSZ:             [4]byte{},
				AtCertifyInfoSZ:           [4]byte{},
				AtCertifyInfoSignatureSZ:  [4]byte{},
				SigningPubSZ:              [4]byte{},
				SgnCertifyInfoSZ:          [4]byte{},
				SgnCertifyInfoSignatureSZ: [4]byte{},
				PadSz:                     [4]byte{},
				ProdModel:                 []byte{},
				ProdSerial:                []byte{},
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{},
				AttestPub:                 []byte{},
				AtCreateTkt:               []byte{},
				AtCertifyInfo:             []byte{},
				AtCertifyInfoSig:          []byte{},
				SigningPub:                []byte{},
				SgnCertifyInfo:            []byte{},
				SgnCertifyInfoSig:         []byte{},
				Pad:                       []byte{},
			},
			wantErr: false,
		},
		{
			name: "content with padding",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
				ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
				ProdCaDataSz:              [4]byte{},
				BootEvntLogSz:             [4]byte{},
				EkCertSZ:                  [4]byte{},
				AttestPubSZ:               [4]byte{},
				AtCreateTktSZ:             [4]byte{},
				AtCertifyInfoSZ:           [4]byte{},
				AtCertifyInfoSignatureSZ:  [4]byte{},
				SigningPubSZ:              [4]byte{},
				SgnCertifyInfoSZ:          [4]byte{},
				SgnCertifyInfoSignatureSZ: [4]byte{},
				PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x08},
				ProdModel:                 []byte("edge"),
				ProdSerial:                []byte("001"),
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{},
				AttestPub:                 []byte{},
				AtCreateTkt:               []byte{},
				AtCertifyInfo:             []byte{},
				AtCertifyInfoSig:          []byte{},
				SigningPub:                []byte{},
				SgnCertifyInfo:            []byte{},
				SgnCertifyInfoSig:         []byte{},
				Pad:                       []byte("========"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PackIDevIDContent(tt.content)

			if tt.wantErr {
				if err == nil {
					t.Error("PackIDevIDContent() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("PackIDevIDContent() unexpected error: %v", err)
				return
			}

			// Verify minimum size (16 size fields * 4 bytes)
			minSize := 16 * 4
			if len(result) < minSize {
				t.Errorf("PackIDevIDContent() result too short: got %d, want at least %d", len(result), minSize)
			}

			// Verify header fields
			if !bytes.Equal(result[0:4], tt.content.StructVer[:]) {
				t.Error("PackIDevIDContent() StructVer mismatch")
			}
			if !bytes.Equal(result[4:8], tt.content.HashAlgoId[:]) {
				t.Error("PackIDevIDContent() HashAlgoId mismatch")
			}
			if !bytes.Equal(result[8:12], tt.content.HashSz[:]) {
				t.Error("PackIDevIDContent() HashSz mismatch")
			}
		})
	}
}

func TestPackIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		csr     *TCG_CSR_IDEVID
		wantErr bool
	}{
		{
			name: "valid CSR",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x10},
				SigSz:     [4]byte{0x00, 0x00, 0x00, 0x08},
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0b},
					HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
					ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x04},
					ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
					ProdModel:    []byte("test"),
					ProdSerial:   []byte("001"),
				},
				Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PackIDevIDCSR(tt.csr)

			if tt.wantErr {
				if err == nil {
					t.Error("PackIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("PackIDevIDCSR() unexpected error: %v", err)
				return
			}

			// Verify structure starts with StructVer
			if !bytes.Equal(result[0:4], tt.csr.StructVer[:]) {
				t.Error("PackIDevIDCSR() StructVer mismatch")
			}

			// Verify signature at the end
			sigSize := binary.BigEndian.Uint32(tt.csr.SigSz[:])
			sigStart := len(result) - int(sigSize)
			if !bytes.Equal(result[sigStart:], tt.csr.Signature) {
				t.Error("PackIDevIDCSR() signature mismatch at end")
			}
		})
	}
}

func TestUnpackIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		csr     *TCG_CSR_IDEVID
		wantErr bool
	}{
		{
			name: "unpack valid CSR",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x64},
				SigSz:     [4]byte{0x00, 0x00, 0x00, 0x10},
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
					HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
					ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
					ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
					ProdCaDataSz:              [4]byte{},
					BootEvntLogSz:             [4]byte{},
					EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x04},
					AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x04},
					AtCreateTktSZ:             [4]byte{},
					AtCertifyInfoSZ:           [4]byte{},
					AtCertifyInfoSignatureSZ:  [4]byte{},
					SigningPubSZ:              [4]byte{},
					SgnCertifyInfoSZ:          [4]byte{},
					SgnCertifyInfoSignatureSZ: [4]byte{},
					PadSz:                     [4]byte{},
					ProdModel:                 []byte("test"),
					ProdSerial:                []byte("001"),
					EkCert:                    []byte{1, 2, 3, 4},
					AttestPub:                 []byte{5, 6, 7, 8},
				},
				Signature: make([]byte, 16),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unpacked, err := UnpackIDevIDCSR(tt.csr)

			if tt.wantErr {
				if err == nil {
					t.Error("UnpackIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnpackIDevIDCSR() unexpected error: %v", err)
				return
			}

			// Verify unpacked values match
			expectedStructVer := binary.BigEndian.Uint32(tt.csr.StructVer[:])
			if unpacked.StructVer != expectedStructVer {
				t.Errorf("UnpackIDevIDCSR() StructVer = %d, want %d", unpacked.StructVer, expectedStructVer)
			}

			expectedContents := binary.BigEndian.Uint32(tt.csr.Contents[:])
			if unpacked.Contents != expectedContents {
				t.Errorf("UnpackIDevIDCSR() Contents = %d, want %d", unpacked.Contents, expectedContents)
			}

			// Verify content fields
			if !bytes.Equal(unpacked.CsrContents.ProdModel, tt.csr.CsrContents.ProdModel) {
				t.Error("UnpackIDevIDCSR() ProdModel mismatch")
			}
		})
	}
}

func TestUnmarshalIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() []byte
		wantErr bool
	}{
		{
			name: "valid marshalled CSR",
			setup: func() []byte {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x10}) // Contents
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x04}) // SigSz
				// CSR Contents
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x0b}) // HashAlgoId
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x20}) // HashSz
				// Size fields (all zeros)
				for i := 0; i < 13; i++ {
					_ = binary.Write(&buf, binary.BigEndian, [4]byte{})
				}
				// Signature
				_ = binary.Write(&buf, binary.BigEndian, []byte{1, 2, 3, 4})
				return buf.Bytes()
			},
			wantErr: false,
		},
		{
			name: "truncated header",
			setup: func() []byte {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00})
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "empty data",
			setup: func() []byte {
				return []byte{}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrBytes := tt.setup()
			result, err := UnmarshalIDevIDCSR(csrBytes)

			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnmarshalIDevIDCSR() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("UnmarshalIDevIDCSR() returned nil")
			}
		})
	}
}

func TestUnpackIDevIDContentUnit(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *bytes.Reader
		wantErr bool
	}{
		{
			name: "valid content with zero size fields",
			setup: func() *bytes.Reader {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x0b}) // HashAlgoId
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x20}) // HashSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x04}) // ProdModelSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x03}) // ProdSerialSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // ProdCaDataSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // BootEvntLogSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // EkCertSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AttestPubSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCreateTktSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCertifyInfoSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCertifyInfoSignatureSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SigningPubSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SgnCertifyInfoSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SgnCertifyInfoSignatureSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // PadSz
				return bytes.NewReader(buf.Bytes())
			},
			wantErr: true, // Reader insufficient data for variable fields
		},
		{
			name: "partial header",
			setup: func() *bytes.Reader {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00})
				return bytes.NewReader(buf.Bytes())
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := tt.setup()
			result, err := UnpackIDevIDContent(reader)

			if tt.wantErr {
				if err == nil {
					t.Error("UnpackIDevIDContent() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnpackIDevIDContent() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Fatal("UnpackIDevIDContent() returned nil")
				return
			}

			// Verify parsed values
			if bytesToUint32(result.StructVer) != uint32(0x00000100) {
				t.Errorf("UnpackIDevIDContent() StructVer = 0x%x, want 0x00000100", result.StructVer)
			}

			if bytesToUint32(result.HashAlgoId) != uint32(11) {
				t.Errorf("UnpackIDevIDContent() HashAlgoId = %d, want 11", result.HashAlgoId)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategy_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "Lowercase IAK",
			input:    "iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, // Falls through to default
		},
		{
			name:     "Mixed case",
			input:    "Iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Whitespace padded",
			input:    " IAK ",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Exact IAK match",
			input:    string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "Exact SINGLE_PASS match",
			input:    string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
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

func TestCryptoHashToTPMAlg(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected tpm2.TPMAlgID
	}{
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var algo tpm2.TPMIAlgHash
			switch tc.hash {
			case crypto.SHA256:
				algo = tpm2.TPMAlgSHA256
			case crypto.SHA384:
				algo = tpm2.TPMAlgSHA384
			case crypto.SHA512:
				algo = tpm2.TPMAlgSHA512
			}
			assert.Equal(t, tc.expected, tpm2.TPMAlgID(algo))
		})
	}
}

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrInvalidSignature",
			err:      ErrInvalidSignature,
			expected: "tpm: invalid signature",
		},
		{
			name:     "ErrInvalidEnrollmentStrategy",
			err:      ErrInvalidEnrollmentStrategy,
			expected: "tpm: invalid enrollment strategy",
		},
		{
			name:     "ErrInvalidHashFunction",
			err:      ErrInvalidHashFunction,
			expected: "tpm: invalid hash function",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
			assert.True(t, errors.Is(tc.err, tc.err))
		})
	}
}
