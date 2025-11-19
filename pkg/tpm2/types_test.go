package tpm2

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

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
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("HierarchyName() expected panic but did not panic")
					}
				}()
			}

			got := HierarchyName(tt.hierarchy)
			if !tt.wantPanic && got != tt.want {
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
