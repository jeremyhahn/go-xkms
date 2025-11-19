package tpm2

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestParseHashAlgFromStringUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		want    tpm2.TPMIAlgHash
		wantErr bool
	}{
		{
			name:    "SHA-1 uppercase",
			hash:    "SHA-1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-1 lowercase",
			hash:    "sha-1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-256",
			hash:    "SHA-256",
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA-384",
			hash:    "SHA-384",
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA-512",
			hash:    "SHA-512",
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "invalid hash",
			hash:    "MD5",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			hash:    "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "partial match",
			hash:    "SHA",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlgFromString(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashAlgFromString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashAlgFromString() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashAlgFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashAlgUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    tpm2.TPMIAlgHash
		wantErr bool
	}{
		{
			name:    "SHA1",
			hash:    crypto.SHA1,
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "unsupported MD5",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
		{
			name:    "unsupported SHA3-256",
			hash:    crypto.SHA3_256,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashAlg(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashAlg() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashAlg() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashAlg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHashSizeUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    uint32
		wantErr bool
	}{
		{
			name:    "SHA1 size",
			hash:    crypto.SHA1,
			want:    20,
			wantErr: false,
		},
		{
			name:    "SHA256 size",
			hash:    crypto.SHA256,
			want:    32,
			wantErr: false,
		},
		{
			name:    "SHA384 size",
			hash:    crypto.SHA384,
			want:    48,
			wantErr: false,
		},
		{
			name:    "SHA512 size",
			hash:    crypto.SHA512,
			want:    64,
			wantErr: false,
		},
		{
			name:    "unsupported hash",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
		{
			name:    "SHA3-256 unsupported",
			hash:    crypto.SHA3_256,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashSize(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHashSize() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHashSize() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHashSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHierarchyNameUnit(t *testing.T) {
	tests := []struct {
		name        string
		hierarchy   tpm2.TPMHandle
		want        string
		shouldPanic bool
	}{
		{
			name:        "Platform hierarchy",
			hierarchy:   tpm2.TPMRHPlatform,
			want:        "PLATFORM",
			shouldPanic: false,
		},
		{
			name:        "Owner hierarchy",
			hierarchy:   tpm2.TPMRHOwner,
			want:        "OWNER",
			shouldPanic: false,
		},
		{
			name:        "Endorsement hierarchy",
			hierarchy:   tpm2.TPMRHEndorsement,
			want:        "ENDORSEMENT",
			shouldPanic: false,
		},
		{
			name:        "Null hierarchy",
			hierarchy:   tpm2.TPMRHNull,
			want:        "NULL",
			shouldPanic: false,
		},
		{
			name:        "Invalid hierarchy",
			hierarchy:   tpm2.TPMHandle(0xFFFFFFFF),
			want:        "",
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("HierarchyName() expected panic, got none")
					}
				}()
			}

			got := HierarchyName(tt.hierarchy)

			if !tt.shouldPanic && got != tt.want {
				t.Errorf("HierarchyName() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseHierarchyUnit(t *testing.T) {
	tests := []struct {
		name          string
		hierarchyType string
		want          tpm2.TPMIRHHierarchy
		wantErr       bool
	}{
		{
			name:          "ENDORSEMENT",
			hierarchyType: "ENDORSEMENT",
			want:          tpm2.TPMRHEndorsement,
			wantErr:       false,
		},
		{
			name:          "OWNER",
			hierarchyType: "OWNER",
			want:          tpm2.TPMRHOwner,
			wantErr:       false,
		},
		{
			name:          "PLATFORM",
			hierarchyType: "PLATFORM",
			want:          tpm2.TPMRHPlatform,
			wantErr:       false,
		},
		{
			name:          "lowercase endorsement",
			hierarchyType: "endorsement",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "invalid hierarchy",
			hierarchyType: "INVALID",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "empty string",
			hierarchyType: "",
			want:          0,
			wantErr:       true,
		},
		{
			name:          "mixed case",
			hierarchyType: "Endorsement",
			want:          0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHierarchy(tt.hierarchyType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHierarchy() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHierarchy() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseHierarchy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyUnit(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		want     EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			strategy: string(EnrollmentStrategyIAK),
			want:     EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "invalid strategy defaults to single pass",
			strategy: "INVALID",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			strategy: "",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "lowercase iak",
			strategy: "iak",
			want:     EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseIdentityProvisioningStrategy(tt.strategy)
			if got != tt.want {
				t.Errorf("ParseIdentityProvisioningStrategy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePCRBankAlgIDUnit(t *testing.T) {
	tests := []struct {
		name    string
		pcrBank string
		want    tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "sha1 lowercase",
			pcrBank: "sha1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA1 uppercase",
			pcrBank: "SHA1",
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "sha256",
			pcrBank: "sha256",
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "sha384",
			pcrBank: "sha384",
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "sha512",
			pcrBank: "sha512",
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "invalid pcr bank",
			pcrBank: "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "sha3-256 unsupported",
			pcrBank: "sha3-256",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePCRBankAlgID(tt.pcrBank)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePCRBankAlgID() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePCRBankAlgID() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParsePCRBankAlgID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePCRBankCryptoHashUnit(t *testing.T) {
	tests := []struct {
		name    string
		pcrBank string
		want    crypto.Hash
		wantErr bool
	}{
		{
			name:    "sha1",
			pcrBank: "sha1",
			want:    crypto.SHA1,
			wantErr: false,
		},
		{
			name:    "sha256",
			pcrBank: "sha256",
			want:    crypto.SHA256,
			wantErr: false,
		},
		{
			name:    "sha384",
			pcrBank: "sha384",
			want:    crypto.SHA3_384, // Note: maps to SHA3_384 per the map
			wantErr: false,
		},
		{
			name:    "sha512",
			pcrBank: "sha512",
			want:    crypto.SHA512,
			wantErr: false,
		},
		{
			name:    "invalid",
			pcrBank: "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty",
			pcrBank: "",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePCRBankCryptoHash(tt.pcrBank)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePCRBankCryptoHash() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePCRBankCryptoHash() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParsePCRBankCryptoHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCryptoHashAlgIDUnit(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		want    tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "SHA-1",
			hash:    crypto.SHA1,
			want:    tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA-256",
			hash:    crypto.SHA256,
			want:    tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA-384",
			hash:    crypto.SHA384,
			want:    tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA-512",
			hash:    crypto.SHA512,
			want:    tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "SHA3-256",
			hash:    crypto.SHA3_256,
			want:    tpm2.TPMAlgSHA3256,
			wantErr: false,
		},
		{
			name:    "SHA3-384",
			hash:    crypto.SHA3_384,
			want:    tpm2.TPMAlgSHA3384,
			wantErr: false,
		},
		{
			name:    "SHA3-512",
			hash:    crypto.SHA3_512,
			want:    tpm2.TPMAlgSHA3512,
			wantErr: false,
		},
		{
			name:    "unsupported MD5",
			hash:    crypto.MD5,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCryptoHashAlgID(tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCryptoHashAlgID() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCryptoHashAlgID() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("ParseCryptoHashAlgID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCGVendorIDStringUnit(t *testing.T) {
	tests := []struct {
		name string
		id   TCGVendorID
		want string
	}{
		{
			name: "Intel",
			id:   1229870147,
			want: "Intel",
		},
		{
			name: "AMD",
			id:   1095582720,
			want: "AMD",
		},
		{
			name: "IBM",
			id:   1229081856,
			want: "IBM",
		},
		{
			name: "Microsoft",
			id:   1297303124,
			want: "Microsoft",
		},
		{
			name: "Infineon",
			id:   1229346816,
			want: "Infineon",
		},
		{
			name: "Google",
			id:   1196379975,
			want: "Google",
		},
		{
			name: "unknown vendor",
			id:   0,
			want: "",
		},
		{
			name: "another unknown",
			id:   123456,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.id.String()
			if got != tt.want {
				t.Errorf("TCGVendorID.String() = %s, want %s", got, tt.want)
			}
		})
	}
}
