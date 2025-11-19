package tpm2

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestConfigVal_ParseHashAlgFromString_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA-1", "SHA-1", tpm2.TPMAlgSHA1, false},
		{"SHA-256", "SHA-256", tpm2.TPMAlgSHA256, false},
		{"SHA-384", "SHA-384", tpm2.TPMAlgSHA384, false},
		{"SHA-512", "SHA-512", tpm2.TPMAlgSHA512, false},
		{"sha-1 lowercase", "sha-1", tpm2.TPMAlgSHA1, false},
		{"sha-256 lowercase", "sha-256", tpm2.TPMAlgSHA256, false},
		{"sha-384 lowercase", "sha-384", tpm2.TPMAlgSHA384, false},
		{"sha-512 lowercase", "sha-512", tpm2.TPMAlgSHA512, false},
		{"Invalid algorithm", "MD5", 0, true},
		{"Empty string", "", 0, true},
		{"Unknown algorithm", "SHA3-256", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlgFromString(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashAlgFromString(%q) expected error, got nil", tt.input)
				}
				if result != 0 {
					t.Errorf("ParseHashAlgFromString(%q) expected 0 on error, got %v", tt.input, result)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashAlgFromString(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashAlgFromString(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHashAlg_Comprehensive(t *testing.T) {
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
		{"MD5", crypto.MD5, 0, true},
		{"SHA3_256", crypto.SHA3_256, 0, true},
		{"BLAKE2b_256", crypto.BLAKE2b_256, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlg(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashAlg(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashAlg(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashAlg(%v) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHashSize_Comprehensive(t *testing.T) {
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
		{"MD5", crypto.MD5, 0, true},
		{"SHA3_256", crypto.SHA3_256, 0, true},
		{"Invalid hash", crypto.Hash(0), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashSize(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashSize(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashSize(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashSize(%v) = %d, want %d", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHierarchy_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIRHHierarchy
		expectError bool
	}{
		{"ENDORSEMENT", "ENDORSEMENT", tpm2.TPMRHEndorsement, false},
		{"OWNER", "OWNER", tpm2.TPMRHOwner, false},
		{"PLATFORM", "PLATFORM", tpm2.TPMRHPlatform, false},
		{"Invalid lowercase", "endorsement", 0, true},
		{"Invalid type", "INVALID", 0, true},
		{"Empty string", "", 0, true},
		{"NULL hierarchy", "NULL", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHierarchy(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHierarchy(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidHierarchyType {
					t.Errorf("ParseHierarchy(%q) expected ErrInvalidHierarchyType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHierarchy(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHierarchy(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseIdentityStrategy_All(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{"IAK strategy", "IAK", EnrollmentStrategyIAK},
		{"IAK_IDEVID_SINGLE_PASS", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for empty", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for unknown", "UNKNOWN", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for lowercase", "iak", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tt.input)
			if result != tt.expected {
				t.Errorf("ParseIdentityProvisioningStrategy(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_ParsePCRBankAlgID_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"sha1 lowercase", "sha1", tpm2.TPMAlgSHA1, false},
		{"sha256 lowercase", "sha256", tpm2.TPMAlgSHA256, false},
		{"sha384 lowercase", "sha384", tpm2.TPMAlgSHA384, false},
		{"sha512 lowercase", "sha512", tpm2.TPMAlgSHA512, false},
		{"SHA1 uppercase", "SHA1", tpm2.TPMAlgSHA1, false},
		{"SHA256 uppercase", "SHA256", tpm2.TPMAlgSHA256, false},
		{"SHA384 uppercase", "SHA384", tpm2.TPMAlgSHA384, false},
		{"SHA512 uppercase", "SHA512", tpm2.TPMAlgSHA512, false},
		{"Invalid bank", "md5", 0, true},
		{"Empty string", "", 0, true},
		{"SHA-256 with dash", "sha-256", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRBankAlgID(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParsePCRBankAlgID(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidPCRBankType {
					t.Errorf("ParsePCRBankAlgID(%q) expected ErrInvalidPCRBankType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePCRBankAlgID(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParsePCRBankAlgID(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParsePCRBankCryptoHash_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    crypto.Hash
		expectError bool
	}{
		{"sha1 lowercase", "sha1", crypto.SHA1, false},
		{"sha256 lowercase", "sha256", crypto.SHA256, false},
		{"sha384 lowercase", "sha384", crypto.SHA3_384, false},
		{"sha512 lowercase", "sha512", crypto.SHA512, false},
		{"SHA1 uppercase", "SHA1", crypto.SHA1, false},
		{"Invalid bank", "md5", 0, true},
		{"Empty string", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRBankCryptoHash(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParsePCRBankCryptoHash(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidPCRBankType {
					t.Errorf("ParsePCRBankCryptoHash(%q) expected ErrInvalidPCRBankType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePCRBankCryptoHash(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParsePCRBankCryptoHash(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseCryptoHashAlgID_All(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"SHA3_256", crypto.SHA3_256, tpm2.TPMAlgSHA3256, false},
		{"SHA3_384", crypto.SHA3_384, tpm2.TPMAlgSHA3384, false},
		{"SHA3_512", crypto.SHA3_512, tpm2.TPMAlgSHA3512, false},
		{"MD5", crypto.MD5, 0, true},
		{"BLAKE2b", crypto.BLAKE2b_256, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCryptoHashAlgID(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseCryptoHashAlgID(%v) expected error, got nil", tt.input)
				}
				if err != ErrInvalidCryptoHashAlgID {
					t.Errorf("ParseCryptoHashAlgID(%v) expected ErrInvalidCryptoHashAlgID, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParseCryptoHashAlgID(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseCryptoHashAlgID(%v) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_HierarchyName_All(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy tpm2.TPMHandle
		expected  string
	}{
		{"PLATFORM", tpm2.TPMRHPlatform, "PLATFORM"},
		{"OWNER", tpm2.TPMRHOwner, "OWNER"},
		{"ENDORSEMENT", tpm2.TPMRHEndorsement, "ENDORSEMENT"},
		{"NULL", tpm2.TPMRHNull, "NULL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HierarchyName(tt.hierarchy)
			if result != tt.expected {
				t.Errorf("HierarchyName(%v) = %q, want %q", tt.hierarchy, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_HierarchyName_Invalid_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("HierarchyName() with invalid hierarchy expected panic, but did not panic")
		}
	}()

	HierarchyName(tpm2.TPMHandle(0xFFFFFFFF))
}

func TestConfigVal_TCGVendorID_String(t *testing.T) {
	tests := []struct {
		name     string
		vendorID TCGVendorID
		expected string
	}{
		{"AMD", 1095582720, "AMD"},
		{"Intel", 1229870147, "Intel"},
		{"Microsoft", 1297303124, "Microsoft"},
		{"Infineon", 1229346816, "Infineon"},
		{"Google", 1196379975, "Google"},
		{"Unknown vendor", 0x12345678, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vendorID.String()
			if result != tt.expected {
				t.Errorf("TCGVendorID(%d).String() = %q, want %q", tt.vendorID, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_PCRBankAlgo_String(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRBankAlgo
		expected string
	}{
		{"sha1", PCRBankAlgo("sha1"), "sha1"},
		{"sha256", PCRBankAlgo("sha256"), "sha256"},
		{"sha384", PCRBankAlgo("sha384"), "sha384"},
		{"sha512", PCRBankAlgo("sha512"), "sha512"},
		{"custom", PCRBankAlgo("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.algo.String()
			if result != tt.expected {
				t.Errorf("PCRBankAlgo(%q).String() = %q, want %q", tt.algo, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_DefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig

	if cfg.Device != "/dev/tpmrm0" {
		t.Errorf("DefaultConfig.Device = %q, want %q", cfg.Device, "/dev/tpmrm0")
	}

	if cfg.Hash != "SHA-256" {
		t.Errorf("DefaultConfig.Hash = %q, want %q", cfg.Hash, "SHA-256")
	}

	if !cfg.UseSimulator {
		t.Error("DefaultConfig.UseSimulator = false, want true")
	}

	if cfg.EK == nil {
		t.Fatal("DefaultConfig.EK is nil")
	}
	if cfg.EK.Handle != 0x81010001 {
		t.Errorf("DefaultConfig.EK.Handle = %#x, want %#x", cfg.EK.Handle, 0x81010001)
	}
	if cfg.EK.CertHandle != 0x01C00002 {
		t.Errorf("DefaultConfig.EK.CertHandle = %#x, want %#x", cfg.EK.CertHandle, 0x01C00002)
	}

	if cfg.IAK == nil {
		t.Fatal("DefaultConfig.IAK is nil")
	}
	if cfg.IAK.Handle != 0x81010002 {
		t.Errorf("DefaultConfig.IAK.Handle = %#x, want %#x", cfg.IAK.Handle, 0x81010002)
	}
	if cfg.IAK.Hash != "SHA-256" {
		t.Errorf("DefaultConfig.IAK.Hash = %q, want %q", cfg.IAK.Hash, "SHA-256")
	}

	if cfg.IDevID == nil {
		t.Fatal("DefaultConfig.IDevID is nil")
	}
	if cfg.IDevID.Handle != 0x81020000 {
		t.Errorf("DefaultConfig.IDevID.Handle = %#x, want %#x", cfg.IDevID.Handle, 0x81020000)
	}
	if cfg.IDevID.CertHandle != 0x01C90000 {
		t.Errorf("DefaultConfig.IDevID.CertHandle = %#x, want %#x", cfg.IDevID.CertHandle, 0x01C90000)
	}
	if cfg.IDevID.Model != "edge" {
		t.Errorf("DefaultConfig.IDevID.Model = %q, want %q", cfg.IDevID.Model, "edge")
	}
	if cfg.IDevID.Serial != "001" {
		t.Errorf("DefaultConfig.IDevID.Serial = %q, want %q", cfg.IDevID.Serial, "001")
	}
	if !cfg.IDevID.Pad {
		t.Error("DefaultConfig.IDevID.Pad = false, want true")
	}

	if cfg.SSRK == nil {
		t.Fatal("DefaultConfig.SSRK is nil")
	}
	if cfg.SSRK.Handle != 0x81000001 {
		t.Errorf("DefaultConfig.SSRK.Handle = %#x, want %#x", cfg.SSRK.Handle, 0x81000001)
	}

	if cfg.PlatformPCR != 16 {
		t.Errorf("DefaultConfig.PlatformPCR = %d, want 16", cfg.PlatformPCR)
	}
	if cfg.PlatformPCRBank != PCRBankSHA256 {
		t.Errorf("DefaultConfig.PlatformPCRBank = %q, want %q", cfg.PlatformPCRBank, PCRBankSHA256)
	}

	expectedStrategy := string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	if cfg.IdentityProvisioningStrategy != expectedStrategy {
		t.Errorf("DefaultConfig.IdentityProvisioningStrategy = %q, want %q", cfg.IdentityProvisioningStrategy, expectedStrategy)
	}
}

func TestConfigVal_EnrollmentStrategy_Constants(t *testing.T) {
	if EnrollmentStrategyIAK != "IAK" {
		t.Errorf("EnrollmentStrategyIAK = %q, want %q", EnrollmentStrategyIAK, "IAK")
	}

	if EnrollmentStrategyIAK_IDEVID_SINGLE_PASS != "IAK_IDEVID_SINGLE_PASS" {
		t.Errorf("EnrollmentStrategyIAK_IDEVID_SINGLE_PASS = %q, want %q", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, "IAK_IDEVID_SINGLE_PASS")
	}
}

func TestConfigVal_PCRBankConstants(t *testing.T) {
	if PCRBankSHA1 != "sha1" {
		t.Errorf("PCRBankSHA1 = %q, want %q", PCRBankSHA1, "sha1")
	}
	if PCRBankSHA256 != "sha256" {
		t.Errorf("PCRBankSHA256 = %q, want %q", PCRBankSHA256, "sha256")
	}
	if PCRBankSHA384 != "sha384" {
		t.Errorf("PCRBankSHA384 = %q, want %q", PCRBankSHA384, "sha384")
	}
	if PCRBankSHA512 != "sha512" {
		t.Errorf("PCRBankSHA512 = %q, want %q", PCRBankSHA512, "sha512")
	}
}

func TestConfigVal_AlgorithmConstants(t *testing.T) {
	if AlgSHA1 != 0x0004 {
		t.Errorf("AlgSHA1 = %#x, want %#x", AlgSHA1, 0x0004)
	}
	if AlgSHA256 != 0x000B {
		t.Errorf("AlgSHA256 = %#x, want %#x", AlgSHA256, 0x000B)
	}
	if AlgSHA384 != 0x000C {
		t.Errorf("AlgSHA384 = %#x, want %#x", AlgSHA384, 0x000C)
	}
	if AlgSHA512 != 0x000D {
		t.Errorf("AlgSHA512 = %#x, want %#x", AlgSHA512, 0x000D)
	}
	if AlgSM3256 != 0x0012 {
		t.Errorf("AlgSM3256 = %#x, want %#x", AlgSM3256, 0x0012)
	}
	if AlgSM3256Alt != 0x2000 {
		t.Errorf("AlgSM3256Alt = %#x, want %#x", AlgSM3256Alt, 0x2000)
	}
}

func TestConfigVal_ErrorTypes(t *testing.T) {
	if ErrInvalidHierarchyType == nil {
		t.Error("ErrInvalidHierarchyType is nil")
	}
	if ErrInvalidPCRBankType == nil {
		t.Error("ErrInvalidPCRBankType is nil")
	}
	if ErrInvalidHashFunction == nil {
		t.Error("ErrInvalidHashFunction is nil")
	}
	if ErrInvalidCryptoHashAlgID == nil {
		t.Error("ErrInvalidCryptoHashAlgID is nil")
	}
	if ErrInvalidEnrollmentStrategy == nil {
		t.Error("ErrInvalidEnrollmentStrategy is nil")
	}

	if ErrInvalidHierarchyType.Error() == "" {
		t.Error("ErrInvalidHierarchyType has empty message")
	}
	if ErrInvalidPCRBankType.Error() == "" {
		t.Error("ErrInvalidPCRBankType has empty message")
	}
}

func TestConfigVal_VendorsMapCompleteness(t *testing.T) {
	importantVendors := map[TCGVendorID]string{
		1095582720: "AMD",
		1229870147: "Intel",
		1297303124: "Microsoft",
		1229346816: "Infineon",
		1196379975: "Google",
		1229081856: "IBM",
		1213220096: "HPE",
		1279610368: "Lenovo",
	}

	for id, name := range importantVendors {
		result := id.String()
		if result != name {
			t.Errorf("vendors[%d] = %q, want %q", id, result, name)
		}
	}
}
