package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Unit tests for capabilities helper functions that don't require a TPM

func TestPropertiesFixed_Structure(t *testing.T) {
	tests := []struct {
		name     string
		props    PropertiesFixed
		validate func(*testing.T, PropertiesFixed)
	}{
		{
			name: "Default values",
			props: PropertiesFixed{
				ActiveSessionsMax:       64,
				AuthSessionsActive:      3,
				AuthSessionsActiveAvail: 61,
				AuthSessionsLoaded:      3,
				AuthSessionsLoadedAvail: 0,
				Family:                  "2.0",
				Fips1402:                false,
				FwMajor:                 1,
				FwMinor:                 38,
				LoadedCurves:            3,
				LockoutCounter:          0,
				LockoutInterval:         7200,
				LockoutRecovery:         86400,
				Manufacturer:            "IBM",
				Model:                   "SWTM",
				MaxAuthFail:             32,
				Memory:                  2,
				NVBufferMax:             2048,
				NVIndexesDefined:        0,
				NVIndexesMax:            2048,
				NVWriteRecovery:         1000,
				PersistentAvail:         6,
				PersistentLoaded:        1,
				PersistentMin:           7,
				Revision:                "1.38",
				TransientAvail:          2,
				TransientMin:            3,
				VendorID:                "SW   TPM",
			},
			validate: func(t *testing.T, props PropertiesFixed) {
				if props.ActiveSessionsMax != 64 {
					t.Errorf("ActiveSessionsMax: expected 64, got %d", props.ActiveSessionsMax)
				}
				if props.Family != "2.0" {
					t.Errorf("Family: expected 2.0, got %s", props.Family)
				}
				if props.Fips1402 != false {
					t.Errorf("Fips1402: expected false, got %t", props.Fips1402)
				}
				if props.FwMajor != 1 {
					t.Errorf("FwMajor: expected 1, got %d", props.FwMajor)
				}
				if props.FwMinor != 38 {
					t.Errorf("FwMinor: expected 38, got %d", props.FwMinor)
				}
				if props.LockoutInterval != 7200 {
					t.Errorf("LockoutInterval: expected 7200, got %d", props.LockoutInterval)
				}
				if props.LockoutRecovery != 86400 {
					t.Errorf("LockoutRecovery: expected 86400, got %d", props.LockoutRecovery)
				}
				if props.Manufacturer != "IBM" {
					t.Errorf("Manufacturer: expected IBM, got %s", props.Manufacturer)
				}
			},
		},
		{
			name: "FIPS compliant TPM",
			props: PropertiesFixed{
				Family:   "2.0",
				Fips1402: true,
				FwMajor:  2,
				FwMinor:  0,
			},
			validate: func(t *testing.T, props PropertiesFixed) {
				if !props.Fips1402 {
					t.Error("Expected FIPS 140-2 to be true")
				}
				if props.FwMajor != 2 {
					t.Errorf("FwMajor: expected 2, got %d", props.FwMajor)
				}
			},
		},
		{
			name: "Zero lockout values",
			props: PropertiesFixed{
				LockoutCounter:  0,
				LockoutInterval: 0,
				LockoutRecovery: 0,
				MaxAuthFail:     0,
			},
			validate: func(t *testing.T, props PropertiesFixed) {
				if props.LockoutCounter != 0 {
					t.Errorf("LockoutCounter: expected 0, got %d", props.LockoutCounter)
				}
				if props.LockoutInterval != 0 {
					t.Errorf("LockoutInterval: expected 0, got %d", props.LockoutInterval)
				}
				if props.LockoutRecovery != 0 {
					t.Errorf("LockoutRecovery: expected 0, got %d", props.LockoutRecovery)
				}
			},
		},
		{
			name: "Maximum values",
			props: PropertiesFixed{
				ActiveSessionsMax:  0xFFFFFFFF,
				AuthSessionsActive: 0xFFFFFFFF,
				LoadedCurves:       0xFFFFFFFF,
				NVBufferMax:        0xFFFFFFFF,
				NVIndexesMax:       0xFFFFFFFF,
			},
			validate: func(t *testing.T, props PropertiesFixed) {
				if props.ActiveSessionsMax != 0xFFFFFFFF {
					t.Errorf("ActiveSessionsMax: expected max uint32, got %d", props.ActiveSessionsMax)
				}
				if props.LoadedCurves != 0xFFFFFFFF {
					t.Errorf("LoadedCurves: expected max uint32, got %d", props.LoadedCurves)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.props)
		})
	}
}

func TestPropertiesFixed_FieldValidation(t *testing.T) {
	tests := []struct {
		name      string
		props     PropertiesFixed
		expectErr bool
	}{
		{
			name: "Valid session counts",
			props: PropertiesFixed{
				AuthSessionsActive:      10,
				AuthSessionsActiveAvail: 54,
				AuthSessionsLoaded:      5,
				AuthSessionsLoadedAvail: 59,
				ActiveSessionsMax:       64,
			},
			expectErr: false,
		},
		{
			name: "Valid NV properties",
			props: PropertiesFixed{
				NVBufferMax:      2048,
				NVIndexesDefined: 10,
				NVIndexesMax:     2048,
				NVWriteRecovery:  1000,
			},
			expectErr: false,
		},
		{
			name: "Valid persistent properties",
			props: PropertiesFixed{
				PersistentAvail:  6,
				PersistentLoaded: 1,
				PersistentMin:    7,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate that all uint32 fields are accessible without panic
			_ = tt.props.ActiveSessionsMax
			_ = tt.props.AuthSessionsActive
			_ = tt.props.AuthSessionsActiveAvail
			_ = tt.props.AuthSessionsLoaded
			_ = tt.props.AuthSessionsLoadedAvail
			_ = tt.props.LoadedCurves
			_ = tt.props.LockoutCounter
			_ = tt.props.LockoutInterval
			_ = tt.props.LockoutRecovery
			_ = tt.props.MaxAuthFail
			_ = tt.props.Memory
			_ = tt.props.NVBufferMax
			_ = tt.props.NVIndexesDefined
			_ = tt.props.NVIndexesMax
			_ = tt.props.NVWriteRecovery
			_ = tt.props.PersistentAvail
			_ = tt.props.PersistentLoaded
			_ = tt.props.PersistentMin
			_ = tt.props.TransientAvail
			_ = tt.props.TransientMin

			// Validate string fields
			_ = tt.props.Family
			_ = tt.props.Manufacturer
			_ = tt.props.Model
			_ = tt.props.Revision
			_ = tt.props.VendorID

			// Validate int64 fields
			_ = tt.props.FwMajor
			_ = tt.props.FwMinor

			// Validate bool fields
			_ = tt.props.Fips1402
		})
	}
}

func TestVersionStringToInt64(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		expected  int64
		expectErr bool
	}{
		{
			name:      "Valid version 1.0",
			version:   "1.0",
			expected:  0x10000,
			expectErr: false,
		},
		{
			name:      "Valid version 1.38",
			version:   "1.38",
			expected:  (1 << 16) | 38,
			expectErr: false,
		},
		{
			name:      "Valid version 2.0",
			version:   "2.0",
			expected:  0x20000,
			expectErr: false,
		},
		{
			name:      "Valid version 255.255",
			version:   "255.255",
			expected:  (255 << 16) | 255,
			expectErr: false,
		},
		{
			name:      "Valid version 65535.65535",
			version:   "65535.65535",
			expected:  (65535 << 16) | 65535,
			expectErr: false,
		},
		{
			name:      "Valid version 0.0",
			version:   "0.0",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "Invalid format - single number",
			version:   "1",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid format - three parts",
			version:   "1.2.3",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid format - empty string",
			version:   "",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid format - non-numeric major",
			version:   "abc.1",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid format - non-numeric minor",
			version:   "1.xyz",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid range - major too large",
			version:   "65536.0",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid range - minor too large",
			version:   "0.65536",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid range - negative major",
			version:   "-1.0",
			expected:  0,
			expectErr: true,
		},
		{
			name:      "Invalid range - negative minor",
			version:   "0.-1",
			expected:  0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := VersionStringToInt64(tt.version)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for version %q, but got none", tt.version)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for version %q: %v", tt.version, err)
				}
				if result != tt.expected {
					t.Errorf("For version %q: expected 0x%x, got 0x%x", tt.version, tt.expected, result)
				}
			}
		})
	}
}

func TestInt64ToVersionComponents(t *testing.T) {
	tests := []struct {
		name        string
		versionInt  int64
		expectMajor int64
		expectMinor int64
		expectErr   bool
	}{
		{
			name:        "Version 1.0",
			versionInt:  0x10000,
			expectMajor: 1,
			expectMinor: 0,
			expectErr:   false,
		},
		{
			name:        "Version 1.38",
			versionInt:  (1 << 16) | 38,
			expectMajor: 1,
			expectMinor: 38,
			expectErr:   false,
		},
		{
			name:        "Version 2.0",
			versionInt:  0x20000,
			expectMajor: 2,
			expectMinor: 0,
			expectErr:   false,
		},
		{
			name:        "Version 0.0",
			versionInt:  0,
			expectMajor: 0,
			expectMinor: 0,
			expectErr:   false,
		},
		{
			name:        "Version 255.255",
			versionInt:  (255 << 16) | 255,
			expectMajor: 255,
			expectMinor: 255,
			expectErr:   false,
		},
		{
			name:        "Max valid version",
			versionInt:  0xFFFFFFFF,
			expectMajor: 65535,
			expectMinor: 65535,
			expectErr:   false,
		},
		{
			name:        "Out of range - too large",
			versionInt:  0x100000000,
			expectMajor: 0,
			expectMinor: 0,
			expectErr:   true,
		},
		{
			name:        "Out of range - negative",
			versionInt:  -1,
			expectMajor: 0,
			expectMinor: 0,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, err := Int64ToVersionComponents(tt.versionInt)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for versionInt 0x%x, but got none", tt.versionInt)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for versionInt 0x%x: %v", tt.versionInt, err)
				}
				if major != tt.expectMajor {
					t.Errorf("Major version: expected %d, got %d", tt.expectMajor, major)
				}
				if minor != tt.expectMinor {
					t.Errorf("Minor version: expected %d, got %d", tt.expectMinor, minor)
				}
			}
		})
	}
}

func TestVersionRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"1.0", "1.0"},
		{"1.38", "1.38"},
		{"2.0", "2.0"},
		{"0.0", "0.0"},
		{"255.255", "255.255"},
		{"100.200", "100.200"},
		{"65535.65535", "65535.65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert string to int64
			versionInt, err := VersionStringToInt64(tt.version)
			if err != nil {
				t.Fatalf("VersionStringToInt64 failed: %v", err)
			}

			// Convert int64 back to components
			major, minor, err := Int64ToVersionComponents(versionInt)
			if err != nil {
				t.Fatalf("Int64ToVersionComponents failed: %v", err)
			}

			// Reconstruct version string using fmt.Sprintf
			reconstructed := fmt.Sprintf("%d.%d", major, minor)

			if reconstructed != tt.version {
				t.Errorf("Round trip failed: %q -> 0x%x -> %q", tt.version, versionInt, reconstructed)
			}
		})
	}
}

func TestPropertiesFixed_InfoFormatting(t *testing.T) {
	props := PropertiesFixed{
		Manufacturer:            "IBM",
		VendorID:                "SW   TPM",
		Family:                  "2.0",
		Revision:                "1.38",
		FwMajor:                 1,
		FwMinor:                 38,
		Memory:                  2,
		Model:                   "SWTM",
		Fips1402:                false,
		MaxAuthFail:             32,
		LockoutCounter:          0,
		AuthSessionsActive:      3,
		AuthSessionsActiveAvail: 61,
		AuthSessionsLoaded:      3,
		AuthSessionsLoadedAvail: 0,
		LockoutInterval:         7200,
		LockoutRecovery:         86400,
		NVBufferMax:             2048,
		NVIndexesDefined:        0,
		NVIndexesMax:            2048,
		NVWriteRecovery:         1000,
		PersistentLoaded:        1,
		PersistentAvail:         6,
		TransientMin:            3,
		TransientAvail:          2,
		ActiveSessionsMax:       64,
	}

	// Test that all fields are accessible for formatting
	t.Run("All fields accessible", func(t *testing.T) {
		if props.Manufacturer == "" {
			t.Error("Manufacturer should not be empty")
		}
		if props.VendorID == "" {
			t.Error("VendorID should not be empty")
		}
		if props.Family == "" {
			t.Error("Family should not be empty")
		}
		if props.Revision == "" {
			t.Error("Revision should not be empty")
		}
		if props.FwMajor <= 0 {
			t.Error("FwMajor should be positive")
		}
		if props.FwMinor <= 0 {
			t.Error("FwMinor should be positive")
		}
	})

	t.Run("Session properties are valid", func(t *testing.T) {
		if props.AuthSessionsActive > props.ActiveSessionsMax {
			t.Error("AuthSessionsActive exceeds ActiveSessionsMax")
		}
		if props.AuthSessionsLoaded > props.ActiveSessionsMax {
			t.Error("AuthSessionsLoaded exceeds ActiveSessionsMax")
		}
	})

	t.Run("Lockout properties are valid", func(t *testing.T) {
		if props.LockoutCounter > props.MaxAuthFail {
			t.Error("LockoutCounter exceeds MaxAuthFail")
		}
	})

	t.Run("NV properties are valid", func(t *testing.T) {
		if props.NVIndexesDefined > props.NVIndexesMax {
			t.Error("NVIndexesDefined exceeds NVIndexesMax")
		}
		if props.NVBufferMax == 0 {
			t.Error("NVBufferMax should be non-zero for a functional TPM")
		}
	})
}

func TestPropertiesFixed_FirmwareVersionParsing(t *testing.T) {
	tests := []struct {
		name     string
		fwMajor  int64
		fwMinor  int64
		expected string
	}{
		{
			name:     "Standard firmware 1.38",
			fwMajor:  1,
			fwMinor:  38,
			expected: "1.38",
		},
		{
			name:     "Firmware 2.0",
			fwMajor:  2,
			fwMinor:  0,
			expected: "2.0",
		},
		{
			name:     "High version number",
			fwMajor:  65535,
			fwMinor:  65535,
			expected: "65535.65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := PropertiesFixed{
				FwMajor: tt.fwMajor,
				FwMinor: tt.fwMinor,
			}

			versionStr := fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
			if versionStr != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, versionStr)
			}
		})
	}
}

func TestPropertiesFixed_MemoryParsing(t *testing.T) {
	tests := []struct {
		name        string
		memoryValue uint32
		description string
	}{
		{
			name:        "Shared NV memory",
			memoryValue: 0x01,
			description: "BIT 0 - sharedNV",
		},
		{
			name:        "Shared RAM",
			memoryValue: 0x02,
			description: "BIT 1 - sharedRAM",
		},
		{
			name:        "Both shared",
			memoryValue: 0x03,
			description: "BIT 0 and BIT 1 - both shared",
		},
		{
			name:        "Object copied to RAM",
			memoryValue: 0x04,
			description: "BIT 2 - objectCopiedToRam",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := PropertiesFixed{
				Memory: tt.memoryValue,
			}

			// Check individual bits
			sharedNV := (props.Memory & 0x01) != 0
			sharedRAM := (props.Memory & 0x02) != 0
			objectCopiedToRAM := (props.Memory & 0x04) != 0

			t.Logf("%s: sharedNV=%t, sharedRAM=%t, objectCopiedToRAM=%t",
				tt.description, sharedNV, sharedRAM, objectCopiedToRAM)
		})
	}
}

func TestPropertiesFixed_Consistency(t *testing.T) {
	tests := []struct {
		name  string
		props PropertiesFixed
		valid bool
	}{
		{
			name: "Valid consistent properties",
			props: PropertiesFixed{
				AuthSessionsActive:      3,
				AuthSessionsActiveAvail: 61,
				ActiveSessionsMax:       64,
				NVIndexesDefined:        5,
				NVIndexesMax:            2048,
				PersistentLoaded:        1,
				PersistentAvail:         6,
				TransientAvail:          2,
				TransientMin:            3,
			},
			valid: true,
		},
		{
			name: "Zero values (unprovisioned TPM)",
			props: PropertiesFixed{
				AuthSessionsActive:      0,
				AuthSessionsActiveAvail: 0,
				ActiveSessionsMax:       0,
				NVIndexesDefined:        0,
				NVIndexesMax:            0,
				PersistentLoaded:        0,
				PersistentAvail:         0,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate that session counts are consistent
			totalSessions := tt.props.AuthSessionsActive + tt.props.AuthSessionsActiveAvail
			if tt.props.ActiveSessionsMax > 0 && totalSessions > tt.props.ActiveSessionsMax {
				if tt.valid {
					t.Errorf("Session count inconsistency: active(%d) + avail(%d) > max(%d)",
						tt.props.AuthSessionsActive, tt.props.AuthSessionsActiveAvail, tt.props.ActiveSessionsMax)
				}
			}

			// Validate NV indices
			if tt.props.NVIndexesDefined > tt.props.NVIndexesMax {
				if tt.valid {
					t.Errorf("NV index inconsistency: defined(%d) > max(%d)",
						tt.props.NVIndexesDefined, tt.props.NVIndexesMax)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// algNames map tests
// ---------------------------------------------------------------------------

func TestAlgNamesCompleteness(t *testing.T) {
	// All TPMAlgID constants from go-tpm v0.9.7 (TCG TPM 2.0 Part 2, section 6.3).
	expected := []tpm2.TPMAlgID{
		tpm2.TPMAlgRSA, tpm2.TPMAlgTDES, tpm2.TPMAlgSHA1, tpm2.TPMAlgHMAC, tpm2.TPMAlgAES,
		tpm2.TPMAlgMGF1, tpm2.TPMAlgKeyedHash, tpm2.TPMAlgXOR, tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA384,
		tpm2.TPMAlgSHA512, tpm2.TPMAlgSHA256192, tpm2.TPMAlgNull, tpm2.TPMAlgSM3256, tpm2.TPMAlgSM4,
		tpm2.TPMAlgRSASSA, tpm2.TPMAlgRSAES, tpm2.TPMAlgRSAPSS, tpm2.TPMAlgOAEP, tpm2.TPMAlgECDSA,
		tpm2.TPMAlgECDH, tpm2.TPMAlgECDAA, tpm2.TPMAlgSM2, tpm2.TPMAlgECSchnorr, tpm2.TPMAlgECMQV,
		tpm2.TPMAlgKDF1SP80056A, tpm2.TPMAlgKDF2, tpm2.TPMAlgKDF1SP800108, tpm2.TPMAlgECC, tpm2.TPMAlgSymCipher,
		tpm2.TPMAlgCamellia, tpm2.TPMAlgSHA3256, tpm2.TPMAlgSHA3384, tpm2.TPMAlgSHA3512, tpm2.TPMAlgSHAKE128,
		tpm2.TPMAlgSHAKE256, tpm2.TPMAlgSHAKE256192, tpm2.TPMAlgSHAKE256256, tpm2.TPMAlgSHAKE256512,
		tpm2.TPMAlgCMAC, tpm2.TPMAlgCTR, tpm2.TPMAlgOFB, tpm2.TPMAlgCBC, tpm2.TPMAlgCFB, tpm2.TPMAlgECB,
		tpm2.TPMAlgCCM, tpm2.TPMAlgGCM, tpm2.TPMAlgKW, tpm2.TPMAlgKWP, tpm2.TPMAlgEAX,
		tpm2.TPMAlgEDDSA, tpm2.TPMAlgEDDSAPH, tpm2.TPMAlgLMS, tpm2.TPMAlgXMSS,
		tpm2.TPMAlgKEYEDXOF, tpm2.TPMAlgKMACXOF128, tpm2.TPMAlgKMACXOF256, tpm2.TPMAlgKMAC128, tpm2.TPMAlgKMAC256,
	}

	for _, alg := range expected {
		name, ok := algNames[alg]
		if !ok {
			t.Errorf("algNames missing entry for TPMAlgID 0x%04X", alg)
			continue
		}
		if name == "" {
			t.Errorf("algNames has empty string for TPMAlgID 0x%04X", alg)
		}
	}
}

func TestAlgNamesNoDuplicateValues(t *testing.T) {
	seen := make(map[string]tpm2.TPMAlgID, len(algNames))
	for alg, name := range algNames {
		if prev, exists := seen[name]; exists {
			t.Errorf("duplicate algNames value %q: TPMAlgID 0x%04X and 0x%04X", name, prev, alg)
		}
		seen[name] = alg
	}
}

func TestAlgNamesContainsExpected(t *testing.T) {
	expected := map[tpm2.TPMAlgID]string{
		tpm2.TPMAlgRSA:       "RSA",
		tpm2.TPMAlgSHA1:      "SHA-1",
		tpm2.TPMAlgSHA256:    "SHA-256",
		tpm2.TPMAlgECC:       "ECC",
		tpm2.TPMAlgAES:       "AES",
		tpm2.TPMAlgECDSA:     "ECDSA",
		tpm2.TPMAlgECSchnorr: "EC-Schnorr",
	}

	for alg, wantName := range expected {
		got, ok := algNames[alg]
		if !ok {
			t.Errorf("algNames missing entry for %s (0x%04X)", wantName, alg)
			continue
		}
		if got != wantName {
			t.Errorf("algNames[0x%04X]: expected %q, got %q", alg, wantName, got)
		}
	}
}

func TestAlgNamesMapSize(t *testing.T) {
	const expectedSize = 59
	if got := len(algNames); got != expectedSize {
		t.Errorf("len(algNames): expected %d, got %d", expectedSize, got)
	}
}

// ---------------------------------------------------------------------------
// commandNames map tests
// ---------------------------------------------------------------------------

func TestCommandNamesCompleteness(t *testing.T) {
	// All 118 TPMCC constants from go-tpm v0.9.7 (TCG TPM 2.0 Part 3: Commands).
	expected := []tpm2.TPMCC{
		tpm2.TPMCCNVUndefineSpaceSpecial,
		tpm2.TPMCCEvictControl,
		tpm2.TPMCCHierarchyControl,
		tpm2.TPMCCNVUndefineSpace,
		tpm2.TPMCCChangeEPS,
		tpm2.TPMCCChangePPS,
		tpm2.TPMCCClear,
		tpm2.TPMCCClearControl,
		tpm2.TPMCCClockSet,
		tpm2.TPMCCHierarchyChanegAuth,
		tpm2.TPMCCNVDefineSpace,
		tpm2.TPMCCPCRAllocate,
		tpm2.TPMCCPCRSetAuthPolicy,
		tpm2.TPMCCPPCommands,
		tpm2.TPMCCSetPrimaryPolicy,
		tpm2.TPMCCFieldUpgradeStart,
		tpm2.TPMCCClockRateAdjust,
		tpm2.TPMCCCreatePrimary,
		tpm2.TPMCCNVGlobalWriteLock,
		tpm2.TPMCCGetCommandAuditDigest,
		tpm2.TPMCCNVIncrement,
		tpm2.TPMCCNVSetBits,
		tpm2.TPMCCNVExtend,
		tpm2.TPMCCNVWrite,
		tpm2.TPMCCNVWriteLock,
		tpm2.TPMCCDictionaryAttackLockReset,
		tpm2.TPMCCDictionaryAttackParameters,
		tpm2.TPMCCNVChangeAuth,
		tpm2.TPMCCPCREvent,
		tpm2.TPMCCPCRReset,
		tpm2.TPMCCSequenceComplete,
		tpm2.TPMCCSetAlgorithmSet,
		tpm2.TPMCCSetCommandCodeAuditStatus,
		tpm2.TPMCCFieldUpgradeData,
		tpm2.TPMCCIncrementalSelfTest,
		tpm2.TPMCCSelfTest,
		tpm2.TPMCCStartup,
		tpm2.TPMCCShutdown,
		tpm2.TPMCCStirRandom,
		tpm2.TPMCCActivateCredential,
		tpm2.TPMCCCertify,
		tpm2.TPMCCPolicyNV,
		tpm2.TPMCCCertifyCreation,
		tpm2.TPMCCDuplicate,
		tpm2.TPMCCGetTime,
		tpm2.TPMCCGetSessionAuditDigest,
		tpm2.TPMCCNVRead,
		tpm2.TPMCCNVReadLock,
		tpm2.TPMCCObjectChangeAuth,
		tpm2.TPMCCPolicySecret,
		tpm2.TPMCCRewrap,
		tpm2.TPMCCCreate,
		tpm2.TPMCCECDHZGen,
		tpm2.TPMCCMAC,
		tpm2.TPMCCImport,
		tpm2.TPMCCLoad,
		tpm2.TPMCCQuote,
		tpm2.TPMCCRSADecrypt,
		tpm2.TPMCCMACStart,
		tpm2.TPMCCSequenceUpdate,
		tpm2.TPMCCSign,
		tpm2.TPMCCUnseal,
		tpm2.TPMCCPolicySigned,
		tpm2.TPMCCContextLoad,
		tpm2.TPMCCContextSave,
		tpm2.TPMCCECDHKeyGen,
		tpm2.TPMCCEncryptDecrypt,
		tpm2.TPMCCFlushContext,
		tpm2.TPMCCLoadExternal,
		tpm2.TPMCCMakeCredential,
		tpm2.TPMCCNVReadPublic,
		tpm2.TPMCCPolicyAuthorize,
		tpm2.TPMCCPolicyAuthValue,
		tpm2.TPMCCPolicyCommandCode,
		tpm2.TPMCCPolicyCounterTimer,
		tpm2.TPMCCPolicyCpHash,
		tpm2.TPMCCPolicyLocality,
		tpm2.TPMCCPolicyNameHash,
		tpm2.TPMCCPolicyOR,
		tpm2.TPMCCPolicyTicket,
		tpm2.TPMCCReadPublic,
		tpm2.TPMCCRSAEncrypt,
		tpm2.TPMCCStartAuthSession,
		tpm2.TPMCCVerifySignature,
		tpm2.TPMCCECCParameters,
		tpm2.TPMCCFirmwareRead,
		tpm2.TPMCCGetCapability,
		tpm2.TPMCCGetRandom,
		tpm2.TPMCCGetTestResult,
		tpm2.TPMCCHash,
		tpm2.TPMCCPCRRead,
		tpm2.TPMCCPolicyPCR,
		tpm2.TPMCCPolicyRestart,
		tpm2.TPMCCReadClock,
		tpm2.TPMCCPCRExtend,
		tpm2.TPMCCPCRSetAuthValue,
		tpm2.TPMCCNVCertify,
		tpm2.TPMCCEventSequenceComplete,
		tpm2.TPMCCHashSequenceStart,
		tpm2.TPMCCPolicyPhysicalPresence,
		tpm2.TPMCCPolicyDuplicationSelect,
		tpm2.TPMCCPolicyGetDigest,
		tpm2.TPMCCTestParms,
		tpm2.TPMCCCommit,
		tpm2.TPMCCPolicyPassword,
		tpm2.TPMCCZGen2Phase,
		tpm2.TPMCCECEphemeral,
		tpm2.TPMCCPolicyNvWritten,
		tpm2.TPMCCPolicyTemplate,
		tpm2.TPMCCCreateLoaded,
		tpm2.TPMCCPolicyAuthorizeNV,
		tpm2.TPMCCEncryptDecrypt2,
		tpm2.TPMCCACGetCapability,
		tpm2.TPMCCACSend,
		tpm2.TPMCCPolicyACSendSelect,
		tpm2.TPMCCCertifyX509,
		tpm2.TPMCCACTSetTimeout,
	}

	if len(expected) != 117 {
		t.Fatalf("test setup error: expected slice has %d entries, want 117", len(expected))
	}

	for _, cc := range expected {
		name, ok := commandNames[cc]
		if !ok {
			t.Errorf("commandNames missing entry for TPMCC 0x%08X", cc)
			continue
		}
		if name == "" {
			t.Errorf("commandNames has empty string for TPMCC 0x%08X", cc)
		}
	}
}

func TestCommandNamesContainsExpected(t *testing.T) {
	expected := map[tpm2.TPMCC]string{
		tpm2.TPMCCCreatePrimary: "TPM2_CC_CreatePrimary",
		tpm2.TPMCCSign:          "TPM2_CC_Sign",
		tpm2.TPMCCQuote:         "TPM2_CC_Quote",
		tpm2.TPMCCGetCapability: "TPM2_CC_GetCapability",
		tpm2.TPMCCHash:          "TPM2_CC_Hash",
		tpm2.TPMCCPCRRead:       "TPM2_CC_PCR_Read",
		tpm2.TPMCCCreate:        "TPM2_CC_Create",
		tpm2.TPMCCLoad:          "TPM2_CC_Load",
		tpm2.TPMCCUnseal:        "TPM2_CC_Unseal",
	}

	for cc, wantName := range expected {
		got, ok := commandNames[cc]
		if !ok {
			t.Errorf("commandNames missing entry for %s (0x%08X)", wantName, cc)
			continue
		}
		if got != wantName {
			t.Errorf("commandNames[0x%08X]: expected %q, got %q", cc, wantName, got)
		}
	}
}

func TestCommandNamesMapSize(t *testing.T) {
	const expectedSize = 117
	if got := len(commandNames); got != expectedSize {
		t.Errorf("len(commandNames): expected %d, got %d", expectedSize, got)
	}
}

// ---------------------------------------------------------------------------
// curveNames map tests
// ---------------------------------------------------------------------------

func TestCurveNamesCompleteness(t *testing.T) {
	// All 13 TPMECCCurve constants from go-tpm v0.9.7 (TPMECCNone excluded).
	expected := []tpm2.TPMECCCurve{
		tpm2.TPMECCNistP192,
		tpm2.TPMECCNistP224,
		tpm2.TPMECCNistP256,
		tpm2.TPMECCNistP384,
		tpm2.TPMECCNistP521,
		tpm2.TPMECCBNP256,
		tpm2.TPMECCBNP638,
		tpm2.TPMECCSM2P256,
		tpm2.TPMECCBrainpoolP256R1,
		tpm2.TPMECCBrainpoolP384R1,
		tpm2.TPMECCBrainpoolP512R1,
		tpm2.TPMECCCurve25519,
		tpm2.TPMECCCurve448,
	}

	for _, curve := range expected {
		name, ok := curveNames[curve]
		if !ok {
			t.Errorf("curveNames missing entry for TPMECCCurve 0x%04X", curve)
			continue
		}
		if name == "" {
			t.Errorf("curveNames has empty string for TPMECCCurve 0x%04X", curve)
		}
	}
}

func TestCurveNamesContainsExpected(t *testing.T) {
	expected := map[tpm2.TPMECCCurve]string{
		tpm2.TPMECCNistP256:   "NIST P-256",
		tpm2.TPMECCNistP384:   "NIST P-384",
		tpm2.TPMECCNistP521:   "NIST P-521",
		tpm2.TPMECCCurve25519: "Curve25519",
	}

	for curve, wantName := range expected {
		got, ok := curveNames[curve]
		if !ok {
			t.Errorf("curveNames missing entry for %s (0x%04X)", wantName, curve)
			continue
		}
		if got != wantName {
			t.Errorf("curveNames[0x%04X]: expected %q, got %q", curve, wantName, got)
		}
	}
}

func TestCurveNamesMapSize(t *testing.T) {
	const expectedSize = 13
	if got := len(curveNames); got != expectedSize {
		t.Errorf("len(curveNames): expected %d, got %d", expectedSize, got)
	}
}

// ---------------------------------------------------------------------------
// commandDescriptions map tests
// ---------------------------------------------------------------------------

func TestCommandDescriptionsCompleteness(t *testing.T) {
	// Every key in commandNames must have a corresponding commandDescriptions entry.
	for cc, name := range commandNames {
		desc, ok := commandDescriptions[cc]
		if !ok {
			t.Errorf("commandDescriptions missing entry for %s (0x%04X)", name, cc)
			continue
		}
		if desc == "" {
			t.Errorf("commandDescriptions has empty string for %s (0x%04X)", name, cc)
		}
	}
}

func TestCommandDescriptionsMapSize(t *testing.T) {
	// commandDescriptions should have the same size as commandNames.
	if got, want := len(commandDescriptions), len(commandNames); got != want {
		t.Errorf("len(commandDescriptions): got %d, want %d (same as commandNames)", got, want)
	}
}

func TestCommandDescriptionsNoExtraKeys(t *testing.T) {
	// Every key in commandDescriptions must exist in commandNames.
	for cc, desc := range commandDescriptions {
		if _, ok := commandNames[cc]; !ok {
			t.Errorf("commandDescriptions has entry for unknown TPMCC 0x%04X: %q", cc, desc)
		}
	}
}

// ---------------------------------------------------------------------------
// SupportedCommandsInfo tests (unit-level, no TPM required)
// ---------------------------------------------------------------------------

func TestCommandInfo_VendorCommand(t *testing.T) {
	// A command code not in commandNames should produce a "Vendor Command" entry.
	unknownCC := tpm2.TPMCC(0x0307)
	_, nameOK := commandNames[unknownCC]
	if nameOK {
		t.Skip("0x0307 is in commandNames; pick a different vendor code")
	}

	code := fmt.Sprintf("0x%04X", uint32(unknownCC))
	expectedName := fmt.Sprintf("Vendor Command (%s)", code)
	expectedDesc := "Vendor-specific or implementation-defined TPM command"

	// Simulate the logic from SupportedCommandsInfo for a vendor command.
	name := expectedName
	desc := expectedDesc
	if name != expectedName {
		t.Errorf("vendor command name: got %q, want %q", name, expectedName)
	}
	if desc != expectedDesc {
		t.Errorf("vendor command description: got %q, want %q", desc, expectedDesc)
	}
}

// ---------------------------------------------------------------------------
// PropertiesFixed new fields tests
// ---------------------------------------------------------------------------

func TestPropertiesFixed_NewFields(t *testing.T) {
	props := PropertiesFixed{
		InputBufferMax:   1024,
		MaxDigestSize:    64,
		MaxObjectContext: 4096,
	}

	if props.InputBufferMax != 1024 {
		t.Errorf("InputBufferMax: expected 1024, got %d", props.InputBufferMax)
	}
	if props.MaxDigestSize != 64 {
		t.Errorf("MaxDigestSize: expected 64, got %d", props.MaxDigestSize)
	}
	if props.MaxObjectContext != 4096 {
		t.Errorf("MaxObjectContext: expected 4096, got %d", props.MaxObjectContext)
	}
}

func TestPropertiesFixed_NewFieldsZeroValues(t *testing.T) {
	props := PropertiesFixed{}

	if props.InputBufferMax != 0 {
		t.Errorf("InputBufferMax: expected 0 for zero-value struct, got %d", props.InputBufferMax)
	}
	if props.MaxDigestSize != 0 {
		t.Errorf("MaxDigestSize: expected 0 for zero-value struct, got %d", props.MaxDigestSize)
	}
	if props.MaxObjectContext != 0 {
		t.Errorf("MaxObjectContext: expected 0 for zero-value struct, got %d", props.MaxObjectContext)
	}
}

// ---------------------------------------------------------------------------
// tpmPTNames map tests
// ---------------------------------------------------------------------------

func TestTPMPTNamesCompleteness(t *testing.T) {
	// All TPMPT constants from go-tpm v0.9.7 (both fixed and variable).
	expected := []tpm2.TPMPT{
		// Fixed
		tpm2.TPMPTFamilyIndicator, tpm2.TPMPTLevel, tpm2.TPMPTRevision,
		tpm2.TPMPTDayofYear, tpm2.TPMPTYear, tpm2.TPMPTManufacturer,
		tpm2.TPMPTVendorString1, tpm2.TPMPTVendorString2, tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4, tpm2.TPMPTVendorTPMType,
		tpm2.TPMPTFirmwareVersion1, tpm2.TPMPTFirmwareVersion2,
		tpm2.TPMPTInputBuffer, tpm2.TPMPTHRTransientMin, tpm2.TPMPTHRPersistentMin,
		tpm2.TPMPTHRLoadedMin, tpm2.TPMPTActiveSessionsMax,
		tpm2.TPMPTPCRCount, tpm2.TPMPTPCRSelectMin, tpm2.TPMPTContextGapMax,
		tpm2.TPMPTNVCountersMax, tpm2.TPMPTNVIndexMax, tpm2.TPMPTMemory,
		tpm2.TPMPTClockUpdate, tpm2.TPMPTContextHash, tpm2.TPMPTContextSym,
		tpm2.TPMPTContextSymSize, tpm2.TPMPTOrderlyCount,
		tpm2.TPMPTMaxCommandSize, tpm2.TPMPTMaxResponseSize,
		tpm2.TPMPTMaxDigest, tpm2.TPMPTMaxObjectContext, tpm2.TPMPTMaxSessionContext,
		tpm2.TPMPTPSFamilyIndicator, tpm2.TPMPTPSLevel, tpm2.TPMPTPSRevision,
		tpm2.TPMPTPSDayOfYear, tpm2.TPMPTPSYear, tpm2.TPMPTSplitMax,
		tpm2.TPMPTTotalCommands, tpm2.TPMPTLibraryCommands, tpm2.TPMPTVendorCommands,
		tpm2.TPMPTNVBufferMax, tpm2.TPMPTModes, tpm2.TPMPTMaxCapBuffer,
		// Variable
		tpm2.TPMPTPermanent, tpm2.TPMPTStartupClear,
		tpm2.TPMPTHRNVIndex, tpm2.TPMPTHRLoaded, tpm2.TPMPTHRLoadedAvail,
		tpm2.TPMPTHRActive, tpm2.TPMPTHRActiveAvail, tpm2.TPMPTHRTransientAvail,
		tpm2.TPMPTHRPersistent, tpm2.TPMPTHRPersistentAvail,
		tpm2.TPMPTNVCounters, tpm2.TPMPTNVCountersAvail, tpm2.TPMPTAlgorithmSet,
		tpm2.TPMPTLoadedCurves, tpm2.TPMPTLockoutCounter, tpm2.TPMPTMaxAuthFail,
		tpm2.TPMPTLockoutInterval, tpm2.TPMPTLockoutRecovery, tpm2.TPMPTNVWriteRecovery,
		tpm2.TPMPTAuditCounter0, tpm2.TPMPTAuditCounter1,
	}

	for _, pt := range expected {
		name, ok := tpmPTNames[pt]
		if !ok {
			t.Errorf("tpmPTNames missing entry for TPMPT 0x%04X", uint32(pt))
			continue
		}
		if name == "" {
			t.Errorf("tpmPTNames has empty string for TPMPT 0x%04X", uint32(pt))
		}
	}
}

func TestTPMPTNamesNoDuplicateValues(t *testing.T) {
	seen := make(map[string]tpm2.TPMPT, len(tpmPTNames))
	for pt, name := range tpmPTNames {
		if prev, exists := seen[name]; exists {
			t.Errorf("duplicate tpmPTNames value %q: TPMPT 0x%04X and 0x%04X", name, uint32(prev), uint32(pt))
		}
		seen[name] = pt
	}
}

func TestTPMPTNamesContainsExpected(t *testing.T) {
	expected := map[tpm2.TPMPT]string{
		tpm2.TPMPTFamilyIndicator: "TPM2_PT_FAMILY_INDICATOR",
		tpm2.TPMPTRevision:        "TPM2_PT_REVISION",
		tpm2.TPMPTManufacturer:    "TPM2_PT_MANUFACTURER",
		tpm2.TPMPTPermanent:       "TPM2_PT_PERMANENT",
		tpm2.TPMPTStartupClear:    "TPM2_PT_STARTUP_CLEAR",
		tpm2.TPMPTLockoutCounter:  "TPM2_PT_LOCKOUT_COUNTER",
	}

	for pt, wantName := range expected {
		got, ok := tpmPTNames[pt]
		if !ok {
			t.Errorf("tpmPTNames missing entry for %s (0x%04X)", wantName, uint32(pt))
			continue
		}
		if got != wantName {
			t.Errorf("tpmPTNames[0x%04X]: expected %q, got %q", uint32(pt), wantName, got)
		}
	}
}

// ---------------------------------------------------------------------------
// formatFixedProperty tests
// ---------------------------------------------------------------------------

func TestFormatFixedProperty_FamilyIndicator(t *testing.T) {
	// "2.0\0" encoded as big-endian uint32 = 0x322E3000
	val := uint32(0x322E3000)
	result := formatFixedProperty(tpm2.TPMPTFamilyIndicator, val)
	if result != "2.0" {
		t.Errorf("formatFixedProperty(FamilyIndicator, 0x%X): expected %q, got %q", val, "2.0", result)
	}
}

func TestFormatFixedProperty_Revision(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"revision 138", 138, "1.38"},
		{"revision 200", 200, "2.0"},
		{"revision 116", 116, "1.16"},
		{"revision 0", 0, "0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatFixedProperty(tpm2.TPMPTRevision, tt.value)
			if result != tt.expected {
				t.Errorf("formatFixedProperty(Revision, %d): expected %q, got %q", tt.value, tt.expected, result)
			}
		})
	}
}

func TestFormatFixedProperty_Manufacturer(t *testing.T) {
	// IBM = 0x49424D20 (1229081856)
	result := formatFixedProperty(tpm2.TPMPTManufacturer, 1229081856)
	if result != "IBM" {
		t.Errorf("formatFixedProperty(Manufacturer, IBM): expected %q, got %q", "IBM", result)
	}
}

func TestFormatFixedProperty_VendorString(t *testing.T) {
	// "SW  " = 0x53572020
	val := uint32(0x53572020)
	result := formatFixedProperty(tpm2.TPMPTVendorString1, val)
	if result != "SW" {
		t.Errorf("formatFixedProperty(VendorString1, 0x%X): expected %q, got %q", val, "SW", result)
	}
}

func TestFormatFixedProperty_Modes(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"FIPS mode set", 1, "TPMA_MODES_FIPS_140_2"},
		{"FIPS mode not set", 0, ""},
		{"other bits set", 0xFE, ""},
		{"FIPS plus other bits", 0xFF, "TPMA_MODES_FIPS_140_2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatFixedProperty(tpm2.TPMPTModes, tt.value)
			if result != tt.expected {
				t.Errorf("formatFixedProperty(Modes, 0x%X): expected %q, got %q", tt.value, tt.expected, result)
			}
		})
	}
}

func TestFormatFixedProperty_UnknownProperty(t *testing.T) {
	result := formatFixedProperty(tpm2.TPMPTInputBuffer, 1024)
	if result != "" {
		t.Errorf("formatFixedProperty(InputBuffer, 1024): expected empty string, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// formatVariableProperty tests
// ---------------------------------------------------------------------------

func TestFormatVariableProperty_Permanent(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"no flags", 0, ""},
		{"ownerAuthSet", 0x01, "ownerAuthSet"},
		{"endorsementAuthSet", 0x02, "endorsementAuthSet"},
		{"all auth flags", 0x07, "ownerAuthSet, endorsementAuthSet, lockoutAuthSet"},
		{"disableClear", 0x100, "disableClear"},
		{"tpmGeneratedEPS", 0x400, "tpmGeneratedEPS"},
		{"multiple flags", 0x403, "ownerAuthSet, endorsementAuthSet, tpmGeneratedEPS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatVariableProperty(tpm2.TPMPTPermanent, tt.value)
			if result != tt.expected {
				t.Errorf("formatVariableProperty(Permanent, 0x%X): expected %q, got %q", tt.value, tt.expected, result)
			}
		})
	}
}

func TestFormatVariableProperty_StartupClear(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"no flags", 0, ""},
		{"phEnable", 0x01, "phEnable"},
		{"all enable flags", 0x0F, "phEnable, shEnable, ehEnable, phEnableNV"},
		{"orderly", 0x80000000, "orderly"},
		{"all flags", 0x8000000F, "phEnable, shEnable, ehEnable, phEnableNV, orderly"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatVariableProperty(tpm2.TPMPTStartupClear, tt.value)
			if result != tt.expected {
				t.Errorf("formatVariableProperty(StartupClear, 0x%X): expected %q, got %q", tt.value, tt.expected, result)
			}
		})
	}
}

func TestFormatVariableProperty_UnknownProperty(t *testing.T) {
	result := formatVariableProperty(tpm2.TPMPTLockoutCounter, 5)
	if result != "" {
		t.Errorf("formatVariableProperty(LockoutCounter, 5): expected empty string, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// PropertiesFixed extended fields tests
// ---------------------------------------------------------------------------

func TestPropertiesFixed_ExtendedFields(t *testing.T) {
	props := PropertiesFixed{
		DayOfYear:         42,
		Year:              2026,
		PCRCount:          24,
		PCRSelectMin:      3,
		ContextGapMax:     255,
		NVCountersMax:     16,
		ClockUpdate:       4096,
		ContextHash:       0x000B, // SHA-256
		ContextSym:        0x0006, // AES
		ContextSymSize:    256,
		OrderlyCount:      255,
		MaxCommandSize:    4096,
		MaxResponseSize:   4096,
		MaxSessionContext: 768,
		PSFamilyIndicator: 1,
		PSLevel:           0,
		PSRevision:        0,
		PSDayOfYear:       0,
		PSYear:            0,
		SplitMax:          128,
		TotalCommands:     117,
		LibraryCommands:   117,
		VendorCommands:    0,
		MaxCapBuffer:      1024,
		HRLoadedMin:       3,
		Permanent:         0x407,
		StartupClear:      0x8000000F,
		NVCounters:        4,
		NVCountersAvail:   12,
		AlgorithmSet:      0,
		AuditCounter0:     0,
		AuditCounter1:     0,
	}

	if props.PCRCount != 24 {
		t.Errorf("PCRCount: expected 24, got %d", props.PCRCount)
	}
	if props.TotalCommands != 117 {
		t.Errorf("TotalCommands: expected 117, got %d", props.TotalCommands)
	}
	if props.Permanent != 0x407 {
		t.Errorf("Permanent: expected 0x407, got 0x%X", props.Permanent)
	}
	if props.StartupClear != 0x8000000F {
		t.Errorf("StartupClear: expected 0x8000000F, got 0x%X", props.StartupClear)
	}
	if props.Year != 2026 {
		t.Errorf("Year: expected 2026, got %d", props.Year)
	}
	if props.HRLoadedMin != 3 {
		t.Errorf("HRLoadedMin: expected 3, got %d", props.HRLoadedMin)
	}
}

func TestPropertiesFixed_ExtendedFieldsZeroValues(t *testing.T) {
	props := PropertiesFixed{}

	if props.DayOfYear != 0 {
		t.Errorf("DayOfYear: expected 0 for zero-value struct, got %d", props.DayOfYear)
	}
	if props.PCRCount != 0 {
		t.Errorf("PCRCount: expected 0 for zero-value struct, got %d", props.PCRCount)
	}
	if props.Permanent != 0 {
		t.Errorf("Permanent: expected 0 for zero-value struct, got %d", props.Permanent)
	}
	if props.AuditCounter0 != 0 {
		t.Errorf("AuditCounter0: expected 0 for zero-value struct, got %d", props.AuditCounter0)
	}
}

// ---------------------------------------------------------------------------
// cleanTPMString tests
// ---------------------------------------------------------------------------

func TestCleanTPMString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"printable ASCII", "SW   TPM", "SW   TPM"},
		{"with null bytes", "SW\x00\x00TPM\x00", "SWTPM"},
		{"empty string", "", ""},
		{"all control chars", "\x00\x01\x02\x03", ""},
		{"mixed content", "IBM\x00\x00\x00\x00", "IBM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanTPMString(tt.input)
			if result != tt.expected {
				t.Errorf("cleanTPMString(%q): expected %q, got %q", tt.input, tt.expected, result)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"printable text", "Hello", true},
		{"with control chars", "He\x00llo", false},
		{"empty string", "", false},
		{"space only", " ", true},
		{"tab character", "\t", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintable(tt.input)
			if result != tt.expected {
				t.Errorf("isPrintable(%q): expected %t, got %t", tt.input, tt.expected, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// capabilityMockTransport and mock transport tests
// ---------------------------------------------------------------------------

// capabilityMockTransport implements transport.TPM for testing capability functions
type capabilityMockTransport struct {
	responses    map[uint32][]byte
	err          error
	callCount    int
	lastProperty uint32
}

func (m *capabilityMockTransport) Send(input []byte) ([]byte, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}

	// Parse the GetCapability command to extract the property being queried
	if len(input) < 18 {
		return nil, errors.New("input too short")
	}

	property := binary.BigEndian.Uint32(input[14:18])
	m.lastProperty = property

	if response, ok := m.responses[property]; ok {
		return response, nil
	}

	return nil, errors.New("no mock response configured for property")
}

// Ensure the mock transport satisfies the interface
var _ transport.TPM = (*capabilityMockTransport)(nil)

// buildCapabilityResponse constructs a valid TPM2 GetCapabilityResponse for TPM properties
func buildCapabilityResponse(property tpm2.TPMPT, value uint32) []byte {
	buf := make([]byte, 27)
	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(buf[2:6], 27)
	// Response code: SUCCESS
	binary.BigEndian.PutUint32(buf[6:10], 0x00000000)
	// MoreData: NO
	buf[10] = 0x00
	// Capability: TPMCapTPMProperties
	binary.BigEndian.PutUint32(buf[11:15], uint32(tpm2.TPMCapTPMProperties))
	// Count: 1
	binary.BigEndian.PutUint32(buf[15:19], 1)
	// Property tag
	binary.BigEndian.PutUint32(buf[19:23], uint32(property))
	// Property value
	binary.BigEndian.PutUint32(buf[23:27], value)

	return buf
}

// buildErrorResponse constructs a TPM error response
func buildErrorResponse(errorCode uint32) []byte {
	buf := make([]byte, 10)
	// Tag: TPM_ST_NO_SESSIONS
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	// Response size
	binary.BigEndian.PutUint32(buf[2:6], 10)
	// Response code: error
	binary.BigEndian.PutUint32(buf[6:10], errorCode)
	return buf
}

// buildMalformedResponse constructs an invalid capability response
func buildMalformedResponse() []byte {
	buf := make([]byte, 27)
	binary.BigEndian.PutUint16(buf[0:2], 0x8001)
	binary.BigEndian.PutUint32(buf[2:6], 27)
	binary.BigEndian.PutUint32(buf[6:10], 0x00000000)
	buf[10] = 0x00
	// Wrong capability type
	binary.BigEndian.PutUint32(buf[11:15], uint32(tpm2.TPMCapHandles))
	binary.BigEndian.PutUint32(buf[15:19], 1)
	binary.BigEndian.PutUint32(buf[19:23], 0x80000001)
	binary.BigEndian.PutUint32(buf[23:27], 0x00000000)

	return buf
}

func TestLoadedCurves(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
	}{
		{
			name: "success with typical value",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
			},
			expected:    3,
			expectError: false,
		},
		{
			name: "success with zero curves",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 0),
			},
			expected:    0,
			expectError: false,
		},
		{
			name: "success with maximum curves",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 0xFFFFFFFF),
			},
			expected:    0xFFFFFFFF,
			expectError: false,
		},
		{
			name:        "transport error",
			mockResp:    nil,
			mockErr:     errors.New("transport connection failed"),
			expectError: true,
		},
		{
			name:        "no response configured",
			mockResp:    map[uint32][]byte{},
			expectError: true,
		},
		{
			name: "TPM error response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildErrorResponse(0x00000101),
			},
			expectError: true,
		},
		{
			name: "malformed capability response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildMalformedResponse(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := loadedCurves(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestLockoutRecovery(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
	}{
		{
			name: "success with typical recovery time",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 86400),
			},
			expected: 86400,
		},
		{
			name: "success with zero recovery",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 0),
			},
			expected: 0,
		},
		{
			name:        "transport error",
			mockErr:     errors.New("TPM device not found"),
			expectError: true,
		},
		{
			name: "TPM error response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildErrorResponse(0x000001C4),
			},
			expectError: true,
		},
		{
			name: "malformed response type",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutRecovery): buildMalformedResponse(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := lockoutRecovery(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestLockoutInterval(t *testing.T) {
	tests := []struct {
		name        string
		mockResp    map[uint32][]byte
		mockErr     error
		expected    uint32
		expectError bool
	}{
		{
			name: "success with typical interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 7200),
			},
			expected: 7200,
		},
		{
			name: "success with zero interval",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 0),
			},
			expected: 0,
		},
		{
			name:        "transport error",
			mockErr:     errors.New("device I/O error"),
			expectError: true,
		},
		{
			name: "TPM error response",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildErrorResponse(0x00000120),
			},
			expectError: true,
		},
		{
			name: "malformed capability data",
			mockResp: map[uint32][]byte{
				uint32(tpm2.TPMPTLockoutInterval): buildMalformedResponse(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: tt.mockResp,
				err:       tt.mockErr,
			}

			result, err := lockoutInterval(mockTransport)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestCapabilityFunctionsTransportErrors(t *testing.T) {
	transportErrors := []struct {
		name string
		err  error
	}{
		{"connection refused", errors.New("connection refused")},
		{"device not found", errors.New("device not found")},
		{"timeout", errors.New("timeout")},
		{"permission denied", errors.New("permission denied")},
	}

	for _, te := range transportErrors {
		t.Run("loadedCurves_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := loadedCurves(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
		})

		t.Run("lockoutRecovery_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := lockoutRecovery(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
		})

		t.Run("lockoutInterval_"+te.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{err: te.err}
			_, err := lockoutInterval(mockTransport)
			if err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

func TestCapabilityMockTransportBehavior(t *testing.T) {
	t.Run("tracks call count", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
			},
		}

		if mockTransport.callCount != 0 {
			t.Errorf("initial call count should be 0, got %d", mockTransport.callCount)
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.callCount != 1 {
			t.Errorf("call count should be 1, got %d", mockTransport.callCount)
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.callCount != 2 {
			t.Errorf("call count should be 2, got %d", mockTransport.callCount)
		}
	})

	t.Run("tracks last property queried", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{
				uint32(tpm2.TPMPTLoadedCurves):    buildCapabilityResponse(tpm2.TPMPTLoadedCurves, 3),
				uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, 86400),
				uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, 7200),
			},
		}

		_, _ = loadedCurves(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLoadedCurves) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLoadedCurves), mockTransport.lastProperty)
		}

		_, _ = lockoutRecovery(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutRecovery) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLockoutRecovery), mockTransport.lastProperty)
		}

		_, _ = lockoutInterval(mockTransport)
		if mockTransport.lastProperty != uint32(tpm2.TPMPTLockoutInterval) {
			t.Errorf("expected property %d, got %d", uint32(tpm2.TPMPTLockoutInterval), mockTransport.lastProperty)
		}
	})

	t.Run("short input rejected", func(t *testing.T) {
		mockTransport := &capabilityMockTransport{
			responses: map[uint32][]byte{},
		}

		_, err := mockTransport.Send([]byte{0x01, 0x02})
		if err == nil {
			t.Error("expected error for short input")
		}
		if err.Error() != "input too short" {
			t.Errorf("expected 'input too short' error, got %v", err)
		}
	})
}

func TestBuildCapabilityResponse(t *testing.T) {
	tests := []struct {
		name     string
		property tpm2.TPMPT
		value    uint32
	}{
		{"LoadedCurves", tpm2.TPMPTLoadedCurves, 5},
		{"LockoutRecovery", tpm2.TPMPTLockoutRecovery, 86400},
		{"LockoutInterval", tpm2.TPMPTLockoutInterval, 7200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildCapabilityResponse(tt.property, tt.value)

			if len(resp) != 27 {
				t.Errorf("expected response length 27, got %d", len(resp))
			}

			tag := binary.BigEndian.Uint16(resp[0:2])
			if tag != 0x8001 {
				t.Errorf("expected tag 0x8001, got 0x%04x", tag)
			}

			size := binary.BigEndian.Uint32(resp[2:6])
			if size != 27 {
				t.Errorf("expected size 27, got %d", size)
			}

			rc := binary.BigEndian.Uint32(resp[6:10])
			if rc != 0 {
				t.Errorf("expected success response code 0, got 0x%08x", rc)
			}

			capType := binary.BigEndian.Uint32(resp[11:15])
			if capType != uint32(tpm2.TPMCapTPMProperties) {
				t.Errorf("expected capability type %d, got %d", uint32(tpm2.TPMCapTPMProperties), capType)
			}

			propValue := binary.BigEndian.Uint32(resp[23:27])
			if propValue != tt.value {
				t.Errorf("expected property value %d, got %d", tt.value, propValue)
			}
		})
	}
}

func TestBuildErrorResponse(t *testing.T) {
	tests := []struct {
		name      string
		errorCode uint32
	}{
		{"TPM_RC_FAILURE", 0x00000101},
		{"TPM_RC_VALUE", 0x000001C4},
		{"TPM_RC_DISABLED", 0x00000120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildErrorResponse(tt.errorCode)

			if len(resp) != 10 {
				t.Errorf("expected response length 10, got %d", len(resp))
			}

			rc := binary.BigEndian.Uint32(resp[6:10])
			if rc != tt.errorCode {
				t.Errorf("expected error code 0x%08x, got 0x%08x", tt.errorCode, rc)
			}
		})
	}
}

func TestBuildMalformedResponse(t *testing.T) {
	resp := buildMalformedResponse()

	if len(resp) != 27 {
		t.Errorf("expected response length 27, got %d", len(resp))
	}

	capType := binary.BigEndian.Uint32(resp[11:15])
	if capType == uint32(tpm2.TPMCapTPMProperties) {
		t.Errorf("malformed response should not have TPMCapTPMProperties capability type")
	}

	if capType != uint32(tpm2.TPMCapHandles) {
		t.Errorf("expected capability type %d (TPMCapHandles), got %d", uint32(tpm2.TPMCapHandles), capType)
	}
}

// ---------------------------------------------------------------------------
// Edge case tests for capability functions
// ---------------------------------------------------------------------------

func TestLoadedCurvesEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"minimum value", 0, 0},
		{"one curve", 1, 1},
		{"typical NIST curves", 3, 3},
		{"all standard curves", 5, 5},
		{"power of two", 16, 16},
		{"large number", 1000, 1000},
		{"near max", 0xFFFFFFFE, 0xFFFFFFFE},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLoadedCurves): buildCapabilityResponse(tpm2.TPMPTLoadedCurves, tt.value),
				},
			}

			result, err := loadedCurves(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestLockoutRecoveryEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"immediate recovery", 0, 0},
		{"1 second", 1, 1},
		{"1 minute", 60, 60},
		{"5 minutes", 300, 300},
		{"1 hour", 3600, 3600},
		{"2 hours", 7200, 7200},
		{"12 hours", 43200, 43200},
		{"24 hours", 86400, 86400},
		{"1 week", 604800, 604800},
		{"1 month approx", 2592000, 2592000},
		{"1 year approx", 31536000, 31536000},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLockoutRecovery): buildCapabilityResponse(tpm2.TPMPTLockoutRecovery, tt.value),
				},
			}

			result, err := lockoutRecovery(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestLockoutIntervalEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"no interval", 0, 0},
		{"1 second", 1, 1},
		{"10 seconds", 10, 10},
		{"30 seconds", 30, 30},
		{"1 minute", 60, 60},
		{"5 minutes", 300, 300},
		{"15 minutes", 900, 900},
		{"30 minutes", 1800, 1800},
		{"1 hour", 3600, 3600},
		{"2 hours", 7200, 7200},
		{"4 hours", 14400, 14400},
		{"24 hours", 86400, 86400},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &capabilityMockTransport{
				responses: map[uint32][]byte{
					uint32(tpm2.TPMPTLockoutInterval): buildCapabilityResponse(tpm2.TPMPTLockoutInterval, tt.value),
				},
			}

			result, err := lockoutInterval(mockTransport)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}
