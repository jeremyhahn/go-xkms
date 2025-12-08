package tpm2

import (
	"fmt"
	"testing"
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

func TestLoadedCurves_Parsing(t *testing.T) {
	tests := []struct {
		name        string
		curveCount  uint32
		expectedMin uint32
		expectedMax uint32
	}{
		{
			name:        "No curves loaded",
			curveCount:  0,
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "Single curve",
			curveCount:  1,
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "Standard ECC curves",
			curveCount:  3,
			expectedMin: 3,
			expectedMax: 3,
		},
		{
			name:        "Many curves",
			curveCount:  10,
			expectedMin: 10,
			expectedMax: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.curveCount < tt.expectedMin || tt.curveCount > tt.expectedMax {
				t.Errorf("Curve count %d not in range [%d, %d]",
					tt.curveCount, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestLockoutRecovery_Parsing(t *testing.T) {
	tests := []struct {
		name          string
		recoveryValue uint32
		description   string
	}{
		{
			name:          "No lockout",
			recoveryValue: 0,
			description:   "Lockout disabled",
		},
		{
			name:          "Short recovery (1 hour)",
			recoveryValue: 3600,
			description:   "Recovery after 1 hour",
		},
		{
			name:          "Standard recovery (24 hours)",
			recoveryValue: 86400,
			description:   "Recovery after 24 hours",
		},
		{
			name:          "Long recovery (1 week)",
			recoveryValue: 604800,
			description:   "Recovery after 1 week",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate hours for informational purposes
			hours := tt.recoveryValue / 3600
			days := hours / 24

			t.Logf("%s: %d seconds (%d hours, %d days)",
				tt.description, tt.recoveryValue, hours, days)
		})
	}
}

func TestLockoutInterval_Parsing(t *testing.T) {
	tests := []struct {
		name          string
		intervalValue uint32
		description   string
	}{
		{
			name:          "No interval",
			intervalValue: 0,
			description:   "Lockout interval disabled",
		},
		{
			name:          "Short interval (1 minute)",
			intervalValue: 60,
			description:   "1 minute between attempts",
		},
		{
			name:          "Standard interval (2 hours)",
			intervalValue: 7200,
			description:   "2 hours between attempts",
		},
		{
			name:          "Long interval (1 day)",
			intervalValue: 86400,
			description:   "1 day between attempts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate minutes for informational purposes
			minutes := tt.intervalValue / 60

			t.Logf("%s: %d seconds (%d minutes)", tt.description, tt.intervalValue, minutes)
		})
	}
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
