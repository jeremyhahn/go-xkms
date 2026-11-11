package tpm2

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Unit tests for capabilities helper functions that don't require a TPM

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

// ---------------------------------------------------------------------------
// algNames map tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// commandNames map tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// curveNames map tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// commandDescriptions map tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SupportedCommandsInfo tests (unit-level, no TPM required)
// ---------------------------------------------------------------------------

// TPM 2.0 Structures, Part 2, Table 12: the assigned command code range runs
// from TPM_CC_FIRST to TPM_CC_LAST. Anything outside it is vendor-specific or
// unassigned, which is precisely the case SupportedCommandsInfo reports as
// "Vendor Command (0xNNNN)".
const (
	tpmCCFirst = tpm2.TPMCC(0x0000011F) // TPM_CC_NV_UndefineSpaceSpecial
	tpmCCLast  = tpm2.TPMCC(0x00000198) // TPM_CC_ACT_SetTimeout
)

// TestCommandNamesWithinAssignedRange pins the invariant that makes
// SupportedCommandsInfo's fallback correct: commandNames must describe only
// codes the TPM 2.0 specification actually assigns. If an out-of-range entry
// were ever added, a genuine vendor command would silently be reported under a
// standard name instead of "Vendor Command (0xNNNN)".
//
// This replaces the former TestCommandInfo_VendorCommand, which was deleted
// because it could not fail: it assigned name := expectedName and then checked
// name != expectedName, exercising no product code at all.
func TestCommandNamesWithinAssignedRange(t *testing.T) {
	if len(commandNames) == 0 {
		t.Fatal("commandNames is empty; the command code table is missing")
	}

	for cc, name := range commandNames {
		if cc < tpmCCFirst || cc > tpmCCLast {
			t.Errorf("commandNames has out-of-range command code 0x%04X (%q); "+
				"assigned range is [0x%04X, 0x%04X]",
				uint32(cc), name, uint32(tpmCCFirst), uint32(tpmCCLast))
		}
	}
}

// TestVendorCommandCodeIsUnassigned proves a vendor command code exists that
// the lookup tables do not claim, so the "Vendor Command" branch of
// SupportedCommandsInfo is reachable rather than dead code.
//
// The code is chosen at run time from just above TPM_CC_LAST instead of being
// hardcoded, so the test can never need a skip guard to protect a hardcoded
// constant from colliding with a newly added command name.
func TestVendorCommandCodeIsUnassigned(t *testing.T) {
	var vendorCC tpm2.TPMCC
	found := false
	for cc := tpmCCLast + 1; cc <= tpmCCLast+0x1000; cc++ {
		if _, named := commandNames[cc]; named {
			continue
		}
		if _, described := commandDescriptions[cc]; described {
			continue
		}
		vendorCC = cc
		found = true
		break
	}

	if !found {
		t.Fatal("no unassigned command code found above TPM_CC_LAST; " +
			"commandNames claims the entire vendor range")
	}

	if _, ok := commandNames[vendorCC]; ok {
		t.Errorf("command code 0x%04X must not be in commandNames", uint32(vendorCC))
	}
	if _, ok := commandDescriptions[vendorCC]; ok {
		t.Errorf("command code 0x%04X must not be in commandDescriptions", uint32(vendorCC))
	}
	if vendorCC <= tpmCCLast {
		t.Errorf("chosen vendor code 0x%04X is inside the assigned range", uint32(vendorCC))
	}
}

// ---------------------------------------------------------------------------
// PropertiesFixed new fields tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// tpmPTNames map tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// formatFixedProperty tests
// ---------------------------------------------------------------------------

// TestFormatFixedProperty_Manufacturer_UnknownVendorFallsBackToASCII proves
// a manufacturer code that is not in the TCG vendor ID registry, but whose
// four bytes are printable ASCII, renders as that ASCII string rather than
// the empty string or the known-vendor name.
func TestFormatFixedProperty_Manufacturer_UnknownVendorFallsBackToASCII(t *testing.T) {
	// "ZZZZ" = 0x5A5A5A5A, not a registered TCG vendor ID.
	result := formatFixedProperty(tpm2.TPMPTManufacturer, 0x5A5A5A5A)
	if result != "ZZZZ" {
		t.Errorf("formatFixedProperty(Manufacturer, unknown ASCII): expected %q, got %q", "ZZZZ", result)
	}
}

// TestFormatFixedProperty_Manufacturer_UnknownVendorNonPrintableIsEmpty
// proves a manufacturer code that is neither a registered vendor ID nor
// printable ASCII renders as the empty string, letting the caller fall back
// to the raw hex value rather than displaying garbage.
func TestFormatFixedProperty_Manufacturer_UnknownVendorNonPrintableIsEmpty(t *testing.T) {
	result := formatFixedProperty(tpm2.TPMPTManufacturer, 0x00000000)
	if result != "" {
		t.Errorf("formatFixedProperty(Manufacturer, non-printable): expected empty string, got %q", result)
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

// ---------------------------------------------------------------------------
// formatVariableProperty tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PropertiesFixed extended fields tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// cleanTPMString tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Edge case tests for capability functions
// ---------------------------------------------------------------------------
