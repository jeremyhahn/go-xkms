package tpm2

import (
	"encoding/hex"
	"testing"
)

func TestEncodeUnit(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0xAB},
			expected: "ab",
		},
		{
			name:     "multiple bytes",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "010203",
		},
		{
			name:     "all zeros",
			input:    []byte{0x00, 0x00, 0x00},
			expected: "000000",
		},
		{
			name:     "all ones",
			input:    []byte{0xFF, 0xFF, 0xFF},
			expected: "ffffff",
		},
		{
			name:     "mixed values",
			input:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expected: "deadbeef",
		},
		{
			name:     "TPM name example",
			input:    []byte{0x00, 0x0B, 0x12, 0x34, 0x56, 0x78},
			expected: "000b12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Encode(tt.input)
			if result != tt.expected {
				t.Errorf("Encode() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestDecodeUnit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "single byte",
			input:    "ab",
			expected: []byte{0xAB},
			wantErr:  false,
		},
		{
			name:     "multiple bytes",
			input:    "010203",
			expected: []byte{0x01, 0x02, 0x03},
			wantErr:  false,
		},
		{
			name:     "deadbeef",
			input:    "deadbeef",
			expected: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			wantErr:  false,
		},
		{
			name:     "uppercase input",
			input:    "DEADBEEF",
			expected: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			wantErr:  false,
		},
		{
			name:     "mixed case",
			input:    "DeAdBeEf",
			expected: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			wantErr:  false,
		},
		{
			name:     "odd length string",
			input:    "abc",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "invalid hex character",
			input:    "xyz",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Decode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("Decode() length = %d, want %d", len(result), len(tt.expected))
				return
			}

			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("Decode()[%d] = 0x%x, want 0x%x", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestEncodeDecodeRoundTripUnit(t *testing.T) {
	tests := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x01, 0x02, 0x03, 0x04},
		{0xDE, 0xAD, 0xBE, 0xEF},
		make([]byte, 32),         // SHA256 hash size
		make([]byte, 64),         // SHA512 hash size
		{0x00, 0x0B},             // TPM Algorithm ID
		{0x81, 0x01, 0x00, 0x01}, // Persistent handle
	}

	for _, original := range tests {
		encoded := Encode(original)
		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("Decode failed for %x: %v", original, err)
			continue
		}

		if len(decoded) != len(original) {
			t.Errorf("round trip length mismatch: got %d, want %d", len(decoded), len(original))
			continue
		}

		for i := range original {
			if decoded[i] != original[i] {
				t.Errorf("round trip byte mismatch at %d: got 0x%x, want 0x%x", i, decoded[i], original[i])
			}
		}
	}
}

func TestHexEncodingLengthUnit(t *testing.T) {
	tests := []struct {
		byteLen int
		hexLen  int
	}{
		{0, 0},
		{1, 2},
		{2, 4},
		{16, 32},  // SHA1 size
		{20, 40},  // SHA1 output
		{32, 64},  // SHA256 output
		{48, 96},  // SHA384 output
		{64, 128}, // SHA512 output
	}

	for _, tt := range tests {
		input := make([]byte, tt.byteLen)
		encoded := Encode(input)
		if len(encoded) != tt.hexLen {
			t.Errorf("Encode(%d bytes) length = %d, want %d", tt.byteLen, len(encoded), tt.hexLen)
		}
	}
}

func TestStandardLibraryCompatibilityUnit(t *testing.T) {
	// Verify our Encode/Decode functions are compatible with standard library
	testData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}

	// Test Encode compatibility
	ourEncoded := Encode(testData)
	stdEncoded := hex.EncodeToString(testData)
	if ourEncoded != stdEncoded {
		t.Errorf("Encode mismatch with standard library: got %s, want %s", ourEncoded, stdEncoded)
	}

	// Test Decode compatibility
	ourDecoded, err := Decode(ourEncoded)
	if err != nil {
		t.Errorf("Decode error: %v", err)
	}
	stdDecoded, err := hex.DecodeString(stdEncoded)
	if err != nil {
		t.Errorf("standard library decode error: %v", err)
	}

	if len(ourDecoded) != len(stdDecoded) {
		t.Errorf("Decode length mismatch: got %d, want %d", len(ourDecoded), len(stdDecoded))
	}

	for i := range ourDecoded {
		if ourDecoded[i] != stdDecoded[i] {
			t.Errorf("Decode byte mismatch at %d: got 0x%x, want 0x%x", i, ourDecoded[i], stdDecoded[i])
		}
	}
}

func TestTPMHandleEncodingUnit(t *testing.T) {
	// Test encoding of typical TPM handle values
	handles := map[string][]byte{
		"TPM_RH_OWNER":       {0x40, 0x00, 0x00, 0x01},
		"TPM_RH_ENDORSEMENT": {0x40, 0x00, 0x00, 0x0B},
		"TPM_RH_PLATFORM":    {0x40, 0x00, 0x00, 0x0C},
		"Persistent EK":      {0x81, 0x01, 0x00, 0x01},
		"Persistent SRK":     {0x81, 0x00, 0x00, 0x01},
	}

	for name, handle := range handles {
		encoded := Encode(handle)
		if len(encoded) != 8 {
			t.Errorf("%s: encoded length = %d, want 8", name, len(encoded))
		}

		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("%s: decode error: %v", name, err)
			continue
		}

		if len(decoded) != 4 {
			t.Errorf("%s: decoded length = %d, want 4", name, len(decoded))
		}

		for i := range handle {
			if decoded[i] != handle[i] {
				t.Errorf("%s: byte %d mismatch: got 0x%x, want 0x%x", name, i, decoded[i], handle[i])
			}
		}
	}
}

func TestAlgorithmIDEncodingUnit(t *testing.T) {
	// Test encoding of TPM algorithm IDs
	algorithms := map[string][]byte{
		"TPM_ALG_SHA1":   {0x00, 0x04},
		"TPM_ALG_SHA256": {0x00, 0x0B},
		"TPM_ALG_SHA384": {0x00, 0x0C},
		"TPM_ALG_SHA512": {0x00, 0x0D},
		"TPM_ALG_RSA":    {0x00, 0x01},
		"TPM_ALG_ECC":    {0x00, 0x23},
	}

	for name, algID := range algorithms {
		encoded := Encode(algID)
		if len(encoded) != 4 {
			t.Errorf("%s: encoded length = %d, want 4", name, len(encoded))
		}

		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("%s: decode error: %v", name, err)
			continue
		}

		if decoded[0] != algID[0] || decoded[1] != algID[1] {
			t.Errorf("%s: algorithm ID mismatch", name)
		}
	}
}
