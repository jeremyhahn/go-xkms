// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestAuthDataFlags_Has(t *testing.T) {
	tests := []struct {
		name     string
		flags    AuthDataFlags
		check    AuthDataFlags
		expected bool
	}{
		{
			name:     "UP flag set and checked",
			flags:    FlagUP,
			check:    FlagUP,
			expected: true,
		},
		{
			name:     "UV flag not set but checked",
			flags:    FlagUP,
			check:    FlagUV,
			expected: false,
		},
		{
			name:     "multiple flags set check single",
			flags:    FlagUP | FlagUV | FlagAT,
			check:    FlagUV,
			expected: true,
		},
		{
			name:     "all flags set",
			flags:    FlagUP | FlagUV | FlagBE | FlagBS | FlagAT | FlagED,
			check:    FlagED,
			expected: true,
		},
		{
			name:     "no flags set",
			flags:    0,
			check:    FlagUP,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.flags.Has(tc.check)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestAuthDataFlags_String(t *testing.T) {
	tests := []struct {
		name     string
		flags    AuthDataFlags
		contains []string
	}{
		{
			name:     "no flags",
			flags:    0,
			contains: []string{"AuthDataFlags{", "}"},
		},
		{
			name:     "UP only",
			flags:    FlagUP,
			contains: []string{"UP"},
		},
		{
			name:     "UP and UV",
			flags:    FlagUP | FlagUV,
			contains: []string{"UP", "UV"},
		},
		{
			name:     "all flags",
			flags:    FlagUP | FlagUV | FlagBE | FlagBS | FlagAT | FlagED,
			contains: []string{"UP", "UV", "BE", "BS", "AT", "ED"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.flags.String()
			for _, substr := range tc.contains {
				if !bytes.Contains([]byte(result), []byte(substr)) {
					t.Errorf("expected string to contain %q, got %q", substr, result)
				}
			}
		})
	}
}

func TestNewAuthDataBuilder(t *testing.T) {
	rpID := "example.com"
	builder := NewAuthDataBuilder(rpID)

	if builder == nil {
		t.Fatal("expected non-nil builder")
	}
	if builder.rpID != rpID {
		t.Errorf("expected rpID %q, got %q", rpID, builder.rpID)
	}
	if builder.extensions == nil {
		t.Error("expected extensions map to be initialized")
	}
}

func TestAuthDataBuilder_Build_MinimalAuthData(t *testing.T) {
	rpID := "example.com"
	signCount := uint32(42)

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP | FlagUV).
		WithSignCount(signCount)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify length (32 + 1 + 4 = 37 bytes)
	if len(data) != minAuthDataLen {
		t.Errorf("expected length %d, got %d", minAuthDataLen, len(data))
	}

	// Verify rpIdHash
	expectedHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], expectedHash[:]) {
		t.Error("rpIdHash mismatch")
	}

	// Verify flags
	if AuthDataFlags(data[32]) != FlagUP|FlagUV {
		t.Errorf("expected flags %x, got %x", FlagUP|FlagUV, data[32])
	}

	// Verify signCount
	parsedCount := binary.BigEndian.Uint32(data[33:37])
	if parsedCount != signCount {
		t.Errorf("expected signCount %d, got %d", signCount, parsedCount)
	}
}

func TestAuthDataBuilder_Build_WithAttestedCredentialData(t *testing.T) {
	rpID := "example.com"
	signCount := uint32(1)
	aaguid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	credentialID := []byte("test-credential-id-1234")

	// Create a minimal COSE key (CBOR-encoded map)
	publicKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,                // kty: EC2
		3:  -7,               // alg: ES256
		-1: 1,                // crv: P-256
		-2: make([]byte, 32), // x coordinate
		-3: make([]byte, 32), // y coordinate
	})

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(signCount).
		WithAttestedCredentialData(aaguid, credentialID, publicKey)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify AT flag is automatically set
	if AuthDataFlags(data[32])&FlagAT == 0 {
		t.Error("expected AT flag to be set")
	}

	// Verify AAGUID at offset 37
	if !bytes.Equal(data[37:53], aaguid[:]) {
		t.Error("AAGUID mismatch")
	}

	// Verify credential ID length
	credIDLen := binary.BigEndian.Uint16(data[53:55])
	if int(credIDLen) != len(credentialID) {
		t.Errorf("expected credentialID length %d, got %d", len(credentialID), credIDLen)
	}

	// Verify credential ID
	credIDStart := 55
	credIDEnd := credIDStart + int(credIDLen)
	if !bytes.Equal(data[credIDStart:credIDEnd], credentialID) {
		t.Error("credentialID mismatch")
	}
}

func TestAuthDataBuilder_Build_WithExtensions(t *testing.T) {
	rpID := "example.com"

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(0).
		WithExtension("credProtect", 2).
		WithExtension("minPinLength", 4)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify ED flag is automatically set
	if AuthDataFlags(data[32])&FlagED == 0 {
		t.Error("expected ED flag to be set")
	}

	// Parse extensions from the data
	extData := data[37:]
	var extensions map[string]interface{}
	if err := cbor.Unmarshal(extData, &extensions); err != nil {
		t.Fatalf("failed to unmarshal extensions: %v", err)
	}

	if extensions["credProtect"] != uint64(2) {
		t.Errorf("expected credProtect=2, got %v", extensions["credProtect"])
	}
	if extensions["minPinLength"] != uint64(4) {
		t.Errorf("expected minPinLength=4, got %v", extensions["minPinLength"])
	}
}

func TestAuthDataBuilder_Build_WithExtensionsMap(t *testing.T) {
	rpID := "example.com"

	extensions := map[string]interface{}{
		"credProtect":  2,
		"minPinLength": 4,
	}

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(0).
		WithExtensions(extensions)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify ED flag is automatically set
	if AuthDataFlags(data[32])&FlagED == 0 {
		t.Error("expected ED flag to be set")
	}
}

func TestAuthDataBuilder_Build_EmptyRPID(t *testing.T) {
	builder := NewAuthDataBuilder("").WithFlags(FlagUP)

	_, err := builder.Build()
	if !errors.Is(err, ErrAuthDataInvalidRPID) {
		t.Errorf("expected ErrAuthDataInvalidRPID, got %v", err)
	}
}

func TestAuthDataBuilder_Build_AttestedWithoutPublicKey(t *testing.T) {
	aaguid := [16]byte{}
	credentialID := []byte("test-cred")

	builder := NewAuthDataBuilder("example.com").
		WithFlags(FlagUP).
		WithAttestedCredentialData(aaguid, credentialID, nil)

	_, err := builder.Build()
	if !errors.Is(err, ErrAuthDataNoPublicKey) {
		t.Errorf("expected ErrAuthDataNoPublicKey, got %v", err)
	}
}

func TestAuthDataBuilder_Build_CredentialIDTooLong(t *testing.T) {
	aaguid := [16]byte{}
	credentialID := make([]byte, 65536) // Exceeds uint16 max
	publicKey, _ := cbor.Marshal(map[int]interface{}{1: 2})

	builder := NewAuthDataBuilder("example.com").
		WithFlags(FlagUP).
		WithAttestedCredentialData(aaguid, credentialID, publicKey)

	_, err := builder.Build()
	if !errors.Is(err, ErrAuthDataCredIDTooLong) {
		t.Errorf("expected ErrAuthDataCredIDTooLong, got %v", err)
	}
}

func TestParseAuthData_Minimal(t *testing.T) {
	rpID := "example.com"
	signCount := uint32(100)

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP | FlagUV).
		WithSignCount(signCount)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	// Verify rpIdHash
	expectedHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(parsed.RPIDHash, expectedHash[:]) {
		t.Error("parsed rpIdHash mismatch")
	}

	// Verify flags
	if parsed.Flags != FlagUP|FlagUV {
		t.Errorf("expected flags %x, got %x", FlagUP|FlagUV, parsed.Flags)
	}

	// Verify signCount
	if parsed.SignCount != signCount {
		t.Errorf("expected signCount %d, got %d", signCount, parsed.SignCount)
	}

	// Verify helper methods
	if !parsed.UserPresent() {
		t.Error("expected UserPresent() to return true")
	}
	if !parsed.UserVerified() {
		t.Error("expected UserVerified() to return true")
	}
	if parsed.HasAttestedCredentialData() {
		t.Error("expected HasAttestedCredentialData() to return false")
	}
	if parsed.HasExtensions() {
		t.Error("expected HasExtensions() to return false")
	}
}

func TestParseAuthData_WithAttestedCredentialData(t *testing.T) {
	rpID := "example.com"
	aaguid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	credentialID := []byte("test-credential-id")
	publicKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: make([]byte, 32),
		-3: make([]byte, 32),
	})

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(1).
		WithAttestedCredentialData(aaguid, credentialID, publicKey)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	if !parsed.HasAttestedCredentialData() {
		t.Error("expected HasAttestedCredentialData() to return true")
	}

	if !bytes.Equal(parsed.AAGUID, aaguid[:]) {
		t.Error("parsed AAGUID mismatch")
	}

	if !bytes.Equal(parsed.CredentialID, credentialID) {
		t.Error("parsed CredentialID mismatch")
	}

	if len(parsed.PublicKey) == 0 {
		t.Error("expected non-empty public key")
	}
}

func TestParseAuthData_WithExtensions(t *testing.T) {
	rpID := "example.com"

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(0).
		WithExtension("credProtect", 2)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	if !parsed.HasExtensions() {
		t.Error("expected HasExtensions() to return true")
	}

	if parsed.Extensions["credProtect"] != uint64(2) {
		t.Errorf("expected credProtect=2, got %v", parsed.Extensions["credProtect"])
	}
}

func TestParseAuthData_TooShort(t *testing.T) {
	shortData := make([]byte, minAuthDataLen-1)

	_, err := ParseAuthData(shortData)
	if !errors.Is(err, ErrAuthDataTooShort) {
		t.Errorf("expected ErrAuthDataTooShort, got %v", err)
	}
}

func TestParseAuthData_TruncatedAAGUID(t *testing.T) {
	// Create minimal auth data with AT flag but truncated AAGUID
	data := make([]byte, minAuthDataLen+5) // Not enough for full AAGUID
	data[32] = byte(FlagAT)                // Set AT flag

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated, got %v", err)
	}
}

func TestParseAuthData_TruncatedCredIDLen(t *testing.T) {
	// Create auth data with AT flag and AAGUID but truncated credID length
	data := make([]byte, minAuthDataLen+aaguidLen) // Missing credIDLen field
	data[32] = byte(FlagAT)

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated, got %v", err)
	}
}

func TestParseAuthData_TruncatedCredID(t *testing.T) {
	// Create auth data with AT flag, AAGUID, credIDLen but truncated credID
	data := make([]byte, minAuthDataLen+aaguidLen+credIDLenFieldLen+5)
	data[32] = byte(FlagAT)
	// Set credIDLen to 100 (more than available)
	binary.BigEndian.PutUint16(data[minAuthDataLen+aaguidLen:], 100)

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated, got %v", err)
	}
}

func TestParseAuthData_InvalidPublicKeyCBOR(t *testing.T) {
	// Create auth data with AT flag and invalid CBOR for public key
	aaguid := [16]byte{}
	credID := []byte("cred")
	invalidCBOR := []byte{0xff, 0xff, 0xff} // Invalid CBOR

	data := make([]byte, 0, minAuthDataLen+aaguidLen+credIDLenFieldLen+len(credID)+len(invalidCBOR))

	// rpIdHash
	rpIDHash := sha256.Sum256([]byte("example.com"))
	data = append(data, rpIDHash[:]...)

	// flags with AT
	data = append(data, byte(FlagAT))

	// signCount
	signCountBytes := make([]byte, 4)
	data = append(data, signCountBytes...)

	// AAGUID
	data = append(data, aaguid[:]...)

	// credIDLen
	credIDLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLenBytes, uint16(len(credID)))
	data = append(data, credIDLenBytes...)

	// credID
	data = append(data, credID...)

	// Invalid CBOR public key
	data = append(data, invalidCBOR...)

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataCBORDecode) {
		t.Errorf("expected ErrAuthDataCBORDecode, got %v", err)
	}
}

func TestParseAuthData_TruncatedExtensions(t *testing.T) {
	// Create minimal auth data with ED flag but no extension data
	data := make([]byte, minAuthDataLen)
	rpIDHash := sha256.Sum256([]byte("example.com"))
	copy(data[:32], rpIDHash[:])
	data[32] = byte(FlagED)

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated, got %v", err)
	}
}

func TestParseAuthData_InvalidExtensionCBOR(t *testing.T) {
	// Create auth data with ED flag and invalid CBOR for extensions
	data := make([]byte, minAuthDataLen+3)
	rpIDHash := sha256.Sum256([]byte("example.com"))
	copy(data[:32], rpIDHash[:])
	data[32] = byte(FlagED)
	// Invalid CBOR at the end
	data[minAuthDataLen] = 0xff
	data[minAuthDataLen+1] = 0xff
	data[minAuthDataLen+2] = 0xff

	_, err := ParseAuthData(data)
	if !errors.Is(err, ErrAuthDataCBORDecode) {
		t.Errorf("expected ErrAuthDataCBORDecode, got %v", err)
	}
}

func TestVerifyRPIDHash(t *testing.T) {
	rpID := "example.com"

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP).
		WithSignCount(0)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	// Should match the correct RP ID
	if !VerifyRPIDHash(parsed, rpID) {
		t.Error("expected VerifyRPIDHash to return true for matching RP ID")
	}

	// Should not match a different RP ID
	if VerifyRPIDHash(parsed, "different.com") {
		t.Error("expected VerifyRPIDHash to return false for different RP ID")
	}
}

func TestAuthenticatorData_BackupFlags(t *testing.T) {
	builder := NewAuthDataBuilder("example.com").
		WithFlags(FlagUP | FlagBE | FlagBS).
		WithSignCount(0)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	if !parsed.BackupEligible() {
		t.Error("expected BackupEligible() to return true")
	}

	if !parsed.BackupState() {
		t.Error("expected BackupState() to return true")
	}
}

func TestAuthDataBuilder_RoundTrip(t *testing.T) {
	rpID := "example.com"
	signCount := uint32(12345)
	aaguid := [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	credentialID := []byte("credential-id-for-roundtrip-test")
	publicKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: bytes.Repeat([]byte{0xaa}, 32),
		-3: bytes.Repeat([]byte{0xbb}, 32),
	})

	builder := NewAuthDataBuilder(rpID).
		WithFlags(FlagUP|FlagUV|FlagBE).
		WithSignCount(signCount).
		WithAttestedCredentialData(aaguid, credentialID, publicKey).
		WithExtension("credProtect", 2).
		WithExtension("minPinLength", 6)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	// Verify all fields
	expectedHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(parsed.RPIDHash, expectedHash[:]) {
		t.Error("RPIDHash mismatch after round-trip")
	}

	// Note: AT and ED flags are automatically added
	expectedFlags := FlagUP | FlagUV | FlagBE | FlagAT | FlagED
	if parsed.Flags != expectedFlags {
		t.Errorf("Flags mismatch: expected %x, got %x", expectedFlags, parsed.Flags)
	}

	if parsed.SignCount != signCount {
		t.Errorf("SignCount mismatch: expected %d, got %d", signCount, parsed.SignCount)
	}

	if !bytes.Equal(parsed.AAGUID, aaguid[:]) {
		t.Error("AAGUID mismatch after round-trip")
	}

	if !bytes.Equal(parsed.CredentialID, credentialID) {
		t.Error("CredentialID mismatch after round-trip")
	}

	if len(parsed.PublicKey) == 0 {
		t.Error("PublicKey should not be empty after round-trip")
	}

	if parsed.Extensions["credProtect"] != uint64(2) {
		t.Errorf("credProtect extension mismatch: got %v", parsed.Extensions["credProtect"])
	}

	if parsed.Extensions["minPinLength"] != uint64(6) {
		t.Errorf("minPinLength extension mismatch: got %v", parsed.Extensions["minPinLength"])
	}
}

func TestParseAuthData_EmptyData(t *testing.T) {
	_, err := ParseAuthData(nil)
	if !errors.Is(err, ErrAuthDataTooShort) {
		t.Errorf("expected ErrAuthDataTooShort for nil data, got %v", err)
	}

	_, err = ParseAuthData([]byte{})
	if !errors.Is(err, ErrAuthDataTooShort) {
		t.Errorf("expected ErrAuthDataTooShort for empty data, got %v", err)
	}
}

func TestAuthDataBuilder_EmptyCredentialID(t *testing.T) {
	aaguid := [16]byte{}
	credentialID := []byte{} // Empty but valid
	publicKey, _ := cbor.Marshal(map[int]interface{}{1: 2})

	builder := NewAuthDataBuilder("example.com").
		WithFlags(FlagUP).
		WithAttestedCredentialData(aaguid, credentialID, publicKey)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	parsed, err := ParseAuthData(data)
	if err != nil {
		t.Fatalf("ParseAuthData() error: %v", err)
	}

	if len(parsed.CredentialID) != 0 {
		t.Errorf("expected empty credential ID, got length %d", len(parsed.CredentialID))
	}
}

func TestCalcCBORLength_ValidData(t *testing.T) {
	// Test with a simple CBOR map
	data, _ := cbor.Marshal(map[int]int{1: 2, 3: 4})
	length, err := calcCBORLength(data)
	if err != nil {
		t.Fatalf("calcCBORLength() error: %v", err)
	}
	if length != len(data) {
		t.Errorf("expected length %d, got %d", len(data), length)
	}

	// Test with a complex COSE key
	coseKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: make([]byte, 32),
		-3: make([]byte, 32),
	})
	length, err = calcCBORLength(coseKey)
	if err != nil {
		t.Fatalf("calcCBORLength() error: %v", err)
	}
	if length != len(coseKey) {
		t.Errorf("expected length %d, got %d", len(coseKey), length)
	}
}

func TestCalcCBORLength_EmptyData(t *testing.T) {
	_, err := calcCBORLength(nil)
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated for nil, got %v", err)
	}

	_, err = calcCBORLength([]byte{})
	if !errors.Is(err, ErrAuthDataTruncated) {
		t.Errorf("expected ErrAuthDataTruncated for empty, got %v", err)
	}
}

func TestCalcCBORLength_InvalidCBOR(t *testing.T) {
	invalidCBOR := []byte{0xff, 0xff, 0xff}
	_, err := calcCBORLength(invalidCBOR)
	if err == nil {
		t.Error("expected error for invalid CBOR")
	}
}

func BenchmarkAuthDataBuilder_Build(b *testing.B) {
	aaguid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	credentialID := []byte("benchmark-credential-id")
	publicKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: make([]byte, 32),
		-3: make([]byte, 32),
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewAuthDataBuilder("example.com").
			WithFlags(FlagUP|FlagUV).
			WithSignCount(uint32(i)).
			WithAttestedCredentialData(aaguid, credentialID, publicKey)

		_, _ = builder.Build()
	}
}

func BenchmarkParseAuthData(b *testing.B) {
	aaguid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	credentialID := []byte("benchmark-credential-id")
	publicKey, _ := cbor.Marshal(map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: make([]byte, 32),
		-3: make([]byte, 32),
	})

	builder := NewAuthDataBuilder("example.com").
		WithFlags(FlagUP|FlagUV).
		WithSignCount(100).
		WithAttestedCredentialData(aaguid, credentialID, publicKey)

	data, _ := builder.Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAuthData(data)
	}
}
