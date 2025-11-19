package tpm2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func TestParsing_EventType_AllKnownTypes(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint32
		expected  string
	}{
		{"EV_UNDEFINED", 0x00000000, "EV_UNDEFINED"},
		{"EV_IPL", 0x00000001, "EV_IPL"},
		{"EV_EVENT_TAG", 0x00000002, "EV_EVENT_TAG"},
		{"EV_NO_ACTION", 0x00000003, "EV_NO_ACTION"},
		{"EV_SEPARATOR", 0x00000004, "EV_SEPARATOR"},
		{"EV_ACTION", 0x00000008, "EV_ACTION"},
		{"EV_EFI_VARIABLE_DRIVER_CONFIG", 0x0000000D, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{"EV_EFI_BOOT_SERVICES_APPLICATION", 0x00000006, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{"EV_S_CRTM_CONTENTS", 0x80000001, "EV_S_CRTM_CONTENTS"},
		{"EV_S_CRTM_VERSION", 0x80000002, "EV_S_CRTM_VERSION"},
		{"EV_S_CPU_MICROCODE", 0x80000003, "EV_S_CPU_MICROCODE"},
		{"EV_S_CRTM_SEPARATOR", 0x80000008, "EV_S_CRTM_SEPARATOR"},
		{"EV_S_POST_CODE", 0x80000006, "EV_S_POST_CODE"},
		{"EV_PLATFORM_CONFIG_FLAGS", 0x800000E0, "EV_PLATFORM_CONFIG_FLAGS"},
		{"Unknown event type", 0x12345678, "Unknown (0x12345678)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEventType(tt.eventType)
			if result != tt.expected {
				t.Errorf("parseEventType(%#x) = %q, want %q", tt.eventType, result, tt.expected)
			}
		})
	}
}

func TestParsing_AlgorithmId_AllKnown(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected string
	}{
		{"SHA1", AlgSHA1, "sha1"},
		{"SHA256", AlgSHA256, "sha256"},
		{"SHA384", AlgSHA384, "sha384"},
		{"SHA512", AlgSHA512, "sha512"},
		{"SM3_256", AlgSM3256, "sm3_256"},
		{"SM3_256_Alt", AlgSM3256Alt, "sm3_256"},
		{"Unknown algorithm", 0xFFFF, "unknown_0xffff"},
		{"Another unknown", 0x1234, "unknown_0x1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAlgorithmId(tt.algID)
			if result != tt.expected {
				t.Errorf("parseAlgorithmId(%#x) = %q, want %q", tt.algID, result, tt.expected)
			}
		})
	}
}

func TestParsing_GetDigestSizeByAlgID_All(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected int
	}{
		{"SHA1", AlgSHA1, 20},
		{"SHA256", AlgSHA256, 32},
		{"SHA384", AlgSHA384, 48},
		{"SHA512", AlgSHA512, 64},
		{"SM3_256", AlgSM3256, 32},
		{"SM3_256_Alt", AlgSM3256Alt, 32},
		{"Unknown algorithm", 0xFFFF, 0},
		{"Another unknown", 0x0001, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDigestSizeByAlgID(tt.algID)
			if result != tt.expected {
				t.Errorf("getDigestSizeByAlgID(%#x) = %d, want %d", tt.algID, result, tt.expected)
			}
		})
	}
}

func TestParsing_EstimateDigestSize_Vendor(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected int
	}{
		{"Vendor extension 0x2000", 0x2000, 32},
		{"Vendor extension 0x2001", 0x2001, 32},
		{"Platform specific 0x6000", 0x6000, 32},
		{"Platform extension 0x7FFF", 0x7FFF, 32},
		{"Standard range unknown", 0x1FFF, 0},
		{"Standard range unknown 0x0001", 0x0001, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := estimateDigestSize(tt.algID)
			if result != tt.expected {
				t.Errorf("estimateDigestSize(%#x) = %d, want %d", tt.algID, result, tt.expected)
			}
		})
	}
}

func TestParsing_GetDigestSize_All(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		expected    int
	}{
		{"sha1", "sha1", sha1.Size},
		{"sha256", "sha256", sha256.Size},
		{"sha384", "sha384", sha512.Size384},
		{"sha512", "sha512", sha512.Size},
		{"sm3_256", "sm3_256", 32},
		{"unknown", "unknown", 0},
		{"empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDigestSize(tt.algorithmId)
			if result != tt.expected {
				t.Errorf("GetDigestSize(%q) = %d, want %d", tt.algorithmId, result, tt.expected)
			}
		})
	}
}

func TestParsing_GetHashFunction_Success(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		digestSize  int
	}{
		{"sha1", "sha1", sha1.Size},
		{"sha256", "sha256", sha256.Size},
		{"sha384", "sha384", sha512.Size384},
		{"sha512", "sha512", sha512.Size},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := GetHashFunction(tt.algorithmId)
			if err != nil {
				t.Errorf("GetHashFunction(%q) unexpected error: %v", tt.algorithmId, err)
				return
			}
			if hasher == nil {
				t.Errorf("GetHashFunction(%q) returned nil hasher", tt.algorithmId)
				return
			}
			if hasher.Size() != tt.digestSize {
				t.Errorf("GetHashFunction(%q).Size() = %d, want %d", tt.algorithmId, hasher.Size(), tt.digestSize)
			}
		})
	}
}

func TestParsing_GetHashFunction_Invalid(t *testing.T) {
	invalidAlgorithms := []string{
		"unknown",
		"md5",
		"SHA-256",
		"",
	}

	for _, alg := range invalidAlgorithms {
		t.Run(alg, func(t *testing.T) {
			hasher, err := GetHashFunction(alg)
			if err == nil {
				t.Errorf("GetHashFunction(%q) expected error, got nil", alg)
			}
			if hasher != nil {
				t.Errorf("GetHashFunction(%q) expected nil hasher, got %v", alg, hasher)
			}
		})
	}
}

func TestParsing_IsSupportedHashAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		expected    bool
	}{
		{"sha1", "sha1", true},
		{"sha256", "sha256", true},
		{"sha384", "sha384", true},
		{"sha512", "sha512", true},
		{"sm3_256", "sm3_256", false},
		{"unknown", "unknown", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSupportedHashAlgorithm(tt.algorithmId)
			if result != tt.expected {
				t.Errorf("isSupportedHashAlgorithm(%q) = %v, want %v", tt.algorithmId, result, tt.expected)
			}
		})
	}
}

func TestParsing_EventString_Inputs(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Simple ASCII", []byte("Hello World"), "Hello World"},
		{"Grub command", []byte("grub_cmd: test command"), "grub_cmd: test command"},
		{"With null bytes", []byte("test\x00\x00\x00string"), "string"},
		{"Multiple sequences", []byte("short\x00\x00\x00\x00longer sequence here"), "longer sequence here"},
		{"Non-printable prefix", []byte{0x01, 0x02, 0x03, 'H', 'e', 'l', 'l', 'o'}, "Hello"},
		{"Empty", []byte{}, ""},
		{"Only non-printable", []byte{0x01, 0x02, 0x03, 0x04}, ""},
		{"Special characters", []byte("test@#$%^&*()"), "test@#$%^&*()"},
		{"With spaces", []byte("   test   "), "   test   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEventString(tt.input)
			if result != tt.expected {
				t.Errorf("parseEventString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParsing_ExtendPCR_Success(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		currentPCR  []byte
		digest      []byte
	}{
		{"SHA1 extend", "sha1", make([]byte, sha1.Size), make([]byte, sha1.Size)},
		{"SHA256 extend", "sha256", make([]byte, sha256.Size), make([]byte, sha256.Size)},
		{"SHA384 extend", "sha384", make([]byte, sha512.Size384), make([]byte, sha512.Size384)},
		{"SHA512 extend", "sha512", make([]byte, sha512.Size), make([]byte, sha512.Size)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtendPCR(tt.currentPCR, tt.digest, tt.algorithmId)
			if err != nil {
				t.Errorf("ExtendPCR() unexpected error: %v", err)
				return
			}
			if len(result) != len(tt.currentPCR) {
				t.Errorf("ExtendPCR() result length = %d, want %d", len(result), len(tt.currentPCR))
			}
			allZero := true
			for _, b := range result {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("ExtendPCR() result is all zeros, expected hash output")
			}
		})
	}
}

func TestParsing_ExtendPCR_Invalid(t *testing.T) {
	currentPCR := make([]byte, 32)
	digest := make([]byte, 32)

	result, err := ExtendPCR(currentPCR, digest, "invalid")
	if err == nil {
		t.Error("ExtendPCR() with invalid algorithm expected error, got nil")
	}
	if result != nil {
		t.Errorf("ExtendPCR() with invalid algorithm expected nil result, got %v", result)
	}
}

func TestParsing_InitializePCRs(t *testing.T) {
	pcrs := InitializePCRs()

	expectedAlgorithms := []string{"sha1", "sha256", "sha384", "sha512"}

	if len(pcrs) != len(expectedAlgorithms) {
		t.Errorf("InitializePCRs() returned %d algorithms, want %d", len(pcrs), len(expectedAlgorithms))
	}

	for _, alg := range expectedAlgorithms {
		if _, exists := pcrs[alg]; !exists {
			t.Errorf("InitializePCRs() missing algorithm %q", alg)
		}
		if pcrs[alg] == nil {
			t.Errorf("InitializePCRs() algorithm %q has nil map", alg)
		}
		if len(pcrs[alg]) != 0 {
			t.Errorf("InitializePCRs() algorithm %q map not empty, got %d entries", alg, len(pcrs[alg]))
		}
	}
}

func TestParsing_CalculatePCRs_Empty(t *testing.T) {
	events := []Event{}
	pcrs := CalculatePCRs(events)

	expectedAlgorithms := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, alg := range expectedAlgorithms {
		if len(pcrs[alg]) != 0 {
			t.Errorf("CalculatePCRs() with empty events: algorithm %q has %d entries, want 0", alg, len(pcrs[alg]))
		}
	}
}

func TestParsing_CalculatePCRs_Single(t *testing.T) {
	events := []Event{
		{
			EventNum:    1,
			PCRIndex:    0,
			EventType:   "EV_IPL",
			DigestCount: 1,
			Digests: []Digest{
				{
					AlgorithmId: "sha256",
					Digest:      hex.EncodeToString(make([]byte, sha256.Size)),
				},
			},
			EventSize:   0,
			EventString: "",
		},
	}

	pcrs := CalculatePCRs(events)

	if _, exists := pcrs["sha256"][0]; !exists {
		t.Error("CalculatePCRs() PCR 0 not extended for sha256")
	}

	pcrValue := pcrs["sha256"][0]
	if len(pcrValue) != sha256.Size {
		t.Errorf("CalculatePCRs() PCR 0 length = %d, want %d", len(pcrValue), sha256.Size)
	}
}

func TestParsing_EventLog_NonExistent(t *testing.T) {
	events, err := ParseEventLog("/nonexistent/path/to/file")
	if err == nil {
		t.Error("ParseEventLog() with non-existent file expected error, got nil")
	}
	if events != nil {
		t.Errorf("ParseEventLog() with non-existent file expected nil events, got %v", events)
	}
}

func TestParsing_EventLog_Empty(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "empty_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	events, err := ParseEventLog(tmpFile.Name())
	if err != nil {
		t.Errorf("ParseEventLog() with empty file unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("ParseEventLog() with empty file expected 0 events, got %d", len(events))
	}
}

func TestParsing_EventLog_TruncatedPCR(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))

	tmpFile, err := os.CreateTemp("", "truncated_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.Write(buf.Bytes())
	_ = tmpFile.Close()

	events, err := ParseEventLog(tmpFile.Name())
	if err == nil {
		t.Error("ParseEventLog() with truncated PCR index expected error, got nil")
	}
	if len(events) > 0 {
		t.Errorf("ParseEventLog() with truncated data should not return events, got %d", len(events))
	}
}

func TestParsing_EventLog_TruncatedType(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))

	tmpFile, err := os.CreateTemp("", "truncated_event_type_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.Write(buf.Bytes())
	_ = tmpFile.Close()

	events, err := ParseEventLog(tmpFile.Name())
	if err == nil {
		t.Error("ParseEventLog() with truncated event type expected error, got nil")
	}
	if len(events) > 0 {
		t.Errorf("ParseEventLog() should not return events on error, got %d", len(events))
	}
}

func TestParsing_EventLog_UnknownAlgoSkipped(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x2001))
	buf.Write(make([]byte, 32))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(4))
	buf.WriteString("test")

	tmpFile, err := os.CreateTemp("", "unknown_algo_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.Write(buf.Bytes())
	_ = tmpFile.Close()

	opts := ParseEventLogOptions{SkipUnknownAlgorithms: true}
	events, err := ParseEventLogWithOptions(tmpFile.Name(), opts)
	if err != nil {
		t.Errorf("ParseEventLogWithOptions() with unknown algorithm unexpected error: %v", err)
		return
	}
	if len(events) != 1 {
		t.Errorf("ParseEventLogWithOptions() expected 1 event, got %d", len(events))
		return
	}
	if len(events[0].Digests) != 1 {
		t.Errorf("ParseEventLogWithOptions() expected 1 digest, got %d", len(events[0].Digests))
	}
}

func TestParsing_EventLog_UnknownAlgoError(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0001))
	buf.Write(make([]byte, 32))

	tmpFile, err := os.CreateTemp("", "unknown_standard_algo_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.Write(buf.Bytes())
	_ = tmpFile.Close()

	opts := ParseEventLogOptions{SkipUnknownAlgorithms: false}
	events, err := ParseEventLogWithOptions(tmpFile.Name(), opts)
	if err == nil {
		t.Error("ParseEventLogWithOptions() with unknown standard algorithm expected error, got nil")
	}
	if len(events) > 0 {
		t.Errorf("ParseEventLogWithOptions() should not return events on error, got %d", len(events))
	}
}

func TestParsing_EventLog_MultiDigest(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(7))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0004))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(AlgSHA1))
	buf.Write(make([]byte, 20))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(AlgSHA256))
	buf.Write(make([]byte, 32))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(AlgSHA384))
	buf.Write(make([]byte, 48))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	tmpFile, err := os.CreateTemp("", "multi_digest_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.Write(buf.Bytes())
	_ = tmpFile.Close()

	events, err := ParseEventLog(tmpFile.Name())
	if err != nil {
		t.Fatalf("ParseEventLog() unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("ParseEventLog() expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.DigestCount != 3 {
		t.Errorf("Event DigestCount = %d, want 3", event.DigestCount)
	}
	if len(event.Digests) != 3 {
		t.Errorf("Event Digests length = %d, want 3", len(event.Digests))
	}

	expectedAlgos := []string{"sha1", "sha256", "sha384"}
	for i, alg := range expectedAlgos {
		if event.Digests[i].AlgorithmId != alg {
			t.Errorf("Digest[%d].AlgorithmId = %q, want %q", i, event.Digests[i].AlgorithmId, alg)
		}
	}
}

func TestParsing_DefaultOptions(t *testing.T) {
	opts := DefaultParseEventLogOptions()

	if !opts.SkipUnknownAlgorithms {
		t.Error("DefaultParseEventLogOptions().SkipUnknownAlgorithms = false, want true")
	}
}

func TestParsing_BytesToUint32(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{"Zero", [4]byte{0, 0, 0, 0}, 0},
		{"One", [4]byte{0, 0, 0, 1}, 1},
		{"Max value", [4]byte{255, 255, 255, 255}, 0xFFFFFFFF},
		{"Mixed bytes", [4]byte{0x01, 0x02, 0x03, 0x04}, 0x01020304},
		{"Little endian representation", [4]byte{0x00, 0x01, 0x00, 0x00}, 0x00010000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesToUint32(tt.input)
			if result != tt.expected {
				t.Errorf("bytesToUint32(%v) = %#x, want %#x", tt.input, result, tt.expected)
			}
		})
	}
}
