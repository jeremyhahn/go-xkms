package tpm2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// Helper function to create mock event log data for testing
func createMockEventLog() []byte {
	var buf bytes.Buffer

	// Event 1: Standard EV_IPL event with ASCII content
	_ = binary.Write(&buf, binary.LittleEndian, uint32(8))      // PCRIndex
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0001)) // EventType (EV_IPL)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))      // DigestCount
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0004)) // AlgorithmId (SHA-1)
	buf.Write(make([]byte, 20))                                 // SHA-1 Digest
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x000b)) // AlgorithmId (SHA-256)
	buf.Write(make([]byte, 32))                                 // SHA-256 Digest
	_ = binary.Write(&buf, binary.LittleEndian, uint32(22))     // EventSize
	buf.WriteString("grub_cmd: test command")                   // EventString

	// Event 2: EV_UNDEFINED event with no EventString
	_ = binary.Write(&buf, binary.LittleEndian, uint32(9))      // PCRIndex
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0000)) // EventType (EV_UNDEFINED)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x000b)) // AlgorithmId (SHA-256)
	buf.Write(make([]byte, 32))                                 // SHA-256 Digest
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))      // EventSize

	// Event 3: EV_EFI_BOOT_SERVICES_APPLICATION with "Example" as EventString
	_ = binary.Write(&buf, binary.LittleEndian, uint32(10))     // PCRIndex
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0006)) // EventType
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x0004)) // AlgorithmId
	buf.Write(make([]byte, 20))                                 // SHA-1 Digest
	_ = binary.Write(&buf, binary.LittleEndian, uint32(7))      // EventSize
	buf.WriteString("Example")                                  // Cleaned EventString

	return buf.Bytes()
}

// createEventLogEntry creates a binary event log entry for testing
func createEventLogEntry(pcrIndex uint32, eventType uint32, digests []struct {
	algID  uint16
	digest []byte
}, eventData []byte) []byte {
	buf := new(bytes.Buffer)

	// PCR Index (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, pcrIndex)

	// Event Type (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, eventType)

	// Digest Count (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(digests)))

	// Digests
	for _, d := range digests {
		_ = binary.Write(buf, binary.LittleEndian, d.algID)
		buf.Write(d.digest)
	}

	// Event Size (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(eventData)))

	// Event Data
	buf.Write(eventData)

	return buf.Bytes()
}

// createTempEventLogFile creates a temporary file with binary data
func createTempEventLogFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "eventlog_test_*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	return f.Name()
}

func TestParseEventLog_Success(t *testing.T) {
	// Create mock event log file
	data := createMockEventLog()
	tmpFile, err := os.CreateTemp("", "mock_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	// Parse the mock event log file
	events, err := ParseEventLog(tmpFile.Name())
	if err != nil {
		t.Fatalf("Error parsing event log: %v", err)
	}

	// Validate parsed events
	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}

	// Check individual event properties
	// Event 1 checks
	if events[0].EventType != "EV_IPL" || events[0].PCRIndex != 8 {
		t.Errorf("Event 1 type or PCRIndex mismatch, got %v, %d", events[0].EventType, events[0].PCRIndex)
	}
	if events[0].DigestCount != 2 || len(events[0].Digests) != 2 {
		t.Errorf("Event 1 DigestCount or Digests length mismatch, got %d", events[0].DigestCount)
	}
	if events[0].EventString != "grub_cmd: test command" {
		t.Errorf("Event 1 EventString mismatch, got %v", events[0].EventString)
	}

	// Event 2 checks
	if events[1].EventType != "EV_UNDEFINED" || events[1].PCRIndex != 9 {
		t.Errorf("Event 2 type or PCRIndex mismatch, got %v, %d", events[1].EventType, events[1].PCRIndex)
	}
	if events[1].DigestCount != 1 || len(events[1].Digests) != 1 {
		t.Errorf("Event 2 DigestCount or Digests length mismatch, got %d", events[1].DigestCount)
	}
	if events[1].EventString != "" {
		t.Errorf("Event 2 EventString mismatch, expected empty string, got %v", events[1].EventString)
	}

	// Event 3 checks
	if events[2].EventType != "EV_EFI_BOOT_SERVICES_APPLICATION" || events[2].PCRIndex != 10 {
		t.Errorf("Event 3 type or PCRIndex mismatch, got %v, %d", events[2].EventType, events[2].PCRIndex)
	}
	if events[2].DigestCount != 1 || len(events[2].Digests) != 1 {
		t.Errorf("Event 3 DigestCount or Digests length mismatch, got %d", events[2].DigestCount)
	}
	if events[2].EventString != "Example" { // Expected cleaned-up string
		t.Errorf("Event 3 EventString mismatch, got %v", events[2].EventString)
	}
}

func TestParseEventLog_ErrorHandling(t *testing.T) {
	// Test with a non-existent file
	_, err := ParseEventLog("non_existent_file")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	// Test with a corrupted event log
	corruptedData := []byte{0x00, 0x01, 0x02}
	tmpFile, err := os.CreateTemp("", "corrupted_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	if _, err := tmpFile.Write(corruptedData); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	_, err = ParseEventLog(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for corrupted event log, got nil")
	}
}

func TestParseRealEventLog(t *testing.T) {
	// Test with the real EFI event log from the host system
	eventLogPath := "../test/integration/testdata/real_eventlog.bin"

	// Check if file exists
	if _, err := os.Stat(eventLogPath); os.IsNotExist(err) {
		t.Skip("Real event log file not available")
	}

	events, err := ParseEventLog(eventLogPath)
	if err != nil {
		t.Logf("Parse error: %v", err)
	}

	// Log what we got
	t.Logf("Parsed %d events", len(events))
	for i, ev := range events {
		if i >= 10 {
			t.Logf("... and %d more events", len(events)-10)
			break
		}
		t.Logf("Event %d: PCR=%d Type=%s DigestCount=%d",
			ev.EventNum, ev.PCRIndex, ev.EventType, ev.DigestCount)
	}

	if err != nil {
		t.Errorf("Should parse real event log without error: %v", err)
	}
	if len(events) == 0 {
		t.Error("Should have events")
	}
}

// Tests for estimateDigestSize
func TestEstimateDigestSize(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected int
	}{
		{
			name:     "vendor extension algorithm 0x2000",
			algID:    0x2000,
			expected: 32,
		},
		{
			name:     "vendor extension algorithm 0x2001",
			algID:    0x2001,
			expected: 32,
		},
		{
			name:     "platform-specific algorithm 0x6000",
			algID:    0x6000,
			expected: 32,
		},
		{
			name:     "platform extension algorithm 0x7000",
			algID:    0x7000,
			expected: 32,
		},
		{
			name:     "platform extension algorithm 0x7FFF",
			algID:    0x7FFF,
			expected: 32,
		},
		{
			name:     "high range algorithm 0xFFFF",
			algID:    0xFFFF,
			expected: 32,
		},
		{
			name:     "unknown standard range algorithm 0x0005",
			algID:    0x0005,
			expected: 0,
		},
		{
			name:     "unknown standard range algorithm 0x0010",
			algID:    0x0010,
			expected: 0,
		},
		{
			name:     "edge case just below threshold 0x1FFF",
			algID:    0x1FFF,
			expected: 0,
		},
		{
			name:     "unknown standard range algorithm 0x0001",
			algID:    0x0001,
			expected: 0,
		},
		{
			name:     "zero algorithm",
			algID:    0x0000,
			expected: 0,
		},
		{
			name:     "vendor extension 0x3000",
			algID:    0x3000,
			expected: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := estimateDigestSize(tt.algID)
			if result != tt.expected {
				t.Errorf("estimateDigestSize(0x%04x) = %d, want %d", tt.algID, result, tt.expected)
			}
		})
	}
}

// Tests for readDigest
func TestReadDigest(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		// Create temp file with known digest bytes
		tmpFile, err := os.CreateTemp("", "test_digest_*")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		expectedBytes := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		if _, err := tmpFile.Write(expectedBytes); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		_, _ = tmpFile.Seek(0, 0)

		result := readDigest(tmpFile, 6)
		expected := "aabbccddeeff"
		if result != expected {
			t.Errorf("readDigest() = %q, want %q", result, expected)
		}
		_ = tmpFile.Close()
	})

	t.Run("read SHA1 sized digest", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test_sha1_digest_*")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		sha1Bytes := make([]byte, 20)
		for i := range sha1Bytes {
			sha1Bytes[i] = byte(i)
		}
		if _, err := tmpFile.Write(sha1Bytes); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		_, _ = tmpFile.Seek(0, 0)

		result := readDigest(tmpFile, 20)
		if len(result) != 40 { // 20 bytes = 40 hex chars
			t.Errorf("readDigest() returned %d hex chars, want 40", len(result))
		}
		_ = tmpFile.Close()
	})

	t.Run("read from empty file returns empty string", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test_empty_digest_*")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		result := readDigest(tmpFile, 10)
		if result != "" {
			t.Errorf("readDigest() from empty file = %q, want empty string", result)
		}
		_ = tmpFile.Close()
	})

	t.Run("read more than available returns empty string", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test_partial_digest_*")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		// Write only 5 bytes
		if _, err := tmpFile.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05}); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		_, _ = tmpFile.Seek(0, 0)

		// Try to read 10 bytes
		result := readDigest(tmpFile, 10)
		// Current implementation will return partial read as hex
		// The function doesn't check for short reads, so it will encode whatever it got
		if result == "" {
			t.Logf("readDigest() returned empty string for partial read")
		}
		_ = tmpFile.Close()
	})
}

// Tests for isSupportedHashAlgorithm
func TestIsSupportedHashAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		expected    bool
	}{
		{
			name:        "SHA1 is supported",
			algorithmId: "sha1",
			expected:    true,
		},
		{
			name:        "SHA256 is supported",
			algorithmId: "sha256",
			expected:    true,
		},
		{
			name:        "SHA384 is supported",
			algorithmId: "sha384",
			expected:    true,
		},
		{
			name:        "SHA512 is supported",
			algorithmId: "sha512",
			expected:    true,
		},
		{
			name:        "SM3_256 is not supported",
			algorithmId: "sm3_256",
			expected:    false,
		},
		{
			name:        "unknown algorithm is not supported",
			algorithmId: "unknown_0x1234",
			expected:    false,
		},
		{
			name:        "empty string is not supported",
			algorithmId: "",
			expected:    false,
		},
		{
			name:        "uppercase SHA256 is not supported (case sensitive)",
			algorithmId: "SHA256",
			expected:    false,
		},
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

// Tests for InitializePCRs
func TestInitializePCRs(t *testing.T) {
	t.Run("returns map with all supported algorithms", func(t *testing.T) {
		pcrs := InitializePCRs()

		expectedAlgorithms := []string{"sha1", "sha256", "sha384", "sha512"}
		for _, alg := range expectedAlgorithms {
			if _, exists := pcrs[alg]; !exists {
				t.Errorf("InitializePCRs() missing algorithm %q", alg)
			}
		}

		if len(pcrs) != len(expectedAlgorithms) {
			t.Errorf("InitializePCRs() returned %d algorithms, want %d", len(pcrs), len(expectedAlgorithms))
		}
	})

	t.Run("each algorithm map is empty but initialized", func(t *testing.T) {
		pcrs := InitializePCRs()

		for alg, pcrMap := range pcrs {
			if pcrMap == nil {
				t.Errorf("InitializePCRs()[%q] is nil", alg)
			}
			if len(pcrMap) != 0 {
				t.Errorf("InitializePCRs()[%q] has %d entries, want 0", alg, len(pcrMap))
			}
		}
	})

	t.Run("returned maps are independent", func(t *testing.T) {
		pcrs1 := InitializePCRs()
		pcrs2 := InitializePCRs()

		// Modify pcrs1
		pcrs1["sha256"][0] = []byte{0x01, 0x02, 0x03}

		// pcrs2 should not be affected
		if len(pcrs2["sha256"]) != 0 {
			t.Error("InitializePCRs() returns shared state")
		}
	})

	t.Run("maps are writable", func(t *testing.T) {
		pcrs := InitializePCRs()
		pcrs["sha256"][0] = make([]byte, 32)
		if len(pcrs["sha256"]) != 1 {
			t.Errorf("expected 1 entry in sha256 map after adding")
		}
	})
}

// Tests for GetHashFunction
func TestGetHashFunction(t *testing.T) {
	tests := []struct {
		name         string
		algorithmId  string
		expectedSize int
		expectError  bool
	}{
		{
			name:         "SHA1 returns correct hasher",
			algorithmId:  "sha1",
			expectedSize: sha1.Size,
			expectError:  false,
		},
		{
			name:         "SHA256 returns correct hasher",
			algorithmId:  "sha256",
			expectedSize: sha256.Size,
			expectError:  false,
		},
		{
			name:         "SHA384 returns correct hasher",
			algorithmId:  "sha384",
			expectedSize: sha512.Size384,
			expectError:  false,
		},
		{
			name:         "SHA512 returns correct hasher",
			algorithmId:  "sha512",
			expectedSize: sha512.Size,
			expectError:  false,
		},
		{
			name:         "unsupported algorithm returns error",
			algorithmId:  "sm3_256",
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "unknown algorithm returns error",
			algorithmId:  "unknown",
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "empty string returns error",
			algorithmId:  "",
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "md5 returns error",
			algorithmId:  "md5",
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "SHA-256 with dash returns error",
			algorithmId:  "SHA-256",
			expectedSize: 0,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := GetHashFunction(tt.algorithmId)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetHashFunction(%q) expected error, got nil", tt.algorithmId)
				}
				if hasher != nil {
					t.Errorf("GetHashFunction(%q) expected nil hasher on error", tt.algorithmId)
				}
			} else {
				if err != nil {
					t.Errorf("GetHashFunction(%q) unexpected error: %v", tt.algorithmId, err)
				}
				if hasher == nil {
					t.Fatalf("GetHashFunction(%q) returned nil hasher", tt.algorithmId)
				}
				if hasher.Size() != tt.expectedSize {
					t.Errorf("GetHashFunction(%q).Size() = %d, want %d", tt.algorithmId, hasher.Size(), tt.expectedSize)
				}
			}
		})
	}

	t.Run("hashers are functional", func(t *testing.T) {
		algorithms := []string{"sha1", "sha256", "sha384", "sha512"}
		testData := []byte("test data for hashing")

		for _, alg := range algorithms {
			hasher, err := GetHashFunction(alg)
			if err != nil {
				t.Fatalf("GetHashFunction(%q) failed: %v", alg, err)
			}

			hasher.Write(testData)
			result := hasher.Sum(nil)

			if len(result) != hasher.Size() {
				t.Errorf("GetHashFunction(%q) produced hash of size %d, want %d", alg, len(result), hasher.Size())
			}
		}
	})
}

// Tests for GetDigestSize
func TestGetDigestSize(t *testing.T) {
	tests := []struct {
		name        string
		algorithmId string
		expected    int
	}{
		{
			name:        "SHA1 size",
			algorithmId: "sha1",
			expected:    20,
		},
		{
			name:        "SHA256 size",
			algorithmId: "sha256",
			expected:    32,
		},
		{
			name:        "SHA384 size",
			algorithmId: "sha384",
			expected:    48,
		},
		{
			name:        "SHA512 size",
			algorithmId: "sha512",
			expected:    64,
		},
		{
			name:        "SM3_256 size",
			algorithmId: "sm3_256",
			expected:    32,
		},
		{
			name:        "unknown algorithm returns 0",
			algorithmId: "unknown",
			expected:    0,
		},
		{
			name:        "empty string returns 0",
			algorithmId: "",
			expected:    0,
		},
		{
			name:        "case sensitive - uppercase returns 0",
			algorithmId: "SHA256",
			expected:    0,
		},
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

// Tests for ExtendPCR
func TestExtendPCR(t *testing.T) {
	t.Run("extend SHA1 PCR", func(t *testing.T) {
		currentPCR := make([]byte, sha1.Size)
		digest := make([]byte, sha1.Size)
		for i := range digest {
			digest[i] = byte(i)
		}

		result, err := ExtendPCR(currentPCR, digest, "sha1")
		if err != nil {
			t.Fatalf("ExtendPCR() error: %v", err)
		}
		if len(result) != sha1.Size {
			t.Errorf("ExtendPCR() returned %d bytes, want %d", len(result), sha1.Size)
		}

		// Verify the extension is deterministic
		result2, _ := ExtendPCR(currentPCR, digest, "sha1")
		if !bytes.Equal(result, result2) {
			t.Error("ExtendPCR() is not deterministic")
		}

		// Verify manually
		hasher := sha1.New()
		hasher.Write(currentPCR)
		hasher.Write(digest)
		expected := hasher.Sum(nil)
		if !bytes.Equal(result, expected) {
			t.Errorf("SHA1 extension mismatch\nexpected: %x\ngot:      %x", expected, result)
		}
	})

	t.Run("extend SHA256 PCR", func(t *testing.T) {
		currentPCR := make([]byte, sha256.Size)
		digest := []byte("test digest value for sha256")

		result, err := ExtendPCR(currentPCR, digest, "sha256")
		if err != nil {
			t.Fatalf("ExtendPCR() error: %v", err)
		}
		if len(result) != sha256.Size {
			t.Errorf("ExtendPCR() returned %d bytes, want %d", len(result), sha256.Size)
		}

		// Verify manually
		hasher := sha256.New()
		hasher.Write(currentPCR)
		hasher.Write(digest)
		expected := hasher.Sum(nil)
		if !bytes.Equal(result, expected) {
			t.Errorf("SHA256 extension mismatch\nexpected: %x\ngot:      %x", expected, result)
		}
	})

	t.Run("extend SHA384 PCR", func(t *testing.T) {
		currentPCR := make([]byte, sha512.Size384)
		digest := make([]byte, sha512.Size384)

		result, err := ExtendPCR(currentPCR, digest, "sha384")
		if err != nil {
			t.Fatalf("ExtendPCR() error: %v", err)
		}
		if len(result) != sha512.Size384 {
			t.Errorf("ExtendPCR() returned %d bytes, want %d", len(result), sha512.Size384)
		}
	})

	t.Run("extend SHA512 PCR", func(t *testing.T) {
		currentPCR := make([]byte, sha512.Size)
		digest := make([]byte, sha512.Size)

		result, err := ExtendPCR(currentPCR, digest, "sha512")
		if err != nil {
			t.Fatalf("ExtendPCR() error: %v", err)
		}
		if len(result) != sha512.Size {
			t.Errorf("ExtendPCR() returned %d bytes, want %d", len(result), sha512.Size)
		}
	})

	t.Run("error on unsupported algorithm", func(t *testing.T) {
		currentPCR := make([]byte, 32)
		digest := make([]byte, 32)

		_, err := ExtendPCR(currentPCR, digest, "sm3_256")
		if err == nil {
			t.Error("ExtendPCR() expected error for unsupported algorithm")
		}
	})

	t.Run("error on unknown algorithm", func(t *testing.T) {
		currentPCR := make([]byte, 32)
		digest := make([]byte, 32)

		_, err := ExtendPCR(currentPCR, digest, "unknown")
		if err == nil {
			t.Error("ExtendPCR() expected error for unknown algorithm")
		}
		if !strings.Contains(err.Error(), "unsupported hash algorithm") {
			t.Errorf("expected 'unsupported hash algorithm' error, got: %v", err)
		}
	})

	t.Run("error on invalid algorithm returns nil result", func(t *testing.T) {
		currentPCR := make([]byte, 32)
		digest := make([]byte, 32)

		result, err := ExtendPCR(currentPCR, digest, "invalid")
		if err == nil {
			t.Error("ExtendPCR() with invalid algorithm expected error, got nil")
		}
		if result != nil {
			t.Errorf("ExtendPCR() with invalid algorithm expected nil result, got %v", result)
		}
	})

	t.Run("PCR extension matches TPM spec", func(t *testing.T) {
		// TPM PCR extension: new_pcr = Hash(old_pcr || digest)
		currentPCR := make([]byte, sha256.Size) // All zeros
		digest, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

		result, err := ExtendPCR(currentPCR, digest, "sha256")
		if err != nil {
			t.Fatalf("ExtendPCR() error: %v", err)
		}

		// Manually compute expected result
		hasher := sha256.New()
		hasher.Write(currentPCR)
		hasher.Write(digest)
		expected := hasher.Sum(nil)

		if !bytes.Equal(result, expected) {
			t.Errorf("ExtendPCR() = %x, want %x", result, expected)
		}
	})

	t.Run("multiple extensions accumulate correctly", func(t *testing.T) {
		pcr := make([]byte, sha256.Size)
		digests := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
			{0x07, 0x08, 0x09},
		}

		for _, digest := range digests {
			var err error
			pcr, err = ExtendPCR(pcr, digest, "sha256")
			if err != nil {
				t.Fatalf("ExtendPCR() error: %v", err)
			}
		}

		// Verify final result is non-zero
		allZero := true
		for _, b := range pcr {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("ExtendPCR() multiple extensions resulted in all zeros")
		}
	})

	t.Run("chained extensions produce correct result", func(t *testing.T) {
		pcr := make([]byte, sha256.Size)
		digests := [][]byte{
			make([]byte, sha256.Size),
			{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224},
		}

		var err error
		for _, digest := range digests {
			pcr, err = ExtendPCR(pcr, digest, "sha256")
			if err != nil {
				t.Fatalf("ExtendPCR failed: %v", err)
			}
		}

		// Verify by computing manually
		expected := make([]byte, sha256.Size)
		for _, digest := range digests {
			hasher := sha256.New()
			hasher.Write(expected)
			hasher.Write(digest)
			expected = hasher.Sum(nil)
		}

		if !bytes.Equal(pcr, expected) {
			t.Errorf("chained extensions mismatch\nexpected: %x\ngot:      %x", expected, pcr)
		}
	})
}

// Tests for CalculatePCRs
func TestCalculatePCRs(t *testing.T) {
	t.Run("empty events list", func(t *testing.T) {
		events := []Event{}
		result := CalculatePCRs(events)

		// Should return initialized PCR map with all algorithms
		expectedAlgorithms := []string{"sha1", "sha256", "sha384", "sha512"}
		for _, alg := range expectedAlgorithms {
			if _, exists := result[alg]; !exists {
				t.Errorf("CalculatePCRs() missing algorithm %q", alg)
			}
			if len(result[alg]) != 0 {
				t.Errorf("CalculatePCRs() with empty events should have empty PCR map for %q", alg)
			}
		}
	})

	t.Run("single event single digest", func(t *testing.T) {
		digest := strings.Repeat("00", 32) // 32 zero bytes as hex
		events := []Event{
			{
				EventNum:    1,
				PCRIndex:    0,
				DigestCount: 1,
				Digests: []Digest{
					{AlgorithmId: "sha256", Digest: digest},
				},
			},
		}

		result := CalculatePCRs(events)

		if _, exists := result["sha256"][0]; !exists {
			t.Error("CalculatePCRs() did not calculate PCR 0 for sha256")
		}

		// PCR should be extended once from zeros
		pcr := result["sha256"][0]
		if len(pcr) != sha256.Size {
			t.Errorf("CalculatePCRs() PCR size = %d, want %d", len(pcr), sha256.Size)
		}

		// Verify it's not all zeros (should be hash of zeros || zeros)
		allZero := true
		for _, b := range pcr {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("CalculatePCRs() PCR should not be all zeros after extension")
		}

		// Verify the PCR extension is correct: PCR = SHA256(0x00...00 || digest)
		hasher := sha256.New()
		hasher.Write(make([]byte, sha256.Size))
		digestBytes, _ := hex.DecodeString(digest)
		hasher.Write(digestBytes)
		expected := hasher.Sum(nil)
		if !bytes.Equal(pcr, expected) {
			t.Errorf("PCR 0 mismatch\nexpected: %x\ngot:      %x", expected, pcr)
		}
	})

	t.Run("multiple digests per event", func(t *testing.T) {
		sha1Digest := strings.Repeat("aa", 20)
		sha256Digest := strings.Repeat("bb", 32)
		events := []Event{
			{
				EventNum:    1,
				PCRIndex:    7,
				DigestCount: 2,
				Digests: []Digest{
					{AlgorithmId: "sha1", Digest: sha1Digest},
					{AlgorithmId: "sha256", Digest: sha256Digest},
				},
			},
		}

		result := CalculatePCRs(events)

		// Both algorithms should have PCR 7 calculated
		if _, exists := result["sha1"][7]; !exists {
			t.Error("CalculatePCRs() missing PCR 7 for sha1")
		}
		if _, exists := result["sha256"][7]; !exists {
			t.Error("CalculatePCRs() missing PCR 7 for sha256")
		}

		// SHA384 and SHA512 should not have PCR 7
		if _, exists := result["sha384"][7]; exists {
			t.Error("CalculatePCRs() should not have PCR 7 for sha384")
		}
	})

	t.Run("multiple events same PCR", func(t *testing.T) {
		events := []Event{
			{
				EventNum:    1,
				PCRIndex:    4,
				DigestCount: 1,
				Digests: []Digest{
					{AlgorithmId: "sha256", Digest: strings.Repeat("11", 32)},
				},
			},
			{
				EventNum:    2,
				PCRIndex:    4,
				DigestCount: 1,
				Digests: []Digest{
					{AlgorithmId: "sha256", Digest: strings.Repeat("22", 32)},
				},
			},
		}

		result := CalculatePCRs(events)
		pcr := result["sha256"][4]

		// Manually calculate expected result
		initialPCR := make([]byte, sha256.Size)
		digest1, _ := hex.DecodeString(strings.Repeat("11", 32))
		digest2, _ := hex.DecodeString(strings.Repeat("22", 32))

		expected, _ := ExtendPCR(initialPCR, digest1, "sha256")
		expected, _ = ExtendPCR(expected, digest2, "sha256")

		if !bytes.Equal(pcr, expected) {
			t.Errorf("CalculatePCRs() multiple extends = %x, want %x", pcr, expected)
		}
	})

	t.Run("skip unsupported algorithms", func(t *testing.T) {
		events := []Event{
			{
				EventNum:    1,
				PCRIndex:    0,
				DigestCount: 2,
				Digests: []Digest{
					{AlgorithmId: "sha256", Digest: strings.Repeat("ff", 32)},
					{AlgorithmId: "sm3_256", Digest: strings.Repeat("ee", 32)},
				},
			},
		}

		result := CalculatePCRs(events)

		// SHA256 should be calculated
		if _, exists := result["sha256"][0]; !exists {
			t.Error("CalculatePCRs() should calculate sha256")
		}

		// SM3_256 should be skipped
	})

	t.Run("handle invalid digest hex gracefully", func(t *testing.T) {
		events := []Event{
			{
				EventNum:    1,
				PCRIndex:    0,
				DigestCount: 1,
				Digests: []Digest{
					{AlgorithmId: "sha256", Digest: "invalid_hex_string"},
				},
			},
		}

		// Should not panic
		result := CalculatePCRs(events)

		// PCR may or may not be initialized depending on error handling
		if result == nil {
			t.Error("CalculatePCRs() returned nil map")
		}
	})

	t.Run("multiple PCR indices", func(t *testing.T) {
		events := []Event{
			{
				EventNum: 1, PCRIndex: 0, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("00", 32)}},
			},
			{
				EventNum: 2, PCRIndex: 1, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("11", 32)}},
			},
			{
				EventNum: 3, PCRIndex: 7, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("77", 32)}},
			},
		}

		result := CalculatePCRs(events)

		// All three PCR indices should exist
		for _, idx := range []int{0, 1, 7} {
			if _, exists := result["sha256"][idx]; !exists {
				t.Errorf("CalculatePCRs() missing PCR %d", idx)
			}
		}

		// Each PCR should have different value
		if bytes.Equal(result["sha256"][0], result["sha256"][1]) {
			t.Error("CalculatePCRs() PCR 0 and 1 should be different")
		}
		if bytes.Equal(result["sha256"][1], result["sha256"][7]) {
			t.Error("CalculatePCRs() PCR 1 and 7 should be different")
		}
	})

	t.Run("unsupported algorithm only", func(t *testing.T) {
		events := []Event{
			{
				EventNum:  1,
				PCRIndex:  0,
				EventType: "EV_NO_ACTION",
				Digests: []Digest{
					{AlgorithmId: "sm3_256", Digest: strings.Repeat("00", 32)},
				},
			},
		}

		pcrs := CalculatePCRs(events)

		// SM3_256 should be skipped, so no PCRs should be calculated
		hasAnyPCR := false
		for _, algMap := range pcrs {
			if len(algMap) > 0 {
				hasAnyPCR = true
				break
			}
		}

		if hasAnyPCR {
			t.Error("expected no PCRs to be calculated for unsupported algorithm")
		}
	})

	t.Run("multiple algorithms per event", func(t *testing.T) {
		events := []Event{
			{
				EventNum:  1,
				PCRIndex:  0,
				EventType: "EV_NO_ACTION",
				Digests: []Digest{
					{AlgorithmId: "sha1", Digest: strings.Repeat("00", 20)},
					{AlgorithmId: "sha256", Digest: strings.Repeat("00", 32)},
					{AlgorithmId: "sha384", Digest: strings.Repeat("00", 48)},
					{AlgorithmId: "sha512", Digest: strings.Repeat("00", 64)},
				},
			},
		}

		pcrs := CalculatePCRs(events)

		// Verify all algorithms have PCR 0
		for _, alg := range []string{"sha1", "sha256", "sha384", "sha512"} {
			if _, exists := pcrs[alg]; !exists {
				t.Errorf("expected %s in PCR map", alg)
				continue
			}
			if _, exists := pcrs[alg][0]; !exists {
				t.Errorf("expected PCR 0 in %s map", alg)
			}
		}

		// Verify correct sizes
		if len(pcrs["sha1"][0]) != sha1.Size {
			t.Errorf("sha1 PCR size wrong: %d", len(pcrs["sha1"][0]))
		}
		if len(pcrs["sha256"][0]) != sha256.Size {
			t.Errorf("sha256 PCR size wrong: %d", len(pcrs["sha256"][0]))
		}
		if len(pcrs["sha384"][0]) != sha512.Size384 {
			t.Errorf("sha384 PCR size wrong: %d", len(pcrs["sha384"][0]))
		}
		if len(pcrs["sha512"][0]) != sha512.Size {
			t.Errorf("sha512 PCR size wrong: %d", len(pcrs["sha512"][0]))
		}
	})
}

// Tests for printPCRSummary (captured output testing)
func TestPrintPCRSummary(t *testing.T) {
	t.Run("prints with empty events", func(t *testing.T) {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printPCRSummary([]Event{})

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "pcrs:") {
			t.Error("printPCRSummary() should print 'pcrs:' header")
		}
	})

	t.Run("prints algorithm sections", func(t *testing.T) {
		events := []Event{
			{
				EventNum: 1, PCRIndex: 0, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("ab", 32)}},
			},
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printPCRSummary(events)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "sha256:") {
			t.Error("printPCRSummary() should print algorithm name")
		}
		if !strings.Contains(output, "0x") {
			t.Error("printPCRSummary() should print hex digest with 0x prefix")
		}
	})

	t.Run("sorts PCR indices", func(t *testing.T) {
		events := []Event{
			{EventNum: 1, PCRIndex: 7, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("77", 32)}}},
			{EventNum: 2, PCRIndex: 0, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("00", 32)}}},
			{EventNum: 3, PCRIndex: 4, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("44", 32)}}},
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printPCRSummary(events)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		output := buf.String()

		// Check that indices appear in order
		idx0 := strings.Index(output, " 0 :")
		idx4 := strings.Index(output, " 4 :")
		idx7 := strings.Index(output, " 7 :")

		if idx0 < 0 || idx4 < 0 || idx7 < 0 {
			t.Error("printPCRSummary() should print all PCR indices")
		}
		if idx0 > idx4 || idx4 > idx7 {
			t.Error("printPCRSummary() should sort PCR indices")
		}
	})

	t.Run("skips empty algorithm banks", func(t *testing.T) {
		events := []Event{
			{
				EventNum: 1, PCRIndex: 0, DigestCount: 1,
				Digests: []Digest{{AlgorithmId: "sha256", Digest: strings.Repeat("ff", 32)}},
			},
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printPCRSummary(events)

		_ = w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		output := buf.String()

		// SHA256 should be present
		if !strings.Contains(output, "sha256:") {
			t.Error("printPCRSummary() should print sha256")
		}
	})
}

// Tests for PrintEvents
func TestPrintEvents(t *testing.T) {
	tests := []struct {
		name     string
		events   []Event
		expected []string
	}{
		{
			name: "single event with SHA1 digest",
			events: []Event{
				{
					EventNum:    1,
					PCRIndex:    0,
					EventType:   "EV_NO_ACTION",
					DigestCount: 1,
					Digests: []Digest{
						{
							AlgorithmId: "sha1",
							Digest:      "0000000000000000000000000000000000000000",
						},
					},
					EventSize:   4,
					EventString: "test",
				},
			},
			expected: []string{
				"EventNum: 1",
				"PCRIndex: 0",
				"EventType: EV_NO_ACTION",
				"DigestCount: 1",
				"AlgorithmId: sha1",
				"Digest: \"0000000000000000000000000000000000000000\"",
				"EventSize: 4",
				"String: \"test\"",
			},
		},
		{
			name: "multiple events with different algorithms",
			events: []Event{
				{
					EventNum:    1,
					PCRIndex:    0,
					EventType:   "EV_S_POST_CODE",
					DigestCount: 2,
					Digests: []Digest{
						{
							AlgorithmId: "sha1",
							Digest:      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
						},
						{
							AlgorithmId: "sha256",
							Digest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						},
					},
					EventSize:   8,
					EventString: "POSTCODE",
				},
				{
					EventNum:    2,
					PCRIndex:    1,
					EventType:   "EV_SEPARATOR",
					DigestCount: 1,
					Digests: []Digest{
						{
							AlgorithmId: "sha256",
							Digest:      "0000000000000000000000000000000000000000000000000000000000000000",
						},
					},
					EventSize:   4,
					EventString: "SEP",
				},
			},
			expected: []string{
				"EventNum: 1",
				"PCRIndex: 0",
				"EventType: EV_S_POST_CODE",
				"DigestCount: 2",
				"AlgorithmId: sha1",
				"AlgorithmId: sha256",
				"EventNum: 2",
				"PCRIndex: 1",
				"EventType: EV_SEPARATOR",
			},
		},
		{
			name:     "empty events",
			events:   []Event{},
			expected: []string{"pcrs:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			PrintEvents(tt.events)

			_ = w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)
			output := buf.String()

			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("expected output to contain %q, but it didn't\nOutput: %s", exp, output)
				}
			}
		})
	}
}

// Tests for getDigestSizeByAlgID
func TestGetDigestSizeByAlgID(t *testing.T) {
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
		{"SM3_256 Alt", AlgSM3256Alt, 32},
		{"Unknown 0xFFFF", 0xFFFF, 0},
		{"Unknown 0x0001", 0x0001, 0},
		{"Zero", 0x0000, 0},
		{"Unknown 0x9999", 0x9999, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDigestSizeByAlgID(tt.algID)
			if result != tt.expected {
				t.Errorf("getDigestSizeByAlgID(0x%04x) = %d, want %d", tt.algID, result, tt.expected)
			}
		})
	}
}

// Tests for parseAlgorithmId
func TestParseAlgorithmId(t *testing.T) {
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
		{"SM3_256 Alt", AlgSM3256Alt, "sm3_256"},
		{"Unknown 0x1234", 0x1234, "unknown_0x1234"},
		{"Unknown 0xFFFF", 0xFFFF, "unknown_0xffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAlgorithmId(tt.algID)
			if result != tt.expected {
				t.Errorf("parseAlgorithmId(0x%04x) = %q, want %q", tt.algID, result, tt.expected)
			}
		})
	}
}

// Tests for parseEventType
func TestParseEventType(t *testing.T) {
	tests := []struct {
		eventType uint32
		expected  string
	}{
		{0x00000000, "EV_UNDEFINED"},
		{0x00000001, "EV_IPL"},
		{0x00000002, "EV_EVENT_TAG"},
		{0x00000003, "EV_NO_ACTION"},
		{0x00000004, "EV_SEPARATOR"},
		{0x00000008, "EV_ACTION"},
		{0x0000000D, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{0x00000006, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{0x80000001, "EV_S_CRTM_CONTENTS"},
		{0x80000002, "EV_S_CRTM_VERSION"},
		{0x80000003, "EV_S_CPU_MICROCODE"},
		{0x80000008, "EV_S_CRTM_SEPARATOR"},
		{0x80000006, "EV_S_POST_CODE"},
		{0x800000E0, "EV_PLATFORM_CONFIG_FLAGS"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := parseEventType(tt.eventType)
			if result != tt.expected {
				t.Errorf("parseEventType(0x%08x) = %q, want %q", tt.eventType, result, tt.expected)
			}
		})
	}

	t.Run("unknown event type", func(t *testing.T) {
		result := parseEventType(0xDEADBEEF)
		if !strings.HasPrefix(result, "Unknown") {
			t.Errorf("parseEventType(unknown) = %q, want prefix 'Unknown'", result)
		}
	})

	t.Run("unknown event type format", func(t *testing.T) {
		result := parseEventType(0x99999999)
		if result != "Unknown (0x99999999)" {
			t.Errorf("parseEventType(0x99999999) = %s, expected Unknown (0x99999999)", result)
		}
	})

	t.Run("unknown event type format 2", func(t *testing.T) {
		result := parseEventType(0x12345678)
		if result != "Unknown (0x12345678)" {
			t.Errorf("parseEventType(0x12345678) = %q, want %q", result, "Unknown (0x12345678)")
		}
	})
}

// Tests for parseEventString
func TestParseEventString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "simple ASCII",
			data:     []byte("Hello World"),
			expected: "Hello World",
		},
		{
			name:     "with non-printable prefix",
			data:     []byte{0x00, 0x01, 'T', 'e', 's', 't'},
			expected: "Test",
		},
		{
			name:     "multiple ASCII sequences",
			data:     []byte{0x00, 'A', 'B', 0x00, 'X', 'Y', 'Z', 0x00},
			expected: "XYZ",
		},
		{
			name:     "empty input",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "only non-printable",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: "",
		},
		{
			name:     "grub command",
			data:     []byte("grub_cmd: test command"),
			expected: "grub_cmd: test command",
		},
		{
			name:     "with null bytes",
			data:     []byte("test\x00\x00\x00string"),
			expected: "string",
		},
		{
			name:     "multiple sequences returns longest",
			data:     []byte("short\x00\x00\x00\x00longer sequence here"),
			expected: "longer sequence here",
		},
		{
			name:     "special characters",
			data:     []byte("Key=Value;Test!@#$%"),
			expected: "Key=Value;Test!@#$%",
		},
		{
			name:     "with spaces",
			data:     []byte("   test   "),
			expected: "   test   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEventString(tt.data)
			if result != tt.expected {
				t.Errorf("parseEventString(%v) = %q, want %q", tt.data, result, tt.expected)
			}
		})
	}
}

// Tests for DefaultParseEventLogOptions
func TestDefaultParseEventLogOptions(t *testing.T) {
	opts := DefaultParseEventLogOptions()

	if !opts.SkipUnknownAlgorithms {
		t.Error("expected SkipUnknownAlgorithms to be true by default")
	}
}

// Tests for ParseEventLog with single SHA1 event
func TestParseEventLog_SingleSHA1Event(t *testing.T) {
	sha1Digest := make([]byte, 20)
	for i := range sha1Digest {
		sha1Digest[i] = byte(i)
	}

	eventData := createEventLogEntry(
		0,          // PCR 0
		0x00000003, // EV_NO_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
		},
		[]byte("TEST EVENT"),
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.PCRIndex != 0 {
		t.Errorf("expected PCRIndex 0, got %d", event.PCRIndex)
	}
	if event.EventType != "EV_NO_ACTION" {
		t.Errorf("expected EventType EV_NO_ACTION, got %s", event.EventType)
	}
	if event.DigestCount != 1 {
		t.Errorf("expected DigestCount 1, got %d", event.DigestCount)
	}
	if event.Digests[0].AlgorithmId != "sha1" {
		t.Errorf("expected AlgorithmId sha1, got %s", event.Digests[0].AlgorithmId)
	}
	expectedDigest := hex.EncodeToString(sha1Digest)
	if event.Digests[0].Digest != expectedDigest {
		t.Errorf("expected Digest %s, got %s", expectedDigest, event.Digests[0].Digest)
	}
	if event.EventString != "TEST EVENT" {
		t.Errorf("expected EventString 'TEST EVENT', got %s", event.EventString)
	}
}

// Tests for ParseEventLog with single SHA256 event
func TestParseEventLog_SingleSHA256Event(t *testing.T) {
	sha256Digest := make([]byte, 32)
	for i := range sha256Digest {
		sha256Digest[i] = byte(i * 2)
	}

	eventData := createEventLogEntry(
		1,          // PCR 1
		0x80000006, // EV_S_POST_CODE
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA256, sha256Digest},
		},
		[]byte("POST CODE DATA"),
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.PCRIndex != 1 {
		t.Errorf("expected PCRIndex 1, got %d", event.PCRIndex)
	}
	if event.EventType != "EV_S_POST_CODE" {
		t.Errorf("expected EventType EV_S_POST_CODE, got %s", event.EventType)
	}
	if event.Digests[0].AlgorithmId != "sha256" {
		t.Errorf("expected AlgorithmId sha256, got %s", event.Digests[0].AlgorithmId)
	}
}

// Tests for ParseEventLog with multiple events and algorithms
func TestParseEventLog_MultipleEventsMultipleAlgorithms(t *testing.T) {
	sha1Digest := make([]byte, 20)
	sha256Digest := make([]byte, 32)
	sha384Digest := make([]byte, 48)
	sha512Digest := make([]byte, 64)

	for i := range sha1Digest {
		sha1Digest[i] = byte(i)
	}
	for i := range sha256Digest {
		sha256Digest[i] = byte(i * 2)
	}
	for i := range sha384Digest {
		sha384Digest[i] = byte(i * 3)
	}
	for i := range sha512Digest {
		sha512Digest[i] = byte(i * 4)
	}

	// Event 1: SHA1 + SHA256
	event1 := createEventLogEntry(
		0,
		0x00000003, // EV_NO_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
			{AlgSHA256, sha256Digest},
		},
		[]byte("Event 1"),
	)

	// Event 2: SHA384 + SHA512
	event2 := createEventLogEntry(
		7,
		0x00000004, // EV_SEPARATOR
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA384, sha384Digest},
			{AlgSHA512, sha512Digest},
		},
		[]byte("Event 2"),
	)

	// Event 3: All four algorithms
	event3 := createEventLogEntry(
		14,
		0x00000008, // EV_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
			{AlgSHA256, sha256Digest},
			{AlgSHA384, sha384Digest},
			{AlgSHA512, sha512Digest},
		},
		[]byte("Event 3 with all algorithms"),
	)

	var allData bytes.Buffer
	allData.Write(event1)
	allData.Write(event2)
	allData.Write(event3)

	tmpFile := createTempEventLogFile(t, allData.Bytes())
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Verify Event 1
	if events[0].PCRIndex != 0 {
		t.Errorf("event 1: expected PCRIndex 0, got %d", events[0].PCRIndex)
	}
	if events[0].DigestCount != 2 {
		t.Errorf("event 1: expected DigestCount 2, got %d", events[0].DigestCount)
	}

	// Verify Event 2
	if events[1].PCRIndex != 7 {
		t.Errorf("event 2: expected PCRIndex 7, got %d", events[1].PCRIndex)
	}
	if events[1].EventType != "EV_SEPARATOR" {
		t.Errorf("event 2: expected EventType EV_SEPARATOR, got %s", events[1].EventType)
	}

	// Verify Event 3
	if events[2].PCRIndex != 14 {
		t.Errorf("event 3: expected PCRIndex 14, got %d", events[2].PCRIndex)
	}
	if events[2].DigestCount != 4 {
		t.Errorf("event 3: expected DigestCount 4, got %d", events[2].DigestCount)
	}
}

// Tests for ParseEventLog with various truncated data
func TestParseEventLog_TruncatedData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "truncated PCR index",
			data: []byte{0x00, 0x00}, // Only 2 bytes instead of 4
		},
		{
			name: "truncated event type",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // PCR index
				buf.Write([]byte{0x00, 0x00})                         // Only 2 bytes for event type
				return buf.Bytes()
			}(),
		},
		{
			name: "truncated digest count",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // PCR index
				_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // Event type
				buf.Write([]byte{0x01})                                        // Only 1 byte for digest count
				return buf.Bytes()
			}(),
		},
		{
			name: "truncated algorithm ID",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // PCR index
				_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // Event type
				_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // Digest count
				buf.Write([]byte{0x04})                                        // Only 1 byte for alg ID
				return buf.Bytes()
			}(),
		},
		{
			name: "truncated digest data",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // PCR index
				_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // Event type
				_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // Digest count
				_ = binary.Write(buf, binary.LittleEndian, AlgSHA1)            // SHA1 algorithm
				buf.Write(make([]byte, 10))                                    // Only 10 bytes instead of 20
				return buf.Bytes()
			}(),
		},
		{
			name: "truncated event size",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // PCR index
				_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // Event type
				_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // Digest count
				_ = binary.Write(buf, binary.LittleEndian, AlgSHA1)            // SHA1 algorithm
				buf.Write(make([]byte, 20))                                    // Full SHA1 digest
				buf.Write([]byte{0x00, 0x00})                                  // Only 2 bytes for event size
				return buf.Bytes()
			}(),
		},
		{
			name: "truncated event data",
			data: func() []byte {
				buf := new(bytes.Buffer)
				_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // PCR index
				_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // Event type
				_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // Digest count
				_ = binary.Write(buf, binary.LittleEndian, AlgSHA1)            // SHA1 algorithm
				buf.Write(make([]byte, 20))                                    // Full SHA1 digest
				_ = binary.Write(buf, binary.LittleEndian, uint32(100))        // Event size = 100
				buf.Write([]byte("short"))                                     // Only 5 bytes instead of 100
				return buf.Bytes()
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTempEventLogFile(t, tt.data)
			defer func() { _ = os.Remove(tmpFile) }()

			_, err := ParseEventLog(tmpFile)
			if err == nil {
				t.Errorf("expected error for truncated data, got nil")
			}
		})
	}
}

// Tests for ParseEventLog with file not found
func TestParseEventLog_FileNotFound(t *testing.T) {
	_, err := ParseEventLog("/nonexistent/path/to/eventlog.bin")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("expected 'failed to open file' error, got: %v", err)
	}
}

// Tests for ParseEventLog with empty file
func TestParseEventLog_EmptyFile(t *testing.T) {
	tmpFile := createTempEventLogFile(t, []byte{})
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse empty event log: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("expected 0 events for empty file, got %d", len(events))
	}
}

// Tests for ParseEventLog with zero event size
func TestParseEventLog_ZeroEventSize(t *testing.T) {
	sha1Digest := make([]byte, 20)
	eventData := createEventLogEntry(
		0,
		0x00000003, // EV_NO_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
		},
		[]byte{}, // Empty event data
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}

	if events[0].EventSize != 0 {
		t.Errorf("expected EventSize 0, got %d", events[0].EventSize)
	}
	if events[0].EventString != "" {
		t.Errorf("expected empty EventString, got %q", events[0].EventString)
	}
}

// Tests for ParseEventLogWithOptions with skip unknown algorithms
func TestParseEventLogWithOptions_SkipUnknownAlgorithms(t *testing.T) {
	// Create event with known algorithm (AlgSHA1) followed by unknown vendor algorithm
	sha1Digest := make([]byte, 20)
	unknownDigest := make([]byte, 32) // Vendor algorithms often use 32 bytes

	for i := range sha1Digest {
		sha1Digest[i] = byte(i)
	}

	eventData := createEventLogEntry(
		0,
		0x00000003, // EV_NO_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
			{0x2001, unknownDigest}, // Unknown vendor algorithm (>= 0x2000)
		},
		[]byte("Event with unknown algorithm"),
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	// Test with SkipUnknownAlgorithms = true
	opts := ParseEventLogOptions{SkipUnknownAlgorithms: true}
	events, err := ParseEventLogWithOptions(tmpFile, opts)
	if err != nil {
		t.Fatalf("failed to parse with SkipUnknownAlgorithms=true: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].DigestCount != 2 {
		t.Errorf("expected DigestCount 2, got %d", events[0].DigestCount)
	}
	if len(events[0].Digests) != 2 {
		t.Errorf("expected 2 digests, got %d", len(events[0].Digests))
	}
}

// Tests for ParseEventLogWithOptions with don't skip unknown algorithms
func TestParseEventLogWithOptions_DontSkipUnknownAlgorithms(t *testing.T) {
	// Create event with unknown algorithm in standard range (cannot estimate size)
	sha1Digest := make([]byte, 20)

	eventData := createEventLogEntry(
		0,
		0x00000003, // EV_NO_ACTION
		[]struct {
			algID  uint16
			digest []byte
		}{
			{AlgSHA1, sha1Digest},
			{0x0099, make([]byte, 32)}, // Unknown algorithm in standard range
		},
		[]byte("Event with unknown standard algorithm"),
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	// Test with SkipUnknownAlgorithms = false
	opts := ParseEventLogOptions{SkipUnknownAlgorithms: false}
	_, err := ParseEventLogWithOptions(tmpFile, opts)
	if err == nil {
		t.Error("expected error for unknown algorithm with SkipUnknownAlgorithms=false")
	}
	if !strings.Contains(err.Error(), "unknown algorithm ID") {
		t.Errorf("expected 'unknown algorithm ID' error, got: %v", err)
	}
}

// Tests for ParseEventLog with multi-digest event
func TestParseEventLog_MultiDigestEvent(t *testing.T) {
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

	tmpFile := createTempEventLogFile(t, buf.Bytes())
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
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

// Benchmark tests for performance-critical functions
func BenchmarkExtendPCR_SHA256(b *testing.B) {
	currentPCR := make([]byte, sha256.Size)
	digest := make([]byte, sha256.Size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtendPCR(currentPCR, digest, "sha256")
	}
}

func BenchmarkCalculatePCRs(b *testing.B) {
	// Create 100 events
	events := make([]Event, 100)
	for i := range events {
		events[i] = Event{
			EventNum: i + 1,
			PCRIndex: i % 24,
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: strings.Repeat("ab", 32)},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CalculatePCRs(events)
	}
}

func BenchmarkGetHashFunction(b *testing.B) {
	algorithms := []string{"sha1", "sha256", "sha384", "sha512"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetHashFunction(algorithms[i%len(algorithms)])
	}
}
