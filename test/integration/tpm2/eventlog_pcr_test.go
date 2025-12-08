//go:build integration

package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// createTestEventLog creates a sample event log with various event types and hash algorithms
func createTestEventLog(t *testing.T) string {
	t.Helper()

	var buf bytes.Buffer

	// Event 1: EV_NO_ACTION with SHA1 and SHA256 (PCR 0)
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0003)) // EventType (EV_NO_ACTION)
	binary.Write(&buf, binary.LittleEndian, uint32(2))      // DigestCount

	// SHA1 digest
	binary.Write(&buf, binary.LittleEndian, uint16(0x0004)) // AlgorithmId (SHA-1)
	sha1Hash := sha1.Sum([]byte("event1"))
	buf.Write(sha1Hash[:])

	// SHA256 digest
	binary.Write(&buf, binary.LittleEndian, uint16(0x000b)) // AlgorithmId (SHA-256)
	sha256Hash := sha256.Sum256([]byte("event1"))
	buf.Write(sha256Hash[:])

	eventData1 := []byte("Spec ID Event03\x00\x00")                  // 17 bytes
	binary.Write(&buf, binary.LittleEndian, uint32(len(eventData1))) // EventSize
	buf.Write(eventData1)

	// Event 2: EV_IPL with SHA256 and SHA384 (PCR 8)
	binary.Write(&buf, binary.LittleEndian, uint32(8))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0001)) // EventType (EV_IPL)
	binary.Write(&buf, binary.LittleEndian, uint32(2))      // DigestCount

	// SHA256 digest
	binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
	sha256Hash2 := sha256.Sum256([]byte("grub_cmd"))
	buf.Write(sha256Hash2[:])

	// SHA384 digest
	binary.Write(&buf, binary.LittleEndian, uint16(0x000c)) // AlgorithmId (SHA-384)
	sha384Hash := sha512.Sum384([]byte("grub_cmd"))
	buf.Write(sha384Hash[:])

	binary.Write(&buf, binary.LittleEndian, uint32(22)) // EventSize
	buf.WriteString("grub_cmd: test command")

	// Event 3: EV_SEPARATOR (PCR 7)
	binary.Write(&buf, binary.LittleEndian, uint32(7))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0004)) // EventType (EV_SEPARATOR)
	binary.Write(&buf, binary.LittleEndian, uint32(3))      // DigestCount

	// SHA1
	binary.Write(&buf, binary.LittleEndian, uint16(0x0004))
	separatorHash1 := sha1.Sum(make([]byte, 4))
	buf.Write(separatorHash1[:])

	// SHA256
	binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
	separatorHash256 := sha256.Sum256(make([]byte, 4))
	buf.Write(separatorHash256[:])

	// SHA512
	binary.Write(&buf, binary.LittleEndian, uint16(0x000d)) // AlgorithmId (SHA-512)
	separatorHash512 := sha512.Sum512(make([]byte, 4))
	buf.Write(separatorHash512[:])

	binary.Write(&buf, binary.LittleEndian, uint32(4)) // EventSize
	buf.Write(make([]byte, 4))                         // Separator bytes

	// Event 4: EV_ACTION (PCR 5) - empty event data
	binary.Write(&buf, binary.LittleEndian, uint32(5))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0008)) // EventType (EV_ACTION)
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount

	binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
	actionHash := sha256.Sum256([]byte("action_test"))
	buf.Write(actionHash[:])

	binary.Write(&buf, binary.LittleEndian, uint32(0)) // EventSize (empty)

	// Event 5: EV_EFI_BOOT_SERVICES_APPLICATION (PCR 4)
	binary.Write(&buf, binary.LittleEndian, uint32(4))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0006)) // EventType
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount

	binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
	efiHash := sha256.Sum256([]byte("efi_application"))
	buf.Write(efiHash[:])

	binary.Write(&buf, binary.LittleEndian, uint32(15))
	buf.WriteString("EFI Application")

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "test_eventlog_*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	tmpFile.Close()
	return tmpFile.Name()
}

// createMalformedEventLog creates an event log with corrupt data
func createMalformedEventLog(t *testing.T, corruptionType string) string {
	t.Helper()

	var buf bytes.Buffer

	switch corruptionType {
	case "truncated_header":
		// Only write partial header
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint16(0x0001))

	case "invalid_algorithm":
		// Use algorithm ID that can be estimated (0xFFFF >= 0x8000)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
		binary.Write(&buf, binary.LittleEndian, uint32(1))
		binary.Write(&buf, binary.LittleEndian, uint16(0xFFFF)) // Unknown algorithm (estimatable)
		buf.Write(make([]byte, 32))                             // 32 bytes as estimated
		binary.Write(&buf, binary.LittleEndian, uint32(0))

	case "unestimatable_algorithm":
		// Use algorithm ID that cannot be estimated (0x00FF - not in known ranges)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
		binary.Write(&buf, binary.LittleEndian, uint32(1))
		binary.Write(&buf, binary.LittleEndian, uint16(0x00FF)) // Unknown algorithm (cannot estimate size)
		buf.Write(make([]byte, 32))
		binary.Write(&buf, binary.LittleEndian, uint32(0))

	case "platform_specific_algorithm":
		// Use algorithm ID in the 0x6XXX range (platform-specific, estimatable)
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
		binary.Write(&buf, binary.LittleEndian, uint32(1))
		binary.Write(&buf, binary.LittleEndian, uint16(0x6600)) // Platform-specific algorithm
		buf.Write(make([]byte, 32))                             // 32 bytes as estimated
		binary.Write(&buf, binary.LittleEndian, uint32(0))

	case "truncated_digest":
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
		binary.Write(&buf, binary.LittleEndian, uint32(1))
		binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
		buf.Write(make([]byte, 10)) // Truncated SHA256 (should be 32 bytes)

	case "truncated_event":
		binary.Write(&buf, binary.LittleEndian, uint32(0))
		binary.Write(&buf, binary.LittleEndian, uint32(0x0001))
		binary.Write(&buf, binary.LittleEndian, uint32(1))
		binary.Write(&buf, binary.LittleEndian, uint16(0x000b))
		buf.Write(make([]byte, 32))
		binary.Write(&buf, binary.LittleEndian, uint32(100)) // Says 100 bytes
		buf.WriteString("short")                             // But only provides 5

	default:
		t.Fatalf("Unknown corruption type: %s", corruptionType)
	}

	tmpFile, err := os.CreateTemp("", "corrupt_eventlog_*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	tmpFile.Close()
	return tmpFile.Name()
}

// TestIntegration_ParseEventLog tests event log parsing with valid data
func TestIntegration_ParseEventLog(t *testing.T) {
	testFile := createTestEventLog(t)
	defer os.Remove(testFile)

	events, err := tpm2lib.ParseEventLog(testFile)
	if err != nil {
		t.Fatalf("Failed to parse event log: %v", err)
	}

	// Verify we got the expected number of events
	expectedEvents := 5
	if len(events) != expectedEvents {
		t.Errorf("Expected %d events, got %d", expectedEvents, len(events))
	}

	// Verify Event 1 (EV_NO_ACTION)
	if len(events) > 0 {
		e := events[0]
		if e.PCRIndex != 0 {
			t.Errorf("Event 1: expected PCR 0, got %d", e.PCRIndex)
		}
		if e.EventType != "EV_NO_ACTION" {
			t.Errorf("Event 1: expected EV_NO_ACTION, got %s", e.EventType)
		}
		if e.DigestCount != 2 {
			t.Errorf("Event 1: expected 2 digests, got %d", e.DigestCount)
		}
		if len(e.Digests) != 2 {
			t.Errorf("Event 1: expected 2 digests in slice, got %d", len(e.Digests))
		}
		// Verify SHA1 and SHA256 are present
		foundSHA1 := false
		foundSHA256 := false
		for _, d := range e.Digests {
			if d.AlgorithmId == "sha1" {
				foundSHA1 = true
			}
			if d.AlgorithmId == "sha256" {
				foundSHA256 = true
			}
		}
		if !foundSHA1 || !foundSHA256 {
			t.Errorf("Event 1: expected sha1 and sha256 digests")
		}
	}

	// Verify Event 2 (EV_IPL)
	if len(events) > 1 {
		e := events[1]
		if e.PCRIndex != 8 {
			t.Errorf("Event 2: expected PCR 8, got %d", e.PCRIndex)
		}
		if e.EventType != "EV_IPL" {
			t.Errorf("Event 2: expected EV_IPL, got %s", e.EventType)
		}
		if !strings.Contains(e.EventString, "grub_cmd") {
			t.Errorf("Event 2: expected event string to contain 'grub_cmd', got '%s'", e.EventString)
		}
	}

	// Verify Event 3 (EV_SEPARATOR with 3 algorithms)
	if len(events) > 2 {
		e := events[2]
		if e.PCRIndex != 7 {
			t.Errorf("Event 3: expected PCR 7, got %d", e.PCRIndex)
		}
		if e.EventType != "EV_SEPARATOR" {
			t.Errorf("Event 3: expected EV_SEPARATOR, got %s", e.EventType)
		}
		if e.DigestCount != 3 {
			t.Errorf("Event 3: expected 3 digests, got %d", e.DigestCount)
		}
	}

	// Verify Event 4 (empty event data)
	if len(events) > 3 {
		e := events[3]
		if e.EventSize != 0 {
			t.Errorf("Event 4: expected empty event, got size %d", e.EventSize)
		}
		if e.EventString != "" {
			t.Errorf("Event 4: expected empty string, got '%s'", e.EventString)
		}
	}

	t.Logf("Successfully parsed %d events from test event log", len(events))
}

// TestIntegration_ParseEventLog_ErrorCases tests error handling
func TestIntegration_ParseEventLog_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		corruptionType string
		useNonExistent bool
		expectError    bool
		errorSubstring string
	}{
		{
			name:           "NonExistentFile",
			useNonExistent: true,
			expectError:    true,
			errorSubstring: "failed to open file",
		},
		{
			name:           "TruncatedHeader",
			corruptionType: "truncated_header",
			expectError:    true,
			errorSubstring: "error reading",
		},
		{
			name:           "UnestimatableAlgorithm",
			corruptionType: "unestimatable_algorithm",
			expectError:    true,
			errorSubstring: "unknown algorithm ID",
		},
		{
			name:           "TruncatedDigest",
			corruptionType: "truncated_digest",
			expectError:    true,
			errorSubstring: "error reading digest",
		},
		{
			name:           "TruncatedEvent",
			corruptionType: "truncated_event",
			expectError:    true,
			errorSubstring: "error reading event data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testFile string
			if tt.useNonExistent {
				testFile = "/nonexistent/path/to/eventlog.bin"
			} else {
				testFile = createMalformedEventLog(t, tt.corruptionType)
				defer os.Remove(testFile)
			}

			_, err := tpm2lib.ParseEventLog(testFile)

			if tt.expectError && err == nil {
				t.Errorf("Expected error containing '%s', got nil", tt.errorSubstring)
			}

			if tt.expectError && err != nil {
				if !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorSubstring, err.Error())
				}
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestIntegration_ParseEventLog_UnknownAlgorithms tests graceful handling of unknown algorithms
func TestIntegration_ParseEventLog_UnknownAlgorithms(t *testing.T) {
	t.Run("PlatformSpecificAlgorithm_0x6600", func(t *testing.T) {
		testFile := createMalformedEventLog(t, "platform_specific_algorithm")
		defer os.Remove(testFile)

		events, err := tpm2lib.ParseEventLog(testFile)
		if err != nil {
			t.Fatalf("Expected to parse event with platform-specific algorithm, got error: %v", err)
		}

		if len(events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(events))
		}

		// Verify the unknown algorithm is captured
		if len(events[0].Digests) != 1 {
			t.Errorf("Expected 1 digest, got %d", len(events[0].Digests))
		}

		digest := events[0].Digests[0]
		if !strings.HasPrefix(digest.AlgorithmId, "unknown_0x") {
			t.Errorf("Expected unknown algorithm ID marker, got '%s'", digest.AlgorithmId)
		}

		if digest.AlgorithmId != "unknown_0x6600" {
			t.Errorf("Expected 'unknown_0x6600', got '%s'", digest.AlgorithmId)
		}

		// Verify digest was read (32 bytes = 64 hex chars)
		if len(digest.Digest) != 64 {
			t.Errorf("Expected 64 hex chars for digest, got %d", len(digest.Digest))
		}

		t.Logf("Successfully parsed event with platform-specific algorithm 0x6600")
	})

	t.Run("ExtendedAlgorithm_0xFFFF", func(t *testing.T) {
		testFile := createMalformedEventLog(t, "invalid_algorithm")
		defer os.Remove(testFile)

		events, err := tpm2lib.ParseEventLog(testFile)
		if err != nil {
			t.Fatalf("Expected to parse event with extended algorithm, got error: %v", err)
		}

		if len(events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(events))
		}

		digest := events[0].Digests[0]
		if digest.AlgorithmId != "unknown_0xffff" {
			t.Errorf("Expected 'unknown_0xffff', got '%s'", digest.AlgorithmId)
		}

		t.Logf("Successfully parsed event with extended algorithm 0xFFFF")
	})

	t.Run("StrictMode_RejectsUnknown", func(t *testing.T) {
		testFile := createMalformedEventLog(t, "invalid_algorithm")
		defer os.Remove(testFile)

		// Use strict options that don't skip unknown algorithms
		opts := tpm2lib.ParseEventLogOptions{
			SkipUnknownAlgorithms: false,
		}

		_, err := tpm2lib.ParseEventLogWithOptions(testFile, opts)
		if err == nil {
			t.Error("Expected error in strict mode for unknown algorithm")
		}

		if err != nil && !strings.Contains(err.Error(), "unknown algorithm ID") {
			t.Errorf("Expected 'unknown algorithm ID' error, got '%s'", err.Error())
		}

		t.Logf("Strict mode correctly rejects unknown algorithm")
	})
}

// TestIntegration_CalculatePCRs tests PCR calculation from event log
func TestIntegration_CalculatePCRs(t *testing.T) {
	testFile := createTestEventLog(t)
	defer os.Remove(testFile)

	events, err := tpm2lib.ParseEventLog(testFile)
	if err != nil {
		t.Fatalf("Failed to parse event log: %v", err)
	}

	pcrValues := tpm2lib.CalculatePCRs(events)
	if pcrValues == nil {
		t.Fatal("CalculatePCRs returned nil")
	}

	// Verify PCR banks exist
	expectedBanks := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, bank := range expectedBanks {
		if _, exists := pcrValues[bank]; !exists {
			t.Errorf("Expected PCR bank '%s' to exist", bank)
		}
	}

	// Verify specific PCR indices were extended
	// From our test events: PCR 0, 4, 5, 7, 8 should be present
	expectedPCRs := []int{0, 4, 5, 7, 8}

	for _, pcrIndex := range expectedPCRs {
		// Check SHA256 bank (all events have SHA256)
		if sha256Bank, ok := pcrValues["sha256"]; ok {
			if _, exists := sha256Bank[pcrIndex]; !exists {
				t.Errorf("Expected PCR %d to exist in sha256 bank", pcrIndex)
			} else {
				// Verify PCR value is not all zeros (was extended)
				pcrValue := sha256Bank[pcrIndex]
				if len(pcrValue) != 32 {
					t.Errorf("SHA256 PCR %d: expected 32 bytes, got %d", pcrIndex, len(pcrValue))
				}

				// At least verify it's not nil/empty
				t.Logf("SHA256 PCR[%d] = %s", pcrIndex, hex.EncodeToString(pcrValue))
			}
		}
	}

	// Verify SHA1 bank has correct digest size
	if sha1Bank, ok := pcrValues["sha1"]; ok {
		for idx, val := range sha1Bank {
			if len(val) != 20 {
				t.Errorf("SHA1 PCR %d: expected 20 bytes, got %d", idx, len(val))
			}
		}
	}

	// Verify SHA384 bank has correct digest size
	if sha384Bank, ok := pcrValues["sha384"]; ok {
		for idx, val := range sha384Bank {
			if len(val) != 48 {
				t.Errorf("SHA384 PCR %d: expected 48 bytes, got %d", idx, len(val))
			}
		}
	}

	// Verify SHA512 bank has correct digest size
	if sha512Bank, ok := pcrValues["sha512"]; ok {
		for idx, val := range sha512Bank {
			if len(val) != 64 {
				t.Errorf("SHA512 PCR %d: expected 64 bytes, got %d", idx, len(val))
			}
		}
	}

	t.Log("Successfully calculated PCR values from event log")
}

// TestIntegration_PCRExtension tests PCR extension operations with real TPM
func TestIntegration_PCRExtension(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpm := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpm)

	pcrIndex := uint(16) // Use debug PCR

	// Read initial PCR value (SHA256 bank)
	pcrRead1 := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
				},
			},
		},
	}

	readRsp1, err := pcrRead1.Execute(tpm)
	if err != nil {
		t.Fatalf("Initial PCRRead failed: %v", err)
	}

	if len(readRsp1.PCRValues.Digests) == 0 {
		t.Fatal("No PCR values returned")
	}

	initialValue := readRsp1.PCRValues.Digests[0].Buffer
	t.Logf("Initial PCR[%d] (SHA256): %s", pcrIndex, hex.EncodeToString(initialValue))

	// Extend PCR with test data
	testData := []byte("integration_test_data")
	extendHash := sha256.Sum256(testData)

	pcrExtend := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcrIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  extendHash[:],
				},
			},
		},
	}

	_, err = pcrExtend.Execute(tpm)
	if err != nil {
		t.Fatalf("PCRExtend failed: %v", err)
	}

	// Read PCR value after extension
	readRsp2, err := pcrRead1.Execute(tpm)
	if err != nil {
		t.Fatalf("Second PCRRead failed: %v", err)
	}

	if len(readRsp2.PCRValues.Digests) == 0 {
		t.Fatal("No PCR values returned after extension")
	}

	extendedValue := readRsp2.PCRValues.Digests[0].Buffer
	t.Logf("Extended PCR[%d] (SHA256): %s", pcrIndex, hex.EncodeToString(extendedValue))

	// Verify PCR value changed
	if bytes.Equal(initialValue, extendedValue) {
		t.Error("PCR value did not change after extension")
	}

	// Calculate expected value using software PCR extension
	expectedValue, err := tpm2lib.ExtendPCR(initialValue, extendHash[:], "sha256")
	if err != nil {
		t.Fatalf("Software ExtendPCR failed: %v", err)
	}

	// Note: Making ExtendPCR exported for testing
	// Verify extended value matches expected
	if !bytes.Equal(extendedValue, expectedValue) {
		t.Errorf("Extended PCR value mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(extendedValue),
			hex.EncodeToString(expectedValue))
	}

	t.Log("Successfully verified PCR extension operation")
}

// TestIntegration_HashFunctions tests hash function retrieval
func TestIntegration_HashFunctions(t *testing.T) {
	tests := []struct {
		algorithm    string
		expectedSize int
		expectError  bool
	}{
		{"sha1", 20, false},
		{"sha256", 32, false},
		{"sha384", 48, false},
		{"sha512", 64, false},
		{"invalid", 0, true},
		{"md5", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			hasher, err := tpm2lib.GetHashFunction(tt.algorithm)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for algorithm '%s', got nil", tt.algorithm)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for algorithm '%s': %v", tt.algorithm, err)
			}

			if hasher == nil {
				t.Fatal("GetHashFunction returned nil hasher")
			}

			// Test hash function works
			testData := []byte("test data for hashing")
			hasher.Write(testData)
			digest := hasher.Sum(nil)

			if len(digest) != tt.expectedSize {
				t.Errorf("Expected digest size %d for %s, got %d",
					tt.expectedSize, tt.algorithm, len(digest))
			}

			t.Logf("%s hash of test data: %s", tt.algorithm, hex.EncodeToString(digest))
		})
	}
}

// TestIntegration_DigestSize tests digest size calculation
func TestIntegration_DigestSize(t *testing.T) {
	tests := []struct {
		algorithm    string
		expectedSize int
	}{
		{"sha1", 20},
		{"sha256", 32},
		{"sha384", 48},
		{"sha512", 64},
		{"unknown", 0},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			size := tpm2lib.GetDigestSize(tt.algorithm)
			if size != tt.expectedSize {
				t.Errorf("Expected size %d for algorithm '%s', got %d",
					tt.expectedSize, tt.algorithm, size)
			}
		})
	}
}

// TestIntegration_InitializePCRs tests PCR initialization
func TestIntegration_InitializePCRs(t *testing.T) {
	pcrs := tpm2lib.InitializePCRs()

	if pcrs == nil {
		t.Fatal("InitializePCRs returned nil")
	}

	// Verify all expected banks exist
	expectedBanks := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, bank := range expectedBanks {
		if _, exists := pcrs[bank]; !exists {
			t.Errorf("Expected PCR bank '%s' to exist", bank)
		}

		// Verify bank is initialized but empty
		bankMap := pcrs[bank]
		if bankMap == nil {
			t.Errorf("PCR bank '%s' is nil", bank)
		}
		if len(bankMap) != 0 {
			t.Errorf("Expected empty PCR bank '%s', got %d entries", bank, len(bankMap))
		}
	}

	t.Log("Successfully verified PCR initialization")
}

// TestIntegration_PrintEvents tests event printing (output capture)
func TestIntegration_PrintEvents(t *testing.T) {
	testFile := createTestEventLog(t)
	defer os.Remove(testFile)

	events, err := tpm2lib.ParseEventLog(testFile)
	if err != nil {
		t.Fatalf("Failed to parse event log: %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call PrintEvents
	tpm2lib.PrintEvents(events)

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected content
	expectedStrings := []string{
		"EventNum:",
		"PCRIndex:",
		"EventType:",
		"DigestCount:",
		"Digests:",
		"AlgorithmId:",
		"Digest:",
		"EventSize:",
		"Event:",
		"pcrs:",
		"sha256:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', but it was not found", expected)
		}
	}

	// Verify event types appear
	eventTypes := []string{"EV_NO_ACTION", "EV_IPL", "EV_SEPARATOR", "EV_ACTION"}
	for _, eventType := range eventTypes {
		if !strings.Contains(output, eventType) {
			t.Errorf("Expected output to contain event type '%s'", eventType)
		}
	}

	t.Logf("PrintEvents produced %d bytes of output", len(output))
}

// TestIntegration_PrintPCRSummary tests PCR summary printing
func TestIntegration_PrintPCRSummary(t *testing.T) {
	testFile := createTestEventLog(t)
	defer os.Remove(testFile)

	events, err := tpm2lib.ParseEventLog(testFile)
	if err != nil {
		t.Fatalf("Failed to parse event log: %v", err)
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call printPCRSummary (via PrintEvents which calls it)
	tpm2lib.PrintEvents(events)

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify PCR summary section exists
	if !strings.Contains(output, "pcrs:") {
		t.Error("Expected output to contain 'pcrs:' section")
	}

	// Verify algorithm sections
	algorithms := []string{"sha1:", "sha256:", "sha384:", "sha512:"}
	foundAlgorithms := 0
	for _, alg := range algorithms {
		if strings.Contains(output, alg) {
			foundAlgorithms++
		}
	}

	if foundAlgorithms == 0 {
		t.Error("Expected at least one algorithm section in PCR summary")
	}

	// Verify PCR indices appear with hex values
	if !strings.Contains(output, "0x") {
		t.Error("Expected PCR values to be displayed in hex format (0x...)")
	}

	t.Logf("PCR summary printed successfully with %d algorithm banks", foundAlgorithms)
}

// TestIntegration_MultipleHashAlgorithms tests PCR operations with different hash algorithms
func TestIntegration_MultipleHashAlgorithms(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpm := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpm)

	pcrIndex := uint(16)

	// Test data
	testData := []byte("multi_algorithm_test")

	// Compute digests for different algorithms
	sha1Digest := sha1.Sum(testData)
	sha256Digest := sha256.Sum256(testData)
	sha384Digest := sha512.Sum384(testData)
	sha512Digest := sha512.Sum512(testData)

	// Read initial values for all algorithms
	algorithms := []struct {
		name   string
		algID  tpm2.TPMAlgID
		digest []byte
		size   int
	}{
		{"SHA1", tpm2.TPMAlgSHA1, sha1Digest[:], 20},
		{"SHA256", tpm2.TPMAlgSHA256, sha256Digest[:], 32},
		{"SHA384", tpm2.TPMAlgSHA384, sha384Digest[:], 48},
		{"SHA512", tpm2.TPMAlgSHA512, sha512Digest[:], 64},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			// Read initial PCR
			pcrRead := tpm2.PCRRead{
				PCRSelectionIn: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{
						{
							Hash:      alg.algID,
							PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
						},
					},
				},
			}

			readRsp, err := pcrRead.Execute(tpm)
			if err != nil {
				t.Fatalf("PCRRead failed for %s: %v", alg.name, err)
			}

			if len(readRsp.PCRValues.Digests) == 0 {
				t.Fatalf("No PCR values returned for %s", alg.name)
			}

			initialValue := readRsp.PCRValues.Digests[0].Buffer

			// Verify digest size
			if len(initialValue) != alg.size {
				t.Errorf("%s PCR: expected size %d, got %d", alg.name, alg.size, len(initialValue))
			}

			t.Logf("%s PCR[%d] initial: %s", alg.name, pcrIndex, hex.EncodeToString(initialValue))
		})
	}
}

// TestIntegration_PCRCalculationAccuracy tests PCR calculation accuracy against real TPM
func TestIntegration_PCRCalculationAccuracy(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpm := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpm)

	pcrIndex := uint(23) // Use debug PCR 23 (PCRs 17-22 are locality-restricted)

	// Generate random test data
	testData := make([]byte, 32)
	_, err := rand.Read(testData)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Calculate digest
	digest := sha256.Sum256(testData)

	// Read initial PCR value
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
				},
			},
		},
	}

	readRsp1, err := pcrRead.Execute(tpm)
	if err != nil {
		t.Fatalf("Initial PCRRead failed: %v", err)
	}

	initialValue := readRsp1.PCRValues.Digests[0].Buffer

	// Extend PCR using TPM
	pcrExtend := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcrIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  digest[:],
				},
			},
		},
	}

	_, err = pcrExtend.Execute(tpm)
	if err != nil {
		t.Fatalf("PCRExtend failed: %v", err)
	}

	// Read extended PCR value from TPM
	readRsp2, err := pcrRead.Execute(tpm)
	if err != nil {
		t.Fatalf("Second PCRRead failed: %v", err)
	}

	tpmExtendedValue := readRsp2.PCRValues.Digests[0].Buffer

	// Calculate expected value using software implementation
	softwareExtendedValue, err := tpm2lib.ExtendPCR(initialValue, digest[:], "sha256")
	if err != nil {
		t.Fatalf("Software ExtendPCR failed: %v", err)
	}

	// Compare TPM and software results
	if !bytes.Equal(tpmExtendedValue, softwareExtendedValue) {
		t.Errorf("PCR extension mismatch:\n  TPM:      %s\n  Software: %s",
			hex.EncodeToString(tpmExtendedValue),
			hex.EncodeToString(softwareExtendedValue))
	} else {
		t.Logf("PCR calculation matches TPM: %s", hex.EncodeToString(tpmExtendedValue))
	}
}

// TestIntegration_EventLogWithRealTPM creates events on real TPM and verifies PCR values
func TestIntegration_EventLogWithRealTPM(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpm := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpm)

	pcrIndex := uint(23) // Use debug PCR 23

	// Create a series of test events
	testEvents := []struct {
		name string
		data []byte
	}{
		{"boot_event", []byte("system_boot")},
		{"config_event", []byte("load_config")},
		{"app_event", []byte("start_application")},
	}

	// Read initial PCR value from TPM (may not be zeros if previously extended)
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrIndex),
				},
			},
		},
	}

	initialRsp, err := pcrRead.Execute(tpm)
	if err != nil {
		t.Fatalf("Initial PCRRead failed: %v", err)
	}

	// Track software PCR starting from actual TPM value
	softwarePCR := initialRsp.PCRValues.Digests[0].Buffer
	t.Logf("Initial PCR[%d] value: %s", pcrIndex, hex.EncodeToString(softwarePCR))

	for i, event := range testEvents {
		// Calculate digest
		digest := sha256.Sum256(event.data)

		// Extend TPM PCR
		pcrExtend := tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(pcrIndex),
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digests: tpm2.TPMLDigestValues{
				Digests: []tpm2.TPMTHA{
					{
						HashAlg: tpm2.TPMAlgSHA256,
						Digest:  digest[:],
					},
				},
			},
		}

		_, err := pcrExtend.Execute(tpm)
		if err != nil {
			t.Fatalf("Event %d (%s): PCRExtend failed: %v", i, event.name, err)
		}

		// Update software PCR
		softwarePCR, err = tpm2lib.ExtendPCR(softwarePCR, digest[:], "sha256")
		if err != nil {
			t.Fatalf("Event %d (%s): Software ExtendPCR failed: %v", i, event.name, err)
		}

		t.Logf("Event %d (%s): extended PCR with %s", i, event.name, hex.EncodeToString(digest[:]))
	}

	// Read final TPM PCR value (reuse pcrRead from earlier)
	finalRsp, err := pcrRead.Execute(tpm)
	if err != nil {
		t.Fatalf("Final PCRRead failed: %v", err)
	}

	tpmFinalValue := finalRsp.PCRValues.Digests[0].Buffer

	// Compare final values
	if !bytes.Equal(tpmFinalValue, softwarePCR) {
		t.Errorf("Final PCR value mismatch after %d events:\n  TPM:      %s\n  Software: %s",
			len(testEvents),
			hex.EncodeToString(tpmFinalValue),
			hex.EncodeToString(softwarePCR))
	} else {
		t.Logf("Successfully verified PCR after %d events: %s",
			len(testEvents),
			hex.EncodeToString(tpmFinalValue))
	}
}

// TestIntegration_EmptyEventLog tests handling of empty event log
func TestIntegration_EmptyEventLog(t *testing.T) {
	// Create empty file
	tmpFile, err := os.CreateTemp("", "empty_eventlog_*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	events, err := tpm2lib.ParseEventLog(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to parse empty event log: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 events from empty log, got %d", len(events))
	}

	// Calculate PCRs from empty event log
	pcrs := tpm2lib.CalculatePCRs(events)
	if pcrs == nil {
		t.Fatal("CalculatePCRs returned nil for empty events")
	}

	// All PCR banks should exist but be empty
	for bank, pcrMap := range pcrs {
		if len(pcrMap) != 0 {
			t.Errorf("Expected empty PCR map for %s bank, got %d entries", bank, len(pcrMap))
		}
	}

	t.Log("Successfully handled empty event log")
}

// TestIntegration_RealEventLog tests parsing of real EFI event log from host system
func TestIntegration_RealEventLog(t *testing.T) {
	realEventLogPath, err := filepath.Abs("testdata/real_eventlog.bin")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	// Check if real event log exists
	if _, err := os.Stat(realEventLogPath); os.IsNotExist(err) {
		t.Fatal("Real event log not available at testdata/real_eventlog.bin")
	}

	events, err := tpm2lib.ParseEventLog(realEventLogPath)
	if err != nil {
		t.Fatalf("Failed to parse real event log: %v", err)
	}

	// Verify we got events
	if len(events) == 0 {
		t.Fatal("Expected events from real event log, got 0")
	}

	t.Logf("Successfully parsed %d events from real EFI event log", len(events))

	// Verify event structure consistency
	for i, event := range events {
		// Event number should match position
		if event.EventNum != i+1 {
			t.Errorf("Event %d: expected EventNum %d, got %d", i, i+1, event.EventNum)
		}

		// PCR index should be in valid range (0-23)
		if event.PCRIndex < 0 || event.PCRIndex > 23 {
			t.Errorf("Event %d: invalid PCR index %d", i, event.PCRIndex)
		}

		// Digest count should match actual digests
		if event.DigestCount != len(event.Digests) {
			t.Errorf("Event %d: DigestCount %d doesn't match len(Digests) %d",
				i, event.DigestCount, len(event.Digests))
		}

		// Verify each digest has valid algorithm and proper length
		for j, digest := range event.Digests {
			expectedSize := 0
			switch digest.AlgorithmId {
			case "sha1":
				expectedSize = 40 // 20 bytes = 40 hex chars
			case "sha256":
				expectedSize = 64 // 32 bytes = 64 hex chars
			case "sha384":
				expectedSize = 96 // 48 bytes = 96 hex chars
			case "sha512":
				expectedSize = 128 // 64 bytes = 128 hex chars
			case "sm3_256":
				expectedSize = 64 // 32 bytes = 64 hex chars
			default:
				if strings.HasPrefix(digest.AlgorithmId, "unknown_0x") {
					// Unknown algorithms should have 32 bytes (64 hex chars) based on estimation
					expectedSize = 64
				}
			}

			if expectedSize > 0 && len(digest.Digest) != expectedSize {
				t.Errorf("Event %d, Digest %d: expected %d hex chars for %s, got %d",
					i, j, expectedSize, digest.AlgorithmId, len(digest.Digest))
			}
		}

		// Event size should be non-negative
		if event.EventSize < 0 {
			t.Errorf("Event %d: invalid negative EventSize %d", i, event.EventSize)
		}
	}

	// Count event types
	eventTypeCounts := make(map[string]int)
	for _, event := range events {
		eventTypeCounts[event.EventType]++
	}

	t.Log("Event type distribution:")
	for eventType, count := range eventTypeCounts {
		t.Logf("  %s: %d", eventType, count)
	}

	// Count PCR usage
	pcrUsage := make(map[int]int)
	for _, event := range events {
		pcrUsage[event.PCRIndex]++
	}

	t.Log("PCR usage:")
	for pcr := 0; pcr <= 23; pcr++ {
		if count, ok := pcrUsage[pcr]; ok {
			t.Logf("  PCR[%d]: %d events", pcr, count)
		}
	}
}

// TestIntegration_RealEventLog_PCRCalculation calculates PCRs from real event log
func TestIntegration_RealEventLog_PCRCalculation(t *testing.T) {
	realEventLogPath, err := filepath.Abs("testdata/real_eventlog.bin")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(realEventLogPath); os.IsNotExist(err) {
		t.Fatal("Real event log not available at testdata/real_eventlog.bin")
	}

	events, err := tpm2lib.ParseEventLog(realEventLogPath)
	if err != nil {
		t.Fatalf("Failed to parse real event log: %v", err)
	}

	pcrs := tpm2lib.CalculatePCRs(events)
	if pcrs == nil {
		t.Fatal("CalculatePCRs returned nil")
	}

	// Verify PCR banks
	t.Log("Calculated PCR values from real event log:")
	for algorithm, pcrMap := range pcrs {
		if len(pcrMap) == 0 {
			continue
		}

		t.Logf("  %s bank (%d PCRs):", algorithm, len(pcrMap))
		for pcrIndex := 0; pcrIndex <= 23; pcrIndex++ {
			if value, ok := pcrMap[pcrIndex]; ok {
				// Verify correct size based on algorithm
				expectedSize := tpm2lib.GetDigestSize(algorithm)
				if len(value) != expectedSize {
					t.Errorf("PCR[%d] %s: expected %d bytes, got %d",
						pcrIndex, algorithm, expectedSize, len(value))
				}

				// Log first 16 bytes of each PCR value
				if len(value) > 0 {
					t.Logf("    PCR[%02d]: %s...", pcrIndex, hex.EncodeToString(value[:min(16, len(value))]))
				}
			}
		}
	}

	// Verify at least some standard PCRs are present (boot process should use 0-7)
	sha256Bank := pcrs["sha256"]
	if sha256Bank == nil {
		t.Error("Expected SHA256 bank to exist")
	} else {
		// Real boot logs should have at least PCR 0, 1, 2, 4, 7
		expectedPCRs := []int{0, 1, 2, 4, 7}
		for _, pcr := range expectedPCRs {
			if _, ok := sha256Bank[pcr]; !ok {
				t.Logf("Warning: PCR[%d] not found in SHA256 bank (may vary by system)", pcr)
			}
		}
	}
}

// TestIntegration_RealEventLog_AlgorithmSupport verifies algorithm support in real logs
func TestIntegration_RealEventLog_AlgorithmSupport(t *testing.T) {
	realEventLogPath, err := filepath.Abs("testdata/real_eventlog.bin")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(realEventLogPath); os.IsNotExist(err) {
		t.Fatal("Real event log not available at testdata/real_eventlog.bin")
	}

	events, err := tpm2lib.ParseEventLog(realEventLogPath)
	if err != nil {
		t.Fatalf("Failed to parse real event log: %v", err)
	}

	// Count algorithms used
	algorithmCounts := make(map[string]int)
	for _, event := range events {
		for _, digest := range event.Digests {
			algorithmCounts[digest.AlgorithmId]++
		}
	}

	t.Log("Algorithm usage in real event log:")
	for alg, count := range algorithmCounts {
		t.Logf("  %s: %d digests", alg, count)
	}

	// Verify at least SHA256 is present (modern systems should have it)
	if algorithmCounts["sha256"] == 0 {
		t.Error("Expected SHA256 digests in modern EFI event log")
	}

	// Check for unknown algorithms
	unknownCount := 0
	for alg := range algorithmCounts {
		if strings.HasPrefix(alg, "unknown_0x") {
			unknownCount++
			t.Logf("Found unknown algorithm: %s", alg)
		}
	}

	if unknownCount > 0 {
		t.Logf("Successfully handled %d unknown algorithm type(s)", unknownCount)
	}
}

// TestIntegration_RealEventLog_PrintEvents tests printing real event log
func TestIntegration_RealEventLog_PrintEvents(t *testing.T) {
	realEventLogPath, err := filepath.Abs("testdata/real_eventlog.bin")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(realEventLogPath); os.IsNotExist(err) {
		t.Fatal("Real event log not available at testdata/real_eventlog.bin")
	}

	events, err := tpm2lib.ParseEventLog(realEventLogPath)
	if err != nil {
		t.Fatalf("Failed to parse real event log: %v", err)
	}

	// Capture stdout for limited events
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Only print first 5 events to avoid massive output
	eventsToShow := events
	if len(events) > 5 {
		eventsToShow = events[:5]
	}
	tpm2lib.PrintEvents(eventsToShow)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify basic structure
	if !strings.Contains(output, "EventNum:") {
		t.Error("Expected EventNum in output")
	}
	if !strings.Contains(output, "PCRIndex:") {
		t.Error("Expected PCRIndex in output")
	}
	if !strings.Contains(output, "EventType:") {
		t.Error("Expected EventType in output")
	}
	if !strings.Contains(output, "pcrs:") {
		t.Error("Expected pcrs summary in output")
	}

	t.Logf("Successfully printed %d events from real event log (%d bytes output)",
		len(eventsToShow), len(output))
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
