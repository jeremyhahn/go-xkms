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

// Helper function to create a binary event log entry
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

// Helper function to create a temporary file with binary data
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

func TestPrintEvents_Coverage(t *testing.T) {
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

func TestParseEventLog_EVNoAction(t *testing.T) {
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
		[]byte("NO ACTION EVENT"),
	)

	tmpFile := createTempEventLogFile(t, eventData)
	defer func() { _ = os.Remove(tmpFile) }()

	events, err := ParseEventLog(tmpFile)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}

	if events[0].EventType != "EV_NO_ACTION" {
		t.Errorf("expected EventType EV_NO_ACTION, got %s", events[0].EventType)
	}
}

func TestParseEventLog_EVPostCode(t *testing.T) {
	sha256Digest := make([]byte, 32)
	eventData := createEventLogEntry(
		0,
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

	if events[0].EventType != "EV_S_POST_CODE" {
		t.Errorf("expected EventType EV_S_POST_CODE, got %s", events[0].EventType)
	}
}

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

func TestParseEventLog_FileNotFound(t *testing.T) {
	_, err := ParseEventLog("/nonexistent/path/to/eventlog.bin")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("expected 'failed to open file' error, got: %v", err)
	}
}

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

func TestCalculatePCRs_SingleEvent(t *testing.T) {
	// Create a single SHA256 event
	digestHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256 of empty string
	events := []Event{
		{
			EventNum:    1,
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []Digest{
				{
					AlgorithmId: "sha256",
					Digest:      digestHex,
				},
			},
			EventSize:   4,
			EventString: "test",
		},
	}

	pcrs := CalculatePCRs(events)

	if pcrs == nil {
		t.Fatal("expected non-nil PCR map")
	}

	sha256PCRs, exists := pcrs["sha256"]
	if !exists {
		t.Fatal("expected sha256 key in PCR map")
	}

	pcr0, exists := sha256PCRs[0]
	if !exists {
		t.Fatal("expected PCR 0 in sha256 map")
	}

	if len(pcr0) != sha256.Size {
		t.Errorf("expected PCR 0 size %d, got %d", sha256.Size, len(pcr0))
	}

	// Verify the PCR extension is correct
	// PCR = SHA256(0x00...00 || digest)
	hasher := sha256.New()
	hasher.Write(make([]byte, sha256.Size)) // Initial PCR value (all zeros)
	digestBytes, _ := hex.DecodeString(digestHex)
	hasher.Write(digestBytes)
	expected := hasher.Sum(nil)

	if !bytes.Equal(pcr0, expected) {
		t.Errorf("PCR 0 mismatch\nexpected: %x\ngot:      %x", expected, pcr0)
	}
}

func TestCalculatePCRs_MultipleEvents(t *testing.T) {
	digest1 := "0000000000000000000000000000000000000000000000000000000000000001"
	digest2 := "0000000000000000000000000000000000000000000000000000000000000002"

	events := []Event{
		{
			EventNum:  1,
			PCRIndex:  0,
			EventType: "EV_NO_ACTION",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: digest1},
			},
		},
		{
			EventNum:  2,
			PCRIndex:  0,
			EventType: "EV_SEPARATOR",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: digest2},
			},
		},
	}

	pcrs := CalculatePCRs(events)

	sha256PCRs := pcrs["sha256"]
	pcr0 := sha256PCRs[0]

	// Calculate expected value manually
	// First extension: SHA256(zeros || digest1)
	hasher := sha256.New()
	hasher.Write(make([]byte, sha256.Size))
	d1, _ := hex.DecodeString(digest1)
	hasher.Write(d1)
	intermediate := hasher.Sum(nil)

	// Second extension: SHA256(intermediate || digest2)
	hasher = sha256.New()
	hasher.Write(intermediate)
	d2, _ := hex.DecodeString(digest2)
	hasher.Write(d2)
	expected := hasher.Sum(nil)

	if !bytes.Equal(pcr0, expected) {
		t.Errorf("PCR 0 after multiple extends mismatch\nexpected: %x\ngot:      %x", expected, pcr0)
	}
}

func TestCalculatePCRs_MultiplePCRs(t *testing.T) {
	events := []Event{
		{
			EventNum:  1,
			PCRIndex:  0,
			EventType: "EV_NO_ACTION",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: strings.Repeat("00", 32)},
			},
		},
		{
			EventNum:  2,
			PCRIndex:  7,
			EventType: "EV_SEPARATOR",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: strings.Repeat("11", 32)},
			},
		},
		{
			EventNum:  3,
			PCRIndex:  14,
			EventType: "EV_ACTION",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: strings.Repeat("22", 32)},
			},
		},
	}

	pcrs := CalculatePCRs(events)

	sha256PCRs := pcrs["sha256"]
	if len(sha256PCRs) != 3 {
		t.Errorf("expected 3 PCRs, got %d", len(sha256PCRs))
	}

	for _, idx := range []int{0, 7, 14} {
		if _, exists := sha256PCRs[idx]; !exists {
			t.Errorf("expected PCR %d to exist", idx)
		}
	}
}

func TestCalculatePCRs_MultipleAlgorithms(t *testing.T) {
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
}

func TestCalculatePCRs_UnsupportedAlgorithm(t *testing.T) {
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
}

func TestCalculatePCRs_InvalidDigestHex(t *testing.T) {
	events := []Event{
		{
			EventNum:  1,
			PCRIndex:  0,
			EventType: "EV_NO_ACTION",
			Digests: []Digest{
				{AlgorithmId: "sha256", Digest: "invalid_hex_string"},
			},
		},
	}

	// Capture stderr for error message verification
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	pcrs := CalculatePCRs(events)

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	// Should not crash, but PCR won't be extended
	if pcrs == nil {
		t.Fatal("expected non-nil PCR map even with invalid digest")
	}
}

func TestCalculatePCRs_EmptyEvents(t *testing.T) {
	events := []Event{}
	pcrs := CalculatePCRs(events)

	if pcrs == nil {
		t.Fatal("expected non-nil PCR map")
	}

	// All algorithm maps should be empty
	for alg, algMap := range pcrs {
		if len(algMap) != 0 {
			t.Errorf("expected empty map for %s, got %d entries", alg, len(algMap))
		}
	}
}

func TestExtendPCR_SHA1(t *testing.T) {
	currentPCR := make([]byte, sha1.Size)
	digest := make([]byte, sha1.Size)
	for i := range digest {
		digest[i] = byte(i)
	}

	result, err := ExtendPCR(currentPCR, digest, "sha1")
	if err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}

	if len(result) != sha1.Size {
		t.Errorf("expected result size %d, got %d", sha1.Size, len(result))
	}

	// Verify manually
	hasher := sha1.New()
	hasher.Write(currentPCR)
	hasher.Write(digest)
	expected := hasher.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("SHA1 extension mismatch\nexpected: %x\ngot:      %x", expected, result)
	}
}

func TestExtendPCR_SHA256(t *testing.T) {
	currentPCR := make([]byte, sha256.Size)
	digest := make([]byte, sha256.Size)
	for i := range digest {
		digest[i] = byte(i * 2)
	}

	result, err := ExtendPCR(currentPCR, digest, "sha256")
	if err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}

	if len(result) != sha256.Size {
		t.Errorf("expected result size %d, got %d", sha256.Size, len(result))
	}

	// Verify manually
	hasher := sha256.New()
	hasher.Write(currentPCR)
	hasher.Write(digest)
	expected := hasher.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("SHA256 extension mismatch\nexpected: %x\ngot:      %x", expected, result)
	}
}

func TestExtendPCR_SHA384(t *testing.T) {
	currentPCR := make([]byte, sha512.Size384)
	digest := make([]byte, sha512.Size384)

	result, err := ExtendPCR(currentPCR, digest, "sha384")
	if err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}

	if len(result) != sha512.Size384 {
		t.Errorf("expected result size %d, got %d", sha512.Size384, len(result))
	}
}

func TestExtendPCR_SHA512(t *testing.T) {
	currentPCR := make([]byte, sha512.Size)
	digest := make([]byte, sha512.Size)

	result, err := ExtendPCR(currentPCR, digest, "sha512")
	if err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}

	if len(result) != sha512.Size {
		t.Errorf("expected result size %d, got %d", sha512.Size, len(result))
	}
}

func TestExtendPCR_UnsupportedAlgorithm(t *testing.T) {
	currentPCR := make([]byte, 32)
	digest := make([]byte, 32)

	_, err := ExtendPCR(currentPCR, digest, "unsupported")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported hash algorithm") {
		t.Errorf("expected 'unsupported hash algorithm' error, got: %v", err)
	}
}

func TestExtendPCR_ChainedExtensions(t *testing.T) {
	// Test that chained extensions produce correct result
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
}

func TestInitializePCRs_Coverage(t *testing.T) {
	pcrs := InitializePCRs()

	if pcrs == nil {
		t.Fatal("expected non-nil PCR map")
	}

	expectedAlgorithms := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, alg := range expectedAlgorithms {
		if _, exists := pcrs[alg]; !exists {
			t.Errorf("expected %s in PCR map", alg)
		}
		if pcrs[alg] == nil {
			t.Errorf("expected non-nil map for %s", alg)
		}
		if len(pcrs[alg]) != 0 {
			t.Errorf("expected empty map for %s, got %d entries", alg, len(pcrs[alg]))
		}
	}

	// Verify we can add to the maps
	pcrs["sha256"][0] = make([]byte, 32)
	if len(pcrs["sha256"]) != 1 {
		t.Errorf("expected 1 entry in sha256 map after adding")
	}
}

func TestInitializePCRs_Independence(t *testing.T) {
	pcrs1 := InitializePCRs()
	pcrs2 := InitializePCRs()

	// Modify pcrs1
	pcrs1["sha256"][0] = make([]byte, 32)

	// pcrs2 should be unaffected
	if len(pcrs2["sha256"]) != 0 {
		t.Error("expected pcrs2 to be independent of pcrs1")
	}
}

func TestGetDigestSize_Coverage(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  int
	}{
		{"sha1", 20},
		{"sha256", 32},
		{"sha384", 48},
		{"sha512", 64},
		{"sm3_256", 32},
		{"unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			size := GetDigestSize(tt.algorithm)
			if size != tt.expected {
				t.Errorf("GetDigestSize(%s) = %d, expected %d", tt.algorithm, size, tt.expected)
			}
		})
	}
}

func TestGetHashFunction_Coverage(t *testing.T) {
	tests := []struct {
		algorithm   string
		expectError bool
		expectedLen int
	}{
		{"sha1", false, 20},
		{"sha256", false, 32},
		{"sha384", false, 48},
		{"sha512", false, 64},
		{"unknown", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			hasher, err := GetHashFunction(tt.algorithm)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for algorithm %s", tt.algorithm)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for algorithm %s: %v", tt.algorithm, err)
				}
				if hasher == nil {
					t.Errorf("expected non-nil hasher for algorithm %s", tt.algorithm)
				} else {
					hasher.Write([]byte("test"))
					result := hasher.Sum(nil)
					if len(result) != tt.expectedLen {
						t.Errorf("expected hash length %d for %s, got %d", tt.expectedLen, tt.algorithm, len(result))
					}
				}
			}
		})
	}
}

func TestParseEventType_Coverage(t *testing.T) {
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
		{0x99999999, "Unknown (0x99999999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := parseEventType(tt.eventType)
			if result != tt.expected {
				t.Errorf("parseEventType(0x%x) = %s, expected %s", tt.eventType, result, tt.expected)
			}
		})
	}
}

func TestParseAlgorithmId_Coverage(t *testing.T) {
	tests := []struct {
		algID    uint16
		expected string
	}{
		{AlgSHA1, "sha1"},
		{AlgSHA256, "sha256"},
		{AlgSHA384, "sha384"},
		{AlgSHA512, "sha512"},
		{AlgSM3256, "sm3_256"},
		{AlgSM3256Alt, "sm3_256"},
		{0x9999, "unknown_0x9999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := parseAlgorithmId(tt.algID)
			if result != tt.expected {
				t.Errorf("parseAlgorithmId(0x%04x) = %s, expected %s", tt.algID, result, tt.expected)
			}
		})
	}
}

func TestParseEventString_Coverage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "simple ASCII string",
			data:     []byte("Hello World"),
			expected: "Hello World",
		},
		{
			name:     "string with binary prefix",
			data:     []byte{0x00, 0x01, 0x02, 'T', 'e', 's', 't'},
			expected: "Test",
		},
		{
			name:     "multiple printable sequences - returns longest",
			data:     []byte("short\x00\x01longer sequence\x00abc"),
			expected: "longer sequence",
		},
		{
			name:     "no printable characters",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: "",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "string with special characters",
			data:     []byte("Key=Value;Test!@#$%"),
			expected: "Key=Value;Test!@#$%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEventString(tt.data)
			if result != tt.expected {
				t.Errorf("parseEventString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetDigestSizeByAlgID_Coverage(t *testing.T) {
	tests := []struct {
		algID    uint16
		expected int
	}{
		{AlgSHA1, 20},
		{AlgSHA256, 32},
		{AlgSHA384, 48},
		{AlgSHA512, 64},
		{AlgSM3256, 32},
		{AlgSM3256Alt, 32},
		{0x0000, 0},
		{0x9999, 0},
	}

	for _, tt := range tests {
		t.Run(parseAlgorithmId(tt.algID), func(t *testing.T) {
			size := getDigestSizeByAlgID(tt.algID)
			if size != tt.expected {
				t.Errorf("getDigestSizeByAlgID(0x%04x) = %d, expected %d", tt.algID, size, tt.expected)
			}
		})
	}
}

func TestEstimateDigestSize_Coverage(t *testing.T) {
	tests := []struct {
		algID    uint16
		expected int
	}{
		{0x2000, 32}, // Vendor algorithm, estimate 32 bytes
		{0x2001, 32},
		{0x3000, 32},
		{0x0099, 0}, // Unknown standard algorithm, cannot estimate
		{0x1FFF, 0},
		{0x0000, 0},
	}

	for _, tt := range tests {
		t.Run(parseAlgorithmId(tt.algID), func(t *testing.T) {
			size := estimateDigestSize(tt.algID)
			if size != tt.expected {
				t.Errorf("estimateDigestSize(0x%04x) = %d, expected %d", tt.algID, size, tt.expected)
			}
		})
	}
}

func TestIsSupportedHashAlgorithm_Coverage(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  bool
	}{
		{"sha1", true},
		{"sha256", true},
		{"sha384", true},
		{"sha512", true},
		{"sm3_256", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			result := isSupportedHashAlgorithm(tt.algorithm)
			if result != tt.expected {
				t.Errorf("isSupportedHashAlgorithm(%s) = %v, expected %v", tt.algorithm, result, tt.expected)
			}
		})
	}
}

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

func TestDefaultParseEventLogOptions_Coverage(t *testing.T) {
	opts := DefaultParseEventLogOptions()

	if !opts.SkipUnknownAlgorithms {
		t.Error("expected SkipUnknownAlgorithms to be true by default")
	}
}
