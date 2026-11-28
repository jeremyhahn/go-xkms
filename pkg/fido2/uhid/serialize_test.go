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

package uhid

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Tests for the UHID wire-format codec (serialize.go). They are deliberately
// NOT build-tagged: the codec is pure byte packing, so the exact bytes the
// Linux device writes to /dev/uhid are verified on every platform the GUI
// builds for. They used to live in the //go:build linux test file, which meant
// a regression in the wire format was invisible on any other platform even
// though the code under test was compiled there.

// createOutputEventBuffer creates a properly formatted UHID_OUTPUT event buffer.
// The Linux kernel uhid_output_req structure is:
//
//	__u8 data[UHID_DATA_MAX];  // 4096 bytes - data FIRST
//	__u16 size;                // 2 bytes - actual size of data
//	__u8 rtype;                // 1 byte - report type
//
// This function creates the correct buffer layout for testing ParseOutputEvent.
func createOutputEventBuffer(data []byte, rtype byte) []byte {
	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)
	binary.LittleEndian.PutUint32(buf[0:4], UHID_OUTPUT)

	// Copy data to beginning of payload (after event header)
	copy(buf[uhidEventHeaderSize:], data)

	// Set size at offset 4096 (after data array)
	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	binary.LittleEndian.PutUint16(buf[sizeOffset:sizeOffset+2], uint16(len(data)))

	// Set rtype at offset 4098
	buf[sizeOffset+2] = rtype

	return buf
}

func TestParseOutputEventDataSizeTooLarge(t *testing.T) {
	// Create a properly formatted buffer with an impossibly large data size
	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)
	binary.LittleEndian.PutUint32(buf[0:4], UHID_OUTPUT)

	// Set size larger than MaxReportDescriptorSize at the correct offset
	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	binary.LittleEndian.PutUint16(buf[sizeOffset:sizeOffset+2], uint16(MaxReportDescriptorSize+1))
	buf[sizeOffset+2] = 0x00 // rtype

	_, err := ParseOutputEvent(buf)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("ParseOutputEvent() error = %v, want %v", err, ErrInvalidPacket)
	}
}

func TestParseOutputEventZeroLength(t *testing.T) {
	// Create a valid output event with zero-length data
	// Note: ParseOutputEvent rejects zero-size data as invalid
	buf := createOutputEventBuffer([]byte{}, 0x00)

	_, err := ParseOutputEvent(buf)
	// Zero data size should return an error
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("ParseOutputEvent() with zero size error = %v, want %v", err, ErrInvalidPacket)
	}
}

func TestSerializeInput2RequestEmpty(t *testing.T) {
	buf := SerializeInput2Request(nil)
	if buf == nil {
		t.Fatal("SerializeInput2Request returned nil")
	}

	// Verify event type
	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_INPUT2 {
		t.Errorf("event type = %d, want %d", eventType, UHID_INPUT2)
	}

	// Verify size is 0
	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	if size != 0 {
		t.Errorf("size = %d, want 0", size)
	}
}

func TestParseOutputEventExactSize(t *testing.T) {
	// Create output event with exact claimed size (64 bytes for FIDO2 HID)
	dataSize := 64
	testData := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		testData[i] = byte(i)
	}

	buf := createOutputEventBuffer(testData, 0x01)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	if len(data) != dataSize {
		t.Errorf("data length = %d, want %d", len(data), dataSize)
	}

	// Verify data content
	for i := 0; i < dataSize; i++ {
		if data[i] != byte(i) {
			t.Errorf("data[%d] = %d, want %d", i, data[i], i)
		}
	}
}

// TestParseOutputEventWithReportIDNonZero tests Report ID stripping with non-zero Report ID.

// TestParseOutputEventWithReportIDNonZero tests Report ID stripping with non-zero Report ID.
func TestParseOutputEventWithReportIDNonZero(t *testing.T) {
	// Test with a non-zero Report ID
	reportID := byte(0x01)
	hidPacket := make([]byte, HIDReportSize)
	for i := 0; i < HIDReportSize; i++ {
		hidPacket[i] = byte(0xFF - i)
	}

	fullData := make([]byte, HIDReportSize+1)
	fullData[0] = reportID
	copy(fullData[1:], hidPacket)

	buf := createOutputEventBuffer(fullData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// Should return 64 bytes (Report ID stripped)
	if len(data) != HIDReportSize {
		t.Errorf("data length = %d, want %d", len(data), HIDReportSize)
	}

	// Verify data content (should be hidPacket, not fullData)
	for i := 0; i < HIDReportSize; i++ {
		expected := byte(0xFF - i)
		if data[i] != expected {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], expected)
		}
	}
}

// TestParseOutputEvent66Bytes tests that 66 bytes is NOT treated as Report ID case.
// Only exactly 65 bytes (HIDReportSize+1) triggers Report ID stripping.

// TestParseOutputEvent66Bytes tests that 66 bytes is NOT treated as Report ID case.
// Only exactly 65 bytes (HIDReportSize+1) triggers Report ID stripping.
func TestParseOutputEvent66Bytes(t *testing.T) {
	// 66 bytes should NOT trigger Report ID stripping
	dataSize := HIDReportSize + 2 // 66 bytes
	testData := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		testData[i] = byte(i)
	}

	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// Should return all 66 bytes (no Report ID stripping)
	if len(data) != dataSize {
		t.Errorf("data length = %d, want %d (no Report ID stripping expected)", len(data), dataSize)
	}

	// Verify all data is preserved
	for i := 0; i < dataSize; i++ {
		if data[i] != byte(i) {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], byte(i))
		}
	}
}

// TestParseOutputEventMaxSizeWithReportIDStripping ensures large data doesn't trigger false Report ID stripping.

// TestParseOutputEventMaxSizeWithReportIDStripping ensures large data doesn't trigger false Report ID stripping.
func TestParseOutputEventMaxSizeWithReportIDStripping(t *testing.T) {
	// Test with maximum size data (4096 bytes) - should NOT trigger Report ID stripping
	dataSize := MaxReportDescriptorSize
	testData := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		testData[i] = byte(i % 256)
	}

	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// Should return full 4096 bytes (no stripping for max size)
	if len(data) != dataSize {
		t.Errorf("data length = %d, want %d", len(data), dataSize)
	}
}

// TestSerializeCreate2RequestNilReportDescriptor tests explicit nil report descriptor handling.
func TestSerializeCreate2RequestNilReportDescriptor(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "TestDevice",
		Phys:             "test-phys",
		Uniq:             "SERIAL",
		VendorID:         0x1234,
		ProductID:        0x5678,
		Version:          0x0100,
		ReportDescriptor: nil, // Explicit nil
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify default FIDO2 report descriptor is used
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != len(FIDO2HIDReportDescriptor) {
		t.Errorf("rd_size = %d, want %d (default FIDO2 descriptor)", rdSize, len(FIDO2HIDReportDescriptor))
	}

	// Verify the actual descriptor bytes
	rdOffset := uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4
	for i, expected := range FIDO2HIDReportDescriptor {
		if buf[rdOffset+i] != expected {
			t.Errorf("rd_data[%d] = 0x%02X, want 0x%02X", i, buf[rdOffset+i], expected)
		}
	}
}

// TestSerializeCreate2RequestEmptyReportDescriptor tests explicit empty report descriptor.

// TestSerializeCreate2RequestEmptyReportDescriptor tests explicit empty report descriptor.
func TestSerializeCreate2RequestEmptyReportDescriptor(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "TestDevice",
		VendorID:         0x1234,
		ProductID:        0x5678,
		ReportDescriptor: []byte{}, // Explicit empty (not nil)
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Empty slice is different from nil - should use the empty slice, not default
	// But looking at the implementation, it checks for nil specifically
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	// Empty slice results in 0 size
	if rdSize != 0 {
		t.Errorf("rd_size = %d, want 0 for empty descriptor", rdSize)
	}
}

// TestDeviceCreateWithAllTruncatedFields tests Create with all fields requiring truncation.

// TestDeviceCreateWithAllTruncatedFields tests Create with all fields requiring truncation.
func TestDeviceCreateWithAllTruncatedFields(t *testing.T) {
	// Create config with all fields at maximum or over-length
	longName := make([]byte, 200)
	longPhys := make([]byte, 100)
	longUniq := make([]byte, 100)
	longRdesc := make([]byte, MaxReportDescriptorSize+500)

	for i := range longName {
		longName[i] = 'N'
	}
	for i := range longPhys {
		longPhys[i] = 'P'
	}
	for i := range longUniq {
		longUniq[i] = 'U'
	}
	for i := range longRdesc {
		longRdesc[i] = byte(i % 256)
	}

	cfg := &CreateConfig{
		Name:             string(longName),
		Phys:             string(longPhys),
		Uniq:             string(longUniq),
		VendorID:         0xFFFF,
		ProductID:        0xFFFF,
		Version:          0xFFFF,
		ReportDescriptor: longRdesc,
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify all fields are properly truncated
	// Name: 127 chars max
	nameOffset := uhidEventHeaderSize
	for i := 0; i < 127; i++ {
		if buf[nameOffset+i] != 'N' {
			t.Errorf("name[%d] = %c, want 'N'", i, buf[nameOffset+i])
		}
	}
	if buf[nameOffset+127] != 0 {
		t.Errorf("name[127] should be null terminator")
	}

	// Phys: 63 chars max
	physOffset := uhidEventHeaderSize + 128
	for i := 0; i < 63; i++ {
		if buf[physOffset+i] != 'P' {
			t.Errorf("phys[%d] = %c, want 'P'", i, buf[physOffset+i])
		}
	}
	if buf[physOffset+63] != 0 {
		t.Errorf("phys[63] should be null terminator")
	}

	// Uniq: 63 chars max
	uniqOffset := uhidEventHeaderSize + 128 + 64
	for i := 0; i < 63; i++ {
		if buf[uniqOffset+i] != 'U' {
			t.Errorf("uniq[%d] = %c, want 'U'", i, buf[uniqOffset+i])
		}
	}
	if buf[uniqOffset+63] != 0 {
		t.Errorf("uniq[63] should be null terminator")
	}

	// Report descriptor: 4096 bytes max
	rdSizeOffset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[rdSizeOffset : rdSizeOffset+2])
	if int(rdSize) != MaxReportDescriptorSize {
		t.Errorf("rd_size = %d, want %d", rdSize, MaxReportDescriptorSize)
	}
}

func TestUHIDCreate2RequestSerializationWithNilConfig(t *testing.T) {
	buf := SerializeCreate2Request(nil)

	// Should use default config
	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_CREATE2 {
		t.Errorf("Event type = %d, want %d", eventType, UHID_CREATE2)
	}
}

func TestUHIDOutputEventDeserialization(t *testing.T) {
	// Create a mock UHID_OUTPUT event buffer matching the Linux kernel structure:
	// struct uhid_output_req {
	//     __u8 data[UHID_DATA_MAX];  // 4096 bytes - data FIRST
	//     __u16 size;                // 2 bytes - actual size of data
	//     __u8 rtype;                // 1 byte - report type
	// };
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)

	// Event type
	binary.LittleEndian.PutUint32(buf[0:4], UHID_OUTPUT)

	// Data (at start of payload, after event header)
	copy(buf[uhidEventHeaderSize:], testData)

	// Size (at offset 4096 after data array)
	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	binary.LittleEndian.PutUint16(buf[sizeOffset:sizeOffset+2], uint16(len(testData)))

	// Report type (1 byte after size)
	buf[sizeOffset+2] = 0x00 // Output report

	data, err := ParseOutputEvent(buf)

	if err != nil {
		t.Fatalf("ParseOutputEvent failed: %v", err)
	}

	if len(data) != len(testData) {
		t.Errorf("Data length = %d, want %d", len(data), len(testData))
	}

	for i, b := range testData {
		if data[i] != b {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], b)
		}
	}
}

func TestUHIDOutputEventDeserializationErrors(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		wantErr error
	}{
		{
			name:    "Empty buffer",
			buf:     []byte{},
			wantErr: ErrInvalidPacket,
		},
		{
			name:    "Buffer too short for header",
			buf:     []byte{0x01, 0x02},
			wantErr: ErrInvalidPacket,
		},
		{
			name: "Wrong event type",
			buf: func() []byte {
				b := make([]byte, uhidEventHeaderSize+10)
				binary.LittleEndian.PutUint32(b[0:4], UHID_INPUT2) // Wrong type
				return b
			}(),
			wantErr: ErrInvalidPacket,
		},
		{
			name: "Output event too short",
			buf: func() []byte {
				b := make([]byte, uhidEventHeaderSize+2) // Missing rtype
				binary.LittleEndian.PutUint32(b[0:4], UHID_OUTPUT)
				return b
			}(),
			wantErr: ErrInvalidPacket,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseOutputEvent(tt.buf)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseOutputEvent error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestSerializeCreate2RequestGoldenWireFormat pins the entire UHID_CREATE2
// buffer, byte for byte, against an independently constructed expectation.
// The offsets below come from the kernel's uhid_create2_req; a field that
// moves or changes width breaks the virtual FIDO2 authenticator at runtime in
// ways a "no error returned" assertion would never notice.
func TestSerializeCreate2RequestGoldenWireFormat(t *testing.T) {
	rdesc := []byte{0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0xC0}
	cfg := &CreateConfig{
		Name:             "xkey-auth",
		Phys:             "xkey-phys",
		Uniq:             "xkey-uniq",
		VendorID:         0x1209,
		ProductID:        0xBEEF,
		Version:          0x0102,
		ReportDescriptor: rdesc,
	}

	want := make([]byte, uhidEventHeaderSize+uhidCreate2ReqSize)
	binary.LittleEndian.PutUint32(want[0:4], UHID_CREATE2)
	copy(want[4:132], "xkey-auth")   // name[128]
	copy(want[132:196], "xkey-phys") // phys[64]
	copy(want[196:260], "xkey-uniq") // uniq[64]
	binary.LittleEndian.PutUint16(want[260:262], uint16(len(rdesc)))
	binary.LittleEndian.PutUint16(want[262:264], BUS_USB)
	binary.LittleEndian.PutUint32(want[264:268], 0x1209)
	binary.LittleEndian.PutUint32(want[268:272], 0xBEEF)
	binary.LittleEndian.PutUint32(want[272:276], 0x0102)
	binary.LittleEndian.PutUint32(want[276:280], 0) // country
	copy(want[280:], rdesc)

	got := SerializeCreate2Request(cfg)
	if len(got) != len(want) {
		t.Fatalf("buffer length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = 0x%02X, want 0x%02X (UHID_CREATE2 wire format changed)", i, got[i], want[i])
		}
	}
}

// TestSerializeInput2RequestGoldenWireFormat pins the UHID_INPUT2 buffer byte
// for byte, including the zero padding after the report: the kernel reads a
// fixed-size structure, so a short or misaligned buffer is rejected outright.
func TestSerializeInput2RequestGoldenWireFormat(t *testing.T) {
	report := make([]byte, HIDReportSize)
	for i := range report {
		report[i] = byte(0xA0 + i%16)
	}

	want := make([]byte, uhidEventHeaderSize+uhidInput2ReqSize)
	binary.LittleEndian.PutUint32(want[0:4], UHID_INPUT2)
	binary.LittleEndian.PutUint16(want[4:6], uint16(HIDReportSize))
	copy(want[6:], report)

	got := SerializeInput2Request(report)
	if len(got) != len(want) {
		t.Fatalf("buffer length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = 0x%02X, want 0x%02X (UHID_INPUT2 wire format changed)", i, got[i], want[i])
		}
	}
}

// TestSerializeInput2RequestTruncatesOverlongReport verifies the bad-input
// path: a report larger than the kernel structure is truncated rather than
// producing an over-long buffer (which the kernel would reject) or panicking.
func TestSerializeInput2RequestTruncatesOverlongReport(t *testing.T) {
	oversized := make([]byte, MaxReportDescriptorSize+256)
	for i := range oversized {
		oversized[i] = byte(i % 251)
	}

	got := SerializeInput2Request(oversized)
	if len(got) != uhidEventHeaderSize+uhidInput2ReqSize {
		t.Fatalf("buffer length = %d, want %d", len(got), uhidEventHeaderSize+uhidInput2ReqSize)
	}
	size := binary.LittleEndian.Uint16(got[4:6])
	if int(size) != MaxReportDescriptorSize {
		t.Fatalf("size field = %d, want %d (the report must be clamped, not wrapped)", size, MaxReportDescriptorSize)
	}
	for i := 0; i < MaxReportDescriptorSize; i++ {
		if got[6+i] != oversized[i] {
			t.Fatalf("payload byte %d = 0x%02X, want 0x%02X", i, got[6+i], oversized[i])
		}
	}
}

// TestParseOutputEventRoundTrip feeds ParseOutputEvent a buffer laid out
// exactly like the kernel's uhid_output_req (data first, then size, then
// rtype) and checks the report comes back intact — the decode half of the
// wire-format contract the encode tests above pin.
func TestParseOutputEventRoundTrip(t *testing.T) {
	report := make([]byte, HIDReportSize)
	for i := range report {
		report[i] = byte(0x10 + i%32)
	}

	// The kernel prepends a report-ID byte when the descriptor declares no
	// explicit report IDs, which is the FIDO2 case.
	withReportID := append([]byte{0x00}, report...)
	// rtype 1 is UHID_OUTPUT_REPORT in the kernel's uhid enum; the parser
	// ignores it, so any value must round-trip the report unchanged.
	buf := createOutputEventBuffer(withReportID, 1)

	got, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent: %v", err)
	}
	if len(got) != HIDReportSize {
		t.Fatalf("report length = %d, want %d (the report ID must be stripped)", len(got), HIDReportSize)
	}
	for i := range report {
		if got[i] != report[i] {
			t.Fatalf("report byte %d = 0x%02X, want 0x%02X", i, got[i], report[i])
		}
	}
}
