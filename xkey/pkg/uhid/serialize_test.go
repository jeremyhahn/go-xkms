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

// TestOpenUHIDNotAvailable verifies that opening a UHID device that does
// not exist reports ErrUHIDNotAvailable. It drives openAt against a path
// inside a temp dir so the result does not depend on whether the host
// exposes /dev/uhid.

func TestSerializeCreate2RequestLargeReportDescriptor(t *testing.T) {
	// Test with a report descriptor larger than MaxReportDescriptorSize
	largeRdesc := make([]byte, MaxReportDescriptorSize+100)
	for i := range largeRdesc {
		largeRdesc[i] = byte(i % 256)
	}

	cfg := &CreateConfig{
		Name:             "Test",
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		ReportDescriptor: largeRdesc,
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify rd_size is capped at MaxReportDescriptorSize
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != MaxReportDescriptorSize {
		t.Errorf("rd_size = %d, want %d", rdSize, MaxReportDescriptorSize)
	}
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

func TestParseOutputEventTruncatedData(t *testing.T) {
	// Create a buffer that's too short (doesn't have the full structure)
	// The minimum required is: header(4) + data(4096) + size(2) = 4102 bytes
	buf := make([]byte, uhidEventHeaderSize+100) // Too short
	binary.LittleEndian.PutUint32(buf[0:4], UHID_OUTPUT)

	_, err := ParseOutputEvent(buf)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("ParseOutputEvent() error = %v, want %v", err, ErrInvalidPacket)
	}
}

func TestParseOutputEventSuccess(t *testing.T) {
	testData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	if len(data) != len(testData) {
		t.Errorf("data length = %d, want %d", len(data), len(testData))
	}

	for i, b := range testData {
		if data[i] != b {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], b)
		}
	}
}

func TestSerializeInput2RequestMaxSize(t *testing.T) {
	// Test with maximum size data
	maxData := make([]byte, MaxReportDescriptorSize)
	for i := range maxData {
		maxData[i] = byte(i % 256)
	}

	buf := SerializeInput2Request(maxData)
	if buf == nil {
		t.Fatal("SerializeInput2Request returned nil")
	}

	// Verify size field
	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	if int(size) != MaxReportDescriptorSize {
		t.Errorf("size = %d, want %d", size, MaxReportDescriptorSize)
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

func TestSerializeCreate2RequestAllFieldOffsets(t *testing.T) {
	// Verify all fields are at correct offsets in the serialized buffer
	cfg := &CreateConfig{
		Name:             "N",
		Phys:             "P",
		Uniq:             "U",
		VendorID:         0x1234,
		ProductID:        0x5678,
		Version:          0x9ABC,
		ReportDescriptor: []byte{0xFF},
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify each field offset
	tests := []struct {
		name   string
		offset int
		size   int
		check  func([]byte) bool
	}{
		{
			name:   "event_type",
			offset: 0,
			size:   4,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint32(b) == UHID_CREATE2
			},
		},
		{
			name:   "name",
			offset: uhidEventHeaderSize,
			size:   128,
			check: func(b []byte) bool {
				return b[0] == 'N' && b[1] == 0
			},
		},
		{
			name:   "phys",
			offset: uhidEventHeaderSize + 128,
			size:   64,
			check: func(b []byte) bool {
				return b[0] == 'P' && b[1] == 0
			},
		},
		{
			name:   "uniq",
			offset: uhidEventHeaderSize + 128 + 64,
			size:   64,
			check: func(b []byte) bool {
				return b[0] == 'U' && b[1] == 0
			},
		},
		{
			name:   "rd_size",
			offset: uhidEventHeaderSize + 128 + 64 + 64,
			size:   2,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint16(b) == 1
			},
		},
		{
			name:   "bus",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2,
			size:   2,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint16(b) == BUS_USB
			},
		},
		{
			name:   "vendor",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2,
			size:   4,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint32(b) == 0x1234
			},
		},
		{
			name:   "product",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2 + 4,
			size:   4,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint32(b) == 0x5678
			},
		},
		{
			name:   "version",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2 + 4 + 4,
			size:   4,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint32(b) == 0x9ABC
			},
		},
		{
			name:   "country",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4,
			size:   4,
			check: func(b []byte) bool {
				return binary.LittleEndian.Uint32(b) == 0
			},
		},
		{
			name:   "rd_data",
			offset: uhidEventHeaderSize + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4,
			size:   1,
			check: func(b []byte) bool {
				return b[0] == 0xFF
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slice := buf[tt.offset : tt.offset+tt.size]
			if !tt.check(slice) {
				t.Errorf("%s: invalid value at offset %d", tt.name, tt.offset)
			}
		})
	}
}

func TestSerializeCreate2RequestPhysTruncation(t *testing.T) {
	// Test that phys field is truncated to 63 characters
	longPhys := make([]byte, 100)
	for i := range longPhys {
		longPhys[i] = 'P'
	}

	cfg := &CreateConfig{
		Name:             "Test",
		Phys:             string(longPhys),
		Uniq:             "U",
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify phys is truncated
	offset := uhidEventHeaderSize + 128
	for i := 0; i < 63; i++ {
		if buf[offset+i] != 'P' {
			t.Errorf("phys byte %d = %c, want 'P'", i, buf[offset+i])
		}
	}
	// Byte 63 should be null (truncated)
	if buf[offset+63] != 0 {
		t.Errorf("phys byte 63 = %d, want 0 (null terminator)", buf[offset+63])
	}
}

func TestSerializeCreate2RequestUniqTruncation(t *testing.T) {
	// Test that uniq field is truncated to 63 characters
	longUniq := make([]byte, 100)
	for i := range longUniq {
		longUniq[i] = 'U'
	}

	cfg := &CreateConfig{
		Name:             "Test",
		Phys:             "P",
		Uniq:             string(longUniq),
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify uniq is truncated
	offset := uhidEventHeaderSize + 128 + 64
	for i := 0; i < 63; i++ {
		if buf[offset+i] != 'U' {
			t.Errorf("uniq byte %d = %c, want 'U'", i, buf[offset+i])
		}
	}
	// Byte 63 should be null (truncated)
	if buf[offset+63] != 0 {
		t.Errorf("uniq byte 63 = %d, want 0 (null terminator)", buf[offset+63])
	}
}

func TestSerializeCreate2RequestEmptyFields(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "",
		Phys:             "",
		Uniq:             "",
		VendorID:         0,
		ProductID:        0,
		Version:          0,
		ReportDescriptor: nil,
	}

	buf := SerializeCreate2Request(cfg)
	if buf == nil {
		t.Fatal("SerializeCreate2Request returned nil")
	}

	// Verify buffer was created with proper size
	expectedSize := uhidEventHeaderSize + uhidCreate2ReqSize
	if len(buf) != expectedSize {
		t.Errorf("buffer size = %d, want %d", len(buf), expectedSize)
	}

	// Verify event type is set
	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_CREATE2 {
		t.Errorf("event type = %d, want %d", eventType, UHID_CREATE2)
	}

	// Verify default report descriptor is used
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != len(FIDO2HIDReportDescriptor) {
		t.Errorf("rd_size = %d, want %d", rdSize, len(FIDO2HIDReportDescriptor))
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

func TestSerializeInput2RequestSingleByte(t *testing.T) {
	data := []byte{0xAB}
	buf := SerializeInput2Request(data)
	if buf == nil {
		t.Fatal("SerializeInput2Request returned nil")
	}

	// Verify size
	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	if size != 1 {
		t.Errorf("size = %d, want 1", size)
	}

	// Verify data
	if buf[uhidEventHeaderSize+2] != 0xAB {
		t.Errorf("data byte = 0x%02X, want 0xAB", buf[uhidEventHeaderSize+2])
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

func TestParseOutputEventLargerBuffer(t *testing.T) {
	// Create output event with data smaller than max
	dataSize := 10
	testData := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		testData[i] = byte(i + 100)
	}

	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// Should only return claimed size
	if len(data) != dataSize {
		t.Errorf("data length = %d, want %d", len(data), dataSize)
	}

	// Verify data content
	for i := 0; i < dataSize; i++ {
		if data[i] != byte(i+100) {
			t.Errorf("data[%d] = %d, want %d", i, data[i], i+100)
		}
	}
}

func TestParseOutputEventAllReportTypes(t *testing.T) {
	// Test various report types (rtype field)
	reportTypes := []byte{0x00, 0x01, 0x02, 0xFF}

	for _, rtype := range reportTypes {
		t.Run("rtype_"+string(rtype+'0'), func(t *testing.T) {
			testData := []byte{0x01, 0x02, 0x03}
			buf := createOutputEventBuffer(testData, rtype)

			data, err := ParseOutputEvent(buf)
			if err != nil {
				t.Fatalf("ParseOutputEvent() error = %v", err)
			}

			if len(data) != len(testData) {
				t.Errorf("data length = %d, want %d", len(data), len(testData))
			}
		})
	}
}

func TestSerializeCreate2RequestBufferSize(t *testing.T) {
	cfg := DefaultCreateConfig()
	buf := SerializeCreate2Request(cfg)

	expectedSize := uhidEventHeaderSize + uhidCreate2ReqSize
	if len(buf) != expectedSize {
		t.Errorf("buffer size = %d, want %d", len(buf), expectedSize)
	}
}

func TestSerializeInput2RequestBufferSize(t *testing.T) {
	data := make([]byte, HIDReportSize)
	buf := SerializeInput2Request(data)

	expectedSize := uhidEventHeaderSize + uhidInput2ReqSize
	if len(buf) != expectedSize {
		t.Errorf("buffer size = %d, want %d", len(buf), expectedSize)
	}
}

// TestParseOutputEventWithReportID tests the Report ID stripping logic.
// When the HID report descriptor doesn't define explicit Report IDs,
// the kernel prepends a Report ID byte (0x00) to the output data.
// For FIDO2 HID, we expect 65 bytes (1 byte Report ID + 64 bytes HID packet).
// ParseOutputEvent should strip the Report ID byte and return the raw 64-byte HID packet.

// TestParseOutputEventWithReportID tests the Report ID stripping logic.
// When the HID report descriptor doesn't define explicit Report IDs,
// the kernel prepends a Report ID byte (0x00) to the output data.
// For FIDO2 HID, we expect 65 bytes (1 byte Report ID + 64 bytes HID packet).
// ParseOutputEvent should strip the Report ID byte and return the raw 64-byte HID packet.
func TestParseOutputEventWithReportID(t *testing.T) {
	// Create a 65-byte payload: Report ID (0x00) + 64 bytes of data
	// This simulates the kernel behavior when no explicit Report IDs are defined
	reportID := byte(0x00)
	hidPacket := make([]byte, HIDReportSize) // 64 bytes
	for i := 0; i < HIDReportSize; i++ {
		hidPacket[i] = byte(i + 1) // 1, 2, 3, ... 64
	}

	// Combine Report ID + HID packet
	fullData := make([]byte, HIDReportSize+1) // 65 bytes
	fullData[0] = reportID
	copy(fullData[1:], hidPacket)

	buf := createOutputEventBuffer(fullData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// ParseOutputEvent should strip the Report ID and return 64 bytes
	if len(data) != HIDReportSize {
		t.Errorf("data length = %d, want %d (Report ID should be stripped)", len(data), HIDReportSize)
	}

	// Verify the data matches the HID packet (without Report ID)
	for i := 0; i < HIDReportSize; i++ {
		expected := byte(i + 1)
		if data[i] != expected {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], expected)
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

// TestParseOutputEvent63Bytes tests that 63 bytes is NOT treated as Report ID case.

// TestParseOutputEvent63Bytes tests that 63 bytes is NOT treated as Report ID case.
func TestParseOutputEvent63Bytes(t *testing.T) {
	// 63 bytes should NOT trigger Report ID stripping
	dataSize := HIDReportSize - 1 // 63 bytes
	testData := make([]byte, dataSize)
	for i := 0; i < dataSize; i++ {
		testData[i] = byte(i + 10)
	}

	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	// Should return all 63 bytes
	if len(data) != dataSize {
		t.Errorf("data length = %d, want %d", len(data), dataSize)
	}

	for i := 0; i < dataSize; i++ {
		expected := byte(i + 10)
		if data[i] != expected {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, data[i], expected)
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

// TestDeviceWriteInputEmptyData tests WriteInput with empty data.

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

// TestParseOutputEventSingleByte tests parsing a single byte output.

// TestParseOutputEventSingleByte tests parsing a single byte output.
func TestParseOutputEventSingleByte(t *testing.T) {
	testData := []byte{0xAA}
	buf := createOutputEventBuffer(testData, 0x00)

	data, err := ParseOutputEvent(buf)
	if err != nil {
		t.Fatalf("ParseOutputEvent() error = %v", err)
	}

	if len(data) != 1 {
		t.Errorf("data length = %d, want 1", len(data))
	}

	if data[0] != 0xAA {
		t.Errorf("data[0] = 0x%02X, want 0xAA", data[0])
	}
}

// The following tests exercise the Linux UHID wire-format helpers
// (SerializeCreate2Request, SerializeInput2Request, ParseOutputEvent).
// They live in the linux-tagged file because those helpers only exist on
// Linux; they run unconditionally wherever the code under test is built.

func TestUHIDCreate2RequestSerialization(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "Test FIDO2 Device",
		Phys:             "test-phys-path",
		Uniq:             "SERIAL001",
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		Version:          0x0100,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)

	// Verify buffer size
	expectedSize := uhidEventHeaderSize + uhidCreate2ReqSize
	if len(buf) != expectedSize {
		t.Errorf("Buffer size = %d, want %d", len(buf), expectedSize)
	}

	// Verify event type
	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_CREATE2 {
		t.Errorf("Event type = %d, want %d (UHID_CREATE2)", eventType, UHID_CREATE2)
	}

	// Verify name is at correct offset
	offset := uhidEventHeaderSize
	name := string(buf[offset : offset+len(cfg.Name)])
	if name != cfg.Name {
		t.Errorf("Name = %q, want %q", name, cfg.Name)
	}

	// Verify phys is at correct offset
	offset += 128
	phys := string(buf[offset : offset+len(cfg.Phys)])
	if phys != cfg.Phys {
		t.Errorf("Phys = %q, want %q", phys, cfg.Phys)
	}

	// Verify uniq is at correct offset
	offset += 64
	uniq := string(buf[offset : offset+len(cfg.Uniq)])
	if uniq != cfg.Uniq {
		t.Errorf("Uniq = %q, want %q", uniq, cfg.Uniq)
	}

	// Verify rd_size
	offset += 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != len(FIDO2HIDReportDescriptor) {
		t.Errorf("rd_size = %d, want %d", rdSize, len(FIDO2HIDReportDescriptor))
	}

	// Verify bus type
	offset += 2
	bus := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if bus != BUS_USB {
		t.Errorf("bus = 0x%04X, want 0x%04X", bus, BUS_USB)
	}

	// Verify vendor ID
	offset += 2
	vendor := binary.LittleEndian.Uint32(buf[offset : offset+4])
	if vendor != uint32(cfg.VendorID) {
		t.Errorf("vendor = 0x%08X, want 0x%08X", vendor, cfg.VendorID)
	}

	// Verify product ID
	offset += 4
	product := binary.LittleEndian.Uint32(buf[offset : offset+4])
	if product != uint32(cfg.ProductID) {
		t.Errorf("product = 0x%08X, want 0x%08X", product, cfg.ProductID)
	}

	// Verify version
	offset += 4
	version := binary.LittleEndian.Uint32(buf[offset : offset+4])
	if version != uint32(cfg.Version) {
		t.Errorf("version = 0x%08X, want 0x%08X", version, cfg.Version)
	}

	// Verify country (should be 0)
	offset += 4
	country := binary.LittleEndian.Uint32(buf[offset : offset+4])
	if country != 0 {
		t.Errorf("country = %d, want 0", country)
	}

	// Verify report descriptor data
	offset += 4
	for i, b := range FIDO2HIDReportDescriptor {
		if buf[offset+i] != b {
			t.Errorf("rd_data[%d] = 0x%02X, want 0x%02X", i, buf[offset+i], b)
		}
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

func TestUHIDInput2RequestSerialization(t *testing.T) {
	testData := make([]byte, HIDReportSize)
	for i := range testData {
		testData[i] = byte(i)
	}

	buf := SerializeInput2Request(testData)

	// Verify event type
	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_INPUT2 {
		t.Errorf("Event type = %d, want %d (UHID_INPUT2)", eventType, UHID_INPUT2)
	}

	// Verify size
	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	if int(size) != len(testData) {
		t.Errorf("Size = %d, want %d", size, len(testData))
	}

	// Verify data
	for i, b := range testData {
		if buf[uhidEventHeaderSize+2+i] != b {
			t.Errorf("data[%d] = 0x%02X, want 0x%02X", i, buf[uhidEventHeaderSize+2+i], b)
		}
	}
}

func TestUHIDInput2RequestSerializationEmptyData(t *testing.T) {
	buf := SerializeInput2Request([]byte{})

	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_INPUT2 {
		t.Errorf("Event type = %d, want %d", eventType, UHID_INPUT2)
	}

	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	if size != 0 {
		t.Errorf("Size = %d, want 0", size)
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

func TestCreateConfigLongStrings(t *testing.T) {
	// Create config with strings longer than the maximum allowed
	longString := make([]byte, 200)
	for i := range longString {
		longString[i] = 'A'
	}

	cfg := &CreateConfig{
		Name:             string(longString),
		Phys:             string(longString),
		Uniq:             string(longString),
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		Version:          0x0100,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)

	// Verify name is truncated to 127 chars (with null terminator in 128 byte field)
	offset := uhidEventHeaderSize
	for i := 0; i < 127; i++ {
		if buf[offset+i] != 'A' {
			t.Errorf("Name byte %d = %c, want 'A'", i, buf[offset+i])
		}
	}
	// Byte 127 should be null (truncated)
	if buf[offset+127] != 0 {
		t.Errorf("Name byte 127 = %d, want 0 (null terminator)", buf[offset+127])
	}
}

func TestCreateConfigEmptyReportDescriptor(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "Test",
		VendorID:         0xF1D0,
		ProductID:        0x0001,
		ReportDescriptor: nil, // Should use default
	}

	buf := SerializeCreate2Request(cfg)

	// Verify default report descriptor is used
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != len(FIDO2HIDReportDescriptor) {
		t.Errorf("rd_size = %d, want %d (default descriptor length)", rdSize, len(FIDO2HIDReportDescriptor))
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
