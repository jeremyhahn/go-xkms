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

//go:build linux

package uhid

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"
)

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

func TestOpenUHIDNotAvailable(t *testing.T) {
	// This test verifies that Open returns ErrUHIDNotAvailable when /dev/uhid doesn't exist.
	// In a containerized or unprivileged environment, /dev/uhid may not be present.

	// Check if /dev/uhid exists
	_, err := os.Stat(UHIDDevicePath)
	if err == nil {
		// /dev/uhid exists, skip this test (it would succeed)
		t.Skip("/dev/uhid exists, skipping unavailable test")
	}

	device, err := Open()
	if device != nil {
		_ = device.Close()
	}

	if !errors.Is(err, ErrUHIDNotAvailable) {
		t.Errorf("Open() error = %v, want %v", err, ErrUHIDNotAvailable)
	}
}

func TestDeviceCreateOnClosedDevice(t *testing.T) {
	// Create a device manually without a real file handle
	device := &Device{}
	device.closed.Store(true)

	err := device.Create(nil)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceReadOutputOnClosedDevice(t *testing.T) {
	device := &Device{}
	device.closed.Store(true)

	_, err := device.ReadOutput()
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("ReadOutput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputOnClosedDevice(t *testing.T) {
	device := &Device{}
	device.closed.Store(true)

	err := device.WriteInput([]byte{0x01, 0x02, 0x03})
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputDataTooLarge(t *testing.T) {
	device := &Device{}
	// Device is not closed but has no file handle

	largeData := make([]byte, MaxReportDescriptorSize+1)
	err := device.WriteInput(largeData)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrInvalidPacket)
	}
}

func TestDeviceCloseIdempotent(t *testing.T) {
	device := &Device{}

	// First close should succeed
	err := device.Close()
	if err != nil {
		t.Errorf("First Close() error = %v, want nil", err)
	}

	// Second close should also succeed (idempotent)
	err = device.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v, want nil", err)
	}
}

func TestDeviceIsCreated(t *testing.T) {
	device := &Device{}

	if device.IsCreated() {
		t.Error("IsCreated() = true, want false")
	}

	device.created.Store(true)

	if !device.IsCreated() {
		t.Error("IsCreated() = false, want true")
	}
}

func TestDeviceIsClosed(t *testing.T) {
	device := &Device{}

	if device.IsClosed() {
		t.Error("IsClosed() = true, want false")
	}

	device.closed.Store(true)

	if !device.IsClosed() {
		t.Error("IsClosed() = false, want true")
	}
}

func TestDeviceFdNotOpen(t *testing.T) {
	device := &Device{}

	fd := device.Fd()
	if fd != -1 {
		t.Errorf("Fd() = %d, want -1", fd)
	}
}

func TestDeviceSetReadTimeout(t *testing.T) {
	device := &Device{}

	// Set timeout
	device.SetReadTimeout(5 * time.Second)

	device.mu.Lock()
	timeout := device.readTimeout
	device.mu.Unlock()

	if timeout != 5*time.Second {
		t.Errorf("readTimeout = %v, want %v", timeout, 5*time.Second)
	}

	// Set zero timeout
	device.SetReadTimeout(0)

	device.mu.Lock()
	timeout = device.readTimeout
	device.mu.Unlock()

	if timeout != 0 {
		t.Errorf("readTimeout = %v, want 0", timeout)
	}
}

func TestDeviceSetNonBlockingNotOpen(t *testing.T) {
	device := &Device{}

	err := device.SetNonBlocking(true)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("SetNonBlocking() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceCreateAlreadyCreated(t *testing.T) {
	device := &Device{}
	device.created.Store(true)

	err := device.Create(nil)
	if !errors.Is(err, ErrDeviceAlreadyCreated) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceAlreadyCreated)
	}
}

func TestDeviceReadOutputNilFile(t *testing.T) {
	device := &Device{}
	// Not closed, but file is nil

	_, err := device.ReadOutput()
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("ReadOutput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputNilFile(t *testing.T) {
	device := &Device{}
	// Not closed, but file is nil

	// Small data to avoid ErrInvalidPacket
	err := device.WriteInput([]byte{0x01})
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

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

func TestDeviceCreateWithNilFile(t *testing.T) {
	device := &Device{}
	// Device is not closed or created, but has nil file

	err := device.Create(DefaultCreateConfig())
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceNotOpen)
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

func TestDeviceCloseWithCreatedFlag(t *testing.T) {
	// Test Close behavior when device is marked as created (should send UHID_DESTROY)
	device := &Device{}
	device.created.Store(true)
	// File is nil, so UHID_DESTROY write will be skipped gracefully

	err := device.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if !device.IsClosed() {
		t.Error("device should be marked as closed")
	}
}

func TestDeviceSetReadTimeoutVariousDurations(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
		{"milliseconds", 100 * time.Millisecond},
		{"seconds", 5 * time.Second},
		{"minutes", 1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &Device{}
			device.SetReadTimeout(tt.timeout)

			device.mu.Lock()
			actual := device.readTimeout
			device.mu.Unlock()

			if actual != tt.timeout {
				t.Errorf("readTimeout = %v, want %v", actual, tt.timeout)
			}
		})
	}
}

func TestDeviceStateTransitions(t *testing.T) {
	t.Run("initial state", func(t *testing.T) {
		device := &Device{}

		if device.IsCreated() {
			t.Error("new device should not be created")
		}
		if device.IsClosed() {
			t.Error("new device should not be closed")
		}
		if device.Fd() != -1 {
			t.Error("new device should have Fd() = -1")
		}
	})

	t.Run("closed state", func(t *testing.T) {
		device := &Device{}
		_ = device.Close()

		if !device.IsClosed() {
			t.Error("closed device should report IsClosed() = true")
		}
		// Can close again without error
		err := device.Close()
		if err != nil {
			t.Errorf("second Close() error = %v", err)
		}
	})

	t.Run("created and closed state", func(t *testing.T) {
		device := &Device{}
		device.created.Store(true)
		_ = device.Close()

		if !device.IsClosed() {
			t.Error("device should be closed")
		}
		// Created flag remains set after close
		if !device.IsCreated() {
			t.Error("created flag should remain set after close")
		}
	})
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

func TestDeviceWriteInputExactMaxSize(t *testing.T) {
	device := &Device{}
	// Device is not closed but has no file handle

	// Exact max size should fail on nil file, not on size check
	exactMaxData := make([]byte, MaxReportDescriptorSize)
	err := device.WriteInput(exactMaxData)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() with exact max size error = %v, want %v", err, ErrDeviceNotOpen)
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

func TestDeviceWriteInputBoundarySize(t *testing.T) {
	device := &Device{}

	// Test at boundary: MaxReportDescriptorSize - 1 should fail on nil file
	boundaryData := make([]byte, MaxReportDescriptorSize-1)
	err := device.WriteInput(boundaryData)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() with boundary size error = %v, want %v", err, ErrDeviceNotOpen)
	}

	// Test at boundary + 1: should fail on size check
	overBoundaryData := make([]byte, MaxReportDescriptorSize+1)
	err = device.WriteInput(overBoundaryData)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("WriteInput() with over boundary size error = %v, want %v", err, ErrInvalidPacket)
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
func TestDeviceWriteInputEmptyData(t *testing.T) {
	device := &Device{}
	// Device is not closed but has no file handle

	// Empty data should fail on nil file
	err := device.WriteInput([]byte{})
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() with empty data error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

// TestDeviceWriteInputNilData tests WriteInput with nil data.
func TestDeviceWriteInputNilData(t *testing.T) {
	device := &Device{}

	// nil data should fail on nil file (len(nil) = 0, which is valid size)
	err := device.WriteInput(nil)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() with nil data error = %v, want %v", err, ErrDeviceNotOpen)
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
