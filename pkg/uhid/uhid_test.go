// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

func TestFIDO2HIDReportDescriptorLength(t *testing.T) {
	// The FIDO2 HID report descriptor must be exactly 34 bytes
	// per the FIDO Alliance HID specification
	const expectedLength = 34

	if len(FIDO2HIDReportDescriptor) != expectedLength {
		t.Errorf("FIDO2HIDReportDescriptor length = %d, want %d",
			len(FIDO2HIDReportDescriptor), expectedLength)
	}
}

func TestFIDO2HIDReportDescriptorContent(t *testing.T) {
	// Verify the report descriptor starts with the FIDO usage page
	if len(FIDO2HIDReportDescriptor) < 3 {
		t.Fatal("Report descriptor too short")
	}

	// First byte should be 0x06 (Usage Page tag for 2-byte value)
	if FIDO2HIDReportDescriptor[0] != 0x06 {
		t.Errorf("First byte = 0x%02X, want 0x06 (Usage Page)", FIDO2HIDReportDescriptor[0])
	}

	// Next two bytes should be 0xD0 0xF1 (FIDO Alliance usage page in little-endian)
	usagePage := uint16(FIDO2HIDReportDescriptor[1]) | uint16(FIDO2HIDReportDescriptor[2])<<8
	if usagePage != 0xF1D0 {
		t.Errorf("Usage page = 0x%04X, want 0xF1D0", usagePage)
	}

	// Verify collection application tag
	if FIDO2HIDReportDescriptor[5] != 0xA1 || FIDO2HIDReportDescriptor[6] != 0x01 {
		t.Error("Missing Collection (Application) tag")
	}

	// Verify end collection tag at the end
	if FIDO2HIDReportDescriptor[33] != 0xC0 {
		t.Errorf("Last byte = 0x%02X, want 0xC0 (End Collection)", FIDO2HIDReportDescriptor[33])
	}
}

func TestCreateConfigDefaults(t *testing.T) {
	cfg := DefaultCreateConfig()

	if cfg == nil {
		t.Fatal("DefaultCreateConfig returned nil")
	}

	// Verify default values
	if cfg.Name == "" {
		t.Error("Default Name is empty")
	}

	if cfg.VendorID != VendorIDVirtualFIDO {
		t.Errorf("VendorID = 0x%04X, want 0x%04X", cfg.VendorID, VendorIDVirtualFIDO)
	}

	if cfg.ProductID != ProductIDVirtualFIDO {
		t.Errorf("ProductID = 0x%04X, want 0x%04X", cfg.ProductID, ProductIDVirtualFIDO)
	}

	if cfg.Version == 0 {
		t.Error("Default Version is 0")
	}

	if cfg.ReportDescriptor == nil {
		t.Error("Default ReportDescriptor is nil")
	}

	if len(cfg.ReportDescriptor) != 34 {
		t.Errorf("Default ReportDescriptor length = %d, want 34", len(cfg.ReportDescriptor))
	}
}

func TestCreateConfigCustomValues(t *testing.T) {
	customRdesc := []byte{0x01, 0x02, 0x03}

	cfg := &CreateConfig{
		Name:             "Test Device",
		Phys:             "test-phys",
		Uniq:             "TEST123",
		VendorID:         0x1234,
		ProductID:        0x5678,
		Version:          0x0200,
		ReportDescriptor: customRdesc,
	}

	if cfg.Name != "Test Device" {
		t.Errorf("Name = %q, want %q", cfg.Name, "Test Device")
	}

	if cfg.Phys != "test-phys" {
		t.Errorf("Phys = %q, want %q", cfg.Phys, "test-phys")
	}

	if cfg.Uniq != "TEST123" {
		t.Errorf("Uniq = %q, want %q", cfg.Uniq, "TEST123")
	}

	if cfg.VendorID != 0x1234 {
		t.Errorf("VendorID = 0x%04X, want 0x1234", cfg.VendorID)
	}

	if cfg.ProductID != 0x5678 {
		t.Errorf("ProductID = 0x%04X, want 0x5678", cfg.ProductID)
	}

	if cfg.Version != 0x0200 {
		t.Errorf("Version = 0x%04X, want 0x0200", cfg.Version)
	}

	if len(cfg.ReportDescriptor) != 3 {
		t.Errorf("ReportDescriptor length = %d, want 3", len(cfg.ReportDescriptor))
	}
}

func TestUHIDEventTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint32
		expected uint32
	}{
		{"UHID_DESTROY", UHID_DESTROY, 1},
		{"UHID_START", UHID_START, 2},
		{"UHID_STOP", UHID_STOP, 3},
		{"UHID_OPEN", UHID_OPEN, 4},
		{"UHID_CLOSE", UHID_CLOSE, 5},
		{"UHID_OUTPUT", UHID_OUTPUT, 6},
		{"UHID_CREATE2", UHID_CREATE2, 11},
		{"UHID_INPUT2", UHID_INPUT2, 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestBusTypeConstants(t *testing.T) {
	if BUS_USB != 0x03 {
		t.Errorf("BUS_USB = 0x%02X, want 0x03", BUS_USB)
	}
}

func TestFIDO2Constants(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
	}{
		{"VendorIDVirtualFIDO", VendorIDVirtualFIDO, uint16(0xF1D0)},
		{"ProductIDVirtualFIDO", ProductIDVirtualFIDO, uint16(0x0003)},
		{"HIDReportSize", HIDReportSize, 64},
		{"MaxReportDescriptorSize", MaxReportDescriptorSize, 4096},
		{"UHIDDevicePath", UHIDDevicePath, "/dev/uhid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch v := tt.value.(type) {
			case uint16:
				if v != tt.expected.(uint16) {
					t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, v, tt.expected)
				}
			case int:
				if v != tt.expected.(int) {
					t.Errorf("%s = %d, want %d", tt.name, v, tt.expected)
				}
			case string:
				if v != tt.expected.(string) {
					t.Errorf("%s = %q, want %q", tt.name, v, tt.expected)
				}
			}
		})
	}
}

func TestUHIDCreate2RequestSerialization(t *testing.T) {
	cfg := &CreateConfig{
		Name:             "Test FIDO2 Device",
		Phys:             "test-phys-path",
		Uniq:             "SERIAL001",
		VendorID:         0xF1D0,
		ProductID:        0x0003,
		Version:          0x0100,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)

	// Skip test on non-Linux where SerializeCreate2Request returns nil
	if buf == nil {
		t.Skip("SerializeCreate2Request not implemented on this platform")
	}

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

	// Skip test on non-Linux where SerializeCreate2Request returns nil
	if buf == nil {
		t.Skip("SerializeCreate2Request not implemented on this platform")
	}

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

	// Skip test on non-Linux where SerializeInput2Request returns nil
	if buf == nil {
		t.Skip("SerializeInput2Request not implemented on this platform")
	}

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

	// Skip test on non-Linux where SerializeInput2Request returns nil
	if buf == nil {
		t.Skip("SerializeInput2Request not implemented on this platform")
	}

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

	// Skip test on non-Linux where ParseOutputEvent returns ErrNotSupported
	if errors.Is(err, ErrNotSupported) {
		t.Skip("ParseOutputEvent not implemented on this platform")
	}

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

			// Skip test on non-Linux
			if errors.Is(err, ErrNotSupported) {
				t.Skip("ParseOutputEvent not implemented on this platform")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseOutputEvent error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrUHIDNotAvailable", ErrUHIDNotAvailable},
		{"ErrDeviceCreationFailed", ErrDeviceCreationFailed},
		{"ErrDeviceNotOpen", ErrDeviceNotOpen},
		{"ErrWriteFailed", ErrWriteFailed},
		{"ErrReadFailed", ErrReadFailed},
		{"ErrInvalidPacket", ErrInvalidPacket},
		{"ErrNotSupported", ErrNotSupported},
		{"ErrDeviceAlreadyCreated", ErrDeviceAlreadyCreated},
		{"ErrTimeout", ErrTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}

			if tt.err.Error() == "" {
				t.Errorf("%s has empty error message", tt.name)
			}

			// Verify error type checking works with errors.Is
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%s, %s) = false, want true", tt.name, tt.name)
			}
		})
	}
}

func TestErrorTypeDistinctness(t *testing.T) {
	errs := []error{
		ErrUHIDNotAvailable,
		ErrDeviceCreationFailed,
		ErrDeviceNotOpen,
		ErrWriteFailed,
		ErrReadFailed,
		ErrInvalidPacket,
		ErrNotSupported,
		ErrDeviceAlreadyCreated,
		ErrTimeout,
	}

	// Ensure all errors are distinct
	for i, err1 := range errs {
		for j, err2 := range errs {
			if i != j {
				if errors.Is(err1, err2) {
					t.Errorf("Error %v should not match error %v", err1, err2)
				}
			}
		}
	}
}

func TestStructSizeConstants(t *testing.T) {
	// Verify struct size constants match expected kernel structure sizes
	// These should match Linux kernel include/uapi/linux/uhid.h

	// uhid_create2_req: name[128] + phys[64] + uniq[64] + rd_size[2] + bus[2] + vendor[4] + product[4] + version[4] + country[4] + rd_data[4096]
	expectedCreate2Size := 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + MaxReportDescriptorSize
	if uhidCreate2ReqSize != expectedCreate2Size {
		t.Errorf("uhidCreate2ReqSize = %d, want %d", uhidCreate2ReqSize, expectedCreate2Size)
	}

	// uhid_input2_req: size[2] + data[4096]
	expectedInput2Size := 2 + MaxReportDescriptorSize
	if uhidInput2ReqSize != expectedInput2Size {
		t.Errorf("uhidInput2ReqSize = %d, want %d", uhidInput2ReqSize, expectedInput2Size)
	}

	// uhid_output: size[2] + rtype[1] + data[4096]
	expectedOutputSize := 2 + 1 + MaxReportDescriptorSize
	if uhidOutputEventSize != expectedOutputSize {
		t.Errorf("uhidOutputEventSize = %d, want %d", uhidOutputEventSize, expectedOutputSize)
	}

	// Event header is just the event type (uint32)
	if uhidEventHeaderSize != 4 {
		t.Errorf("uhidEventHeaderSize = %d, want 4", uhidEventHeaderSize)
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
		ProductID:        0x0003,
		Version:          0x0100,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}

	buf := SerializeCreate2Request(cfg)

	// Skip test on non-Linux
	if buf == nil {
		t.Skip("SerializeCreate2Request not implemented on this platform")
	}

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
		ProductID:        0x0003,
		ReportDescriptor: nil, // Should use default
	}

	buf := SerializeCreate2Request(cfg)

	// Skip test on non-Linux
	if buf == nil {
		t.Skip("SerializeCreate2Request not implemented on this platform")
	}

	// Verify default report descriptor is used
	offset := uhidEventHeaderSize + 128 + 64 + 64
	rdSize := binary.LittleEndian.Uint16(buf[offset : offset+2])
	if int(rdSize) != len(FIDO2HIDReportDescriptor) {
		t.Errorf("rd_size = %d, want %d (default descriptor length)", rdSize, len(FIDO2HIDReportDescriptor))
	}
}
