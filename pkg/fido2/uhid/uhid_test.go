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
	"errors"
	"testing"
)

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
		{"ProductIDVirtualFIDO", ProductIDVirtualFIDO, uint16(0x0001)},
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
