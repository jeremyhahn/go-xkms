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

package ccid

import "testing"

func TestCCIDDescriptor_Length(t *testing.T) {
	desc := CCIDDescriptor()
	if len(desc) != CCIDClassDescriptorLength {
		t.Errorf("Descriptor length = %d, want %d", len(desc), CCIDClassDescriptorLength)
	}
}

func TestCCIDDescriptor_Type(t *testing.T) {
	desc := CCIDDescriptor()
	if desc[1] != CCIDDescriptorType {
		t.Errorf("Descriptor type = 0x%02X, want 0x%02X", desc[1], CCIDDescriptorType)
	}
}

func TestCCIDDescriptor_BcdVersion(t *testing.T) {
	desc := CCIDDescriptor()
	version := uint16(desc[2]) | uint16(desc[3])<<8
	if version != CCIDBCDVersion {
		t.Errorf("BCD version = 0x%04X, want 0x%04X", version, CCIDBCDVersion)
	}
}

func TestCCIDDescriptor_MaxSlotIndex(t *testing.T) {
	desc := CCIDDescriptor()
	if desc[4] != CCIDMaxSlotIndex {
		t.Errorf("MaxSlotIndex = %d, want %d", desc[4], CCIDMaxSlotIndex)
	}
}

func TestCCIDDescriptor_VoltageSupport(t *testing.T) {
	desc := CCIDDescriptor()
	if desc[5] != CCIDVoltageSupport {
		t.Errorf("VoltageSupport = 0x%02X, want 0x%02X", desc[5], CCIDVoltageSupport)
	}
}

func TestCCIDDescriptor_PINSupport(t *testing.T) {
	desc := CCIDDescriptor()
	// bPINSupport at offset 52
	if desc[52] != 0x03 {
		t.Errorf("PINSupport = 0x%02X, want 0x03", desc[52])
	}
}

func TestCCIDDescriptor_MaxBusySlots(t *testing.T) {
	desc := CCIDDescriptor()
	// bMaxCCIDBusySlots at offset 53
	if desc[53] != 0x01 {
		t.Errorf("MaxBusySlots = %d, want 1", desc[53])
	}
}

func TestCCIDDescriptor_Deterministic(t *testing.T) {
	desc1 := CCIDDescriptor()
	desc2 := CCIDDescriptor()

	if len(desc1) != len(desc2) {
		t.Fatal("Descriptor lengths differ")
	}

	for i := range desc1 {
		if desc1[i] != desc2[i] {
			t.Errorf("Descriptor byte %d differs: 0x%02X vs 0x%02X", i, desc1[i], desc2[i])
		}
	}
}

func TestCCIDHIDReportDescriptor_NotEmpty(t *testing.T) {
	if len(CCIDHIDReportDescriptor) == 0 {
		t.Fatal("CCIDHIDReportDescriptor is empty")
	}
}

func TestCCIDHIDReportDescriptor_VendorUsagePage(t *testing.T) {
	// Should start with Usage Page (Vendor Defined 0xFF00)
	if CCIDHIDReportDescriptor[0] != 0x06 {
		t.Errorf("First byte = 0x%02X, want 0x06 (Usage Page)", CCIDHIDReportDescriptor[0])
	}
	if CCIDHIDReportDescriptor[1] != 0x00 || CCIDHIDReportDescriptor[2] != 0xFF {
		t.Errorf("Usage page = %02X%02X, want 00FF", CCIDHIDReportDescriptor[1], CCIDHIDReportDescriptor[2])
	}
}

func TestCCIDHIDReportDescriptor_EndsWithEndCollection(t *testing.T) {
	lastByte := CCIDHIDReportDescriptor[len(CCIDHIDReportDescriptor)-1]
	if lastByte != 0xC0 {
		t.Errorf("Last byte = 0x%02X, want 0xC0 (End Collection)", lastByte)
	}
}

func TestDefaultATR(t *testing.T) {
	atr := DefaultATR()

	if len(atr) == 0 {
		t.Fatal("DefaultATR returned empty")
	}

	// TS byte should be 0x3B (direct convention)
	if atr[0] != 0x3B {
		t.Errorf("TS = 0x%02X, want 0x3B", atr[0])
	}

	// T0 byte should indicate TD1 present
	if atr[1]&0x80 == 0 {
		t.Error("T0 does not indicate TD1 present")
	}
}

func TestDefaultATR_ContainsIdentifier(t *testing.T) {
	atr := DefaultATR()
	atrStr := string(atr)

	if len(atrStr) < 4 {
		t.Fatal("ATR too short to contain identifier")
	}

	// Should contain "xKey" in the historical bytes
	found := false
	for i := 2; i < len(atr)-3; i++ {
		if atr[i] == 'x' && atr[i+1] == 'K' {
			found = true
			break
		}
	}
	if !found {
		t.Error("ATR does not contain 'xKey' identifier")
	}
}

func TestDeviceConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
	}{
		{"VendorIDCCID", VendorIDCCID, uint16(0xF1D0)},
		{"ProductIDCCID", ProductIDCCID, uint16(0x0004)},
		{"CCIDDeviceVersion", CCIDDeviceVersion, uint16(0x0100)},
		{"CCIDDeviceName", CCIDDeviceName, "xKey CCID Smartcard Reader"},
		{"CCIDDevicePhys", CCIDDevicePhys, "xkey-ccid"},
		{"CCIDDeviceSerial", CCIDDeviceSerial, "XKEYCCID001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch v := tt.value.(type) {
			case uint16:
				if v != tt.expected.(uint16) {
					t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, v, tt.expected)
				}
			case string:
				if v != tt.expected.(string) {
					t.Errorf("%s = %q, want %q", tt.name, v, tt.expected)
				}
			}
		})
	}
}
