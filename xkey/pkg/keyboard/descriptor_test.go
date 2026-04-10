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

package keyboard

import (
	"testing"
)

func TestBootKeyboardReportDescriptor_Length(t *testing.T) {
	// USB HID Boot Protocol keyboard descriptor is 63 bytes.
	// Items: Usage Page(2) + Usage(2) + Collection(2) + Usage Page(2) +
	//        Usage Min(2) + Usage Max(2) + Logical Min(2) + Logical Max(2) +
	//        Report Size(2) + Report Count(2) + Input(2) +
	//        Report Count(2) + Report Size(2) + Input(2) +
	//        Report Count(2) + Report Size(2) + Logical Min(2) + Logical Max(2) +
	//        Usage Page(2) + Usage Min(2) + Usage Max(2) + Input(2) +
	//        End Collection(1) = 45 bytes
	const expectedLength = 45

	if len(BootKeyboardReportDescriptor) != expectedLength {
		t.Errorf("BootKeyboardReportDescriptor length = %d, want %d",
			len(BootKeyboardReportDescriptor), expectedLength)
	}
}

func TestBootKeyboardReportDescriptor_UsagePage(t *testing.T) {
	if len(BootKeyboardReportDescriptor) < 2 {
		t.Fatal("descriptor too short to contain Usage Page")
	}

	// First byte: 0x05 = Usage Page (1-byte value)
	if BootKeyboardReportDescriptor[0] != 0x05 {
		t.Errorf("first byte = 0x%02X, want 0x05 (Usage Page tag)",
			BootKeyboardReportDescriptor[0])
	}

	// Second byte: 0x01 = Generic Desktop
	if BootKeyboardReportDescriptor[1] != 0x01 {
		t.Errorf("Usage Page value = 0x%02X, want 0x01 (Generic Desktop)",
			BootKeyboardReportDescriptor[1])
	}
}

func TestBootKeyboardReportDescriptor_UsageKeyboard(t *testing.T) {
	if len(BootKeyboardReportDescriptor) < 4 {
		t.Fatal("descriptor too short to contain Usage")
	}

	// Bytes 2-3: 0x09, 0x06 = Usage (Keyboard)
	if BootKeyboardReportDescriptor[2] != 0x09 {
		t.Errorf("Usage tag = 0x%02X, want 0x09", BootKeyboardReportDescriptor[2])
	}
	if BootKeyboardReportDescriptor[3] != 0x06 {
		t.Errorf("Usage value = 0x%02X, want 0x06 (Keyboard)",
			BootKeyboardReportDescriptor[3])
	}
}

func TestBootKeyboardReportDescriptor_CollectionApplication(t *testing.T) {
	if len(BootKeyboardReportDescriptor) < 6 {
		t.Fatal("descriptor too short to contain Collection")
	}

	// Bytes 4-5: 0xA1, 0x01 = Collection (Application)
	if BootKeyboardReportDescriptor[4] != 0xA1 {
		t.Errorf("Collection tag = 0x%02X, want 0xA1", BootKeyboardReportDescriptor[4])
	}
	if BootKeyboardReportDescriptor[5] != 0x01 {
		t.Errorf("Collection value = 0x%02X, want 0x01 (Application)",
			BootKeyboardReportDescriptor[5])
	}
}

func TestBootKeyboardReportDescriptor_EndCollection(t *testing.T) {
	if len(BootKeyboardReportDescriptor) == 0 {
		t.Fatal("descriptor is empty")
	}

	// Last byte must be 0xC0 (End Collection)
	lastByte := BootKeyboardReportDescriptor[len(BootKeyboardReportDescriptor)-1]
	if lastByte != 0xC0 {
		t.Errorf("last byte = 0x%02X, want 0xC0 (End Collection)", lastByte)
	}
}

func TestBootKeyboardReportDescriptor_CompleteCollection(t *testing.T) {
	// Verify there is exactly one Collection (0xA1) matched by one End Collection (0xC0)
	collectionCount := 0
	endCollectionCount := 0

	for _, b := range BootKeyboardReportDescriptor {
		if b == 0xA1 {
			collectionCount++
		}
		if b == 0xC0 {
			endCollectionCount++
		}
	}

	if collectionCount != 1 {
		t.Errorf("Collection (0xA1) count = %d, want 1", collectionCount)
	}
	if endCollectionCount != 1 {
		t.Errorf("End Collection (0xC0) count = %d, want 1", endCollectionCount)
	}
}

func TestBootKeyboardReportDescriptor_KeyCodesUsagePage(t *testing.T) {
	// Verify the descriptor contains the Key Codes usage page (0x05, 0x07)
	found := false
	for i := 0; i < len(BootKeyboardReportDescriptor)-1; i++ {
		if BootKeyboardReportDescriptor[i] == 0x05 && BootKeyboardReportDescriptor[i+1] == 0x07 {
			found = true
			break
		}
	}
	if !found {
		t.Error("descriptor missing Key Codes Usage Page (0x05, 0x07)")
	}
}

func TestBootKeyboardReportDescriptor_ModifierBits(t *testing.T) {
	// Verify Usage Minimum 224 (0xE0) and Usage Maximum 231 (0xE7) for modifier keys
	foundMin := false
	foundMax := false
	for i := 0; i < len(BootKeyboardReportDescriptor)-1; i++ {
		if BootKeyboardReportDescriptor[i] == 0x19 && BootKeyboardReportDescriptor[i+1] == 0xE0 {
			foundMin = true
		}
		if BootKeyboardReportDescriptor[i] == 0x29 && BootKeyboardReportDescriptor[i+1] == 0xE7 {
			foundMax = true
		}
	}
	if !foundMin {
		t.Error("descriptor missing Usage Minimum 224 (0x19, 0xE0) for modifier keys")
	}
	if !foundMax {
		t.Error("descriptor missing Usage Maximum 231 (0x29, 0xE7) for modifier keys")
	}
}

func TestBootKeyboardReportDescriptor_NotNil(t *testing.T) {
	if BootKeyboardReportDescriptor == nil {
		t.Error("BootKeyboardReportDescriptor is nil")
	}
}
