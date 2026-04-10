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

package gadget

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildCCIDDescriptors_MagicAndFlags(t *testing.T) {
	blob := BuildCCIDDescriptors()
	if len(blob) < 12 {
		t.Fatalf("descriptor blob too short: %d bytes", len(blob))
	}

	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != functionFSMagicV2 {
		t.Errorf("magic: got 0x%08x, want 0x%08x", magic, functionFSMagicV2)
	}

	length := binary.LittleEndian.Uint32(blob[4:8])
	if length == 0 {
		t.Error("length field is zero")
	}

	flags := binary.LittleEndian.Uint32(blob[8:12])
	wantFlags := ffsFlagFSDescs | ffsFlagHSDescs
	if flags != wantFlags {
		t.Errorf("flags: got 0x%08x, want 0x%08x", flags, wantFlags)
	}
}

func TestBuildCCIDDescriptors_FSCount(t *testing.T) {
	blob := BuildCCIDDescriptors()
	if len(blob) < 16 {
		t.Fatalf("descriptor blob too short: %d bytes", len(blob))
	}

	fsCount := binary.LittleEndian.Uint32(blob[12:16])
	if fsCount != descriptorsPerSpeed {
		t.Errorf("fs_count: got %d, want %d", fsCount, descriptorsPerSpeed)
	}
}

func TestBuildCCIDDescriptors_HSCount(t *testing.T) {
	blob := BuildCCIDDescriptors()
	if len(blob) < 20 {
		t.Fatalf("descriptor blob too short: %d bytes", len(blob))
	}

	hsCount := binary.LittleEndian.Uint32(blob[16:20])
	if hsCount != descriptorsPerSpeed {
		t.Errorf("hs_count: got %d, want %d", hsCount, descriptorsPerSpeed)
	}
}

func TestBuildCCIDDescriptors_InterfaceClass(t *testing.T) {
	blob := BuildCCIDDescriptors()

	// FS descriptors start at offset 20 (after the header).
	// First descriptor is the interface descriptor (9 bytes).
	// bInterfaceClass is at offset 5 within the interface descriptor.
	ifaceStart := ffsHeaderSize
	if len(blob) < ifaceStart+9 {
		t.Fatalf("descriptor blob too short for interface descriptor")
	}

	// Verify it is an interface descriptor.
	bLength := blob[ifaceStart]
	bDescType := blob[ifaceStart+1]
	if bLength != usbDTInterfaceSize {
		t.Errorf("interface bLength: got %d, want %d", bLength, usbDTInterfaceSize)
	}
	if bDescType != usbDTInterface {
		t.Errorf("interface bDescriptorType: got %d, want %d", bDescType, usbDTInterface)
	}

	bInterfaceClass := blob[ifaceStart+5]
	if bInterfaceClass != usbClassSmartCard {
		t.Errorf("bInterfaceClass: got 0x%02x, want 0x%02x", bInterfaceClass, usbClassSmartCard)
	}
}

func TestBuildCCIDDescriptors_CCIDClassDescriptor(t *testing.T) {
	blob := BuildCCIDDescriptors()

	// The CCID class descriptor follows the interface descriptor at offset 20+9=29.
	ccidStart := ffsHeaderSize + int(usbDTInterfaceSize)
	if len(blob) < ccidStart+int(ccidClassDescriptorLength) {
		t.Fatalf("descriptor blob too short for CCID class descriptor")
	}

	bLength := blob[ccidStart]
	if bLength != ccidClassDescriptorLength {
		t.Errorf("CCID bLength: got %d, want %d", bLength, ccidClassDescriptorLength)
	}

	bDescType := blob[ccidStart+1]
	if bDescType != ccidDescriptorType {
		t.Errorf("CCID bDescriptorType: got 0x%02x, want 0x%02x", bDescType, ccidDescriptorType)
	}
}

func TestBuildCCIDDescriptors_EndpointCount(t *testing.T) {
	blob := BuildCCIDDescriptors()

	// Count all endpoint descriptors in the blob (bDescriptorType == 5).
	count := 0
	for i := ffsHeaderSize; i < len(blob); {
		if i+1 >= len(blob) {
			break
		}
		bLen := int(blob[i])
		if bLen == 0 {
			break
		}
		bDescType := blob[i+1]
		if bDescType == usbDTEndpoint {
			count++
		}
		i += bLen
	}

	// 3 endpoints per speed * 2 speeds = 6 total.
	wantCount := 6
	if count != wantCount {
		t.Errorf("endpoint descriptor count: got %d, want %d", count, wantCount)
	}
}

func TestBuildCCIDDescriptors_TotalLength(t *testing.T) {
	blob := BuildCCIDDescriptors()

	length := binary.LittleEndian.Uint32(blob[4:8])
	if int(length) != len(blob) {
		t.Errorf("length field %d does not match actual blob length %d", length, len(blob))
	}
}

func TestBuildFunctionFSStrings_Magic(t *testing.T) {
	blob := BuildFunctionFSStrings()
	if len(blob) < 4 {
		t.Fatalf("string blob too short: %d bytes", len(blob))
	}

	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != functionFSStringsMagic {
		t.Errorf("magic: got 0x%08x, want 0x%08x", magic, functionFSStringsMagic)
	}
}

func TestBuildFunctionFSStrings_Content(t *testing.T) {
	blob := BuildFunctionFSStrings()

	if !bytes.Contains(blob, []byte(ccidInterfaceName)) {
		t.Errorf("string blob does not contain %q", ccidInterfaceName)
	}
}

func TestBuildFunctionFSStrings_Length(t *testing.T) {
	blob := BuildFunctionFSStrings()
	if len(blob) < 8 {
		t.Fatalf("string blob too short: %d bytes", len(blob))
	}

	length := binary.LittleEndian.Uint32(blob[4:8])
	if int(length) != len(blob) {
		t.Errorf("length field %d does not match actual blob length %d", length, len(blob))
	}
}

func TestBuildFunctionFSStrings_LanguageID(t *testing.T) {
	blob := BuildFunctionFSStrings()
	// Language ID is at offset 16 (after magic+length+str_count+lang_count).
	if len(blob) < 18 {
		t.Fatalf("string blob too short for language ID")
	}

	langID := binary.LittleEndian.Uint16(blob[16:18])
	if langID != langIDEnglishUS {
		t.Errorf("language ID: got 0x%04x, want 0x%04x", langID, langIDEnglishUS)
	}
}

func TestBuildInterfaceDescriptor_Length(t *testing.T) {
	desc := buildInterfaceDescriptor(3, usbClassSmartCard, 0, 0)
	if len(desc) != int(usbDTInterfaceSize) {
		t.Errorf("interface descriptor length: got %d, want %d", len(desc), usbDTInterfaceSize)
	}
}

func TestBuildInterfaceDescriptor_Fields(t *testing.T) {
	desc := buildInterfaceDescriptor(3, usbClassSmartCard, 0x01, 0x02)
	if desc[4] != 3 {
		t.Errorf("bNumEndpoints: got %d, want 3", desc[4])
	}
	if desc[5] != usbClassSmartCard {
		t.Errorf("bInterfaceClass: got 0x%02x, want 0x%02x", desc[5], usbClassSmartCard)
	}
	if desc[6] != 0x01 {
		t.Errorf("bInterfaceSubClass: got 0x%02x, want 0x01", desc[6])
	}
	if desc[7] != 0x02 {
		t.Errorf("bInterfaceProtocol: got 0x%02x, want 0x02", desc[7])
	}
}

func TestBuildEndpointDescriptor_Length(t *testing.T) {
	desc := buildEndpointDescriptor(0x01, usbEndpointXferBulk, 64, 0)
	if len(desc) != int(usbDTEndpointSize) {
		t.Errorf("endpoint descriptor length: got %d, want %d", len(desc), usbDTEndpointSize)
	}
}

func TestBuildEndpointDescriptor_Fields(t *testing.T) {
	desc := buildEndpointDescriptor(0x82, usbEndpointXferBulk, 512, 0)
	if desc[2] != 0x82 {
		t.Errorf("bEndpointAddress: got 0x%02x, want 0x82", desc[2])
	}
	if desc[3] != usbEndpointXferBulk {
		t.Errorf("bmAttributes: got 0x%02x, want 0x%02x", desc[3], usbEndpointXferBulk)
	}
	maxPacket := binary.LittleEndian.Uint16(desc[4:6])
	if maxPacket != 512 {
		t.Errorf("wMaxPacketSize: got %d, want 512", maxPacket)
	}
	if desc[6] != 0 {
		t.Errorf("bInterval: got %d, want 0", desc[6])
	}
}

func TestBuildEndpointDescriptor_InterruptFields(t *testing.T) {
	desc := buildEndpointDescriptor(0x83, usbEndpointXferInterrupt, 8, 32)
	if desc[2] != 0x83 {
		t.Errorf("bEndpointAddress: got 0x%02x, want 0x83", desc[2])
	}
	if desc[3] != usbEndpointXferInterrupt {
		t.Errorf("bmAttributes: got 0x%02x, want 0x%02x", desc[3], usbEndpointXferInterrupt)
	}
	maxPacket := binary.LittleEndian.Uint16(desc[4:6])
	if maxPacket != 8 {
		t.Errorf("wMaxPacketSize: got %d, want 8", maxPacket)
	}
	if desc[6] != 32 {
		t.Errorf("bInterval: got %d, want 32", desc[6])
	}
}

func TestBuildCCIDClassDescriptor_Length(t *testing.T) {
	desc := buildCCIDClassDescriptor()
	if len(desc) != int(ccidClassDescriptorLength) {
		t.Errorf("CCID class descriptor length: got %d, want %d", len(desc), ccidClassDescriptorLength)
	}
}

func TestBuildCCIDClassDescriptor_Fields(t *testing.T) {
	desc := buildCCIDClassDescriptor()

	if desc[0] != ccidClassDescriptorLength {
		t.Errorf("bLength: got %d, want %d", desc[0], ccidClassDescriptorLength)
	}
	if desc[1] != ccidDescriptorType {
		t.Errorf("bDescriptorType: got 0x%02x, want 0x%02x", desc[1], ccidDescriptorType)
	}

	bcdCCID := binary.LittleEndian.Uint16(desc[2:4])
	if bcdCCID != ccidBCDVersion {
		t.Errorf("bcdCCID: got 0x%04x, want 0x%04x", bcdCCID, ccidBCDVersion)
	}

	features := binary.LittleEndian.Uint32(desc[40:44])
	if features != ccidFeatures {
		t.Errorf("dwFeatures: got 0x%08x, want 0x%08x", features, ccidFeatures)
	}

	maxMsg := binary.LittleEndian.Uint32(desc[44:48])
	if maxMsg != ccidMaxCCIDMessageLength {
		t.Errorf("dwMaxCCIDMessageLength: got %d, want %d", maxMsg, ccidMaxCCIDMessageLength)
	}
}

func TestBuildCCIDDescriptors_FullFieldValidation(t *testing.T) {
	blob := BuildCCIDDescriptors()

	// Scan for the CCID class descriptor in the FS section (starts after header at offset 20).
	ccidStart := -1
	for i := ffsHeaderSize; i < len(blob); {
		if i+1 >= len(blob) {
			break
		}
		bLen := int(blob[i])
		if bLen == 0 {
			break
		}
		if blob[i] == ccidClassDescriptorLength && blob[i+1] == ccidDescriptorType {
			ccidStart = i
			break
		}
		i += bLen
	}
	if ccidStart < 0 {
		t.Fatalf("CCID class descriptor (bLength=54, bDescriptorType=0x21) not found in FS descriptors")
	}

	desc := blob[ccidStart : ccidStart+int(ccidClassDescriptorLength)]

	// bLength (byte 0)
	if desc[0] != 54 {
		t.Errorf("bLength: got %d, want 54", desc[0])
	}

	// bDescriptorType (byte 1)
	if desc[1] != 0x21 {
		t.Errorf("bDescriptorType: got %#02x, want %#02x", desc[1], byte(0x21))
	}

	// bcdCCID (bytes 2-3, little-endian)
	bcdCCID := binary.LittleEndian.Uint16(desc[2:4])
	if bcdCCID != 0x0110 {
		t.Errorf("bcdCCID: got %#04x, want %#04x", bcdCCID, uint16(0x0110))
	}

	// bMaxSlotIndex (byte 4)
	if desc[4] != 0x00 {
		t.Errorf("bMaxSlotIndex: got %#02x, want %#02x", desc[4], byte(0x00))
	}

	// bVoltageSupport (byte 5)
	if desc[5] != 0x07 {
		t.Errorf("bVoltageSupport: got %#02x, want %#02x", desc[5], byte(0x07))
	}

	// dwProtocols (bytes 6-9)
	protocols := binary.LittleEndian.Uint32(desc[6:10])
	if protocols != 0x00000003 {
		t.Errorf("dwProtocols: got %#08x, want %#08x", protocols, uint32(0x00000003))
	}

	// dwDefaultClock (bytes 10-13)
	defaultClock := binary.LittleEndian.Uint32(desc[10:14])
	if defaultClock != 4000 {
		t.Errorf("dwDefaultClock: got %d, want 4000", defaultClock)
	}

	// dwMaximumClock (bytes 14-17)
	maxClock := binary.LittleEndian.Uint32(desc[14:18])
	if maxClock != 4000 {
		t.Errorf("dwMaximumClock: got %d, want 4000", maxClock)
	}

	// dwDefaultDataRate (bytes 19-22)
	defaultDataRate := binary.LittleEndian.Uint32(desc[19:23])
	if defaultDataRate != 9600 {
		t.Errorf("dwDefaultDataRate: got %d, want 9600", defaultDataRate)
	}

	// dwMaximumDataRate (bytes 23-26)
	maxDataRate := binary.LittleEndian.Uint32(desc[23:27])
	if maxDataRate != 115200 {
		t.Errorf("dwMaximumDataRate: got %d, want 115200", maxDataRate)
	}

	// dwMaxIFSD (bytes 28-31)
	maxIFSD := binary.LittleEndian.Uint32(desc[28:32])
	if maxIFSD != 254 {
		t.Errorf("dwMaxIFSD: got %d, want 254", maxIFSD)
	}

	// dwFeatures (bytes 40-43)
	features := binary.LittleEndian.Uint32(desc[40:44])
	if features != 0x000100FE {
		t.Errorf("dwFeatures: got %#08x, want %#08x", features, uint32(0x000100FE))
	}

	// dwMaxCCIDMessageLength (bytes 44-47)
	maxMsg := binary.LittleEndian.Uint32(desc[44:48])
	if maxMsg != 271 {
		t.Errorf("dwMaxCCIDMessageLength: got %d, want 271", maxMsg)
	}

	// bPINSupport (byte 52)
	if desc[52] != 0x03 {
		t.Errorf("bPINSupport: got %#02x, want %#02x", desc[52], byte(0x03))
	}

	// bMaxCCIDBusySlots (byte 53)
	if desc[53] != 0x01 {
		t.Errorf("bMaxCCIDBusySlots: got %#02x, want %#02x", desc[53], byte(0x01))
	}
}

func TestBuildCCIDDescriptors_EndpointDetails(t *testing.T) {
	blob := BuildCCIDDescriptors()

	// Collect all endpoint descriptors per speed section.
	// FS starts at offset 20, HS starts after FS.
	type epInfo struct {
		address    byte
		attributes byte
		maxPacket  uint16
		interval   byte
	}

	parseEndpoints := func(section []byte) []epInfo {
		var eps []epInfo
		for i := 0; i < len(section); {
			if i+1 >= len(section) {
				break
			}
			bLen := int(section[i])
			if bLen == 0 || i+bLen > len(section) {
				break
			}
			if section[i+1] == usbDTEndpoint && bLen >= int(usbDTEndpointSize) {
				ep := epInfo{
					address:    section[i+2],
					attributes: section[i+3],
					maxPacket:  binary.LittleEndian.Uint16(section[i+4 : i+6]),
					interval:   section[i+6],
				}
				eps = append(eps, ep)
			}
			i += bLen
		}
		return eps
	}

	// Calculate FS section size: 9 (iface) + 54 (ccid) + 3*7 (endpoints) = 84
	fsSize := int(usbDTInterfaceSize) + int(ccidClassDescriptorLength) + 3*int(usbDTEndpointSize)
	fsSection := blob[ffsHeaderSize : ffsHeaderSize+fsSize]
	hsSection := blob[ffsHeaderSize+fsSize:]

	fsEps := parseEndpoints(fsSection)
	hsEps := parseEndpoints(hsSection)

	if len(fsEps) != 3 {
		t.Fatalf("FS endpoint count: got %d, want 3", len(fsEps))
	}
	if len(hsEps) != 3 {
		t.Fatalf("HS endpoint count: got %d, want 3", len(hsEps))
	}

	// EP1 (Bulk OUT): address=0x01, attributes=0x02, interval=0
	if fsEps[0].address != 0x01 {
		t.Errorf("FS EP1 address: got %#02x, want %#02x", fsEps[0].address, byte(0x01))
	}
	if fsEps[0].attributes != 0x02 {
		t.Errorf("FS EP1 attributes: got %#02x, want %#02x", fsEps[0].attributes, byte(0x02))
	}
	if fsEps[0].interval != 0 {
		t.Errorf("FS EP1 interval: got %d, want 0", fsEps[0].interval)
	}

	// EP2 (Bulk IN): address=0x82, attributes=0x02, interval=0
	if fsEps[1].address != 0x82 {
		t.Errorf("FS EP2 address: got %#02x, want %#02x", fsEps[1].address, byte(0x82))
	}
	if fsEps[1].attributes != 0x02 {
		t.Errorf("FS EP2 attributes: got %#02x, want %#02x", fsEps[1].attributes, byte(0x02))
	}
	if fsEps[1].interval != 0 {
		t.Errorf("FS EP2 interval: got %d, want 0", fsEps[1].interval)
	}

	// EP3 (Interrupt IN): address=0x83, attributes=0x03, interval=32
	if fsEps[2].address != 0x83 {
		t.Errorf("FS EP3 address: got %#02x, want %#02x", fsEps[2].address, byte(0x83))
	}
	if fsEps[2].attributes != 0x03 {
		t.Errorf("FS EP3 attributes: got %#02x, want %#02x", fsEps[2].attributes, byte(0x03))
	}
	if fsEps[2].interval != 32 {
		t.Errorf("FS EP3 interval: got %d, want 32", fsEps[2].interval)
	}

	// FS max packet sizes: bulk=64, interrupt=8
	if fsEps[0].maxPacket != 64 {
		t.Errorf("FS bulk OUT maxPacket: got %d, want 64", fsEps[0].maxPacket)
	}
	if fsEps[1].maxPacket != 64 {
		t.Errorf("FS bulk IN maxPacket: got %d, want 64", fsEps[1].maxPacket)
	}
	if fsEps[2].maxPacket != 8 {
		t.Errorf("FS interrupt maxPacket: got %d, want 8", fsEps[2].maxPacket)
	}

	// HS max packet sizes: bulk=512, interrupt=8
	if hsEps[0].maxPacket != 512 {
		t.Errorf("HS bulk OUT maxPacket: got %d, want 512", hsEps[0].maxPacket)
	}
	if hsEps[1].maxPacket != 512 {
		t.Errorf("HS bulk IN maxPacket: got %d, want 512", hsEps[1].maxPacket)
	}
	if hsEps[2].maxPacket != 8 {
		t.Errorf("HS interrupt maxPacket: got %d, want 8", hsEps[2].maxPacket)
	}
}

func TestBuildFunctionFSStrings_FullValidation(t *testing.T) {
	blob := BuildFunctionFSStrings()

	if len(blob) < 18 {
		t.Fatalf("string blob too short: %d bytes, need at least 18", len(blob))
	}

	// Magic = 2 (bytes 0-3)
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != 2 {
		t.Errorf("magic: got %d, want 2", magic)
	}

	// Total length (bytes 4-7) must match blob length
	length := binary.LittleEndian.Uint32(blob[4:8])
	if int(length) != len(blob) {
		t.Errorf("length: got %d, want %d", length, len(blob))
	}

	// str_count = 1 (bytes 8-11)
	strCount := binary.LittleEndian.Uint32(blob[8:12])
	if strCount != 1 {
		t.Errorf("str_count: got %d, want 1", strCount)
	}

	// lang_count = 1 (bytes 12-15)
	langCount := binary.LittleEndian.Uint32(blob[12:16])
	if langCount != 1 {
		t.Errorf("lang_count: got %d, want 1", langCount)
	}

	// lang = 0x0409 (bytes 16-17)
	lang := binary.LittleEndian.Uint16(blob[16:18])
	if lang != 0x0409 {
		t.Errorf("lang: got %#04x, want %#04x", lang, uint16(0x0409))
	}

	// String payload starts at byte 18 and must be null-terminated "xKey CCID"
	strPayload := blob[18:]
	wantStr := "xKey CCID"
	wantBytes := append([]byte(wantStr), 0)
	if !bytes.Equal(strPayload, wantBytes) {
		t.Errorf("string payload: got %q (len=%d), want %q (len=%d)",
			strPayload, len(strPayload), wantBytes, len(wantBytes))
	}
}
