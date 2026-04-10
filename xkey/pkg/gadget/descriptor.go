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
)

const (
	// functionFSMagicV2 is the FunctionFS v2 descriptor magic number.
	functionFSMagicV2 uint32 = 3

	// functionFSStringsMagic is the FunctionFS string descriptor magic number.
	functionFSStringsMagic uint32 = 2

	// FunctionFS descriptor flags.
	ffsFlagFSDescs uint32 = 0x01
	ffsFlagHSDescs uint32 = 0x02

	// USB class codes.
	usbClassSmartCard byte = 0x0B

	// USB descriptor types.
	usbDTInterface byte = 4
	usbDTEndpoint  byte = 5

	// USB endpoint types.
	usbEndpointXferBulk      byte = 0x02
	usbEndpointXferInterrupt byte = 0x03
	usbEndpointDirIN         byte = 0x80

	// CCID endpoint sizes.
	ccidBulkMaxPacketFS uint16 = 64
	ccidBulkMaxPacketHS uint16 = 512
	ccidIntrMaxPacket   uint16 = 8
	ccidIntrInterval    byte   = 32 // polling interval in frames

	// Descriptor lengths.
	usbDTInterfaceSize byte = 9
	usbDTEndpointSize  byte = 7

	// ccidInterfaceName is the FunctionFS string descriptor for the CCID interface.
	ccidInterfaceName = "xKey CCID"

	// langIDEnglishUS is the USB language ID for English (US).
	langIDEnglishUS uint16 = 0x0409

	// descriptorsPerSpeed is the number of USB descriptors per speed
	// (1 interface + 1 CCID class + 3 endpoints).
	descriptorsPerSpeed uint32 = 5

	// ffsHeaderSize is the size of the FunctionFS v2 header with FS+HS counts.
	// magic(4) + length(4) + flags(4) + fs_count(4) + hs_count(4) = 20
	ffsHeaderSize = 20

	// CCID class descriptor constants (mirrors ccid package to avoid import cycle).
	ccidClassDescriptorLength byte   = 54
	ccidDescriptorType        byte   = 0x21
	ccidBCDVersion            uint16 = 0x0110
	ccidMaxSlotIndex          byte   = 0x00
	ccidVoltageSupport        byte   = 0x07
	ccidProtocols             uint32 = 0x00000003
	ccidDefaultClock          uint32 = 4000
	ccidMaximumClock          uint32 = 4000
	ccidDefaultDataRate       uint32 = 9600
	ccidMaximumDataRate       uint32 = 115200
	ccidMaxIFSD               uint32 = 254
	ccidFeatures              uint32 = 0x000100FE
	ccidMaxCCIDMessageLength  uint32 = 271
)

// BuildCCIDDescriptors builds the complete FunctionFS v2 descriptor blob
// for the CCID function. The blob contains both Full-Speed and High-Speed
// descriptor sets, each consisting of an interface descriptor, CCID class
// descriptor, and three endpoint descriptors (bulk OUT, bulk IN, interrupt IN).
func BuildCCIDDescriptors() []byte {
	fsDescs := buildSpeedDescriptors(ccidBulkMaxPacketFS)
	hsDescs := buildSpeedDescriptors(ccidBulkMaxPacketHS)

	totalLength := uint32(ffsHeaderSize + len(fsDescs) + len(hsDescs))

	var buf bytes.Buffer
	buf.Grow(int(totalLength))

	// FunctionFS v2 header.
	binary.Write(&buf, binary.LittleEndian, functionFSMagicV2)
	binary.Write(&buf, binary.LittleEndian, totalLength)
	binary.Write(&buf, binary.LittleEndian, ffsFlagFSDescs|ffsFlagHSDescs)
	binary.Write(&buf, binary.LittleEndian, descriptorsPerSpeed) // fs_count
	binary.Write(&buf, binary.LittleEndian, descriptorsPerSpeed) // hs_count

	// Full-Speed descriptors followed by High-Speed descriptors.
	buf.Write(fsDescs)
	buf.Write(hsDescs)

	return buf.Bytes()
}

// BuildFunctionFSStrings builds the FunctionFS string descriptor blob.
// This must be written to ep0 after the descriptor blob. It contains the
// CCID interface name string in English (US).
func BuildFunctionFSStrings() []byte {
	str := append([]byte(ccidInterfaceName), 0) // null-terminated

	// header: magic(4) + length(4) + str_count(4) + lang_count(4) + lang(2) = 18
	headerSize := uint32(18)
	totalLength := headerSize + uint32(len(str))

	var buf bytes.Buffer
	buf.Grow(int(totalLength))

	binary.Write(&buf, binary.LittleEndian, functionFSStringsMagic)
	binary.Write(&buf, binary.LittleEndian, totalLength)
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // str_count
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // lang_count
	binary.Write(&buf, binary.LittleEndian, langIDEnglishUS)
	buf.Write(str)

	return buf.Bytes()
}

// buildSpeedDescriptors builds the descriptor set for one speed (FS or HS).
// Returns the concatenated interface + CCID class + endpoint descriptors.
func buildSpeedDescriptors(bulkMaxPacket uint16) []byte {
	var buf bytes.Buffer

	// Interface descriptor.
	buf.Write(buildInterfaceDescriptor(3, usbClassSmartCard, 0x00, 0x00))

	// CCID class descriptor.
	buf.Write(buildCCIDClassDescriptor())

	// Bulk OUT endpoint (EP1, OUT).
	buf.Write(buildEndpointDescriptor(0x01, usbEndpointXferBulk, bulkMaxPacket, 0))

	// Bulk IN endpoint (EP2, IN).
	buf.Write(buildEndpointDescriptor(0x02|usbEndpointDirIN, usbEndpointXferBulk, bulkMaxPacket, 0))

	// Interrupt IN endpoint (EP3, IN).
	buf.Write(buildEndpointDescriptor(0x03|usbEndpointDirIN, usbEndpointXferInterrupt, ccidIntrMaxPacket, ccidIntrInterval))

	return buf.Bytes()
}

// buildInterfaceDescriptor builds a 9-byte USB interface descriptor.
func buildInterfaceDescriptor(numEndpoints, class, subclass, protocol byte) []byte {
	return []byte{
		usbDTInterfaceSize, // bLength
		usbDTInterface,     // bDescriptorType
		0x00,               // bInterfaceNumber
		0x00,               // bAlternateSetting
		numEndpoints,       // bNumEndpoints
		class,              // bInterfaceClass
		subclass,           // bInterfaceSubClass
		protocol,           // bInterfaceProtocol
		0x01,               // iInterface (string index 1)
	}
}

// buildEndpointDescriptor builds a 7-byte USB endpoint descriptor.
func buildEndpointDescriptor(address, attributes byte, maxPacket uint16, interval byte) []byte {
	desc := make([]byte, usbDTEndpointSize)
	desc[0] = usbDTEndpointSize // bLength
	desc[1] = usbDTEndpoint     // bDescriptorType
	desc[2] = address           // bEndpointAddress
	desc[3] = attributes        // bmAttributes
	binary.LittleEndian.PutUint16(desc[4:6], maxPacket)
	desc[6] = interval // bInterval
	return desc
}

// buildCCIDClassDescriptor builds the 54-byte CCID class descriptor.
// This is equivalent to ccid.CCIDDescriptor() but is built locally to
// avoid an import cycle (ccid imports gadget for Transport).
func buildCCIDClassDescriptor() []byte {
	desc := make([]byte, ccidClassDescriptorLength)

	desc[0] = ccidClassDescriptorLength // bLength
	desc[1] = ccidDescriptorType        // bDescriptorType

	binary.LittleEndian.PutUint16(desc[2:4], ccidBCDVersion)
	desc[4] = ccidMaxSlotIndex
	desc[5] = ccidVoltageSupport
	binary.LittleEndian.PutUint32(desc[6:10], ccidProtocols)
	binary.LittleEndian.PutUint32(desc[10:14], ccidDefaultClock)
	binary.LittleEndian.PutUint32(desc[14:18], ccidMaximumClock)
	desc[18] = 0x00 // bNumClockSupported
	binary.LittleEndian.PutUint32(desc[19:23], ccidDefaultDataRate)
	binary.LittleEndian.PutUint32(desc[23:27], ccidMaximumDataRate)
	desc[27] = 0x00 // bNumDataRatesSupported
	binary.LittleEndian.PutUint32(desc[28:32], ccidMaxIFSD)
	binary.LittleEndian.PutUint32(desc[32:36], 0) // dwSynchProtocols
	binary.LittleEndian.PutUint32(desc[36:40], 0) // dwMechanical
	binary.LittleEndian.PutUint32(desc[40:44], ccidFeatures)
	binary.LittleEndian.PutUint32(desc[44:48], ccidMaxCCIDMessageLength)
	desc[48] = 0xFF // bClassGetResponse
	desc[49] = 0xFF // bClassEnvelope
	desc[50] = 0x00 // wLcdLayout low
	desc[51] = 0x00 // wLcdLayout high
	desc[52] = 0x03 // bPINSupport
	desc[53] = 0x01 // bMaxCCIDBusySlots

	return desc
}
