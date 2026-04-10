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

import "encoding/binary"

// USB device identification for the virtual CCID smartcard reader.
const (
	// VendorIDCCID is the USB vendor ID for the virtual CCID device.
	// Uses a test/prototype range to avoid conflicts with real hardware.
	VendorIDCCID uint16 = 0xF1D0

	// ProductIDCCID is the USB product ID for the virtual CCID device.
	ProductIDCCID uint16 = 0x0004

	// CCIDDeviceVersion is the device version number.
	CCIDDeviceVersion uint16 = 0x0100

	// CCIDDeviceName is the human-readable device name.
	CCIDDeviceName = "xKey CCID Smartcard Reader"

	// CCIDDevicePhys is the physical path identifier.
	CCIDDevicePhys = "xkey-ccid"

	// CCIDDeviceSerial is the default serial number.
	CCIDDeviceSerial = "XKEYCCID001"
)

// CCID USB class descriptor constants (USB Device Class 0x0B).
const (
	// CCIDClassDescriptorLength is the length of the CCID class descriptor (54 bytes).
	CCIDClassDescriptorLength = 54

	// CCIDDescriptorType is the descriptor type for CCID (0x21 = functional descriptor).
	CCIDDescriptorType = 0x21

	// CCIDBCDVersion is the CCID specification version (1.10).
	CCIDBCDVersion uint16 = 0x0110

	// CCIDMaxSlotIndex is the highest slot index (0 = single slot).
	CCIDMaxSlotIndex = 0x00

	// CCIDVoltageSupport indicates supported voltages.
	// Bit 0: 5V, Bit 1: 3V, Bit 2: 1.8V.
	CCIDVoltageSupport = 0x07

	// CCIDProtocols indicates supported protocols.
	// Bit 0: T=0, Bit 1: T=1.
	CCIDProtocols uint32 = 0x00000003

	// CCIDDefaultClock is the default ICC clock frequency in kHz.
	CCIDDefaultClock uint32 = 4000

	// CCIDMaximumClock is the maximum ICC clock frequency in kHz.
	CCIDMaximumClock uint32 = 4000

	// CCIDDefaultDataRate is the default data rate in bps.
	CCIDDefaultDataRate uint32 = 9600

	// CCIDMaximumDataRate is the maximum data rate in bps.
	CCIDMaximumDataRate uint32 = 115200

	// CCIDMaxIFSD is the maximum IFSD (Information Field Size Device).
	CCIDMaxIFSD uint32 = 254

	// CCIDFeatures indicates device features.
	// Bit 1: Automatic parameter configuration based on ATR.
	// Bit 2: Automatic activation of ICC on inserting.
	// Bit 3: Automatic ICC voltage selection.
	// Bit 4: Automatic ICC clock frequency change.
	// Bit 5: Automatic baud rate change.
	// Bit 6: Automatic parameters negotiation.
	// Bit 7: Automatic PPS.
	// Bit 16: TPDU level exchange with CCID.
	CCIDFeatures uint32 = 0x000100FE

	// CCIDMaxCCIDMessageLength is the maximum CCID message length.
	CCIDMaxCCIDMessageLength uint32 = 271

	// MaxCCIDDataLength is the maximum APDU data that can be transferred
	// in a single CCID XfrBlock message. This is the data portion
	// after the 10-byte CCID header.
	MaxCCIDDataLength = 261

	// CCIDHeaderLength is the length of the CCID message header.
	CCIDHeaderLength = 10
)

// CCID HID Report Descriptor.
//
// This descriptor presents the device as a HID device with Usage Page set
// to a vendor-specific range that the kernel's CCID class driver recognizes.
// It defines 271-byte input and output reports to carry CCID messages:
//   - Input:  RDR_to_PC messages (device to host)
//   - Output: PC_to_RDR messages (host to device)
//
// Note: A real USB CCID device uses the CCID class (0x0B) directly, not HID.
// However, since UHID only creates HID devices, we use a HID report descriptor
// that carries CCID framing inside HID reports. Applications must understand
// this encapsulation. For VM passthrough, the hypervisor sees a USB HID device
// with this specific usage page and can route it as a smartcard reader.
var CCIDHIDReportDescriptor = []byte{
	// Usage Page (Vendor Defined 0xFF00 - smartcard class)
	0x06, 0x00, 0xFF,
	// Usage (Vendor Usage 1)
	0x09, 0x01,
	// Collection (Application)
	0xA1, 0x01,

	//   --- Input Report (RDR_to_PC) ---
	//   Usage (Vendor Input)
	0x09, 0x20,
	//   Logical Minimum (0)
	0x15, 0x00,
	//   Logical Maximum (255)
	0x26, 0xFF, 0x00,
	//   Report Size (8 bits)
	0x75, 0x08,
	//   Report Count (271) - max CCID message
	0x96, 0x0F, 0x01,
	//   Input (Data, Variable, Absolute)
	0x81, 0x02,

	//   --- Output Report (PC_to_RDR) ---
	//   Usage (Vendor Output)
	0x09, 0x21,
	//   Logical Minimum (0)
	0x15, 0x00,
	//   Logical Maximum (255)
	0x26, 0xFF, 0x00,
	//   Report Size (8 bits)
	0x75, 0x08,
	//   Report Count (271) - max CCID message
	0x96, 0x0F, 0x01,
	//   Output (Data, Variable, Absolute)
	0x91, 0x02,

	// End Collection
	0xC0,
}

// CCIDDescriptor returns the raw CCID class descriptor bytes.
//
// This is the 54-byte Smart Card Device Class Descriptor as defined
// by the USB Device Class specification for Smart Card Devices (CCID).
//
// The returned bytes can be embedded in a USB configuration descriptor
// to identify the device as a CCID reader.
func CCIDDescriptor() []byte {
	desc := make([]byte, CCIDClassDescriptorLength)

	// bLength: Size of this descriptor in bytes.
	desc[0] = CCIDClassDescriptorLength

	// bDescriptorType: Functional descriptor type.
	desc[1] = CCIDDescriptorType

	// bcdCCID: CCID specification release number (1.10).
	binary.LittleEndian.PutUint16(desc[2:4], CCIDBCDVersion)

	// bMaxSlotIndex: Highest available slot index.
	desc[4] = CCIDMaxSlotIndex

	// bVoltageSupport: Voltage support bitmap.
	desc[5] = CCIDVoltageSupport

	// dwProtocols: Supported protocol types (T=0 and T=1).
	binary.LittleEndian.PutUint32(desc[6:10], CCIDProtocols)

	// dwDefaultClock: Default ICC clock frequency in kHz.
	binary.LittleEndian.PutUint32(desc[10:14], CCIDDefaultClock)

	// dwMaximumClock: Maximum ICC clock frequency in kHz.
	binary.LittleEndian.PutUint32(desc[14:18], CCIDMaximumClock)

	// bNumClockSupported: Number of clock frequencies (0 = only default).
	desc[18] = 0x00

	// dwDataRate: Default data rate in bps.
	binary.LittleEndian.PutUint32(desc[19:23], CCIDDefaultDataRate)

	// dwMaxDataRate: Maximum data rate in bps.
	binary.LittleEndian.PutUint32(desc[23:27], CCIDMaximumDataRate)

	// bNumDataRatesSupported: Number of data rates (0 = only default).
	desc[27] = 0x00

	// dwMaxIFSD: Maximum IFSD.
	binary.LittleEndian.PutUint32(desc[28:32], CCIDMaxIFSD)

	// dwSynchProtocols: No synchronous protocols supported.
	binary.LittleEndian.PutUint32(desc[32:36], 0)

	// dwMechanical: No mechanical features.
	binary.LittleEndian.PutUint32(desc[36:40], 0)

	// dwFeatures: Device features bitmap.
	binary.LittleEndian.PutUint32(desc[40:44], CCIDFeatures)

	// dwMaxCCIDMessageLength: Maximum CCID message length.
	binary.LittleEndian.PutUint32(desc[44:48], CCIDMaxCCIDMessageLength)

	// bClassGetResponse: Echo of class byte for GET RESPONSE.
	desc[48] = 0xFF

	// bClassEnvelope: Echo of class byte for ENVELOPE.
	desc[49] = 0xFF

	// wLcdLayout: No LCD (0x0000).
	desc[50] = 0x00
	desc[51] = 0x00

	// bPINSupport: PIN verification and modification supported.
	// Bit 0: PIN verification, Bit 1: PIN modification.
	desc[52] = 0x03

	// bMaxCCIDBusySlots: Maximum simultaneous busy slots.
	desc[53] = 0x01

	return desc
}

// DefaultATR returns a standard Answer To Reset byte sequence for the
// virtual smartcard. This ATR identifies the card as a generic
// ISO 7816-4 compliant device supporting T=1 protocol.
//
// ATR breakdown:
//
//	TS=0x3B  - Direct convention
//	T0=0x8D  - TD1 present, 13 historical bytes
//	TD1=0x01 - T=1 protocol, no further interface bytes
//	T1..T13  - Historical bytes (application identifier)
//	TCK      - Check byte (XOR of T0..T13)
func DefaultATR() []byte {
	return []byte{
		0x3B, // TS: Direct convention
		0x8D, // T0: TD1 present, 13 historical bytes
		0x01, // TD1: T=1 protocol
		'x',  // Historical bytes: "xKey CCID v1.0"
		'K', 'e', 'y', ' ',
		'C', 'C', 'I', 'D',
		' ', 'v', '1', '.', '0',
	}
}
