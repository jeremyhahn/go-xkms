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

// UHID event types as defined in Linux kernel include/uapi/linux/uhid.h
const (
	// UHID_DESTROY destroys a UHID device.
	UHID_DESTROY uint32 = 1

	// UHID_START is sent by the kernel when a driver starts using the device.
	UHID_START uint32 = 2

	// UHID_STOP is sent by the kernel when a driver stops using the device.
	UHID_STOP uint32 = 3

	// UHID_OPEN is sent by the kernel when user-space opens the device.
	UHID_OPEN uint32 = 4

	// UHID_CLOSE is sent by the kernel when user-space closes the device.
	UHID_CLOSE uint32 = 5

	// UHID_OUTPUT is sent by the kernel with HID output reports (host to device).
	UHID_OUTPUT uint32 = 6

	// UHID_CREATE2 creates a new UHID device (v2 API).
	UHID_CREATE2 uint32 = 11

	// UHID_INPUT2 sends HID input reports to the kernel (device to host).
	UHID_INPUT2 uint32 = 12
)

// Bus types for UHID devices.
const (
	// BUS_USB indicates a USB bus type.
	BUS_USB uint16 = 0x03
)

// FIDO2 HID constants.
const (
	// VendorIDVirtualFIDO is the vendor ID for virtual FIDO devices.
	VendorIDVirtualFIDO uint16 = 0xF1D0

	// ProductIDVirtualFIDO is the product ID for virtual FIDO devices.
	ProductIDVirtualFIDO uint16 = 0x0003

	// HIDReportSize is the standard HID report size for FIDO2.
	HIDReportSize = 64

	// MaxReportDescriptorSize is the maximum size of a HID report descriptor.
	MaxReportDescriptorSize = 4096

	// UHIDDevicePath is the path to the UHID device.
	UHIDDevicePath = "/dev/uhid"
)

// FIDO2HIDReportDescriptor is the HID report descriptor for FIDO2 devices
// as specified by the FIDO Alliance. This 34-byte descriptor defines:
// - Usage Page: FIDO Alliance (0xF1D0)
// - Usage: U2F Authenticator Device (0x01)
// - Input/Output reports of 64 bytes each
var FIDO2HIDReportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (U2F Authenticator Device)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, // End Collection
}

// uhidCreate2Req is the kernel structure for UHID_CREATE2 requests.
// This matches the Linux kernel uhid_create2_req structure.
// Total size: 276 bytes header + 4096 bytes rd_data = 4372 bytes
//
//nolint:unused // kernel structure definition for documentation; actual serialization uses binary encoding
type uhidCreate2Req struct {
	// name is the device name (128 bytes, null-terminated)
	name [128]byte

	// phys is the physical device path (64 bytes, null-terminated)
	phys [64]byte

	// uniq is the unique identifier (64 bytes, null-terminated)
	uniq [64]byte

	// rdSize is the size of the report descriptor
	rdSize uint16

	// bus is the bus type (e.g., BUS_USB)
	bus uint16

	// vendor is the USB vendor ID
	vendor uint32

	// product is the USB product ID
	product uint32

	// version is the device version
	version uint32

	// country is the HID country code
	country uint32

	// rdData is the HID report descriptor (max 4096 bytes)
	rdData [MaxReportDescriptorSize]byte
}

// uhidCreate2ReqSize is the size of the uhid_create2_req structure.
const uhidCreate2ReqSize = 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + MaxReportDescriptorSize

// uhidInput2Req is the kernel structure for UHID_INPUT2 requests.
// This is used to send HID input reports from the device to the host.
//
//nolint:unused // kernel structure definition for documentation; actual serialization uses binary encoding
type uhidInput2Req struct {
	// size is the size of the data
	size uint16

	// data is the HID report data (max 4096 bytes)
	data [MaxReportDescriptorSize]byte
}

// uhidInput2ReqSize is the size of the uhid_input2_req structure.
const uhidInput2ReqSize = 2 + MaxReportDescriptorSize

// uhidOutputEvent is the kernel structure for UHID_OUTPUT events.
// This is received when the host sends HID output reports to the device.
// Linux kernel uhid_output_req structure (packed):
//
//	__u8 data[UHID_DATA_MAX];  // 4096 bytes - data comes FIRST
//	__u16 size;                // 2 bytes - actual size of data
//	__u8 rtype;                // 1 byte - report type
//
//nolint:unused // kernel structure definition for documentation; actual serialization uses binary encoding
type uhidOutputEvent struct {
	// data is the HID report data (max 4096 bytes) - MUST BE FIRST
	data [MaxReportDescriptorSize]byte

	// size is the actual size of the data
	size uint16

	// rtype is the report type
	rtype uint8
}

// uhidOutputEventSize is the size of the uhid_output structure.
// data[4096] + size[2] + rtype[1] = 4099 bytes
const uhidOutputEventSize = MaxReportDescriptorSize + 2 + 1

// uhidEventHeaderSize is the size of the event type field.
const uhidEventHeaderSize = 4

// CreateConfig contains configuration for creating a UHID device.
type CreateConfig struct {
	// Name is the device name (max 127 characters).
	Name string

	// Phys is the physical device path (max 63 characters).
	Phys string

	// Uniq is the unique identifier/serial number (max 63 characters).
	Uniq string

	// VendorID is the USB vendor ID.
	VendorID uint16

	// ProductID is the USB product ID.
	ProductID uint16

	// Version is the device version.
	Version uint16

	// ReportDescriptor is the HID report descriptor.
	// If nil, FIDO2HIDReportDescriptor is used.
	ReportDescriptor []byte
}

// DefaultCreateConfig returns a CreateConfig with default values for a virtual FIDO2 device.
func DefaultCreateConfig() *CreateConfig {
	return &CreateConfig{
		Name:             "go-keychain FIDO2",
		Phys:             "go-keychain-fido2",
		Uniq:             "VFIDO001",
		VendorID:         VendorIDVirtualFIDO,
		ProductID:        ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: FIDO2HIDReportDescriptor,
	}
}
