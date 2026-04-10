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

package phone

// Android Open Accessory (AOA) protocol constants and helpers.
//
// AOA allows an Android device to act as a USB accessory while the
// laptop/desktop acts as the USB host. The host sends AOA control
// transfers to the Android device to switch it into accessory mode,
// then communicates via bulk endpoints.
//
// Reference: https://source.android.com/docs/core/interaction/accessories/protocol

// AOA USB vendor and product IDs.
const (
	// AOAVendorID is Google's USB vendor ID used for AOA devices.
	AOAVendorID = 0x18D1

	// AOAProductID is the product ID for an AOA device without ADB.
	AOAProductID = 0x2D00

	// AOAProductIDADB is the product ID for an AOA device with ADB enabled.
	AOAProductIDADB = 0x2D01
)

// AOA control request types.
const (
	// AOARequestGetProtocol is the control request to get the AOA protocol version.
	// bmRequestType: 0xC0 (device-to-host, vendor, device)
	// bRequest: 51
	AOARequestGetProtocol = 51

	// AOARequestSendString is the control request to send an identifying string.
	// bmRequestType: 0x40 (host-to-device, vendor, device)
	// bRequest: 52
	// wIndex: string ID (0=manufacturer, 1=model, 2=description, 3=version, 4=URI, 5=serial)
	AOARequestSendString = 52

	// AOARequestStart is the control request to start accessory mode.
	// bmRequestType: 0x40 (host-to-device, vendor, device)
	// bRequest: 53
	AOARequestStart = 53
)

// AOA string descriptor indices for AOARequestSendString.
const (
	// AOAStringManufacturer identifies the accessory manufacturer.
	AOAStringManufacturer = 0

	// AOAStringModel identifies the accessory model.
	AOAStringModel = 1

	// AOAStringDescription provides a description of the accessory.
	AOAStringDescription = 2

	// AOAStringVersion provides the accessory version.
	AOAStringVersion = 3

	// AOAStringURI provides a URL for the accessory.
	AOAStringURI = 4

	// AOAStringSerial provides the accessory serial number.
	AOAStringSerial = 5
)

// xKey AOA accessory identification strings.
// These must match the values in usb_accessory_filter.xml on Android.
const (
	// XKeyAOAManufacturer is the manufacturer string sent during AOA setup.
	XKeyAOAManufacturer = "xKey"

	// XKeyAOAModel is the model string sent during AOA setup.
	XKeyAOAModel = "Desktop"

	// XKeyAOADescription is the description string sent during AOA setup.
	XKeyAOADescription = "xKey Desktop Security Key Client"

	// XKeyAOAVersion is the version string sent during AOA setup.
	XKeyAOAVersion = "1.0"
)

// IsAOADevice returns true if the given USB vendor and product IDs
// indicate an Android device already in AOA accessory mode.
func IsAOADevice(vendorID, productID uint16) bool {
	return vendorID == AOAVendorID &&
		(productID == AOAProductID || productID == AOAProductIDADB)
}
