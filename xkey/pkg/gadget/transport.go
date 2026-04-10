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

import "context"

// Transport abstracts USB data I/O for a single USB function.
// Both UHID and FunctionFS implement this interface. The interface
// is deliberately small to accommodate future transports such as NFC.
type Transport interface {
	// Read blocks until a message is available from the host or the
	// context is cancelled. For HID functions, messages are 64-byte
	// CTAP-HID packets. For CCID functions, messages are variable-length
	// CCID command blocks.
	Read(ctx context.Context) ([]byte, error)

	// Write sends a response message to the host.
	Write(data []byte) error

	// Close releases the transport resources.
	Close() error
}

// TransportType identifies the USB transport mechanism.
type TransportType string

const (
	// TransportUHID uses Linux UHID (/dev/uhid) for software HID emulation.
	TransportUHID TransportType = "uhid"

	// TransportGadget uses Linux USB Gadget API (ConfigFS/FunctionFS)
	// for real USB device emulation on OTG-capable hardware.
	TransportGadget TransportType = "gadget"
)

// String returns the string representation of the TransportType.
func (t TransportType) String() string {
	return string(t)
}
