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

//go:build linux

package fido2

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	virtualfido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/u2f"
)

// ErrVirtualDeviceClosed is returned when operating on a closed virtual device.
var ErrVirtualDeviceClosed = errors.New("fido2: virtual device is closed")

const (
	// VirtualFIDOVendorID is the vendor ID for virtual FIDO devices.
	VirtualFIDOVendorID = 0xF1D0 // FIDO Alliance

	// VirtualFIDOProductID is the product ID for virtual FIDO devices.
	VirtualFIDOProductID = 0x0001

	// VirtualFIDOPathPrefix is the path prefix for virtual devices.
	VirtualFIDOPathPrefix = "virtualfido://"
)

// VirtualFIDO2Device implements HIDDevice interface by wrapping the
// virtual-fido library. It provides a virtual FIDO2/U2F authenticator
// that can be used for testing without hardware.
type VirtualFIDO2Device struct {
	path         string
	fidoClient   virtualfido.FIDOClient
	hidServer    *ctap_hid.CTAPHIDServer
	ctapServer   *ctap.CTAPServer
	u2fServer    *u2f.U2FServer
	manufacturer string
	product      string
	serialNumber string

	// Response channel for async HID communication
	respChan chan []byte

	mu     sync.Mutex
	closed atomic.Bool
}

// VirtualDeviceConfig contains configuration for creating a virtual FIDO2 device.
type VirtualDeviceConfig struct {
	// SerialNumber is the device serial number.
	SerialNumber string

	// Manufacturer is the manufacturer name.
	Manufacturer string

	// Product is the product name.
	Product string

	// FIDOClient is the virtual-fido client to use.
	// This is required.
	FIDOClient virtualfido.FIDOClient
}

// NewVirtualFIDO2Device creates a new virtual FIDO2 device.
func NewVirtualFIDO2Device(config *VirtualDeviceConfig) (*VirtualFIDO2Device, error) {
	if config == nil {
		config = &VirtualDeviceConfig{}
	}

	// Set defaults
	if config.SerialNumber == "" {
		config.SerialNumber = "VFIDO001"
	}
	if config.Manufacturer == "" {
		config.Manufacturer = "go-keychain"
	}
	if config.Product == "" {
		config.Product = "VirtualFIDO"
	}

	if config.FIDOClient == nil {
		return nil, fmt.Errorf("fido2: FIDOClient is required")
	}

	device := &VirtualFIDO2Device{
		path:         VirtualFIDOPathPrefix + config.SerialNumber,
		fidoClient:   config.FIDOClient,
		manufacturer: config.Manufacturer,
		product:      config.Product,
		serialNumber: config.SerialNumber,
		respChan:     make(chan []byte, 64),
	}

	// Initialize CTAP and U2F servers with the FIDO client
	device.ctapServer = ctap.NewCTAPServer(config.FIDOClient)
	device.u2fServer = u2f.NewU2FServer(config.FIDOClient)

	// Initialize CTAPHID handler with both CTAP and U2F servers
	device.hidServer = ctap_hid.NewCTAPHIDServer(device.ctapServer, device.u2fServer)

	// Set up response handler to receive HID responses
	device.hidServer.SetResponseHandler(func(response []byte) {
		// Non-blocking send to response channel
		select {
		case device.respChan <- response:
		default:
			// Channel full - drop oldest response
			select {
			case <-device.respChan:
			default:
			}
			select {
			case device.respChan <- response:
			default:
			}
		}
	})

	return device, nil
}

// Write sends data to the virtual device (HID output report).
// This is called by the FIDO2 handler to send CTAP commands.
func (d *VirtualFIDO2Device) Write(data []byte) (int, error) {
	if d.closed.Load() {
		return 0, ErrVirtualDeviceClosed
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Process the HID packet through virtual-fido's CTAPHID handler
	// Response will be delivered via the callback to respChan
	d.hidServer.HandleMessage(data)

	return len(data), nil
}

// Read receives data from the virtual device (HID input report).
// This is called by the FIDO2 handler to receive CTAP responses.
func (d *VirtualFIDO2Device) Read(data []byte) (int, error) {
	if d.closed.Load() {
		return 0, ErrVirtualDeviceClosed
	}

	// Wait for response from the device
	response := <-d.respChan
	if response == nil {
		return 0, ErrVirtualDeviceClosed
	}

	n := copy(data, response)
	return n, nil
}

// Close closes the virtual device.
func (d *VirtualFIDO2Device) Close() error {
	if d.closed.Swap(true) {
		return nil // Already closed
	}

	close(d.respChan)
	return nil
}

// Path returns the virtual device path.
func (d *VirtualFIDO2Device) Path() string {
	return d.path
}

// ProductID returns the USB product ID.
func (d *VirtualFIDO2Device) ProductID() uint16 {
	return VirtualFIDOProductID
}

// VendorID returns the USB vendor ID.
func (d *VirtualFIDO2Device) VendorID() uint16 {
	return VirtualFIDOVendorID
}

// Product returns the product name.
func (d *VirtualFIDO2Device) Product() string {
	return d.product
}

// Manufacturer returns the manufacturer name.
func (d *VirtualFIDO2Device) Manufacturer() string {
	return d.manufacturer
}

// SerialNumber returns the device serial number.
func (d *VirtualFIDO2Device) SerialNumber() string {
	return d.serialNumber
}

// FIDOClient returns the underlying virtual-fido client.
func (d *VirtualFIDO2Device) FIDOClient() virtualfido.FIDOClient {
	return d.fidoClient
}

// Ensure VirtualFIDO2Device implements HIDDevice.
var _ HIDDevice = (*VirtualFIDO2Device)(nil)
