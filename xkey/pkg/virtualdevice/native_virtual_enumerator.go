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

package virtualdevice

import (
	"errors"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// NativeVirtualDeviceEnumerator errors.
var (
	// ErrNativeEnumeratorDeviceNil indicates the device is nil.
	ErrNativeEnumeratorDeviceNil = errors.New("fido2: native enumerator device is nil")

	// ErrNativeEnumeratorDeviceExists indicates the device already exists.
	ErrNativeEnumeratorDeviceExists = errors.New("fido2: native enumerator device already registered")

	// ErrNativeEnumeratorDeviceNotFound indicates the device was not found.
	ErrNativeEnumeratorDeviceNotFound = errors.New("fido2: native enumerator device not found")
)

// nativeVirtualDeviceWrapper wraps a NativeVirtualDevice to prevent Close()
// from actually closing the underlying device. This allows the device to be
// reused across multiple operations.
type nativeVirtualDeviceWrapper struct {
	device *NativeVirtualDevice
}

func (w *nativeVirtualDeviceWrapper) Path() string {
	return w.device.Path()
}

func (w *nativeVirtualDeviceWrapper) VendorID() uint16 {
	return w.device.VendorID()
}

func (w *nativeVirtualDeviceWrapper) ProductID() uint16 {
	return w.device.ProductID()
}

func (w *nativeVirtualDeviceWrapper) Manufacturer() string {
	return w.device.Manufacturer()
}

func (w *nativeVirtualDeviceWrapper) Product() string {
	return w.device.Product()
}

func (w *nativeVirtualDeviceWrapper) SerialNumber() string {
	return w.device.SerialNumber()
}

func (w *nativeVirtualDeviceWrapper) Write(data []byte) (int, error) {
	return w.device.Write(data)
}

func (w *nativeVirtualDeviceWrapper) Read(data []byte) (int, error) {
	return w.device.Read(data)
}

// Close is a no-op for the wrapper to keep the underlying device alive.
func (w *nativeVirtualDeviceWrapper) Close() error {
	// Do not close the underlying device - it may be reused
	return nil
}

// Ensure nativeVirtualDeviceWrapper implements fido2.HIDDevice.
var _ fido2.HIDDevice = (*nativeVirtualDeviceWrapper)(nil)

// NativeVirtualDeviceEnumerator implements fido2.HIDDeviceEnumerator for NativeVirtualDevice.
// It manages a registry of native virtual devices that can be enumerated and opened
// like physical HID devices.
type NativeVirtualDeviceEnumerator struct {
	devices map[string]*NativeVirtualDevice
	mu      sync.RWMutex
}

// NewNativeVirtualDeviceEnumerator creates a new native virtual device enumerator.
func NewNativeVirtualDeviceEnumerator() *NativeVirtualDeviceEnumerator {
	return &NativeVirtualDeviceEnumerator{
		devices: make(map[string]*NativeVirtualDevice),
	}
}

// RegisterDevice adds a native virtual device to the enumerator's registry.
// The device will be discoverable via Enumerate() and openable via Open().
func (e *NativeVirtualDeviceEnumerator) RegisterDevice(device *NativeVirtualDevice) error {
	if device == nil {
		return ErrNativeEnumeratorDeviceNil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	path := device.Path()
	if _, exists := e.devices[path]; exists {
		return ErrNativeEnumeratorDeviceExists
	}

	e.devices[path] = device
	return nil
}

// UnregisterDevice removes a native virtual device from the enumerator's registry.
func (e *NativeVirtualDeviceEnumerator) UnregisterDevice(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.devices[path]; !exists {
		return ErrNativeEnumeratorDeviceNotFound
	}

	delete(e.devices, path)
	return nil
}

// Enumerate returns all registered native virtual devices that match the given
// vendor and product IDs. If vendorID and productID are both 0, all
// native virtual devices are returned.
// Returns wrappers that don't close the underlying devices, allowing them
// to be reused across multiple operations.
func (e *NativeVirtualDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]fido2.HIDDevice, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var devices []fido2.HIDDevice
	for _, device := range e.devices {
		// Match all if both IDs are 0
		if vendorID == 0 && productID == 0 {
			devices = append(devices, &nativeVirtualDeviceWrapper{device: device})
			continue
		}

		// Match by vendor ID
		if vendorID != 0 && device.VendorID() != vendorID {
			continue
		}

		// Match by product ID
		if productID != 0 && device.ProductID() != productID {
			continue
		}

		devices = append(devices, &nativeVirtualDeviceWrapper{device: device})
	}

	return devices, nil
}

// Open opens a native virtual device by its path.
// Returns a wrapper that doesn't close the underlying device, allowing it
// to be reused across multiple operations.
func (e *NativeVirtualDeviceEnumerator) Open(path string) (fido2.HIDDevice, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Handle native virtual device paths
	if strings.HasPrefix(path, NativeVirtualDevicePathPrefix) {
		device, exists := e.devices[path]
		if !exists {
			return nil, ErrNativeEnumeratorDeviceNotFound
		}
		return &nativeVirtualDeviceWrapper{device: device}, nil
	}

	// Check if any registered device matches the path
	for devicePath, device := range e.devices {
		if devicePath == path {
			return &nativeVirtualDeviceWrapper{device: device}, nil
		}
	}

	return nil, ErrNativeEnumeratorDeviceNotFound
}

// DeviceCount returns the number of registered native virtual devices.
func (e *NativeVirtualDeviceEnumerator) DeviceCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.devices)
}

// Close unregisters all devices and releases resources.
func (e *NativeVirtualDeviceEnumerator) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for path, device := range e.devices {
		_ = device.Close()
		delete(e.devices, path)
	}

	return nil
}

// Ensure NativeVirtualDeviceEnumerator implements fido2.HIDDeviceEnumerator.
var _ fido2.HIDDeviceEnumerator = (*NativeVirtualDeviceEnumerator)(nil)
