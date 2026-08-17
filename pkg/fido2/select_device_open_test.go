// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package fido2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metadataOnlyDevice mimics what LinuxHIDDeviceEnumerator.Enumerate returns:
// a handle carrying sysfs metadata whose file was never opened, so every
// Read/Write fails until the enumerator re-opens it by path.
type metadataOnlyDevice struct {
	path   string
	closed bool
}

func (d *metadataOnlyDevice) Write([]byte) (int, error) { return 0, errors.New("device not open") }
func (d *metadataOnlyDevice) Read([]byte) (int, error)  { return 0, errors.New("device not open") }
func (d *metadataOnlyDevice) Close() error              { d.closed = true; return nil }
func (d *metadataOnlyDevice) Path() string              { return d.path }
func (d *metadataOnlyDevice) ProductID() uint16         { return 0x0001 }
func (d *metadataOnlyDevice) VendorID() uint16          { return FIDOAllianceVID }
func (d *metadataOnlyDevice) Product() string           { return "meta" }
func (d *metadataOnlyDevice) Manufacturer() string      { return "meta" }
func (d *metadataOnlyDevice) SerialNumber() string      { return "meta" }

// reopeningEnumerator enumerates metadata-only handles and produces the live
// device from Open, the contract the Linux enumerator implements.
type reopeningEnumerator struct {
	scan    HIDDevice
	live    HIDDevice
	openErr error
	opened  []string
}

func (e *reopeningEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return []HIDDevice{e.scan}, nil
}

func (e *reopeningEnumerator) Open(path string) (HIDDevice, error) {
	e.opened = append(e.opened, path)
	if e.openErr != nil {
		return nil, e.openErr
	}
	return e.live, nil
}

// TestSelectDevice_ReopensEnumeratedHandle pins the regression behind the
// login-matrix fido2 failure: enumeration handles are metadata-only, so
// selectDevice must hand back the device the enumerator OPENED, closing the
// scan handle it replaces.
func TestSelectDevice_ReopensEnumeratedHandle(t *testing.T) {
	scan := &metadataOnlyDevice{path: "/dev/hidraw9"}
	live := &metadataOnlyDevice{path: "/dev/hidraw9"}
	enum := &reopeningEnumerator{scan: scan, live: live}

	cfg := DefaultConfig
	h, err := NewHandler(&cfg, enum)
	require.NoError(t, err)

	device, err := h.selectDevice()
	require.NoError(t, err)
	assert.Same(t, live, device, "selectDevice must return the enumerator-opened device")
	assert.Equal(t, []string{"/dev/hidraw9"}, enum.opened, "the selected path must be re-opened")
	assert.True(t, scan.closed, "the metadata-only scan handle must be closed after re-open")
	assert.False(t, live.closed, "the live device must remain open")
}

// TestSelectDevice_SameInstanceFromOpen covers in-process enumerators whose
// Open returns the exact device Enumerate produced: selectDevice must use it
// as-is and must NOT close it.
func TestSelectDevice_SameInstanceFromOpen(t *testing.T) {
	dev := &metadataOnlyDevice{path: "/dev/hidraw3"}
	enum := &reopeningEnumerator{scan: dev, live: dev}

	cfg := DefaultConfig
	h, err := NewHandler(&cfg, enum)
	require.NoError(t, err)

	device, err := h.selectDevice()
	require.NoError(t, err)
	assert.Same(t, dev, device)
	assert.False(t, dev.closed, "a same-instance device must not be closed by the swap")
}

// TestSelectDevice_OpenFailure proves the error path: a device that
// enumerates but cannot be opened yields a typed failure, not a handle whose
// first write explodes.
func TestSelectDevice_OpenFailure(t *testing.T) {
	scan := &metadataOnlyDevice{path: "/dev/hidraw7"}
	enum := &reopeningEnumerator{scan: scan, openErr: errors.New("permission denied")}

	cfg := DefaultConfig
	h, err := NewHandler(&cfg, enum)
	require.NoError(t, err)

	device, err := h.selectDevice()
	require.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to open selected device /dev/hidraw7")
}
