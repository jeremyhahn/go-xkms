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

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
)

// --- fido2Ceremony guard paths ---
//
// The options-JSON parsing that used to live here (parseCreationOptions,
// decodeWebAuthnBase64) moved to the canonical FIDO2 CTAP2 implementation
// (pkg/fido2.ParseWebAuthnRegistrationOptions, exercised through
// webauthnclient.HardwareAdapter), which is the single ceremony driver now.
// Its own test suite covers those parsing paths; what remains here is the
// xkey-local wrapping: bad options and a cancelled context must still stop a
// ceremony before any authenticator is touched.

// TestFIDO2Ceremony_RegisterRejectsBadOptions verifies malformed options are
// rejected before any authenticator is touched, and reported as a
// registration failure rather than a missing PIN or a panic on the
// zero-value ceremony.
func TestFIDO2Ceremony_RegisterRejectsBadOptions(t *testing.T) {
	ceremony := &fido2Ceremony{}

	_, err := ceremony.Register(context.Background(), CeremonyRequest{
		OptionsJSON: []byte("{not json"),
		Origin:      "https://rp.example",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnRegistrationFailed)
	assert.NotErrorIs(t, err, ErrWebAuthnPINRequired)
}

// TestFIDO2Ceremony_RegisterHonorsContext verifies a cancelled context stops
// the ceremony before the authenticator prompt.
func TestFIDO2Ceremony_RegisterHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ceremony := &fido2Ceremony{}
	_, err := ceremony.Register(ctx, CeremonyRequest{
		OptionsJSON: []byte(`{"publicKey":{}}`),
		Origin:      "https://rp.example",
	})
	assert.ErrorIs(t, err, context.Canceled)
}

// --- authenticator discovery ---

// fakeHIDDevice is a HID device double. Only the descriptive accessors the
// enumeration path reads are exercised; the transport methods are never
// reached because no ceremony is driven against it.
type fakeHIDDevice struct {
	path   string
	closed bool
}

func (d *fakeHIDDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *fakeHIDDevice) Read(p []byte) (int, error)  { return 0, nil }
func (d *fakeHIDDevice) Close() error {
	d.closed = true
	return nil
}
func (d *fakeHIDDevice) Path() string         { return d.path }
func (d *fakeHIDDevice) ProductID() uint16    { return 0x0001 }
func (d *fakeHIDDevice) VendorID() uint16     { return 0xF1D0 }
func (d *fakeHIDDevice) Product() string      { return "Test Authenticator" }
func (d *fakeHIDDevice) Manufacturer() string { return "xKey Tests" }
func (d *fakeHIDDevice) SerialNumber() string { return "TEST-0001" }

// fakeEnumerator is a HID enumerator double that reports a scripted device
// list, so authenticator discovery can be exercised without hardware.
type fakeEnumerator struct {
	devices []fido2.HIDDevice
	err     error
}

func (e *fakeEnumerator) Enumerate(_, _ uint16) ([]fido2.HIDDevice, error) {
	return e.devices, e.err
}

func (e *fakeEnumerator) Open(path string) (fido2.HIDDevice, error) {
	if e.err != nil {
		return nil, e.err
	}
	return &fakeHIDDevice{path: path}, nil
}

// installEnumerator points authenticator discovery at the supplied double.
func installEnumerator(t *testing.T, enumerator fido2.HIDDeviceEnumerator) {
	t.Helper()

	original := webauthnEnumeratorFactory
	webauthnEnumeratorFactory = func() fido2.HIDDeviceEnumerator { return enumerator }
	t.Cleanup(func() { webauthnEnumeratorFactory = original })
}

// TestNewFIDO2Ceremony_NoAuthenticator verifies discovery fails closed when
// no CTAP2 device is attached, so a ceremony is never reported as completed
// without an authenticator.
func TestNewFIDO2Ceremony_NoAuthenticator(t *testing.T) {
	installEnumerator(t, &fakeEnumerator{})

	ceremony, err := newFIDO2Ceremony()
	assert.Nil(t, ceremony)
	assert.ErrorIs(t, err, ErrWebAuthnAuthenticatorUnavailable)
}

// TestNewFIDO2Ceremony_EnumerationFails verifies an enumeration error also
// fails closed.
func TestNewFIDO2Ceremony_EnumerationFails(t *testing.T) {
	installEnumerator(t, &fakeEnumerator{err: errors.New("hidraw permission denied")})

	ceremony, err := newFIDO2Ceremony()
	assert.Nil(t, ceremony)
	require.ErrorIs(t, err, ErrWebAuthnAuthenticatorUnavailable)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestNewFIDO2Ceremony_DeviceAttached verifies a ceremony driver is built and
// released when an authenticator is present.
func TestNewFIDO2Ceremony_DeviceAttached(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	installEnumerator(t, &fakeEnumerator{devices: []fido2.HIDDevice{device}})

	ceremony, err := newFIDO2Ceremony()
	require.NoError(t, err)
	require.NotNil(t, ceremony)
	assert.True(t, device.closed, "enumeration must release the probed device")
	assert.NoError(t, ceremony.Close())
}
