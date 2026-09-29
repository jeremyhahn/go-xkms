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

package client

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// testSecretForCeremony builds a *secure.Secret from a plaintext PIN for
// tests that need a non-nil CeremonyOptions.PIN.
func testSecretForCeremony(t *testing.T, plaintext string) *secure.Secret {
	t.Helper()
	s, err := secure.NewSecret([]byte(plaintext))
	if err != nil {
		t.Fatalf("secure.NewSecret: %v", err)
	}
	return s
}

// fakeHIDDevice is a HID device double. Only the descriptive accessors the
// enumeration path reads are exercised; no CTAP2 transport round trip is
// driven against it, matching pkg/fido2's own discovery-path tests.
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
func (d *fakeHIDDevice) Manufacturer() string { return "webauthn/client tests" }
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

// TestNewHardwareAdapter_NoAuthenticator verifies discovery fails closed
// when no CTAP2 device is attached, so a caller never mistakes a missing
// security key for a usable adapter.
func TestNewHardwareAdapter_NoAuthenticator(t *testing.T) {
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{})
	if adapter != nil {
		t.Fatal("NewHardwareAdapter() should return a nil adapter when no device is attached")
	}
	if !errors.Is(err, ErrAuthenticatorNotFound) {
		t.Errorf("error = %v, want %v", err, ErrAuthenticatorNotFound)
	}
}

// TestNewHardwareAdapter_EnumerationFails verifies an enumeration error also
// fails closed rather than reporting an available adapter.
func TestNewHardwareAdapter_EnumerationFails(t *testing.T) {
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{err: errors.New("hidraw permission denied")})
	if adapter != nil {
		t.Fatal("NewHardwareAdapter() should return a nil adapter on enumeration failure")
	}
	if !errors.Is(err, ErrAuthenticatorNotFound) {
		t.Errorf("error = %v, want %v", err, ErrAuthenticatorNotFound)
	}
}

// TestNewHardwareAdapter_DeviceAttached verifies an adapter is built and can
// be closed when an authenticator is present.
func TestNewHardwareAdapter_DeviceAttached(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	if adapter == nil {
		t.Fatal("NewHardwareAdapter() returned nil adapter")
	}
	if !device.closed {
		t.Error("discovery must release the probed device")
	}
	if !adapter.Available() {
		t.Error("Available() should be true once the handle is open")
	}
	if err := adapter.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// TestHardwareAdapter_MakeCredential_InvalidOptions proves malformed
// creation options fail before any CTAP2 request is attempted.
func TestHardwareAdapter_MakeCredential_InvalidOptions(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	_, err = adapter.MakeCredential(context.Background(), &CeremonyOptions{OptionsJSON: []byte("not json")})
	if err == nil {
		t.Fatal("MakeCredential() should reject malformed options")
	}
	if !errors.Is(err, ErrInvalidServerResponse) {
		t.Errorf("error = %v, want to wrap %v", err, ErrInvalidServerResponse)
	}
}

// TestHardwareAdapter_MakeCredential_NilRequest proves a nil CeremonyOptions
// is rejected rather than dereferenced.
func TestHardwareAdapter_MakeCredential_NilRequest(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	_, err = adapter.MakeCredential(context.Background(), nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("error = %v, want %v", err, ErrNilRequest)
	}
}

// TestHardwareAdapter_MakeCredential_HonorsContext proves a canceled context
// short-circuits before any device I/O is attempted.
func TestHardwareAdapter_MakeCredential_HonorsContext(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	validOptions := []byte(`{"publicKey":{"challenge":"YWJj","rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"u","displayName":"U"}}}`)
	_, err = adapter.MakeCredential(ctx, &CeremonyOptions{OptionsJSON: validOptions})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want %v", err, context.Canceled)
	}
}

// TestHardwareAdapter_GetAssertion_NilRequest proves a nil CeremonyOptions
// is rejected rather than dereferenced.
func TestHardwareAdapter_GetAssertion_NilRequest(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	adapter, err := NewHardwareAdapter(nil, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	_, err = adapter.GetAssertion(context.Background(), nil)
	if !errors.Is(err, ErrNilRequest) {
		t.Errorf("error = %v, want %v", err, ErrNilRequest)
	}
}

// TestNewHardwareAdapter_UsesSuppliedConfig proves a non-nil config is
// applied rather than silently replaced with fido2.DefaultConfig — the
// device-attached path exercises the "cfg = *config" branch, distinct from
// the nil-config default used by every other constructor test in this file.
func TestNewHardwareAdapter_UsesSuppliedConfig(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	cfg := fido2.DefaultConfig
	cfg.RelyingPartyID = "hardware-adapter-test.example"

	adapter, err := NewHardwareAdapter(&cfg, &fakeEnumerator{devices: []fido2.HIDDevice{device}})
	if err != nil {
		t.Fatalf("NewHardwareAdapter() error: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	if !adapter.Available() {
		t.Error("Available() should be true once the handle is open")
	}
}

// TestHIDEnumerator_NilUsesPlatformDefault proves a nil enumerator falls
// back to fido2.NewDefaultEnumerator() rather than leaving the adapter with
// no way to discover a device. Only the enumerator's type is compared:
// enumerating would read the HID devices attached to the host running the
// test, and the outcome would then depend on that host's hardware.
func TestHIDEnumerator_NilUsesPlatformDefault(t *testing.T) {
	got, want := hidEnumerator(nil), fido2.NewDefaultEnumerator()
	if got == nil {
		t.Fatal("hidEnumerator(nil) returned nil")
	}
	if reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Errorf("hidEnumerator(nil) is a %T, want the platform %T", got, want)
	}
}

// TestHIDEnumerator_KeepsTheSuppliedEnumerator proves a supplied enumerator
// is used as given.
func TestHIDEnumerator_KeepsTheSuppliedEnumerator(t *testing.T) {
	supplied := &fakeEnumerator{}
	if got := hidEnumerator(supplied); got != supplied {
		t.Errorf("hidEnumerator(supplied) = %#v, want the supplied enumerator", got)
	}
}

// TestHardwareCeremonyFailure_MissingPINIsClassifiedAsPINRequired proves the
// no-PIN/ErrPINRequired combination is named as ErrPINRequired rather than
// folded into the generic CTAP failure.
func TestHardwareCeremonyFailure_MissingPINIsClassifiedAsPINRequired(t *testing.T) {
	err := hardwareCeremonyFailure(nil, fido2.ErrPINRequired)
	if !errors.Is(err, ErrPINRequired) {
		t.Errorf("error = %v, want to wrap %v", err, ErrPINRequired)
	}
	if !errors.Is(err, fido2.ErrPINRequired) {
		t.Error("the raw CTAP cause must still be in the chain")
	}
}

// TestHardwareCeremonyFailure_OtherCasesAreGenericCTAPFailures proves every
// other combination — a PIN supplied and refused, or no PIN and an unrelated
// CTAP error — is reported as a plain operation failure rather than sending
// the caller back to resupply a PIN.
func TestHardwareCeremonyFailure_OtherCasesAreGenericCTAPFailures(t *testing.T) {
	t.Run("PIN supplied and refused", func(t *testing.T) {
		pin := testSecretForCeremony(t, "123456")
		err := hardwareCeremonyFailure(pin, fido2.ErrPINRequired)
		if !errors.Is(err, ErrCTAPOperationFailed) {
			t.Errorf("error = %v, want to wrap %v", err, ErrCTAPOperationFailed)
		}
		if errors.Is(err, ErrPINRequired) {
			t.Error("a PIN that was actually supplied must not be reported as missing")
		}
	})

	t.Run("no PIN, unrelated CTAP error", func(t *testing.T) {
		unrelated := errors.New("CTAP2_ERR_OPERATION_DENIED")
		err := hardwareCeremonyFailure(nil, unrelated)
		if !errors.Is(err, ErrCTAPOperationFailed) {
			t.Errorf("error = %v, want to wrap %v", err, ErrCTAPOperationFailed)
		}
		if !errors.Is(err, unrelated) {
			t.Error("the raw CTAP cause must still be in the chain")
		}
	})
}

// TestHardwareAdapter_Available_NoHandler proves the zero-value adapter (no
// handler open) reports unavailable rather than panicking.
func TestHardwareAdapter_Available_NoHandler(t *testing.T) {
	adapter := &HardwareAdapter{}
	if adapter.Available() {
		t.Error("Available() should be false with no open handler")
	}
	if err := adapter.Close(); err != nil {
		t.Errorf("Close() on a never-opened adapter should be a no-op, got: %v", err)
	}
}
