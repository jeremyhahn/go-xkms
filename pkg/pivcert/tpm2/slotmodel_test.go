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

package tpm2

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// TestPIVSlotToCertID_Pinned pins the on-device identifiers. Changing one
// orphans every certificate already stored under the old value, so this test
// exists to make such a change deliberate.
func TestPIVSlotToCertID_Pinned(t *testing.T) {
	tests := []struct {
		slot pivcert.PIVSlot
		want string
	}{
		{pivcert.PIVSlotAuthentication, "piv-cert-9a"},
		{pivcert.PIVSlotDigitalSignature, "piv-cert-9c"},
		{pivcert.PIVSlotKeyManagement, "piv-cert-9d"},
		{pivcert.PIVSlotCardAuthentication, "piv-cert-9e"},
		{pivcert.PIVSlotAttestation, "piv-cert-f9"},
		{pivcert.PIVSlotRetired1, "piv-cert-82"},
		{pivcert.PIVSlotRetired20, "piv-cert-95"},
	}

	for _, tt := range tests {
		t.Run(string(tt.slot), func(t *testing.T) {
			got, ok := PIVSlotToCertID(tt.slot)
			if !ok {
				t.Fatalf("PIVSlotToCertID(%q) reported no mapping", tt.slot)
			}
			if got != tt.want {
				t.Errorf("PIVSlotToCertID(%q) = %q, want %q", tt.slot, got, tt.want)
			}
		})
	}
}

// TestPIVSlotToCertID_UnknownSlot verifies unknown slots are rejected rather
// than mapped onto an arbitrary NV record.
func TestPIVSlotToCertID_UnknownSlot(t *testing.T) {
	unknown := []pivcert.PIVSlot{"", "zz", "9A", "0x9a", "96"}

	for _, slot := range unknown {
		if id, ok := PIVSlotToCertID(slot); ok {
			t.Errorf("PIVSlotToCertID(%q) = (%q, true), want no mapping", slot, id)
		}
		if _, err := certIDFor(slot); !errors.Is(err, pivcert.ErrInvalidSlot) {
			t.Errorf("certIDFor(%q) error = %v, want ErrInvalidSlot", slot, err)
		}
	}
}

// TestCertIDToPIVSlot_ForeignID verifies certificate IDs written by other
// subsystems into the same NV range do not resolve to a PIV slot.
func TestCertIDToPIVSlot_ForeignID(t *testing.T) {
	foreign := []string{"", "root-ca", "piv-cert-", "piv-cert-zz", "0x01800000", "PIV-CERT-9A"}

	for _, id := range foreign {
		if slot, ok := CertIDToPIVSlot(id); ok {
			t.Errorf("CertIDToPIVSlot(%q) = (%q, true), want no mapping", id, slot)
		}
	}
}

// TestNewPIVSlotModel_NilStorage verifies the slot model refuses to be built
// without a certificate store.
func TestNewPIVSlotModel_NilStorage(t *testing.T) {
	model, err := NewPIVSlotModel(nil)
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Fatalf("NewPIVSlotModel(nil) error = %v, want ErrInvalidConfig", err)
	}
	if model != nil {
		t.Error("NewPIVSlotModel(nil) returned a model")
	}
}

// TestNewFromCertStorage_NilStorage verifies the adapter refuses a nil store.
func TestNewFromCertStorage_NilStorage(t *testing.T) {
	store, err := NewFromCertStorage(nil)
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Fatalf("NewFromCertStorage(nil) error = %v, want ErrInvalidConfig", err)
	}
	if store != nil {
		t.Error("NewFromCertStorage(nil) returned a store")
	}
}

// TestConfig_HardwareConfigDefaults verifies unset fields fall back to the PIV
// defaults and set fields are passed through untouched.
func TestConfig_HardwareConfigDefaults(t *testing.T) {
	defaults := (&Config{TPM: stubTPM{}}).hardwareConfig()
	if defaults.BaseIndex != DefaultBaseIndex {
		t.Errorf("BaseIndex = %#x, want %#x", defaults.BaseIndex, DefaultBaseIndex)
	}
	if defaults.MaxCertSize != DefaultMaxCertSize {
		t.Errorf("MaxCertSize = %d, want %d", defaults.MaxCertSize, DefaultMaxCertSize)
	}
	if defaults.OwnerAuth != nil {
		t.Errorf("OwnerAuth = %v, want nil", defaults.OwnerAuth)
	}

	explicit := (&Config{
		TPM:         stubTPM{},
		BaseIndex:   0x01900000,
		MaxCertSize: 1024,
		OwnerAuth:   []byte("auth"),
	}).hardwareConfig()
	if explicit.BaseIndex != 0x01900000 {
		t.Errorf("BaseIndex = %#x, want 0x01900000", explicit.BaseIndex)
	}
	if explicit.MaxCertSize != 1024 {
		t.Errorf("MaxCertSize = %d, want 1024", explicit.MaxCertSize)
	}
	if string(explicit.OwnerAuth) != "auth" {
		t.Errorf("OwnerAuth = %q, want auth", explicit.OwnerAuth)
	}
}

// TestNew_InvalidBaseIndex verifies a base index outside NV RAM is rejected by
// the hardware layer and surfaces as a PIV storage error.
func TestNew_InvalidBaseIndex(t *testing.T) {
	// pivcert.DefaultTPM2BaseIndex sits above the NV range the hardware
	// certificate storage addresses, so it must be refused rather than
	// silently wrap around.
	for _, index := range []uint32{0x00FFFFFF, 0x01C00000, pivcert.DefaultTPM2BaseIndex} {
		store, err := New(&Config{TPM: stubTPM{}, BaseIndex: index})
		if err == nil {
			_ = store.Close()
			t.Fatalf("New(BaseIndex=%#x) error = nil, want a rejection", index)
		}
		if store != nil {
			t.Errorf("New(BaseIndex=%#x) returned a store alongside the error", index)
		}
	}
}

// TestNew_InvalidConfig verifies the constructor refuses a configuration that
// cannot address a TPM or that allows certificates beyond the PIV limit.
func TestNew_InvalidConfig(t *testing.T) {
	store, err := New(nil)
	if !errors.Is(err, pivcert.ErrInvalidConfig) {
		t.Fatalf("New(nil) error = %v, want ErrInvalidConfig", err)
	}
	if store != nil {
		t.Error("New(nil) returned a store")
	}

	if _, err := New(&Config{}); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Fatalf("New(no TPM) error = %v, want ErrTPMNotAvailable", err)
	}

	tooLarge := &Config{TPM: stubTPM{}, MaxCertSize: pivcert.MaxCertSizeTPM2 + 1}
	if _, err := New(tooLarge); !errors.Is(err, pivcert.ErrCertificateTooLarge) {
		t.Fatalf("New(MaxCertSize beyond the PIV limit) error = %v, want ErrCertificateTooLarge", err)
	}
}

// TestNew_InvalidCertSize verifies a record size the hardware layer cannot
// honour is rejected.
func TestNew_InvalidCertSize(t *testing.T) {
	store, err := New(&Config{TPM: stubTPM{}, MaxCertSize: 128})
	if err == nil {
		_ = store.Close()
		t.Fatal("New(MaxCertSize=128) error = nil, want a rejection")
	}
}

// TestType verifies the storage reports its backend kind.
func TestType(t *testing.T) {
	store, err := New(&Config{TPM: stubTPM{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if got := store.Type(); got != pivcert.StorageTypeTPM2 {
		t.Errorf("Type() = %q, want %q", got, pivcert.StorageTypeTPM2)
	}
}

// TestRetainedTPM_CloseLeavesConnectionOpen verifies the PIV store never closes
// a TPM connection it does not own.
func TestRetainedTPM_CloseLeavesConnectionOpen(t *testing.T) {
	underlying := &countingTPM{}
	retained := &retainedTPM{tpm: underlying}

	if _, err := retained.Send([]byte{0x01}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if underlying.sends != 1 {
		t.Errorf("underlying sends = %d, want 1", underlying.sends)
	}
	if underlying.closed {
		t.Error("Close() closed the caller's TPM connection")
	}
}

// stubTPM satisfies transport.TPM for configuration tests that never issue a
// command. Any command it does receive fails loudly.
type stubTPM struct{}

func (stubTPM) Send(input []byte) ([]byte, error) {
	return nil, errNoTPMCommands
}

var errNoTPMCommands = errors.New("pivcert/tpm2: stub TPM received a command")

// countingTPM records the calls a retainedTPM forwards.
type countingTPM struct {
	sends  int
	closed bool
}

func (c *countingTPM) Send(input []byte) ([]byte, error) {
	c.sends++
	return nil, nil
}

func (c *countingTPM) Close() error {
	c.closed = true
	return nil
}
