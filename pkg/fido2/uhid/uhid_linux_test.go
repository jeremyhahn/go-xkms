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

//go:build linux

package uhid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenUHIDNotAvailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "uhid-does-not-exist")

	device, err := openAt(missing)
	if device != nil {
		_ = device.Close()
		t.Fatal("openAt() returned a device for a non-existent path")
	}

	if !errors.Is(err, ErrUHIDNotAvailable) {
		t.Errorf("openAt() error = %v, want %v", err, ErrUHIDNotAvailable)
	}
}

// TestOpenUHIDPermissionDenied verifies that a UHID node which exists but
// cannot be opened is reported as ErrUHIDNotAvailable with the underlying
// cause preserved, rather than being reported as absent.
func TestOpenUHIDPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root bypasses file permission bits, so make the parent directory
		// the thing that fails instead: a path whose parent is a regular
		// file cannot be opened on any Linux system, root or not.
		dir := t.TempDir()
		notADir := filepath.Join(dir, "regular-file")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatalf("failed to create fixture file: %v", err)
		}
		device, err := openAt(filepath.Join(notADir, "uhid"))
		if device != nil {
			_ = device.Close()
			t.Fatal("openAt() returned a device for an unopenable path")
		}
		if !errors.Is(err, ErrUHIDNotAvailable) {
			t.Errorf("openAt() error = %v, want %v", err, ErrUHIDNotAvailable)
		}
		return
	}

	unreadable := filepath.Join(t.TempDir(), "uhid-no-perms")
	if err := os.WriteFile(unreadable, []byte("x"), 0o000); err != nil {
		t.Fatalf("failed to create fixture file: %v", err)
	}

	device, err := openAt(unreadable)
	if device != nil {
		_ = device.Close()
		t.Fatal("openAt() returned a device for an unreadable path")
	}

	if !errors.Is(err, ErrUHIDNotAvailable) {
		t.Errorf("openAt() error = %v, want %v", err, ErrUHIDNotAvailable)
	}

	var sentinel *SentinelCauseError
	if !errors.As(err, &sentinel) {
		t.Fatalf("openAt() error = %T, want *SentinelCauseError carrying the cause", err)
	}
	if !errors.Is(sentinel.Cause, os.ErrPermission) {
		t.Errorf("SentinelCauseError.Cause = %v, want a permission error", sentinel.Cause)
	}
}

func TestDeviceCreateOnClosedDevice(t *testing.T) {
	// Create a device manually without a real file handle
	device := &Device{}
	device.closed.Store(true)

	err := device.Create(nil)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceReadOutputOnClosedDevice(t *testing.T) {
	device := &Device{}
	device.closed.Store(true)

	_, err := device.ReadOutput()
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("ReadOutput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputOnClosedDevice(t *testing.T) {
	device := &Device{}
	device.closed.Store(true)

	err := device.WriteInput([]byte{0x01, 0x02, 0x03})
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputDataTooLarge(t *testing.T) {
	device := &Device{}
	// Device is not closed but has no file handle

	largeData := make([]byte, MaxReportDescriptorSize+1)
	err := device.WriteInput(largeData)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrInvalidPacket)
	}
}

func TestDeviceSetNonBlockingNotOpen(t *testing.T) {
	device := &Device{}

	err := device.SetNonBlocking(true)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("SetNonBlocking() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceCreateAlreadyCreated(t *testing.T) {
	device := &Device{}
	device.created.Store(true)

	err := device.Create(nil)
	if !errors.Is(err, ErrDeviceAlreadyCreated) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceAlreadyCreated)
	}
}

func TestDeviceReadOutputNilFile(t *testing.T) {
	device := &Device{}
	// Not closed, but file is nil

	_, err := device.ReadOutput()
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("ReadOutput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceWriteInputNilFile(t *testing.T) {
	device := &Device{}
	// Not closed, but file is nil

	// Small data to avoid ErrInvalidPacket
	err := device.WriteInput([]byte{0x01})
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceCreateWithNilFile(t *testing.T) {
	device := &Device{}
	// Device is not closed or created, but has nil file

	err := device.Create(DefaultCreateConfig())
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("Create() error = %v, want %v", err, ErrDeviceNotOpen)
	}
}

func TestDeviceCloseWithCreatedFlag(t *testing.T) {
	// Test Close behavior when device is marked as created (should send UHID_DESTROY)
	device := &Device{}
	device.created.Store(true)
	// File is nil, so UHID_DESTROY write will be skipped gracefully

	err := device.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if !device.IsClosed() {
		t.Error("device should be marked as closed")
	}
}

func TestDeviceSetReadTimeoutVariousDurations(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
		{"milliseconds", 100 * time.Millisecond},
		{"seconds", 5 * time.Second},
		{"minutes", 1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &Device{}
			device.SetReadTimeout(tt.timeout)

			device.mu.Lock()
			actual := device.readTimeout
			device.mu.Unlock()

			if actual != tt.timeout {
				t.Errorf("readTimeout = %v, want %v", actual, tt.timeout)
			}
		})
	}
}

func TestDeviceStateTransitions(t *testing.T) {
	t.Run("initial state", func(t *testing.T) {
		device := &Device{}

		if device.IsCreated() {
			t.Error("new device should not be created")
		}
		if device.IsClosed() {
			t.Error("new device should not be closed")
		}
		if device.Fd() != -1 {
			t.Error("new device should have Fd() = -1")
		}
	})

	t.Run("closed state", func(t *testing.T) {
		device := &Device{}
		_ = device.Close()

		if !device.IsClosed() {
			t.Error("closed device should report IsClosed() = true")
		}
		// Can close again without error
		err := device.Close()
		if err != nil {
			t.Errorf("second Close() error = %v", err)
		}
	})

	t.Run("created and closed state", func(t *testing.T) {
		device := &Device{}
		device.created.Store(true)
		_ = device.Close()

		if !device.IsClosed() {
			t.Error("device should be closed")
		}
		// Created flag remains set after close
		if !device.IsCreated() {
			t.Error("created flag should remain set after close")
		}
	})
}

func TestDeviceWriteInputExactMaxSize(t *testing.T) {
	device := &Device{}
	// Device is not closed but has no file handle

	// Exact max size should fail on nil file, not on size check
	exactMaxData := make([]byte, MaxReportDescriptorSize)
	err := device.WriteInput(exactMaxData)
	if !errors.Is(err, ErrDeviceNotOpen) {
		t.Errorf("WriteInput() with exact max size error = %v, want %v", err, ErrDeviceNotOpen)
	}
}
