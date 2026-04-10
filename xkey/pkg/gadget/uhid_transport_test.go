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

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewUHIDTransport_NilDevice(t *testing.T) {
	_, err := NewUHIDTransport(nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil device")
	}
	if !errors.Is(err, ErrNilDevice) {
		t.Fatalf("expected ErrNilDevice, got: %v", err)
	}
}

func TestNewUHIDTransport_NilLogger(t *testing.T) {
	// uhid.Device is a struct so we can take a pointer to a zero value.
	// The constructor only checks for nil, not whether the device is open.
	dev := &uhid.Device{}
	_, err := NewUHIDTransport(dev, nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !errors.Is(err, ErrNilLogger) {
		t.Fatalf("expected ErrNilLogger, got: %v", err)
	}
}

func TestNewUHIDTransport_Valid(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Device() != dev {
		t.Fatal("Device() should return the same device passed to the constructor")
	}
}

func TestUHIDTransport_CloseIdempotent(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// First close may return an error from the underlying device (it is
	// not open), but we only care that the second close is safe.
	_ = tr.Close()
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close should return nil, got: %v", err)
	}
}

func TestUHIDTransport_ReadAfterClose(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = tr.Close()

	_, readErr := tr.Read(context.Background())
	if readErr == nil {
		t.Fatal("expected error reading from closed transport")
	}
	if !errors.Is(readErr, ErrTransportClosed) {
		t.Fatalf("expected ErrTransportClosed, got: %v", readErr)
	}
}

func TestUHIDTransport_WriteAfterClose(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = tr.Close()

	writeErr := tr.Write([]byte{0x01, 0x02, 0x03})
	if writeErr == nil {
		t.Fatal("expected error writing to closed transport")
	}
	if !errors.Is(writeErr, ErrTransportClosed) {
		t.Fatalf("expected ErrTransportClosed, got: %v", writeErr)
	}
}

func TestUHIDTransport_ReadCancelledContext(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, readErr := tr.Read(ctx)
	if readErr == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(readErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", readErr)
	}
}

// Integration tests covering full Read/Write paths require /dev/uhid
// (Linux, root) and are located in the integration test suite under
// test/integration/gadget/.

func TestUHIDTransport_DeviceReturnsOriginal(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	got := tr.Device()
	if got != dev {
		t.Errorf("Device() returned %p, want original %p", got, dev)
	}
}

func TestUHIDTransport_ReadContextDeadline(t *testing.T) {
	dev := &uhid.Device{}
	tr, err := NewUHIDTransport(dev, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	// Create an already-expired deadline context.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, readErr := tr.Read(ctx)
	if readErr == nil {
		t.Fatal("expected error from expired deadline context")
	}
	if !errors.Is(readErr, context.DeadlineExceeded) {
		t.Errorf("got %v, want context.DeadlineExceeded", readErr)
	}
}
