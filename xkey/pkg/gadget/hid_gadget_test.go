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
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNewHIDGadgetTransport_NilLogger(t *testing.T) {
	_, err := NewHIDGadgetTransport("/dev/hidg0", nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !errors.Is(err, ErrNilLogger) {
		t.Fatalf("expected ErrNilLogger, got: %v", err)
	}
}

func TestNewHIDGadgetTransport_DefaultPath(t *testing.T) {
	_, err := NewHIDGadgetTransport("", testLogger())
	if err == nil {
		t.Fatal("expected error when /dev/hidg0 does not exist")
	}
	if !errors.Is(err, ErrEndpointOpenFailed) {
		t.Fatalf("expected ErrEndpointOpenFailed, got: %v", err)
	}
}

func TestNewHIDGadgetTransport_InvalidPath(t *testing.T) {
	_, err := NewHIDGadgetTransport("/dev/nonexistent-hidg", testLogger())
	if err == nil {
		t.Fatal("expected error for nonexistent device")
	}
	if !errors.Is(err, ErrEndpointOpenFailed) {
		t.Fatalf("expected ErrEndpointOpenFailed, got: %v", err)
	}
}

func TestHIDGadgetTransport_DevicePath(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	if got := tr.DevicePath(); got != tmp {
		t.Fatalf("expected DevicePath() = %q, got %q", tmp, got)
	}
}

func TestHIDGadgetTransport_CloseIdempotent(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close should return nil, got: %v", err)
	}
}

func TestHIDGadgetTransport_ReadAfterClose(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
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

func TestHIDGadgetTransport_WriteAfterClose(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
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

func TestHIDGadgetTransport_WriteData(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	payload := make([]byte, hidReportSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	if err := tr.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read back from the file to verify the write.
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("failed to read temp file: %v", err)
	}
	if len(data) != hidReportSize {
		t.Fatalf("expected %d bytes, got %d", hidReportSize, len(data))
	}
	for i, b := range data {
		if b != byte(i) {
			t.Fatalf("byte %d: expected 0x%02x, got 0x%02x", i, byte(i), b)
		}
	}
}

func TestHIDGadgetTransport_ReadFromFile(t *testing.T) {
	// Create a temp file pre-populated with data to simulate a device
	// that has a report ready.
	tmp := createTempDeviceFile(t)

	payload := make([]byte, hidReportSize)
	for i := range payload {
		payload[i] = byte(i + 0x10)
	}
	if err := os.WriteFile(tmp, payload, 0600); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	data, err := tr.Read(context.Background())
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(data) != hidReportSize {
		t.Fatalf("expected %d bytes, got %d", hidReportSize, len(data))
	}
	for i, b := range data {
		if b != byte(i+0x10) {
			t.Fatalf("byte %d: expected 0x%02x, got 0x%02x", i, byte(i+0x10), b)
		}
	}
}

func TestHIDGadgetTransport_ReadCancelledContext(t *testing.T) {
	// Use a FIFO (named pipe) so that Read blocks, allowing the context
	// cancellation path to be exercised. On regular files Read returns
	// immediately so context cancellation would race with the read result.
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "testpipe")

	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatalf("failed to create FIFO: %v", err)
	}

	// Open the write end in a goroutine so OpenFile on the read end doesn't
	// block forever (FIFOs require both ends to be opened).
	writerReady := make(chan *os.File, 1)
	go func() {
		w, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		if err != nil {
			writerReady <- nil
			return
		}
		writerReady <- w
	}()

	tr, err := NewHIDGadgetTransport(fifoPath, testLogger())
	if err != nil {
		t.Fatalf("unexpected error opening FIFO: %v", err)
	}
	defer func() { _ = tr.Close() }()

	writer := <-writerReady
	if writer == nil {
		t.Fatal("failed to open write end of FIFO")
	}
	defer func() { _ = writer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, readErr := tr.Read(ctx)
	if readErr == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(readErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", readErr)
	}
}

// createTempDeviceFile creates a temporary file that simulates a device file
// for testing purposes. The file is cleaned up when the test completes.
func createTempDeviceFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "hidg-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	name := f.Name()
	f.Close()
	return name
}

func TestHIDGadgetTransport_ReportSizeConstant(t *testing.T) {
	if hidReportSize != 64 {
		t.Errorf("hidReportSize: got %d, want 64 (FIDO2 standard)", hidReportSize)
	}
}

func TestHIDGadgetTransport_WriteVerifyExactBytes(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	// Build a known 64-byte pattern.
	pattern := make([]byte, 64)
	for i := range pattern {
		pattern[i] = byte(0xA0 ^ byte(i))
	}

	if err := tr.Write(pattern); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Seek back to beginning and read the file content.
	readBack, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("failed to read back temp file: %v", err)
	}

	if len(readBack) != 64 {
		t.Fatalf("read back length: got %d, want 64", len(readBack))
	}

	for i := 0; i < 64; i++ {
		want := byte(0xA0 ^ byte(i))
		if readBack[i] != want {
			t.Errorf("byte[%d]: got %#02x, want %#02x", i, readBack[i], want)
		}
	}
}

func TestHIDGadgetTransport_ReadExactBytes(t *testing.T) {
	tmp := createTempDeviceFile(t)

	// Pre-populate file with a known 64-byte pattern.
	pattern := make([]byte, 64)
	for i := range pattern {
		pattern[i] = byte(0xBB ^ byte(i))
	}
	if err := os.WriteFile(tmp, pattern, 0600); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = tr.Close() }()

	data, err := tr.Read(context.Background())
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(data) != 64 {
		t.Fatalf("Read length: got %d, want 64", len(data))
	}

	for i := 0; i < 64; i++ {
		want := byte(0xBB ^ byte(i))
		if data[i] != want {
			t.Errorf("byte[%d]: got %#02x, want %#02x", i, data[i], want)
		}
	}
}
