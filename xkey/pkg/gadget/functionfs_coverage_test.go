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
	"testing"
	"time"
)

func TestFunctionFSTransport_Initialize_Success(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = tr.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if tr.closed.Load() {
		t.Error("transport should not be closed after Initialize")
	}
	if !tr.running.Load() {
		t.Error("transport should be running after Initialize")
	}

	cancel()
	// Give the monitor goroutine time to exit.
	time.Sleep(50 * time.Millisecond)

	err = tr.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestFunctionFSTransport_Initialize_AlreadyClosed(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	tr.Close()

	err = tr.Initialize(context.Background())
	if !errors.Is(err, ErrTransportClosed) {
		t.Errorf("Initialize after close: got %v, want ErrTransportClosed", err)
	}
}

func TestFunctionFSTransport_Initialize_Ep0OpenFailed(t *testing.T) {
	dir := t.TempDir()
	// No ep0 file exists.

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = tr.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected error when ep0 does not exist")
	}
	if !errors.Is(err, ErrEndpointOpenFailed) {
		t.Errorf("got %v, want ErrEndpointOpenFailed", err)
	}
}

func TestFunctionFSTransport_Initialize_DescriptorWriteFailed(t *testing.T) {
	dir := t.TempDir()
	// Create ep0 as a directory so Write to it fails.
	if err := os.Mkdir(filepath.Join(dir, "ep0"), 0755); err != nil {
		t.Fatal(err)
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = tr.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected error when writing descriptors to directory")
	}
	// ep0 opened successfully (dirs can be opened) but Write should fail.
	// On Linux, opening a directory with O_RDWR fails, so this will be
	// ErrEndpointOpenFailed. Either way, we expect an error.
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, err)
	}
}

func TestFunctionFSTransport_Initialize_Ep1OpenFailed(t *testing.T) {
	dir := t.TempDir()
	// Create ep0 (file) but no ep1.
	for _, ep := range []string{"ep0"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = tr.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected error when ep1 does not exist")
	}
	if !errors.Is(err, ErrEndpointOpenFailed) {
		t.Errorf("got %v, want ErrEndpointOpenFailed", err)
	}
}

func TestFunctionFSTransport_Initialize_Ep2OpenFailed(t *testing.T) {
	dir := t.TempDir()
	// Create ep0 and ep1 but no ep2.
	for _, ep := range []string{"ep0", "ep1"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = tr.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected error when ep2 does not exist")
	}
	if !errors.Is(err, ErrEndpointOpenFailed) {
		t.Errorf("got %v, want ErrEndpointOpenFailed", err)
	}
}

func TestFunctionFSTransport_ReadWrite_WithFiles(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate ep1 with data (simulates host sending data).
	testData := []byte("hello from host")
	if err := os.WriteFile(filepath.Join(dir, "ep1"), testData, 0644); err != nil {
		t.Fatal(err)
	}

	// Create ep0 and ep2 as regular files.
	for _, ep := range []string{"ep0", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Read from transport (reads ep1 / epOut).
	// On regular files, SetReadDeadline is a no-op, and Read returns immediately.
	data, err := tr.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(data) != string(testData) {
		t.Errorf("Read data = %q, want %q", data, testData)
	}

	// Write to transport (writes ep2 / epIn).
	writeData := []byte("response to host")
	err = tr.Write(writeData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	tr.Close()
}

func TestFunctionFSTransport_Read_EOF(t *testing.T) {
	dir := t.TempDir()

	// Create empty ep1 so Read hits EOF immediately.
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Read from empty file hits EOF, which is not a timeout error.
	_, readErr := tr.Read(ctx)
	if readErr == nil {
		t.Fatal("expected error from Read on empty file (EOF)")
	}
	if !errors.Is(readErr, ErrEndpointIOFailed) {
		t.Errorf("got %v, want ErrEndpointIOFailed", readErr)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	tr.Close()
}

func TestFunctionFSTransport_Read_ContextCancelled(t *testing.T) {
	dir := t.TempDir()

	// Create endpoint files.
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	initCtx, initCancel := context.WithCancel(context.Background())
	defer initCancel()

	if err := tr.Initialize(initCtx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Cancel context before Read.
	readCtx, readCancel := context.WithCancel(context.Background())
	readCancel()

	_, readErr := tr.Read(readCtx)
	if !errors.Is(readErr, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", readErr)
	}

	initCancel()
	time.Sleep(50 * time.Millisecond)
	tr.Close()
}

func TestFunctionFSTransport_Read_ClosedDuringLoop(t *testing.T) {
	dir := t.TempDir()

	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close the transport, then try to Read. The second closed check
	// in the loop body should catch it.
	tr.closed.Store(true)

	_, readErr := tr.Read(ctx)
	if !errors.Is(readErr, ErrTransportClosed) {
		t.Errorf("got %v, want ErrTransportClosed", readErr)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestFunctionFSTransport_Write_Error(t *testing.T) {
	dir := t.TempDir()

	for _, ep := range []string{"ep0", "ep1"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	// Create ep2 as a read-only file, then open it for writing during
	// Initialize. The O_WRONLY open in Initialize will succeed on a regular
	// file, but we can close the underlying fd to force a write error.
	f, err := os.Create(filepath.Join(dir, "ep2"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close the underlying epIn fd to force Write error.
	tr.epIn.Close()

	writeErr := tr.Write([]byte("test data"))
	if writeErr == nil {
		t.Fatal("expected error from Write on closed fd")
	}
	if !errors.Is(writeErr, ErrEndpointIOFailed) {
		t.Errorf("got %v, want ErrEndpointIOFailed", writeErr)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestFunctionFSTransport_Close_WithOpenEndpoints(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)

	// Close should succeed and nil out all endpoints.
	err = tr.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if tr.epIn != nil {
		t.Error("epIn should be nil after Close")
	}
	if tr.epOut != nil {
		t.Error("epOut should be nil after Close")
	}
	if tr.ep0 != nil {
		t.Error("ep0 should be nil after Close")
	}
	if !tr.closed.Load() {
		t.Error("closed should be true after Close")
	}
	if tr.running.Load() {
		t.Error("running should be false after Close")
	}
}

func TestFunctionFSTransport_MonitorEvents_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Cancel context to stop the monitor goroutine.
	cancel()
	// Give the monitor goroutine time to detect cancellation and exit.
	time.Sleep(300 * time.Millisecond)

	// Verify transport is still operational (monitor exiting does not close transport).
	if tr.closed.Load() {
		t.Error("transport should not be closed just because monitor exited")
	}

	tr.Close()
}

func TestFunctionFSTransport_MonitorEvents_Closed(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close the transport; the monitor should detect closed state and exit.
	tr.Close()
	time.Sleep(300 * time.Millisecond)

	cancel()
}

func TestFunctionFSTransport_MonitorEvents_EOF(t *testing.T) {
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	tr, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Close ep0 directly so the monitor gets EOF.
	tr.ep0.Close()
	tr.ep0 = nil
	time.Sleep(300 * time.Millisecond)

	cancel()
}
