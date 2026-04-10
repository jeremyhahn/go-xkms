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
	"testing"
)

func TestNewFunctionFSTransport_NilFS(t *testing.T) {
	_, err := NewFunctionFSTransport("/dev/ffs-ccid", nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil fs")
	}
	if !errors.Is(err, ErrNilTransport) {
		t.Errorf("got %v, want ErrNilTransport", err)
	}
}

func TestNewFunctionFSTransport_NilLogger(t *testing.T) {
	_, err := NewFunctionFSTransport("/dev/ffs-ccid", &OSFileSystem{}, nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("got %v, want ErrNilLogger", err)
	}
}

func TestNewFunctionFSTransport_EmptyMountDir(t *testing.T) {
	_, err := NewFunctionFSTransport("", &OSFileSystem{}, testLogger())
	if err == nil {
		t.Fatal("expected error for empty mount dir")
	}
	if !errors.Is(err, ErrFunctionFSMountFailed) {
		t.Errorf("got %v, want ErrFunctionFSMountFailed", err)
	}
}

func TestNewFunctionFSTransport_Valid(t *testing.T) {
	tr, err := NewFunctionFSTransport("/dev/ffs-ccid", &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("transport is nil")
	}
	if tr.MountDir() != "/dev/ffs-ccid" {
		t.Errorf("MountDir: got %q, want %q", tr.MountDir(), "/dev/ffs-ccid")
	}
}

func TestFunctionFSTransport_CloseIdempotent(t *testing.T) {
	tr, err := NewFunctionFSTransport("/dev/ffs-ccid", &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First close should succeed (no endpoints open, so nothing to close).
	if err := tr.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second close should also succeed (idempotent).
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFunctionFSTransport_ReadAfterClose(t *testing.T) {
	tr, err := NewFunctionFSTransport("/dev/ffs-ccid", &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr.Close()

	_, err = tr.Read(context.Background())
	if !errors.Is(err, ErrTransportClosed) {
		t.Errorf("Read after close: got %v, want ErrTransportClosed", err)
	}
}

func TestFunctionFSTransport_WriteAfterClose(t *testing.T) {
	tr, err := NewFunctionFSTransport("/dev/ffs-ccid", &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr.Close()

	err = tr.Write([]byte{0x01, 0x02})
	if !errors.Is(err, ErrTransportClosed) {
		t.Errorf("Write after close: got %v, want ErrTransportClosed", err)
	}
}

func TestFunctionFSTransport_MountDir(t *testing.T) {
	wantDir := "/dev/ffs-test-ccid"
	tr, err := NewFunctionFSTransport(wantDir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := tr.MountDir()
	if got != wantDir {
		t.Errorf("MountDir(): got %q, want %q", got, wantDir)
	}
}

func TestNewFunctionFSTransport_EmptyMountDir_ErrorType(t *testing.T) {
	_, err := NewFunctionFSTransport("", &OSFileSystem{}, testLogger())
	if err == nil {
		t.Fatal("expected error for empty mount dir")
	}

	// Verify it wraps ErrFunctionFSMountFailed.
	if !errors.Is(err, ErrFunctionFSMountFailed) {
		t.Errorf("errors.Is: got %v, want ErrFunctionFSMountFailed", err)
	}

	// Verify it is a *GadgetError with correct Operation.
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Fatalf("errors.As: got %T, want *GadgetError", err)
	}
	if ge.Operation != "NewFunctionFSTransport" {
		t.Errorf("GadgetError.Operation: got %q, want %q", ge.Operation, "NewFunctionFSTransport")
	}
}
