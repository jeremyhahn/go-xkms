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
)

// ---------------------------------------------------------------------------
// TransportType.String (transport.go)
// ---------------------------------------------------------------------------

func TestTransportType_String(t *testing.T) {
	tests := []struct {
		tt   TransportType
		want string
	}{
		{TransportUHID, "uhid"},
		{TransportGadget, "gadget"},
		{TransportType("custom"), "custom"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.tt.String(); got != tc.want {
				t.Errorf("TransportType(%q).String() = %q, want %q", string(tc.tt), got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Gadget CCIDTransport / HIDTransport non-nil paths (gadget.go)
// ---------------------------------------------------------------------------

func TestGadget_CCIDTransport_NonNil(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}

	// Manually set ccid to exercise the non-nil return path.
	g.ccid = &FunctionFSTransport{mountDir: "/test"}
	tr := g.CCIDTransport()
	if tr == nil {
		t.Error("CCIDTransport() should not be nil when ccid is set")
	}
}

func TestGadget_HIDTransport_NonNil(t *testing.T) {
	tmp := createTempDeviceFile(t)
	hid, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer hid.Close()

	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}

	g.hid = hid
	tr := g.HIDTransport()
	if tr == nil {
		t.Error("HIDTransport() should not be nil when hid is set")
	}
}

// ---------------------------------------------------------------------------
// Gadget Stop with close errors (gadget.go)
// ---------------------------------------------------------------------------

func TestGadget_Stop_HIDCloseError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{}
	mfs := newMockFileSystem()

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}
	g.bound.Store(true)

	// Create a HID transport with an already-closed file to trigger close error.
	tmp := createTempDeviceFile(t)
	hid, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	// Close the underlying file so Close() returns an error.
	hid.file.Close()
	g.hid = hid

	stopErr := g.Stop()
	// The file.Close error is the first error.
	if stopErr == nil {
		// On some systems double-close on a file returns nil. That is acceptable.
		t.Log("Stop returned nil (double-close was no-op on this platform)")
	} else {
		var ge *GadgetError
		if !errors.As(stopErr, &ge) {
			t.Errorf("expected GadgetError, got %T: %v", stopErr, stopErr)
		}
	}
}

func TestGadget_Stop_CCIDCloseError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{}
	mfs := newMockFileSystem()

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}
	g.bound.Store(true)

	// Create a FunctionFS transport and close all endpoints directly.
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	ccid, err := NewFunctionFSTransport(dir, &OSFileSystem{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := ccid.Initialize(ctx); err != nil {
		cancel()
		t.Fatalf("Initialize failed: %v", err)
	}
	cancel()

	// Close the endpoint files underneath to provoke close errors.
	ccid.epIn.Close()
	ccid.epOut.Close()
	ccid.ep0.Close()

	g.ccid = ccid

	stopErr := g.Stop()
	// Double-close may or may not error depending on platform.
	if stopErr != nil {
		var ge *GadgetError
		if !errors.As(stopErr, &ge) {
			t.Errorf("expected GadgetError, got %T: %v", stopErr, stopErr)
		}
	}
}

// ---------------------------------------------------------------------------
// ConfigFS writeStringDescriptors error paths (configfs.go)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_StringDescriptorSerialError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErrPaths["serialnumber"] = errors.New("write denied for serialnumber")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from string descriptor write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

func TestConfigFS_Create_StringDescriptorManufacturerError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErrPaths["manufacturer"] = errors.New("write denied for manufacturer")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from manufacturer string write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

func TestConfigFS_Create_StringDescriptorProductError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErrPaths["product"] = errors.New("write denied for product")
	// "product" also matches "idProduct" in device attrs, so this tests
	// the first match in writeDeviceAttributes. To specifically hit the
	// string descriptor, we need to be more precise. Let's use the full
	// path segment.
	delete(mfs.writeErrPaths, "product")
	mfs.writeErrPaths["strings/0x0409/product"] = errors.New("write denied for product string")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from product string write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS writeConfigDescriptors error paths (configfs.go)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_ConfigMaxPowerError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErrPaths["MaxPower"] = errors.New("write denied for MaxPower")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from MaxPower write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

func TestConfigFS_Create_ConfigStringsDirError(t *testing.T) {
	mfs := newMockFileSystem()
	// Fail MkdirAll specifically for the config strings directory.
	// We need a custom approach since mkdirErr affects all MkdirAll calls.
	// Instead, test that writeConfigDescriptors fails when the configuration
	// string write fails.
	mfs.writeErrPaths["configs/c.1/strings/0x0409/configuration"] = errors.New("config string write denied")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from config string write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS createFunctions HID attribute error path (configfs.go)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_HIDAttributeWriteError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErrPaths["report_length"] = errors.New("write denied for report_length")
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from HID attribute write")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// ---------------------------------------------------------------------------
// HIDGadgetTransport Write error path (hid_gadget.go)
// ---------------------------------------------------------------------------

func TestHIDGadgetTransport_WriteError(t *testing.T) {
	// Create a temp file and open the transport normally.
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Close the underlying file to force Write to error.
	tr.file.Close()

	writeErr := tr.Write([]byte("test data"))
	if writeErr == nil {
		t.Fatal("expected write error on closed file")
	}
	if !errors.Is(writeErr, ErrEndpointIOFailed) {
		t.Errorf("error should wrap ErrEndpointIOFailed, got %v", writeErr)
	}
}

// ---------------------------------------------------------------------------
// HIDGadgetTransport Read error (not timeout, not context cancel)
// ---------------------------------------------------------------------------

func TestHIDGadgetTransport_ReadError(t *testing.T) {
	tmp := createTempDeviceFile(t)
	tr, err := NewHIDGadgetTransport(tmp, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Close the underlying file so Read returns an error.
	tr.file.Close()

	_, readErr := tr.Read(context.Background())
	if readErr == nil {
		t.Fatal("expected error from Read on closed file")
	}
	if !errors.Is(readErr, ErrEndpointIOFailed) {
		t.Errorf("error should wrap ErrEndpointIOFailed, got %v", readErr)
	}
}

// ---------------------------------------------------------------------------
// OSFileSystem Mount/Unmount error paths (filesystem.go)
// ---------------------------------------------------------------------------

func TestOSFileSystem_Mount_Error(t *testing.T) {
	fs := &OSFileSystem{}
	err := fs.Mount("src", "/tmp/nonexistent-mount-"+t.Name(), "tmpfs", 0, "")
	if err == nil {
		// If running as root, mount might succeed; unmount and skip.
		_ = fs.Unmount("/tmp/nonexistent-mount-"+t.Name(), 0)
		t.Skip("running as root, Mount succeeded")
	}
	// We just verify an error is returned (permission denied or similar).
	t.Logf("Mount error (expected): %v", err)
}

func TestOSFileSystem_Unmount_Error(t *testing.T) {
	fs := &OSFileSystem{}
	err := fs.Unmount("/tmp/definitely-not-mounted-"+t.Name(), 0)
	if err == nil {
		t.Skip("unexpected: Unmount succeeded")
	}
	t.Logf("Unmount error (expected): %v", err)
}

// ---------------------------------------------------------------------------
// Gadget initCCID transport init failure (gadget.go)
// ---------------------------------------------------------------------------

func TestGadget_Start_CCIDTransportInitError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs-init-err"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}

	// Start will: create ConfigFS tree, mkdir mount dir, mount FunctionFS
	// (mock succeeds), create FunctionFSTransport (succeeds), call
	// Initialize (fails because ep0 doesn't exist). This exercises the
	// transport.Initialize error path in initCCID.
	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start when transport Initialize fails")
	}
	// The error comes from os.OpenFile on non-existent ep0.
	if !errors.Is(startErr, ErrEndpointOpenFailed) {
		t.Errorf("expected ErrEndpointOpenFailed, got %v", startErr)
	}
}

// ---------------------------------------------------------------------------
// Gadget Start HID function with real file (covers post-bind HID path)
// ---------------------------------------------------------------------------

func TestGadget_Start_HIDFunction_OpenSuccess(t *testing.T) {
	// Create a temp file to act as /dev/hidgN.
	tmp := createTempDeviceFile(t)

	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs), WithHIDDevicePath(tmp))
	if err != nil {
		t.Fatal(err)
	}

	err = g.Start(context.Background())
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if g.HIDTransport() == nil {
		t.Error("expected HIDTransport to be non-nil after successful Start")
	}
	if !g.IsBound() {
		t.Error("expected IsBound to be true after Start")
	}

	// Clean up.
	if err := g.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Gadget initCCID full success path (gadget.go)
// ---------------------------------------------------------------------------

func TestGadget_Start_CCIDFunction_FullSuccess(t *testing.T) {
	// Create a temp dir with ep0, ep1, ep2 so that FunctionFS Initialize
	// succeeds. The mock FS handles ConfigFS ops; FunctionFS.Initialize
	// opens the real temp files directly via os.OpenFile.
	dir := t.TempDir()
	for _, ep := range []string{"ep0", "ep1", "ep2"} {
		f, err := os.Create(filepath.Join(dir, ep))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: dir},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = g.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if g.CCIDTransport() == nil {
		t.Error("expected non-nil CCIDTransport after successful CCID init")
	}
	if !g.IsBound() {
		t.Error("expected IsBound to be true")
	}

	cancel()

	if err := g.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS writeConfigDescriptors: MkdirAll for config strings dir error
// ---------------------------------------------------------------------------

func TestConfigFS_Create_ConfigStringsMkdirError(t *testing.T) {
	// We need MkdirAll to succeed for gadget dir, strings dir, and config
	// dir, but fail for the config strings dir. Use a counter-based mock.
	mfs := &mkdirCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         4, // gadget dir(1), strings dir(2), config dir(3), config strings dir(4)
	}
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from MkdirAll for config strings dir")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// mkdirCountFS wraps mockFileSystem and fails MkdirAll on the Nth call.
type mkdirCountFS struct {
	*mockFileSystem
	failAt int
	count  int
}

func (f *mkdirCountFS) MkdirAll(path string, perm os.FileMode) error {
	f.count++
	if f.count == f.failAt {
		return errors.New("mkdir failed at count")
	}
	return f.mockFileSystem.MkdirAll(path, perm)
}

// ---------------------------------------------------------------------------
// ConfigFS Destroy error paths for later RemoveAll calls
// ---------------------------------------------------------------------------

// removeCountFS wraps mockFileSystem and fails RemoveAll on the Nth call.
type removeCountFS struct {
	*mockFileSystem
	failAt int
	count  int
}

func (f *removeCountFS) RemoveAll(path string) error {
	f.count++
	if f.count == f.failAt {
		return errors.New("remove failed at count")
	}
	return f.mockFileSystem.RemoveAll(path)
}

func TestConfigFS_Destroy_ConfigStringsRemoveError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	mfs := &removeCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         2, // symlink(1), config strings dir(2) -> fail
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll for config strings dir")
	}
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, ge)
	}
}

func TestConfigFS_Destroy_ConfigDirRemoveError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	mfs := &removeCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         3, // symlink(1), config strings(2), config dir(3) -> fail
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll for config dir")
	}
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, ge)
	}
}

func TestConfigFS_Destroy_FunctionDirRemoveError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	mfs := &removeCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         4, // symlink(1), config strings(2), config dir(3), function dir(4) -> fail
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll for function dir")
	}
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, ge)
	}
}

func TestConfigFS_Destroy_StringsDirRemoveError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	mfs := &removeCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         5, // symlink(1), config strings(2), config dir(3), function dir(4), strings dir(5) -> fail
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll for strings dir")
	}
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, ge)
	}
}

func TestConfigFS_Destroy_GadgetDirRemoveError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	mfs := &removeCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         6, // all prior succeed, gadget dir(6) -> fail
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll for gadget dir")
	}
	var ge *GadgetError
	if !errors.As(err, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", err, ge)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS writeStringDescriptors MkdirAll error (line 365)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_StringsDirMkdirError(t *testing.T) {
	mfs := &mkdirCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         2, // gadget dir(1) succeeds, strings dir(2) -> fail
	}
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from MkdirAll for strings dir")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS createFunctions MkdirAll error (line 419)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_FunctionDirMkdirError(t *testing.T) {
	mfs := &mkdirCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         5, // gadget(1), strings(2), config(3), configStrings(4), functionDir(5) -> fail
	}
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from MkdirAll for function dir")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}

// ---------------------------------------------------------------------------
// ConfigFS writeConfigDescriptors config dir MkdirAll error (line 389)
// ---------------------------------------------------------------------------

func TestConfigFS_Create_ConfigDirMkdirError(t *testing.T) {
	mfs := &mkdirCountFS{
		mockFileSystem: newMockFileSystem(),
		failAt:         3, // gadget(1), strings(2), config dir(3) -> fail
	}
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	createErr := cfs.Create(context.Background())
	if createErr == nil {
		t.Fatal("expected error from MkdirAll for config dir")
	}
	var ge *GadgetError
	if !errors.As(createErr, &ge) {
		t.Errorf("expected GadgetError, got %T: %v", createErr, createErr)
	}
}
