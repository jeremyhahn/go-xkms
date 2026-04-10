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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNew_NilConfig(t *testing.T) {
	_, err := New(nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !errors.Is(err, ErrConfigFSNotAvailable) {
		t.Errorf("expected ErrConfigFSNotAvailable, got %v", err)
	}
}

func TestNew_NilLogger(t *testing.T) {
	cfg := DefaultGadgetConfig()
	_, err := New(cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestNew_Valid(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g == nil {
		t.Fatal("expected non-nil Gadget")
	}
	if g.IsBound() {
		t.Error("expected IsBound() == false after construction")
	}
}

func TestNew_WithFileSystem(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.fs != mfs {
		t.Error("WithFileSystem option was not applied")
	}
}

func TestNew_WithHIDDevicePath(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs), WithHIDDevicePath("/dev/hidg1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.hidDevPath != "/dev/hidg1" {
		t.Errorf("hidDevPath = %q, want %q", g.hidDevPath, "/dev/hidg1")
	}
}

func TestNew_DefaultFileSystem(t *testing.T) {
	cfg := DefaultGadgetConfig()
	g, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := g.fs.(*OSFileSystem); !ok {
		t.Errorf("default FileSystem is %T, want *OSFileSystem", g.fs)
	}
}

func TestNew_DefaultHIDDevicePath(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.hidDevPath != defaultHIDGadgetPath {
		t.Errorf("hidDevPath = %q, want %q", g.hidDevPath, defaultHIDGadgetPath)
	}
}

func TestNew_DefaultGadgetConfig(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.config.Name != "xkey" {
		t.Errorf("config.Name = %q, want %q", g.config.Name, "xkey")
	}
}

// ---------------------------------------------------------------------------
// Start tests
// ---------------------------------------------------------------------------

func TestGadget_Start_CreatesConfigFSTree(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{} // no functions, just tree creation

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := g.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	calls := mfs.getCalls()
	gadgDir := g.configFS.GadgetDir()

	if !hasExactCall(t, calls, "MkdirAll", gadgDir) {
		t.Error("MkdirAll not called for gadget dir")
	}

	stringsDir := filepath.Join(gadgDir, "strings", langEnUS)
	if !hasExactCall(t, calls, "MkdirAll", stringsDir) {
		t.Error("MkdirAll not called for strings dir")
	}

	if !g.IsBound() {
		t.Error("expected IsBound() == true after Start")
	}
}

func TestGadget_Start_CCIDFunction_MountAndMkdir(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs-ccid"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Start will fail at FunctionFSTransport.Initialize because ep0 does
	// not exist in the mock FS. That is expected. We verify the
	// orchestration steps that occur before the transport initialization.
	startErr := g.Start(context.Background())

	calls := mfs.getCalls()

	// Verify MkdirAll called for the FunctionFS mount dir.
	if !hasExactCall(t, calls, "MkdirAll", "/tmp/test-ffs-ccid") {
		t.Error("MkdirAll not called for FunctionFS mount dir")
	}

	// Verify Mount called with functionfs type.
	mountFound := false
	for _, c := range calls {
		if c.method == "Mount" && len(c.args) >= 3 {
			if c.args[0] == funcNameCCID && c.args[1] == "/tmp/test-ffs-ccid" && c.args[2] == "functionfs" {
				mountFound = true
				break
			}
		}
	}
	if !mountFound {
		t.Error("Mount not called with expected arguments for CCID FunctionFS")
	}

	// Start should have failed because ep0 does not exist.
	if startErr == nil {
		t.Error("expected Start to fail (ep0 does not exist in mock), but it succeeded")
	}
}

func TestGadget_Start_CCIDFunction_DefaultMountDir(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID}, // empty MountDir
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Will fail at transport init, but we verify the default mount dir.
	_ = g.Start(context.Background())

	calls := mfs.getCalls()
	if !hasExactCall(t, calls, "MkdirAll", defaultFunctionFSMountDir) {
		t.Error("MkdirAll not called for default FunctionFS mount dir")
	}
}

func TestGadget_Start_HIDFunction_ReportDescriptor(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Start will fail at NewHIDGadgetTransport because /dev/hidg0 does
	// not exist. But the report_desc write happens before the bind.
	_ = g.Start(context.Background())

	gadgDir := g.configFS.GadgetDir()
	reportDescPath := filepath.Join(gadgDir, "functions", funcNameHID, "report_desc")

	data, ok := mfs.getWritten(reportDescPath)
	if !ok {
		t.Fatal("WriteFile not called for report_desc")
	}
	if !bytes.Equal(data, fido2HIDReportDescriptor) {
		t.Errorf("report_desc length = %d, want %d", len(data), len(fido2HIDReportDescriptor))
	}
}

func TestGadget_Start_HIDFunction_ReportDescWriteError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allow ConfigFS.Create to succeed, then inject write error for
	// the report_desc write. Since writeErr affects all writes including
	// Create, we need a more targeted approach. We use a wrapping FS.
	// For simplicity, just set writeErr after Create would have been called.
	// But mockFileSystem uses a single writeErr for all writes.
	// Instead, test with writeErr from the start; Create will fail first.
	mfs.writeErr = errors.New("write denied")

	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start")
	}
	if !errors.As(startErr, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T: %v", startErr, startErr)
	}
}

func TestGadget_Start_CreateError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	// Make ConfigFS.Create fail by simulating existing gadget.
	mfs.readDirMap[cfg.ConfigFSPath] = readDirResult{
		entries: []os.DirEntry{&mockDirEntry{name: cfg.Name, isDir: true}},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start when ConfigFS.Create fails")
	}
	if !errors.Is(startErr, ErrGadgetAlreadyExists) {
		t.Errorf("expected ErrGadgetAlreadyExists, got %v", startErr)
	}
}

func TestGadget_Start_BindError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "" // auto-detect
	cfg.Functions = []FunctionConfig{}

	// No UDC entries means Bind fails.
	mfs.readDirMap[udcSysPath] = readDirResult{
		entries: []os.DirEntry{},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start when Bind fails")
	}
	if !errors.Is(startErr, ErrUDCNotFound) {
		t.Errorf("expected ErrUDCNotFound, got %v", startErr)
	}
}

func TestGadget_Start_CancelledContext(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	startErr := g.Start(ctx)
	if startErr == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(startErr, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", startErr)
	}
}

func TestGadget_Start_CCIDMountError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.mountErr = errors.New("mount denied")
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start when Mount fails")
	}
	if !errors.Is(startErr, ErrFunctionFSMountFailed) {
		t.Errorf("expected ErrFunctionFSMountFailed, got %v", startErr)
	}
}

func TestGadget_Start_CCIDMkdirError(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs"},
	}

	// Use a FS that fails MkdirAll only for the mount dir.
	// The simplest approach: set mkdirErr which will fail during
	// ConfigFS.Create before we even reach CCID init.
	mfs := newMockFileSystem()
	mfs.mkdirErr = errors.New("mkdir denied")

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	startErr := g.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected error from Start when MkdirAll fails")
	}
	if !errors.As(startErr, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T: %v", startErr, startErr)
	}
}

// ---------------------------------------------------------------------------
// Stop tests
// ---------------------------------------------------------------------------

func TestGadget_Stop_NoTransports(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := g.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := g.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if g.IsBound() {
		t.Error("expected IsBound() == false after Stop")
	}

	// Verify Destroy was called (RemoveAll for gadget dir).
	calls := mfs.getCalls()
	gadgDir := g.configFS.GadgetDir()
	if !hasExactCall(t, calls, "RemoveAll", gadgDir) {
		t.Error("RemoveAll not called for gadget dir during Stop")
	}
}

func TestGadget_Stop_UnmountCCID(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs-ccid"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate a started gadget without real transports.
	g.bound.Store(true)

	if err := g.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	calls := mfs.getCalls()
	unmountFound := false
	for _, c := range calls {
		if c.method == "Unmount" && len(c.args) > 0 && c.args[0] == "/tmp/test-ffs-ccid" {
			unmountFound = true
			break
		}
	}
	if !unmountFound {
		t.Error("Unmount not called for CCID FunctionFS mount dir")
	}
}

func TestGadget_Stop_UnmountDefaultCCIDDir(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID}, // empty MountDir
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	g.bound.Store(true)

	if err := g.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	calls := mfs.getCalls()
	unmountFound := false
	for _, c := range calls {
		if c.method == "Unmount" && len(c.args) > 0 && c.args[0] == defaultFunctionFSMountDir {
			unmountFound = true
			break
		}
	}
	if !unmountFound {
		t.Error("Unmount not called for default FunctionFS mount dir")
	}
}

func TestGadget_Stop_DestroyError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.removeErr = errors.New("remove denied")
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	g.bound.Store(true)

	stopErr := g.Stop()
	if stopErr == nil {
		t.Fatal("expected error from Stop when Destroy fails")
	}
	if !errors.As(stopErr, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T: %v", stopErr, stopErr)
	}
}

func TestGadget_Stop_UnmountError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.unmountErr = errors.New("unmount denied")
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	g.bound.Store(true)

	stopErr := g.Stop()
	if stopErr == nil {
		t.Fatal("expected error from Stop when Unmount fails")
	}
	if !errors.As(stopErr, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T: %v", stopErr, stopErr)
	}
}

// ---------------------------------------------------------------------------
// Accessor tests
// ---------------------------------------------------------------------------

func TestGadget_CCIDTransport_Nil(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.CCIDTransport() != nil {
		t.Error("expected CCIDTransport() == nil when no CCID function configured")
	}
}

func TestGadget_HIDTransport_Nil(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.HIDTransport() != nil {
		t.Error("expected HIDTransport() == nil when no HID function configured")
	}
}

func TestGadget_IsBound_Initial(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if g.IsBound() {
		t.Error("expected IsBound() == false before Start")
	}
}

// ---------------------------------------------------------------------------
// Report descriptor validation
// ---------------------------------------------------------------------------

func TestFIDO2HIDReportDescriptor_Length(t *testing.T) {
	// The FIDO2 CTAP-HID report descriptor is 34 bytes.
	if len(fido2HIDReportDescriptor) != 34 {
		t.Errorf("report descriptor length = %d, want 34", len(fido2HIDReportDescriptor))
	}
}

func TestFIDO2HIDReportDescriptor_UsagePage(t *testing.T) {
	// First three bytes should be Usage Page (FIDO Alliance: 0xF1D0).
	if fido2HIDReportDescriptor[0] != 0x06 {
		t.Errorf("byte[0] = 0x%02x, want 0x06 (Usage Page)", fido2HIDReportDescriptor[0])
	}
	if fido2HIDReportDescriptor[1] != 0xD0 {
		t.Errorf("byte[1] = 0x%02x, want 0xD0", fido2HIDReportDescriptor[1])
	}
	if fido2HIDReportDescriptor[2] != 0xF1 {
		t.Errorf("byte[2] = 0x%02x, want 0xF1", fido2HIDReportDescriptor[2])
	}
}

func TestFIDO2HIDReportDescriptor_EndCollection(t *testing.T) {
	// Last byte should be End Collection (0xC0).
	last := fido2HIDReportDescriptor[len(fido2HIDReportDescriptor)-1]
	if last != 0xC0 {
		t.Errorf("last byte = 0x%02x, want 0xC0 (End Collection)", last)
	}
}

// ---------------------------------------------------------------------------
// Field verification after New
// ---------------------------------------------------------------------------

func TestNew_VerifyFields(t *testing.T) {
	cfg := DefaultGadgetConfig()
	mfs := newMockFileSystem()
	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// config must match passed config
	if g.config != cfg {
		t.Errorf("g.config pointer mismatch: got %p, want %p", g.config, cfg)
	}

	// fs must be the custom mock
	if g.fs != mfs {
		t.Errorf("g.fs = %T, want *mockFileSystem", g.fs)
	}

	// IsBound must be false
	if g.IsBound() {
		t.Error("IsBound() = true, want false after New()")
	}

	// CCIDTransport must be nil
	if g.CCIDTransport() != nil {
		t.Error("CCIDTransport() is non-nil, want nil after New()")
	}

	// HIDTransport must be nil
	if g.HIDTransport() != nil {
		t.Error("HIDTransport() is non-nil, want nil after New()")
	}
}

func TestNew_VerifyDefaultFSType(t *testing.T) {
	cfg := DefaultGadgetConfig()
	g, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := g.fs.(*OSFileSystem); !ok {
		t.Errorf("default fs type: got %T, want *OSFileSystem", g.fs)
	}
}

// ---------------------------------------------------------------------------
// Mount parameter verification
// ---------------------------------------------------------------------------

func TestGadget_Start_VerifyCCIDMountParams(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ccid-mount"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Start will fail at transport Initialize (no ep0), but Mount is called before that.
	_ = g.Start(context.Background())

	calls := mfs.getCalls()
	mountFound := false
	for _, c := range calls {
		if c.method == "Mount" && len(c.args) >= 3 {
			if c.args[0] != "ffs.ccid" {
				t.Errorf("Mount source: got %q, want %q", c.args[0], "ffs.ccid")
			}
			if c.args[1] != "/tmp/test-ccid-mount" {
				t.Errorf("Mount target: got %q, want %q", c.args[1], "/tmp/test-ccid-mount")
			}
			if c.args[2] != "functionfs" {
				t.Errorf("Mount fstype: got %q, want %q", c.args[2], "functionfs")
			}
			mountFound = true
			break
		}
	}
	if !mountFound {
		t.Fatal("Mount was not called during CCID init")
	}
}

// ---------------------------------------------------------------------------
// HID report descriptor content verification
// ---------------------------------------------------------------------------

func TestGadget_Start_VerifyHIDReportDescContent(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Will fail at NewHIDGadgetTransport, but report_desc is written before bind.
	_ = g.Start(context.Background())

	gadgDir := g.configFS.GadgetDir()
	reportDescPath := filepath.Join(gadgDir, "functions", funcNameHID, "report_desc")

	data, ok := mfs.getWritten(reportDescPath)
	if !ok {
		t.Fatal("report_desc not written")
	}

	if len(data) != 34 {
		t.Fatalf("report_desc length: got %d, want 34", len(data))
	}

	// Verify all 34 bytes of the FIDO2 HID report descriptor.
	wantDesc := []byte{
		0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
		0x09, 0x01, // Usage (U2F Authenticator Device)
		0xA1, 0x01, // Collection (Application)
		0x09, 0x20, //   Usage (Input Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x81, 0x02, //   Input (Data, Var, Abs)
		0x09, 0x21, //   Usage (Output Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x91, 0x02, //   Output (Data, Var, Abs)
		0xC0, // End Collection
	}

	for i, want := range wantDesc {
		if data[i] != want {
			t.Errorf("report_desc[%d]: got %#02x, want %#02x", i, data[i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// Stop unmount verification
// ---------------------------------------------------------------------------

func TestGadget_Stop_VerifyUnmountCalled(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.UDC = "dummy_udc.0"
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/tmp/test-ffs-unmount"},
	}

	g, err := New(cfg, testLogger(), WithFileSystem(mfs))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate started state without real transports.
	g.bound.Store(true)

	if err := g.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	calls := mfs.getCalls()
	unmountFound := false
	for _, c := range calls {
		if c.method == "Unmount" && len(c.args) > 0 &&
			c.args[0] == "/tmp/test-ffs-unmount" {
			unmountFound = true
			break
		}
	}
	if !unmountFound {
		t.Errorf("Unmount not called with path %q", "/tmp/test-ffs-unmount")
	}
}
