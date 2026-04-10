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
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"strings"
	"testing"
	"time"
)

// fsCall records a single filesystem operation with its arguments.
type fsCall struct {
	method string
	args   []string
}

// mockFileSystem records all calls and returns configurable results.
type mockFileSystem struct {
	mu           sync.Mutex
	calls        []fsCall
	mkdirErr     error
	writeErr     error
	writeErrPaths map[string]error // fail WriteFile for paths containing these substrings
	symlinkErr   error
	removeErr    error
	readDirMap   map[string]readDirResult
	readFileData []byte
	readFileErr  error
	mountErr     error
	unmountErr   error
	writtenFiles map[string][]byte
}

type readDirResult struct {
	entries []os.DirEntry
	err     error
}

func newMockFileSystem() *mockFileSystem {
	return &mockFileSystem{
		writeErrPaths: make(map[string]error),
		writtenFiles: make(map[string][]byte),
		readDirMap:   make(map[string]readDirResult),
	}
}

func (m *mockFileSystem) record(method string, args ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fsCall{method: method, args: args})
}

func (m *mockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	m.record("MkdirAll", path)
	if m.mkdirErr != nil {
		return m.mkdirErr
	}
	return nil
}

func (m *mockFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	m.record("WriteFile", path)
	for substr, err := range m.writeErrPaths {
		if strings.Contains(path, substr) {
			return err
		}
	}
	if m.writeErr != nil {
		return m.writeErr
	}
	m.mu.Lock()
	m.writtenFiles[path] = append([]byte(nil), data...)
	m.mu.Unlock()
	return nil
}

func (m *mockFileSystem) ReadFile(path string) ([]byte, error) {
	m.record("ReadFile", path)
	return m.readFileData, m.readFileErr
}

func (m *mockFileSystem) Symlink(oldname, newname string) error {
	m.record("Symlink", oldname, newname)
	return m.symlinkErr
}

func (m *mockFileSystem) RemoveAll(path string) error {
	m.record("RemoveAll", path)
	return m.removeErr
}

func (m *mockFileSystem) ReadDir(path string) ([]os.DirEntry, error) {
	m.record("ReadDir", path)
	m.mu.Lock()
	defer m.mu.Unlock()
	if result, ok := m.readDirMap[path]; ok {
		return result.entries, result.err
	}
	return nil, nil
}

func (m *mockFileSystem) Mount(source, target, fstype string, flags uintptr, data string) error {
	m.record("Mount", source, target, fstype)
	return m.mountErr
}

func (m *mockFileSystem) Unmount(target string, flags int) error {
	m.record("Unmount", target)
	return m.unmountErr
}

func (m *mockFileSystem) getCalls() []fsCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]fsCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockFileSystem) getWritten(path string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.writtenFiles[path]
	return data, ok
}

// mockDirEntry implements os.DirEntry for testing.
type mockDirEntry struct {
	name  string
	isDir bool
}

func (d *mockDirEntry) Name() string              { return d.name }
func (d *mockDirEntry) IsDir() bool                { return d.isDir }
func (d *mockDirEntry) Type() fs.FileMode          { return 0 }
func (d *mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// hasExactCall returns true if a call with the exact method and first argument exists.
func hasExactCall(t *testing.T, calls []fsCall, method, arg string) bool {
	t.Helper()
	for _, c := range calls {
		if c.method == method && len(c.args) > 0 && c.args[0] == arg {
			return true
		}
	}
	return false
}

func ccidConfig() *GadgetConfig {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}
	return cfg
}

func compositeConfig() *GadgetConfig {
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
		{Type: FunctionHID},
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewConfigFS_NilConfig(t *testing.T) {
	_, err := NewConfigFS(nil, newMockFileSystem(), testLogger())
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !errors.Is(err, ErrConfigFSNotAvailable) {
		t.Errorf("expected ErrConfigFSNotAvailable, got %v", err)
	}
}

func TestNewConfigFS_NilFileSystem(t *testing.T) {
	_, err := NewConfigFS(DefaultGadgetConfig(), nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil filesystem")
	}
	if !errors.Is(err, ErrNilTransport) {
		t.Errorf("expected ErrNilTransport, got %v", err)
	}
}

func TestNewConfigFS_NilLogger(t *testing.T) {
	_, err := NewConfigFS(DefaultGadgetConfig(), newMockFileSystem(), nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("expected ErrNilLogger, got %v", err)
	}
}

func TestNewConfigFS_Valid(t *testing.T) {
	cfg := DefaultGadgetConfig()
	cfs, err := NewConfigFS(cfg, newMockFileSystem(), testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := filepath.Join(cfg.ConfigFSPath, cfg.Name)
	if cfs.GadgetDir() != expected {
		t.Errorf("GadgetDir() = %q, want %q", cfs.GadgetDir(), expected)
	}
	if cfs.IsBound() {
		t.Error("expected IsBound() == false after construction")
	}
}

// ---------------------------------------------------------------------------
// Create tests
// ---------------------------------------------------------------------------

func TestConfigFS_Create_DirectoryStructure(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Verify MkdirAll for gadget dir
	if !hasExactCall(t, calls, "MkdirAll", gadgDir) {
		t.Error("MkdirAll not called for gadget dir")
	}

	// Verify MkdirAll for strings dir
	stringsDir := filepath.Join(gadgDir, "strings", langEnUS)
	if !hasExactCall(t, calls, "MkdirAll", stringsDir) {
		t.Errorf("MkdirAll not called for %s", stringsDir)
	}

	// Verify MkdirAll for configs dir
	configDir := filepath.Join(gadgDir, "configs", configName)
	if !hasExactCall(t, calls, "MkdirAll", configDir) {
		t.Errorf("MkdirAll not called for %s", configDir)
	}

	// Verify MkdirAll for function dir
	funcDir := filepath.Join(gadgDir, "functions", funcNameCCID)
	if !hasExactCall(t, calls, "MkdirAll", funcDir) {
		t.Errorf("MkdirAll not called for %s", funcDir)
	}

	// Verify device attributes written
	deviceAttrs := map[string]string{
		"idVendor":        "0xf1d0",
		"idProduct":       "0x0001",
		"bcdDevice":       "0x0100",
		"bcdUSB":          "0x0210",
		"bDeviceClass":    "0xef",
		"bDeviceSubClass": "0x02",
		"bDeviceProtocol": "0x01",
	}
	for attr, expected := range deviceAttrs {
		path := filepath.Join(gadgDir, attr)
		data, ok := mfs.getWritten(path)
		if !ok {
			t.Errorf("WriteFile not called for %s", path)
			continue
		}
		if string(data) != expected {
			t.Errorf("%s = %q, want %q", attr, string(data), expected)
		}
	}

	// Verify string descriptors
	stringAttrs := map[string]string{
		"serialnumber": cfg.SerialNumber,
		"manufacturer": cfg.Manufacturer,
		"product":      cfg.Product,
	}
	for attr, expected := range stringAttrs {
		path := filepath.Join(stringsDir, attr)
		data, ok := mfs.getWritten(path)
		if !ok {
			t.Errorf("WriteFile not called for %s", path)
			continue
		}
		if string(data) != expected {
			t.Errorf("%s = %q, want %q", attr, string(data), expected)
		}
	}

	// Verify MaxPower
	maxPowerPath := filepath.Join(configDir, "MaxPower")
	data, ok := mfs.getWritten(maxPowerPath)
	if !ok {
		t.Error("WriteFile not called for MaxPower")
	} else if string(data) != "100" {
		t.Errorf("MaxPower = %q, want %q", string(data), "100")
	}

	// Verify configuration string descriptor
	configStrPath := filepath.Join(configDir, "strings", langEnUS, "configuration")
	data, ok = mfs.getWritten(configStrPath)
	if !ok {
		t.Error("WriteFile not called for configuration string")
	} else if string(data) != configDescription {
		t.Errorf("configuration = %q, want %q", string(data), configDescription)
	}

	// Verify Symlink for CCID function
	linkPath := filepath.Join(gadgDir, "configs", configName, funcNameCCID)
	found := false
	for _, c := range calls {
		if c.method == "Symlink" && len(c.args) == 2 && c.args[0] == funcDir && c.args[1] == linkPath {
			found = true
			break
		}
	}
	if !found {
		t.Error("Symlink not called for CCID function")
	}
}

func TestConfigFS_Create_CompositeCCIDAndHID(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := compositeConfig()
	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Both function dirs should be created
	ccidDir := filepath.Join(gadgDir, "functions", funcNameCCID)
	hidDir := filepath.Join(gadgDir, "functions", funcNameHID)

	if !hasExactCall(t, calls, "MkdirAll", ccidDir) {
		t.Error("MkdirAll not called for CCID function dir")
	}
	if !hasExactCall(t, calls, "MkdirAll", hidDir) {
		t.Error("MkdirAll not called for HID function dir")
	}

	// Both symlinks should be created
	ccidLink := filepath.Join(gadgDir, "configs", configName, funcNameCCID)
	hidLink := filepath.Join(gadgDir, "configs", configName, funcNameHID)

	ccidLinkFound := false
	hidLinkFound := false
	for _, c := range calls {
		if c.method != "Symlink" || len(c.args) != 2 {
			continue
		}
		if c.args[0] == ccidDir && c.args[1] == ccidLink {
			ccidLinkFound = true
		}
		if c.args[0] == hidDir && c.args[1] == hidLink {
			hidLinkFound = true
		}
	}
	if !ccidLinkFound {
		t.Error("Symlink not called for CCID function")
	}
	if !hidLinkFound {
		t.Error("Symlink not called for HID function")
	}

	// HID function should have protocol, subclass, and report_length written
	hidAttrs := []string{"protocol", "subclass", "report_length"}
	for _, attr := range hidAttrs {
		path := filepath.Join(hidDir, attr)
		if _, ok := mfs.getWritten(path); !ok {
			t.Errorf("WriteFile not called for HID attribute %s", attr)
		}
	}
}

func TestConfigFS_Create_GadgetAlreadyExists(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()

	// Simulate gadget dir already existing
	mfs.readDirMap[cfg.ConfigFSPath] = readDirResult{
		entries: []os.DirEntry{&mockDirEntry{name: cfg.Name, isDir: true}},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Create(context.Background())
	if err == nil {
		t.Fatal("expected error for existing gadget")
	}
	if !errors.Is(err, ErrGadgetAlreadyExists) {
		t.Errorf("expected ErrGadgetAlreadyExists, got %v", err)
	}
}

func TestConfigFS_Create_MkdirError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.mkdirErr = errors.New("permission denied")
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Create(context.Background())
	if err == nil {
		t.Fatal("expected error from MkdirAll")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

func TestConfigFS_Create_WriteError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.writeErr = errors.New("write failed")
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Create(context.Background())
	if err == nil {
		t.Fatal("expected error from WriteFile")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

func TestConfigFS_Create_CancelledContext(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cfs.Create(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestConfigFS_Create_SymlinkError(t *testing.T) {
	mfs := newMockFileSystem()
	mfs.symlinkErr = errors.New("symlink failed")
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Create(context.Background())
	if err == nil {
		t.Fatal("expected error from Symlink")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

func TestConfigFS_Create_ReadDirError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	mfs.readDirMap[cfg.ConfigFSPath] = readDirResult{
		err: errors.New("configfs not mounted"),
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Create(context.Background())
	if err == nil {
		t.Fatal("expected error from ReadDir")
	}
	if !errors.Is(err, ErrConfigFSNotAvailable) {
		t.Errorf("expected ErrConfigFSNotAvailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bind tests
// ---------------------------------------------------------------------------

func TestConfigFS_Bind_AutoDetectUDC(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = ""

	mfs.readDirMap[udcSysPath] = readDirResult{
		entries: []os.DirEntry{&mockDirEntry{name: "dummy_udc.0"}},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
	data, ok := mfs.getWritten(udcPath)
	if !ok {
		t.Fatal("WriteFile not called for UDC")
	}
	if string(data) != "dummy_udc.0" {
		t.Errorf("UDC = %q, want %q", string(data), "dummy_udc.0")
	}
	if !cfs.IsBound() {
		t.Error("expected IsBound() == true after Bind")
	}
}

func TestConfigFS_Bind_ExplicitUDC(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "fe980000.usb"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
	data, ok := mfs.getWritten(udcPath)
	if !ok {
		t.Fatal("WriteFile not called for UDC")
	}
	if string(data) != "fe980000.usb" {
		t.Errorf("UDC = %q, want %q", string(data), "fe980000.usb")
	}
	if !cfs.IsBound() {
		t.Error("expected IsBound() == true after Bind")
	}
}

func TestConfigFS_Bind_NoUDC(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = ""

	// Empty readDir for UDC path
	mfs.readDirMap[udcSysPath] = readDirResult{
		entries: []os.DirEntry{},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Bind(context.Background())
	if err == nil {
		t.Fatal("expected error for no UDC")
	}
	if !errors.Is(err, ErrUDCNotFound) {
		t.Errorf("expected ErrUDCNotFound, got %v", err)
	}
	if cfs.IsBound() {
		t.Error("expected IsBound() == false when Bind fails")
	}
}

func TestConfigFS_Bind_CancelledContext(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cfs.Bind(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestConfigFS_Bind_WriteError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"
	mfs.writeErr = errors.New("write failed")

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Bind(context.Background())
	if err == nil {
		t.Fatal("expected error from WriteFile")
	}
	if !errors.Is(err, ErrConfigFSNotAvailable) {
		t.Errorf("expected ErrConfigFSNotAvailable, got %v", err)
	}
}

func TestConfigFS_Bind_ReadDirError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = ""
	mfs.readDirMap[udcSysPath] = readDirResult{
		err: errors.New("sysfs not available"),
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = cfs.Bind(context.Background())
	if err == nil {
		t.Fatal("expected error from ReadDir")
	}
	if !errors.Is(err, ErrUDCNotFound) {
		t.Errorf("expected ErrUDCNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Unbind tests
// ---------------------------------------------------------------------------

func TestConfigFS_Unbind_Bound(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if !cfs.IsBound() {
		t.Fatal("expected IsBound() == true after Bind")
	}

	if err := cfs.Unbind(); err != nil {
		t.Fatalf("Unbind failed: %v", err)
	}

	udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
	data, ok := mfs.getWritten(udcPath)
	if !ok {
		t.Fatal("WriteFile not called for UDC during Unbind")
	}
	if string(data) != "\n" {
		t.Errorf("UDC after Unbind = %q, want newline", string(data))
	}
	if cfs.IsBound() {
		t.Error("expected IsBound() == false after Unbind")
	}
}

func TestConfigFS_Unbind_NotBound(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unbind without binding should be a no-op
	if err := cfs.Unbind(); err != nil {
		t.Fatalf("Unbind on unbound gadget should return nil, got %v", err)
	}
}

func TestConfigFS_Unbind_WriteError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Now inject a write error for the unbind
	mfs.writeErr = errors.New("write failed")

	err = cfs.Unbind()
	if err == nil {
		t.Fatal("expected error from Unbind WriteFile")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// Destroy tests
// ---------------------------------------------------------------------------

func TestConfigFS_Destroy_Clean(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := compositeConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if err := cfs.Destroy(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	if cfs.IsBound() {
		t.Error("expected IsBound() == false after Destroy")
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Verify RemoveAll for function symlinks
	ccidLink := filepath.Join(gadgDir, "configs", configName, funcNameCCID)
	hidLink := filepath.Join(gadgDir, "configs", configName, funcNameHID)
	if !hasExactCall(t, calls, "RemoveAll", ccidLink) {
		t.Error("RemoveAll not called for CCID symlink")
	}
	if !hasExactCall(t, calls, "RemoveAll", hidLink) {
		t.Error("RemoveAll not called for HID symlink")
	}

	// Verify RemoveAll for config strings
	configStrings := filepath.Join(gadgDir, "configs", configName, "strings", langEnUS)
	if !hasExactCall(t, calls, "RemoveAll", configStrings) {
		t.Error("RemoveAll not called for config strings dir")
	}

	// Verify RemoveAll for config dir
	cfgDir := filepath.Join(gadgDir, "configs", configName)
	if !hasExactCall(t, calls, "RemoveAll", cfgDir) {
		t.Error("RemoveAll not called for config dir")
	}

	// Verify RemoveAll for function dirs
	ccidFunc := filepath.Join(gadgDir, "functions", funcNameCCID)
	hidFunc := filepath.Join(gadgDir, "functions", funcNameHID)
	if !hasExactCall(t, calls, "RemoveAll", ccidFunc) {
		t.Error("RemoveAll not called for CCID function dir")
	}
	if !hasExactCall(t, calls, "RemoveAll", hidFunc) {
		t.Error("RemoveAll not called for HID function dir")
	}

	// Verify RemoveAll for strings dir
	stringsDir := filepath.Join(gadgDir, "strings", langEnUS)
	if !hasExactCall(t, calls, "RemoveAll", stringsDir) {
		t.Error("RemoveAll not called for strings dir")
	}

	// Verify RemoveAll for gadget dir itself
	if !hasExactCall(t, calls, "RemoveAll", gadgDir) {
		t.Error("RemoveAll not called for gadget dir")
	}
}

func TestConfigFS_Destroy_NotBound(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Destroy without binding should still clean up dirs
	if err := cfs.Destroy(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	calls := mfs.getCalls()
	gadgDir := cfs.GadgetDir()
	if !hasExactCall(t, calls, "RemoveAll", gadgDir) {
		t.Error("RemoveAll not called for gadget dir")
	}
}

func TestConfigFS_Destroy_RemoveError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject remove error
	mfs.removeErr = errors.New("remove denied")

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from RemoveAll")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

func TestConfigFS_Destroy_UnbindError(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Inject write error so Unbind fails
	mfs.writeErr = errors.New("write failed")

	err = cfs.Destroy()
	if err == nil {
		t.Fatal("expected error from Unbind during Destroy")
	}
	if !errors.As(err, new(*GadgetError)) {
		t.Errorf("expected GadgetError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// DefaultGadgetConfig test
// ---------------------------------------------------------------------------

func TestDefaultGadgetConfig(t *testing.T) {
	cfg := DefaultGadgetConfig()

	if cfg.Name != "xkey" {
		t.Errorf("Name = %q, want %q", cfg.Name, "xkey")
	}
	if cfg.VendorID != 0xF1D0 {
		t.Errorf("VendorID = 0x%04x, want 0xF1D0", cfg.VendorID)
	}
	if cfg.ProductID != 0x0001 {
		t.Errorf("ProductID = 0x%04x, want 0x0001", cfg.ProductID)
	}
	if cfg.DeviceVersion != 0x0100 {
		t.Errorf("DeviceVersion = 0x%04x, want 0x0100", cfg.DeviceVersion)
	}
	if cfg.SerialNumber != "XKEY001" {
		t.Errorf("SerialNumber = %q, want %q", cfg.SerialNumber, "XKEY001")
	}
	if cfg.Manufacturer != "Automate The Things" {
		t.Errorf("Manufacturer = %q, want %q", cfg.Manufacturer, "Automate The Things")
	}
	if cfg.Product != "xKey OTP+FIDO+CCID" {
		t.Errorf("Product = %q, want %q", cfg.Product, "xKey OTP+FIDO+CCID")
	}
	if cfg.ConfigFSPath != "/sys/kernel/config/usb_gadget" {
		t.Errorf("ConfigFSPath = %q, want default", cfg.ConfigFSPath)
	}
	if cfg.MaxPower != 100 {
		t.Errorf("MaxPower = %d, want 100", cfg.MaxPower)
	}
	if cfg.Functions != nil {
		t.Errorf("Functions = %v, want nil", cfg.Functions)
	}
}

// ---------------------------------------------------------------------------
// Context timeout test
// ---------------------------------------------------------------------------

func TestConfigFS_Bind_ContextTimeout(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := ccidConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), -1*time.Second)
	defer cancel()

	err = cfs.Bind(ctx)
	if err == nil {
		t.Fatal("expected error for timed-out context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// HID attributes test
// ---------------------------------------------------------------------------

func TestConfigFS_Create_HIDAttributes(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionHID},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	hidDir := filepath.Join(gadgDir, "functions", funcNameHID)

	expectedAttrs := map[string]string{
		"protocol":      "0",
		"subclass":      "0",
		"report_length": "64",
	}
	for attr, expected := range expectedAttrs {
		path := filepath.Join(hidDir, attr)
		data, ok := mfs.getWritten(path)
		if !ok {
			t.Errorf("WriteFile not called for HID attribute %s", attr)
			continue
		}
		if string(data) != expected {
			t.Errorf("HID %s = %q, want %q", attr, string(data), expected)
		}
	}
}

// ---------------------------------------------------------------------------
// functionDirName coverage
// ---------------------------------------------------------------------------

func TestFunctionDirName(t *testing.T) {
	tests := []struct {
		input    FunctionType
		expected string
	}{
		{FunctionCCID, funcNameCCID},
		{FunctionHID, funcNameHID},
		{FunctionType("custom"), "custom"},
	}
	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := functionDirName(tt.input)
			if got != tt.expected {
				t.Errorf("functionDirName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Attribute value verification
// ---------------------------------------------------------------------------

func TestConfigFS_Create_VerifyAllAttributes(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()

	// Device attributes with exact expected format.
	wantAttrs := map[string]string{
		"idVendor":        "0xf1d0",
		"idProduct":       "0x0001",
		"bcdDevice":       "0x0100",
		"bcdUSB":          "0x0210",
		"bDeviceClass":    "0xef",
		"bDeviceSubClass": "0x02",
		"bDeviceProtocol": "0x01",
	}
	for name, want := range wantAttrs {
		path := filepath.Join(gadgDir, name)
		data, ok := mfs.getWritten(path)
		if !ok {
			t.Errorf("%s: WriteFile not called", name)
			continue
		}
		got := string(data)
		if got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}

	// String descriptors.
	stringsDir := filepath.Join(gadgDir, "strings", langEnUS)
	wantStrings := map[string]string{
		"serialnumber": "XKEY001",
		"manufacturer": "Automate The Things",
		"product":      "xKey OTP+FIDO+CCID",
	}
	for name, want := range wantStrings {
		path := filepath.Join(stringsDir, name)
		data, ok := mfs.getWritten(path)
		if !ok {
			t.Errorf("strings/%s: WriteFile not called", name)
			continue
		}
		got := string(data)
		if got != want {
			t.Errorf("strings/%s: got %q, want %q", name, got, want)
		}
	}

	// MaxPower
	configDir := filepath.Join(gadgDir, "configs", configName)
	maxPowerPath := filepath.Join(configDir, "MaxPower")
	data, ok := mfs.getWritten(maxPowerPath)
	if !ok {
		t.Fatal("MaxPower: WriteFile not called")
	}
	if got := string(data); got != "100" {
		t.Errorf("MaxPower: got %q, want %q", got, "100")
	}

	// Configuration string
	configStrPath := filepath.Join(configDir, "strings", langEnUS, "configuration")
	data, ok = mfs.getWritten(configStrPath)
	if !ok {
		t.Fatal("configuration: WriteFile not called")
	}
	if got := string(data); got != "xKey Composite Device" {
		t.Errorf("configuration: got %q, want %q", got, "xKey Composite Device")
	}
}

func TestConfigFS_Create_VerifySymlinks(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := compositeConfig()

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Expected symlinks: source (function dir) -> target (config link).
	wantLinks := []struct {
		source string
		target string
	}{
		{
			source: filepath.Join(gadgDir, "functions", funcNameCCID),
			target: filepath.Join(gadgDir, "configs", configName, funcNameCCID),
		},
		{
			source: filepath.Join(gadgDir, "functions", funcNameHID),
			target: filepath.Join(gadgDir, "configs", configName, funcNameHID),
		},
	}

	for _, wl := range wantLinks {
		found := false
		for _, c := range calls {
			if c.method == "Symlink" && len(c.args) == 2 &&
				c.args[0] == wl.source && c.args[1] == wl.target {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Symlink not called: source=%q target=%q", wl.source, wl.target)
		}
	}
}

func TestConfigFS_Create_VerifyCallOrder(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := DefaultGadgetConfig()
	cfg.Functions = []FunctionConfig{
		{Type: FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Find index of first MkdirAll for gadget dir and first WriteFile for any attribute.
	mkdirIdx := -1
	writeIdx := -1
	for i, c := range calls {
		if c.method == "MkdirAll" && len(c.args) > 0 && c.args[0] == gadgDir && mkdirIdx < 0 {
			mkdirIdx = i
		}
		if c.method == "WriteFile" && writeIdx < 0 {
			writeIdx = i
		}
	}
	if mkdirIdx < 0 {
		t.Fatal("MkdirAll not called for gadget dir")
	}
	if writeIdx < 0 {
		t.Fatal("no WriteFile calls recorded")
	}
	if mkdirIdx >= writeIdx {
		t.Errorf("gadget dir MkdirAll (index %d) must be called before first WriteFile (index %d)",
			mkdirIdx, writeIdx)
	}
}

func TestConfigFS_Bind_VerifyUDCValue(t *testing.T) {
	tests := []struct {
		name     string
		udc      string
		autoUDC  string
		wantUDC  string
	}{
		{
			name:    "explicit UDC",
			udc:     "musb-hdrc.0",
			wantUDC: "musb-hdrc.0",
		},
		{
			name:    "auto-detected UDC",
			udc:     "",
			autoUDC: "fe980000.usb",
			wantUDC: "fe980000.usb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs := newMockFileSystem()
			cfg := ccidConfig()
			cfg.UDC = tt.udc

			if tt.autoUDC != "" {
				mfs.readDirMap[udcSysPath] = readDirResult{
					entries: []os.DirEntry{&mockDirEntry{name: tt.autoUDC}},
				}
			}

			cfs, err := NewConfigFS(cfg, mfs, testLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if err := cfs.Bind(context.Background()); err != nil {
				t.Fatalf("Bind failed: %v", err)
			}

			udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
			data, ok := mfs.getWritten(udcPath)
			if !ok {
				t.Fatal("WriteFile not called for UDC")
			}
			got := string(data)
			if got != tt.wantUDC {
				t.Errorf("UDC value: got %q, want %q", got, tt.wantUDC)
			}
		})
	}
}

func TestConfigFS_Destroy_VerifyRemovalOrder(t *testing.T) {
	mfs := newMockFileSystem()
	cfg := compositeConfig()
	cfg.UDC = "dummy_udc.0"

	cfs, err := NewConfigFS(cfg, mfs, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cfs.Create(context.Background()); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := cfs.Bind(context.Background()); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if err := cfs.Destroy(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	gadgDir := cfs.GadgetDir()
	calls := mfs.getCalls()

	// Collect RemoveAll calls in order.
	var removals []string
	for _, c := range calls {
		if c.method == "RemoveAll" && len(c.args) > 0 {
			removals = append(removals, c.args[0])
		}
	}

	// Build expected paths for ordering.
	ccidLink := filepath.Join(gadgDir, "configs", configName, funcNameCCID)
	hidLink := filepath.Join(gadgDir, "configs", configName, funcNameHID)
	configStrings := filepath.Join(gadgDir, "configs", configName, "strings", langEnUS)
	cfgDir := filepath.Join(gadgDir, "configs", configName)
	ccidFunc := filepath.Join(gadgDir, "functions", funcNameCCID)
	hidFunc := filepath.Join(gadgDir, "functions", funcNameHID)
	stringsDir := filepath.Join(gadgDir, "strings", langEnUS)

	// indexOfPath returns the first index of path in removals, or -1.
	indexOfPath := func(path string) int {
		for i, p := range removals {
			if p == path {
				return i
			}
		}
		return -1
	}

	// Symlinks must be removed before config dir.
	ccidLinkIdx := indexOfPath(ccidLink)
	hidLinkIdx := indexOfPath(hidLink)
	cfgDirIdx := indexOfPath(cfgDir)
	if ccidLinkIdx < 0 {
		t.Fatal("RemoveAll not called for CCID symlink")
	}
	if hidLinkIdx < 0 {
		t.Fatal("RemoveAll not called for HID symlink")
	}
	if cfgDirIdx < 0 {
		t.Fatal("RemoveAll not called for config dir")
	}
	if ccidLinkIdx >= cfgDirIdx {
		t.Errorf("CCID symlink removal (index %d) must precede config dir removal (index %d)",
			ccidLinkIdx, cfgDirIdx)
	}
	if hidLinkIdx >= cfgDirIdx {
		t.Errorf("HID symlink removal (index %d) must precede config dir removal (index %d)",
			hidLinkIdx, cfgDirIdx)
	}

	// Config strings dir must be removed before config dir.
	configStringsIdx := indexOfPath(configStrings)
	if configStringsIdx < 0 {
		t.Fatal("RemoveAll not called for config strings dir")
	}
	if configStringsIdx >= cfgDirIdx {
		t.Errorf("config strings removal (index %d) must precede config dir removal (index %d)",
			configStringsIdx, cfgDirIdx)
	}

	// Config dir must be removed before function dirs.
	ccidFuncIdx := indexOfPath(ccidFunc)
	hidFuncIdx := indexOfPath(hidFunc)
	if ccidFuncIdx < 0 {
		t.Fatal("RemoveAll not called for CCID function dir")
	}
	if hidFuncIdx < 0 {
		t.Fatal("RemoveAll not called for HID function dir")
	}
	if cfgDirIdx >= ccidFuncIdx {
		t.Errorf("config dir removal (index %d) must precede CCID function dir removal (index %d)",
			cfgDirIdx, ccidFuncIdx)
	}

	// Function dirs must be removed before strings dir.
	stringsDirIdx := indexOfPath(stringsDir)
	if stringsDirIdx < 0 {
		t.Fatal("RemoveAll not called for strings dir")
	}
	if ccidFuncIdx >= stringsDirIdx {
		t.Errorf("CCID function removal (index %d) must precede strings dir removal (index %d)",
			ccidFuncIdx, stringsDirIdx)
	}

	// Strings dir must be removed before gadget dir.
	gadgDirIdx := indexOfPath(gadgDir)
	if gadgDirIdx < 0 {
		t.Fatal("RemoveAll not called for gadget dir")
	}
	if stringsDirIdx >= gadgDirIdx {
		t.Errorf("strings dir removal (index %d) must precede gadget dir removal (index %d)",
			stringsDirIdx, gadgDirIdx)
	}
}
