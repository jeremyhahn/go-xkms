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

//go:build integration && linux

package gadget

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gadget"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	configFSGadgetPath = "/sys/kernel/config/usb_gadget"
	udcSysPath         = "/sys/class/udc"
)

// requireDummyHCD verifies the dummy_hcd kernel module is loaded.
// Fails the test if it is not available — in the integration test
// container, the entrypoint must load it before tests run.
func requireDummyHCD(t *testing.T) {
	t.Helper()

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		t.Fatalf("cannot read /proc/modules: %v", err)
	}
	if !strings.Contains(string(data), "dummy_hcd") {
		t.Fatal("dummy_hcd module is not loaded; the Docker entrypoint must load it before tests run")
	}
}

// requireConfigFS verifies ConfigFS is mounted at /sys/kernel/config/usb_gadget.
// Fails the test if not available — the Docker entrypoint must mount it.
func requireConfigFS(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(configFSGadgetPath); err != nil {
		t.Fatalf("ConfigFS not available at %s: %v — the Docker entrypoint must mount configfs", configFSGadgetPath, err)
	}
}

// findUDC returns the first available UDC name, or fails the test.
func findUDC(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir(udcSysPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", udcSysPath, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no UDC available in %s; dummy_hcd must be loaded", udcSysPath)
	}
	return entries[0].Name()
}

// uniqueGadgetName returns a unique gadget name derived from the test name.
// It sanitizes the test name to be a valid ConfigFS directory name.
func uniqueGadgetName(t *testing.T) string {
	t.Helper()

	name := strings.ReplaceAll(t.Name(), "/", "-")
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ToLower(name)
	// Truncate to avoid exceeding filesystem limits.
	if len(name) > 40 {
		name = name[:40]
	}
	return fmt.Sprintf("xkey-test-%s-%d", name, time.Now().UnixNano()%10000)
}

// testLogger returns a structured logger for integration tests.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// forceUnbindUDC writes a newline to the gadget's UDC file to force-release
// the UDC controller. This is a last-resort cleanup that ensures subsequent
// tests are not blocked by a stuck UDC binding.
func forceUnbindUDC(t *testing.T, gadgDir string) {
	t.Helper()
	udcPath := filepath.Join(gadgDir, "UDC")
	if _, err := os.Stat(udcPath); err != nil {
		return // gadget directory already removed
	}
	if err := os.WriteFile(udcPath, []byte("\n"), 0644); err != nil {
		t.Logf("force unbind UDC failed: %v", err)
	}
}

// cleanupGadget registers a t.Cleanup that destroys the gadget and, as a
// fallback, force-unbinds the UDC. This prevents a stuck UDC from cascading
// failures across tests that share the same dummy_udc.
func cleanupGadget(t *testing.T, cfs *gadget.ConfigFS) {
	t.Helper()
	t.Cleanup(func() {
		if err := cfs.Destroy(); err != nil {
			t.Logf("cleanup Destroy failed: %v", err)
			forceUnbindUDC(t, cfs.GadgetDir())
		}
	})
}

func TestIntegration_ConfigFS_CreateAndDestroy(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionHID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err, "NewConfigFS should succeed")

	err = cfs.Create(ctx)
	require.NoError(t, err, "Create should succeed")

	cleanupGadget(t, cfs)

	gadgDir := cfs.GadgetDir()

	// Verify gadget directory exists.
	info, err := os.Stat(gadgDir)
	require.NoError(t, err, "gadget directory should exist")
	assert.True(t, info.IsDir(), "gadget path should be a directory")

	// Verify device attribute files exist and have correct values.
	attrChecks := []struct {
		file     string
		expected string
	}{
		{"idVendor", "0xf1d0"},
		{"idProduct", "0x0001"},
		{"bcdDevice", "0x0100"},
		{"bcdUSB", "0x0210"},
	}
	for _, ac := range attrChecks {
		data, readErr := os.ReadFile(filepath.Join(gadgDir, ac.file))
		require.NoError(t, readErr, "should read %s", ac.file)
		assert.Equal(t, ac.expected, strings.TrimSpace(string(data)),
			"attribute %s should match", ac.file)
	}

	// Verify string descriptors directory and values.
	stringsDir := filepath.Join(gadgDir, "strings", "0x0409")
	_, err = os.Stat(stringsDir)
	require.NoError(t, err, "strings directory should exist")

	stringChecks := []struct {
		file     string
		expected string
	}{
		{"serialnumber", "XKEY001"},
		{"manufacturer", "Automate The Things"},
		{"product", "xKey OTP+FIDO+CCID"},
	}
	for _, sc := range stringChecks {
		data, readErr := os.ReadFile(filepath.Join(stringsDir, sc.file))
		require.NoError(t, readErr, "should read string %s", sc.file)
		assert.Equal(t, sc.expected, strings.TrimSpace(string(data)),
			"string descriptor %s should match", sc.file)
	}

	// Verify functions directory exists.
	functionsDir := filepath.Join(gadgDir, "functions")
	_, err = os.Stat(functionsDir)
	require.NoError(t, err, "functions directory should exist")

	// Destroy and verify removal.
	err = cfs.Destroy()
	require.NoError(t, err, "Destroy should succeed")

	_, err = os.Stat(gadgDir)
	assert.True(t, os.IsNotExist(err), "gadget directory should be removed after Destroy")
}

func TestIntegration_ConfigFS_BindUnbind(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)
	udcName := findUDC(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.UDC = udcName
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionHID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err)

	err = cfs.Create(ctx)
	require.NoError(t, err)

	cleanupGadget(t, cfs)

	// Bind to UDC.
	err = cfs.Bind(ctx)
	require.NoError(t, err, "Bind should succeed")
	assert.True(t, cfs.IsBound(), "gadget should be bound after Bind")

	// Read UDC file and verify it contains the UDC name.
	udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
	data, err := os.ReadFile(udcPath)
	require.NoError(t, err, "should read UDC file")
	assert.Equal(t, udcName, strings.TrimSpace(string(data)),
		"UDC file should contain the bound controller name")

	// Unbind.
	err = cfs.Unbind()
	require.NoError(t, err, "Unbind should succeed")
	assert.False(t, cfs.IsBound(), "gadget should not be bound after Unbind")

	// Read UDC file and verify it is empty.
	data, err = os.ReadFile(udcPath)
	require.NoError(t, err, "should read UDC file after unbind")
	assert.Empty(t, strings.TrimSpace(string(data)),
		"UDC file should be empty after Unbind")
}

func TestIntegration_ConfigFS_HIDFunction(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)
	udcName := findUDC(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.UDC = udcName
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionHID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err)

	err = cfs.Create(ctx)
	require.NoError(t, err)

	cleanupGadget(t, cfs)

	gadgDir := cfs.GadgetDir()

	// Verify HID function directory exists.
	hidFuncDir := filepath.Join(gadgDir, "functions", "hid.usb0")
	info, err := os.Stat(hidFuncDir)
	require.NoError(t, err, "HID function directory should exist")
	assert.True(t, info.IsDir(), "HID function path should be a directory")

	// Read and verify HID function attributes.
	hidAttrChecks := []struct {
		file     string
		expected string
	}{
		{"protocol", "0"},
		{"subclass", "0"},
		{"report_length", "64"},
	}
	for _, ac := range hidAttrChecks {
		data, readErr := os.ReadFile(filepath.Join(hidFuncDir, ac.file))
		require.NoError(t, readErr, "should read HID attribute %s", ac.file)
		assert.Equal(t, ac.expected, strings.TrimSpace(string(data)),
			"HID attribute %s should match", ac.file)
	}

	// Verify symlink exists in configuration.
	hidLink := filepath.Join(gadgDir, "configs", "c.1", "hid.usb0")
	linkInfo, err := os.Lstat(hidLink)
	require.NoError(t, err, "HID function symlink should exist in config")
	assert.True(t, linkInfo.Mode()&os.ModeSymlink != 0,
		"hid.usb0 in configs should be a symlink")

	// Bind and check if /dev/hidg0 appears.
	err = cfs.Bind(ctx)
	require.NoError(t, err, "Bind should succeed")

	// /dev/hidg0 may take a moment to appear; poll briefly.
	var hidDevFound bool
	for i := 0; i < 20; i++ {
		if _, statErr := os.Stat("/dev/hidg0"); statErr == nil {
			hidDevFound = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hidDevFound {
		t.Log("/dev/hidg0 device appeared after bind")
	} else {
		t.Log("/dev/hidg0 did not appear (dummy_hcd may not create device nodes)")
	}
}

func TestIntegration_ConfigFS_CCIDFunction(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionCCID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err)

	err = cfs.Create(ctx)
	require.NoError(t, err)

	cleanupGadget(t, cfs)

	gadgDir := cfs.GadgetDir()

	// Verify FunctionFS CCID function directory exists.
	ccidFuncDir := filepath.Join(gadgDir, "functions", "ffs.ccid")
	info, err := os.Stat(ccidFuncDir)
	require.NoError(t, err, "CCID function directory should exist")
	assert.True(t, info.IsDir(), "CCID function path should be a directory")

	// Verify symlink exists in configuration.
	ccidLink := filepath.Join(gadgDir, "configs", "c.1", "ffs.ccid")
	linkInfo, err := os.Lstat(ccidLink)
	require.NoError(t, err, "CCID function symlink should exist in config")
	assert.True(t, linkInfo.Mode()&os.ModeSymlink != 0,
		"ffs.ccid in configs should be a symlink")

	// Note: FunctionFS cannot be fully tested without mounting and writing
	// descriptors to ep0. We verify ConfigFS structure only.
}

func TestIntegration_ConfigFS_CompositeDevice(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)
	udcName := findUDC(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.UDC = udcName
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionCCID},
		{Type: gadget.FunctionHID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err)

	err = cfs.Create(ctx)
	require.NoError(t, err)

	cleanupGadget(t, cfs)

	gadgDir := cfs.GadgetDir()

	// Verify both function directories exist.
	for _, funcName := range []string{"ffs.ccid", "hid.usb0"} {
		funcDir := filepath.Join(gadgDir, "functions", funcName)
		info, statErr := os.Stat(funcDir)
		require.NoError(t, statErr, "function directory %s should exist", funcName)
		assert.True(t, info.IsDir(), "%s should be a directory", funcName)
	}

	// Verify both symlinks exist in configuration.
	for _, funcName := range []string{"ffs.ccid", "hid.usb0"} {
		linkPath := filepath.Join(gadgDir, "configs", "c.1", funcName)
		linkInfo, statErr := os.Lstat(linkPath)
		require.NoError(t, statErr, "symlink %s should exist in config", funcName)
		assert.True(t, linkInfo.Mode()&os.ModeSymlink != 0,
			"%s should be a symlink", funcName)
	}

	// Note: Binding a composite gadget that includes FunctionFS (ffs.ccid)
	// requires mounting FunctionFS and writing descriptors to ep0 before the
	// kernel will accept the bind. Without that, the kernel returns EBUSY.
	// We verify ConfigFS structure only; binding is tested in HIDFunction
	// and UDCAutoDetect tests.
}

func TestIntegration_UDCAutoDetect(t *testing.T) {
	requireConfigFS(t)
	requireDummyHCD(t)

	// Ensure at least one UDC exists before auto-detect test.
	findUDC(t)

	ctx := context.Background()
	logger := testLogger(t)
	name := uniqueGadgetName(t)

	config := gadget.DefaultGadgetConfig()
	config.Name = name
	config.UDC = "" // Force auto-detection.
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionHID},
	}

	fs := &gadget.OSFileSystem{}
	cfs, err := gadget.NewConfigFS(config, fs, logger)
	require.NoError(t, err)

	err = cfs.Create(ctx)
	require.NoError(t, err)

	cleanupGadget(t, cfs)

	// Bind with empty UDC (should auto-detect).
	err = cfs.Bind(ctx)
	require.NoError(t, err, "Bind with auto-detect should succeed")
	assert.True(t, cfs.IsBound(), "gadget should be bound after auto-detect Bind")

	// Verify the UDC file has a non-empty value.
	udcPath := filepath.Join(cfs.GadgetDir(), "UDC")
	data, err := os.ReadFile(udcPath)
	require.NoError(t, err, "should read UDC file")
	assert.NotEmpty(t, strings.TrimSpace(string(data)),
		"UDC file should have a non-empty value after auto-detect bind")
	t.Logf("auto-detected UDC: %s", strings.TrimSpace(string(data)))
}
