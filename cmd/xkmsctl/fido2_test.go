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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/spf13/cobra"
)

// =============================================================================
// Command Structure Tests
// =============================================================================

// =============================================================================
// decodeCredentialData Tests
// =============================================================================

// =============================================================================
// Flag and Argument Tests
// =============================================================================

func TestFIDO2RegisterCmd_FlagDefaults(t *testing.T) {
	flags := fido2RegisterCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-xkms" {
		t.Errorf("rp-id default = %v, want go-xkms", rpIDFlag.DefValue)
	}

	rpNameFlag := flags.Lookup("rp-name")
	if rpNameFlag.DefValue != "Go xKMS" {
		t.Errorf("rp-name default = %v, want 'Go xKMS'", rpNameFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

func TestFIDO2AuthenticateCmd_FlagDefaults(t *testing.T) {
	flags := fido2AuthenticateCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-xkms" {
		t.Errorf("rp-id default = %v, want go-xkms", rpIDFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

func TestFIDO2WaitDeviceCmd_TimeoutDefault(t *testing.T) {
	flags := fido2WaitDeviceCmd.Flags()

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "1m0s" {
		t.Errorf("timeout default = %v, want 1m0s", timeoutFlag.DefValue)
	}
}

// =============================================================================
// Type Construction Tests
// =============================================================================

// =============================================================================
// defaultFIDO2HandlerFactory Tests
// =============================================================================

func TestDefaultFIDO2HandlerFactory_DefaultEnumerator(t *testing.T) {
	config := &fido2.Config{}

	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

// TestDefaultFIDO2HandlerFactory_IgnoresVirtualSwitch is a regression test for
// go-xkms#807: the release factory must never build a software authenticator,
// no matter what the process environment says. FIDO2_VIRTUAL_STATE_DIR is set
// to a path that cannot be created; if defaultFIDO2HandlerFactory still
// consulted the virtual-device switch, it would try to initialize file-backed
// credential storage there and fail with ErrVirtualStorageInit (see the
// //go:build integration && fido2 tests for that failure mode). It must
// instead ignore both variables entirely and enumerate hardware.
func TestDefaultFIDO2HandlerFactory_IgnoresVirtualSwitch(t *testing.T) {
	t.Setenv("FIDO2_USE_VIRTUAL", "true")
	t.Setenv("FIDO2_VIRTUAL_STATE_DIR", "/dev/null/impossible/path")

	config := &fido2.Config{}

	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory must ignore FIDO2_USE_VIRTUAL and FIDO2_VIRTUAL_STATE_DIR, got error: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

// TestFIDO2HandlerFactory_DefaultsToHardwareFactory asserts that the
// package-level factory variable used by every fido2 command is, in the
// release build (no "integration fido2" tags), the hardware-only
// defaultFIDO2HandlerFactory and nothing else can have swapped it out at
// init time.
func TestFIDO2HandlerFactory_DefaultsToHardwareFactory(t *testing.T) {
	got := reflect.ValueOf(fido2HandlerFactory).Pointer()
	want := reflect.ValueOf(FIDO2HandlerFactory(defaultFIDO2HandlerFactory)).Pointer()
	if got != want {
		t.Fatal("fido2HandlerFactory must be defaultFIDO2HandlerFactory in the release build; found it overridden")
	}
}

func TestDefaultFIDO2HandlerFactory_NilConfig(t *testing.T) {
	handler, err := defaultFIDO2HandlerFactory(nil)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory with nil config failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

// =============================================================================
// Mock Handler and Test Helpers
// =============================================================================

// mockFIDO2Handler implements fido2.Handler for testing command execution
type mockFIDO2Handler struct {
	devices          []fido2.Device
	enrollResult     *fido2.EnrollmentResult
	derivedKey       []byte
	listDevicesErr   error
	waitForDeviceErr error
	enrollKeyErr     error
	unlockWithKeyErr error
	waitForDeviceDev *fido2.Device

	// lastAuthConfig records the configuration UnlockWithKey was called
	// with, so a test can assert which derivation the CLI selected.
	lastAuthConfig *fido2.AuthenticationConfig
}

func (m *mockFIDO2Handler) ListDevices() ([]fido2.Device, error) {
	if m.listDevicesErr != nil {
		return nil, m.listDevicesErr
	}
	return m.devices, nil
}

func (m *mockFIDO2Handler) WaitForDevice(ctx context.Context) (*fido2.Device, error) {
	if m.waitForDeviceErr != nil {
		return nil, m.waitForDeviceErr
	}
	if m.waitForDeviceDev != nil {
		return m.waitForDeviceDev, nil
	}
	if len(m.devices) > 0 {
		return &m.devices[0], nil
	}
	return nil, fido2.ErrNoDeviceFound
}

func (m *mockFIDO2Handler) EnrollKey(config *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	if m.enrollKeyErr != nil {
		return nil, m.enrollKeyErr
	}
	return m.enrollResult, nil
}

func (m *mockFIDO2Handler) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	m.lastAuthConfig = config
	if m.unlockWithKeyErr != nil {
		return nil, m.unlockWithKeyErr
	}
	return m.derivedKey, nil
}

func (m *mockFIDO2Handler) DeriveHMACSecret(config *fido2.AuthenticationConfig) (*fido2.AuthenticationResult, error) {
	m.lastAuthConfig = config
	if m.unlockWithKeyErr != nil {
		return nil, m.unlockWithKeyErr
	}
	return &fido2.AuthenticationResult{HMACSecret: m.derivedKey}, nil
}

func (m *mockFIDO2Handler) Close() error {
	return nil
}

// Ensure mockFIDO2Handler implements fido2.Handler
var _ fido2.Handler = (*mockFIDO2Handler)(nil)

// testSetupFIDO2 saves the original factory and restores it after the test
func testSetupFIDO2(t *testing.T) func() {
	originalFactory := fido2HandlerFactory
	originalExitFunc := exitFunc

	// Capture exit calls instead of actually exiting
	exitFunc = func(code int) {
		// Do nothing - just capture the exit
	}

	return func() {
		fido2HandlerFactory = originalFactory
		exitFunc = originalExitFunc
	}
}

// createMockFIDO2HandlerFactory creates a factory that returns the mock handler
func createMockFIDO2HandlerFactory(handler *mockFIDO2Handler, err error) FIDO2HandlerFactory {
	return func(config *fido2.Config) (fido2.Handler, error) {
		if err != nil {
			return nil, err
		}
		return handler, nil
	}
}

// =============================================================================
// List Devices Command Execution Tests
// =============================================================================

func TestFIDO2ListDevicesCmd_Success(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			SerialNumber: "12345",
			Transport:    "usb",
		},
		{
			Path:         "/dev/hidraw1",
			VendorID:     0x1050,
			ProductID:    0x0408,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5C",
			SerialNumber: "67890",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "FIDO2 Devices:") {
		t.Errorf("expected output to contain 'FIDO2 Devices:', got: %s", output)
	}
	if !strings.Contains(output, "/dev/hidraw0") {
		t.Errorf("expected output to contain '/dev/hidraw0', got: %s", output)
	}
	if !strings.Contains(output, "YubiKey 5") {
		t.Errorf("expected output to contain 'YubiKey 5', got: %s", output)
	}
}

func TestFIDO2ListDevicesCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2ListDevicesCmd_ListError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		listDevicesErr: errors.New("enumeration failed"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2ListDevicesCmd_JSONOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "json"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "\"devices\"") {
		t.Errorf("expected JSON output with 'devices' key, got: %s", output)
	}
	if !strings.Contains(output, "/dev/hidraw0") {
		t.Errorf("expected output to contain device path, got: %s", output)
	}
}

func TestFIDO2ListDevicesCmd_TableOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "table"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "PATH") {
		t.Errorf("expected table output with 'PATH' header, got: %s", output)
	}
}

// =============================================================================
// Wait Device Command Execution Tests
// =============================================================================

func TestFIDO2WaitDeviceCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 100*time.Millisecond, "")

	runFIDO2WaitDeviceWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2WaitDeviceCmd_WaitError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		waitForDeviceErr: errors.New("timeout waiting for device"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 100*time.Millisecond, "")

	runFIDO2WaitDeviceWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

// =============================================================================
// Register Command Execution Tests
// =============================================================================

func TestFIDO2RegisterCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")

	runFIDO2RegisterWithWriter(cmd, []string{"testuser"}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2RegisterCmd_EnrollError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		enrollKeyErr: errors.New("enrollment failed"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")

	runFIDO2RegisterWithWriter(cmd, []string{"testuser"}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2RegisterCmd_JSONOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	enrollResult := &fido2.EnrollmentResult{
		CredentialID: []byte("test-credential-id"),
		PublicKey:    []byte("test-public-key"),
		AAGUID:       []byte("test-aaguid"),
		Salt:         []byte("test-salt"),
		User: fido2.User{
			ID:          []byte("user-id"),
			Name:        "testuser",
			DisplayName: "Test User",
		},
		RelyingParty: fido2.RelyingParty{
			ID:   "example.com",
			Name: "Example",
		},
		Created: time.Now(),
	}

	mockHandler := &mockFIDO2Handler{enrollResult: enrollResult}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "json"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")

	runFIDO2RegisterWithWriter(cmd, []string{"testuser"}, &buf)

	output := buf.String()
	if !strings.Contains(output, "credential_id") {
		t.Errorf("expected JSON output with 'credential_id', got: %s", output)
	}
}

// =============================================================================
// Authenticate Command Execution Tests
// =============================================================================

func TestFIDO2AuthenticateCmd_HexOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	mockHandler := &mockFIDO2Handler{derivedKey: derivedKey}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", true, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	expectedHex := hex.EncodeToString(derivedKey)
	if !strings.Contains(output, expectedHex) {
		t.Errorf("expected hex output '%s' in output, got: %s", expectedHex, output)
	}
}

func TestFIDO2AuthenticateCmd_JSONOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	mockHandler := &mockFIDO2Handler{derivedKey: derivedKey}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "json"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "\"success\"") {
		t.Errorf("expected JSON output with 'success' key, got: %s", output)
	}
	if !strings.Contains(output, "\"derived_key\"") {
		t.Errorf("expected JSON output with 'derived_key' key, got: %s", output)
	}
}

func TestFIDO2AuthenticateCmd_MissingCredentialID(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", "", "")
	cmd.Flags().String("salt", "test-salt", "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2AuthenticateCmd_MissingSalt(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", "", "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2AuthenticateCmd_InvalidCredentialID(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", "not-valid-base64-or-hex!!!", "")
	cmd.Flags().String("salt", base64.StdEncoding.EncodeToString([]byte("test-salt")), "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2AuthenticateCmd_InvalidSalt(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", "not-valid-base64-or-hex!!!", "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2AuthenticateCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if no panic occurs
}

func TestFIDO2AuthenticateCmd_UnlockError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		unlockWithKeyErr: errors.New("unlock failed"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)
	// Passes if no panic occurs
}

func TestFIDO2AuthenticateCmd_HexEncodedCredentials(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	mockHandler := &mockFIDO2Handler{derivedKey: derivedKey}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	// Use hex encoding instead of base64
	credID := hex.EncodeToString([]byte("test-credential-id"))
	salt := hex.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "Authentication successful") {
		t.Errorf("expected 'Authentication successful', got: %s", output)
	}
}

// =============================================================================
// Info Command Execution Tests
// =============================================================================

func TestFIDO2InfoCmd_Success(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			SerialNumber: "12345",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "FIDO2 Device Information") {
		t.Errorf("expected 'FIDO2 Device Information', got: %s", output)
	}
	if !strings.Contains(output, "YubiKey 5") {
		t.Errorf("expected 'YubiKey 5' in output, got: %s", output)
	}
}

func TestFIDO2InfoCmd_WithDevicePath(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			Transport:    "usb",
		},
		{
			Path:         "/dev/hidraw1",
			VendorID:     0x1050,
			ProductID:    0x0408,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5C",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "/dev/hidraw1", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "YubiKey 5C") {
		t.Errorf("expected 'YubiKey 5C' for specified device, got: %s", output)
	}
}

func TestFIDO2InfoCmd_DeviceNotFound(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:    "/dev/hidraw0",
			Product: "YubiKey 5",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "/dev/hidraw99", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2InfoCmd_NoDevices(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{devices: []fido2.Device{}}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)
	// Passes if handleError was called without panic
}

func TestFIDO2InfoCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)
	// Passes if no panic occurs
}

func TestFIDO2InfoCmd_ListError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{
		listDevicesErr: errors.New("enumeration failed"),
	}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)
	// Passes if no panic occurs
}

func TestFIDO2InfoCmd_JSONOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	devices := []fido2.Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey 5",
			SerialNumber: "12345",
			Transport:    "usb",
		},
	}

	mockHandler := &mockFIDO2Handler{devices: devices}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "json"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")

	runFIDO2InfoWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "\"path\"") {
		t.Errorf("expected JSON output with 'path' key, got: %s", output)
	}
	if !strings.Contains(output, "\"vendor_id\"") {
		t.Errorf("expected JSON output with 'vendor_id' key, got: %s", output)
	}
}

// =============================================================================
// hmac-secret derivation
// =============================================================================

// newAuthenticateFlagSet builds the flag set the authenticate command reads.
func newAuthenticateFlagSet(credID, salt string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")
	return cmd
}

// TestFIDO2AuthenticateCmd_UsesCTAP2Derivation checks that the CLI always
// selects the CTAP2 derivation and never warns: the deprecated
// --legacy-hmac-derivation opt-in was removed outright (owner rule
// 2026-09-22, PR 2).
func TestFIDO2AuthenticateCmd_UsesCTAP2Derivation(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{derivedKey: make([]byte, 64)}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	defer func(previous *Config) { globalConfig = previous }(globalConfig)
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	var buf bytes.Buffer
	runFIDO2AuthenticateWithWriter(newAuthenticateFlagSet(credID, salt), []string{}, &buf)

	if mockHandler.lastAuthConfig == nil {
		t.Fatal("expected UnlockWithKey to be called")
	}
	if mockHandler.lastAuthConfig.DerivationMode != fido2.DerivationModeCTAP2 {
		t.Errorf("expected the CTAP2 derivation, got %v", mockHandler.lastAuthConfig.DerivationMode)
	}
	if strings.Contains(buf.String(), "WARNING") {
		t.Errorf("authentication must not warn, got: %s", buf.String())
	}
}

// TestPrinterPrintWarning checks the warning surface used by the legacy
// opt-in.
func TestPrinterPrintWarning(t *testing.T) {
	var buf bytes.Buffer

	printer := NewPrinter("text", &buf)
	if err := printer.PrintWarning("do not do this"); err != nil {
		t.Fatalf("PrintWarning returned an error: %v", err)
	}
	if !strings.Contains(buf.String(), "WARNING: do not do this") {
		t.Errorf("expected the warning in the output, got: %s", buf.String())
	}

	// JSON output must stay a clean document, so the warning is diverted.
	buf.Reset()
	jsonPrinter := NewPrinter("json", &buf)
	if err := jsonPrinter.PrintWarning("do not do this"); err != nil {
		t.Fatalf("PrintWarning returned an error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected JSON output to stay clean, got: %s", buf.String())
	}
}

// TestPrinterPrintWarning_UnknownFormat checks the error path.
func TestPrinterPrintWarning_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer

	printer := NewPrinter("yaml-ish", &buf)
	if err := printer.PrintWarning("message"); err == nil {
		t.Error("expected an error for an unknown output format")
	}
}
