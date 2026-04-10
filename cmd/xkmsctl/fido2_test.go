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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/spf13/cobra"
)

// =============================================================================
// Command Structure Tests
// =============================================================================

func TestFIDO2Cmd_Exists(t *testing.T) {
	if fido2Cmd == nil {
		t.Fatal("fido2Cmd should not be nil")
	}
}

func TestFIDO2Cmd_Properties(t *testing.T) {
	if fido2Cmd.Use != "fido2" {
		t.Errorf("fido2Cmd.Use = %v, want fido2", fido2Cmd.Use)
	}

	if fido2Cmd.Short == "" {
		t.Error("fido2Cmd.Short should not be empty")
	}
}

func TestFIDO2Cmd_HasSubcommands(t *testing.T) {
	subcommands := fido2Cmd.Commands()

	expectedCmds := []string{
		"list-devices",
		"wait-device",
		"register",
		"authenticate",
		"info",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestFIDO2ListDevicesCmd_Exists(t *testing.T) {
	if fido2ListDevicesCmd == nil {
		t.Fatal("fido2ListDevicesCmd should not be nil")
	}
}

func TestFIDO2ListDevicesCmd_Properties(t *testing.T) {
	if fido2ListDevicesCmd.Use != "list-devices" {
		t.Errorf("fido2ListDevicesCmd.Use = %v, want list-devices", fido2ListDevicesCmd.Use)
	}
}

func TestFIDO2WaitDeviceCmd_Exists(t *testing.T) {
	if fido2WaitDeviceCmd == nil {
		t.Fatal("fido2WaitDeviceCmd should not be nil")
	}
}

func TestFIDO2WaitDeviceCmd_HasFlags(t *testing.T) {
	flags := fido2WaitDeviceCmd.Flags()

	if flags.Lookup("timeout") == nil {
		t.Error("expected flag 'timeout' not found on fido2WaitDeviceCmd")
	}
}

func TestFIDO2RegisterCmd_Exists(t *testing.T) {
	if fido2RegisterCmd == nil {
		t.Fatal("fido2RegisterCmd should not be nil")
	}
}

func TestFIDO2RegisterCmd_Properties(t *testing.T) {
	if fido2RegisterCmd.Use != "register <username>" {
		t.Errorf("fido2RegisterCmd.Use = %v, want 'register <username>'", fido2RegisterCmd.Use)
	}
}

func TestFIDO2RegisterCmd_HasFlags(t *testing.T) {
	flags := fido2RegisterCmd.Flags()

	expectedFlags := []string{
		"rp-id",
		"rp-name",
		"display-name",
		"timeout",
		"device",
		"user-verification",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on fido2RegisterCmd", flag)
		}
	}
}

func TestFIDO2AuthenticateCmd_Exists(t *testing.T) {
	if fido2AuthenticateCmd == nil {
		t.Fatal("fido2AuthenticateCmd should not be nil")
	}
}

func TestFIDO2AuthenticateCmd_Properties(t *testing.T) {
	if fido2AuthenticateCmd.Use != "authenticate" {
		t.Errorf("fido2AuthenticateCmd.Use = %v, want authenticate", fido2AuthenticateCmd.Use)
	}
}

func TestFIDO2AuthenticateCmd_HasFlags(t *testing.T) {
	flags := fido2AuthenticateCmd.Flags()

	expectedFlags := []string{
		"credential-id",
		"salt",
		"rp-id",
		"timeout",
		"device",
		"user-verification",
		"hex",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on fido2AuthenticateCmd", flag)
		}
	}
}

func TestFIDO2InfoCmd_Exists(t *testing.T) {
	if fido2InfoCmd == nil {
		t.Fatal("fido2InfoCmd should not be nil")
	}
}

func TestFIDO2InfoCmd_HasFlags(t *testing.T) {
	flags := fido2InfoCmd.Flags()

	if flags.Lookup("device") == nil {
		t.Error("expected flag 'device' not found on fido2InfoCmd")
	}
}

// =============================================================================
// decodeCredentialData Tests
// =============================================================================

func TestDecodeCredentialData_Base64(t *testing.T) {
	originalData := []byte("test credential data")
	encoded := base64.StdEncoding.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Base64URL(t *testing.T) {
	originalData := []byte("test credential data with special chars")
	encoded := base64.URLEncoding.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Hex(t *testing.T) {
	originalData := []byte("test hex data")
	encoded := hex.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Invalid(t *testing.T) {
	// Invalid data that's not valid base64 or hex
	invalidData := "not-valid-base64-or-hex!!!"

	_, err := decodeCredentialData(invalidData)
	if err == nil {
		t.Error("decodeCredentialData should return error for invalid data")
	}
}

func TestDecodeCredentialData_Empty(t *testing.T) {
	decoded, err := decodeCredentialData("")
	if err != nil {
		t.Fatalf("decodeCredentialData failed for empty string: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("decoded length = %d, want 0", len(decoded))
	}
}

// =============================================================================
// Flag and Argument Tests
// =============================================================================

func TestFIDO2RegisterCmd_Arguments(t *testing.T) {
	// Verify command expects exactly one argument (username)
	if fido2RegisterCmd.Args == nil {
		t.Error("fido2RegisterCmd.Args should be set")
	}
}

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

func TestFIDO2Device_Type(t *testing.T) {
	device := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey",
		SerialNumber: "12345",
		Transport:    "usb",
	}

	if device.Path != "/dev/hidraw0" {
		t.Error("device.Path not set correctly")
	}
	if device.VendorID != 0x1050 {
		t.Error("device.VendorID not set correctly")
	}
}

func TestFIDO2User_Type(t *testing.T) {
	user := fido2User{
		ID:          []byte("user-id"),
		Name:        "test@example.com",
		DisplayName: "Test User",
		Icon:        "",
	}

	if user.Name != "test@example.com" {
		t.Error("user.Name not set correctly")
	}
	if user.DisplayName != "Test User" {
		t.Error("user.DisplayName not set correctly")
	}
}

func TestFIDO2RelyingParty_Type(t *testing.T) {
	rp := fido2RelyingParty{
		ID:   "example.com",
		Name: "Example",
		Icon: "",
	}

	if rp.ID != "example.com" {
		t.Error("rp.ID not set correctly")
	}
	if rp.Name != "Example" {
		t.Error("rp.Name not set correctly")
	}
}

func TestFIDO2EnrollmentResult_Type(t *testing.T) {
	result := &fido2EnrollmentResult{
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pub-key"),
		AAGUID:       []byte("aaguid"),
		SignCount:    0,
		Salt:         []byte("salt"),
		User: fido2User{
			ID:   []byte("user-id"),
			Name: "test@example.com",
		},
		RelyingParty: fido2RelyingParty{
			ID:   "example.com",
			Name: "Example",
		},
	}

	if len(result.CredentialID) == 0 {
		t.Error("result.CredentialID should not be empty")
	}
	if len(result.PublicKey) == 0 {
		t.Error("result.PublicKey should not be empty")
	}
}

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

func TestDefaultFIDO2HandlerFactory_VirtualEnumerator(t *testing.T) {
	originalValue := os.Getenv("FIDO2_USE_VIRTUAL")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "true"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	defer func() {
		if originalValue == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalValue)
		}
	}()

	config := &fido2.Config{}

	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory with virtual failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory with virtual returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

func TestDefaultFIDO2HandlerFactory_VirtualEnumeratorFalse(t *testing.T) {
	originalValue := os.Getenv("FIDO2_USE_VIRTUAL")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "false"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	defer func() {
		if originalValue == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalValue)
		}
	}()

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

func TestDefaultFIDO2HandlerFactory_VirtualEnumeratorOtherValue(t *testing.T) {
	originalValue := os.Getenv("FIDO2_USE_VIRTUAL")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "yes"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	defer func() {
		if originalValue == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalValue)
		}
	}()

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
	if m.unlockWithKeyErr != nil {
		return nil, m.unlockWithKeyErr
	}
	return m.derivedKey, nil
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

func TestFIDO2ListDevicesCmd_NoDevices(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	mockHandler := &mockFIDO2Handler{devices: []fido2.Device{}}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "No FIDO2 devices found") {
		t.Errorf("expected 'No FIDO2 devices found', got: %s", output)
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

func TestFIDO2WaitDeviceCmd_Success(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	device := &fido2.Device{
		Path:    "/dev/hidraw0",
		Product: "YubiKey 5",
	}

	mockHandler := &mockFIDO2Handler{waitForDeviceDev: device}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 100*time.Millisecond, "")

	runFIDO2WaitDeviceWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "Device found") {
		t.Errorf("expected 'Device found' in output, got: %s", output)
	}
}

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

func TestFIDO2RegisterCmd_Success(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	enrollResult := &fido2.EnrollmentResult{
		CredentialID: []byte("test-credential-id"),
		PublicKey:    []byte("test-public-key"),
		AAGUID:       []byte("test-aaguid"),
		SignCount:    0,
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

	output := buf.String()
	if !strings.Contains(output, "FIDO2 Credential Registration Successful") {
		t.Errorf("expected 'FIDO2 Credential Registration Successful', got: %s", output)
	}
}

func TestFIDO2RegisterCmd_WithDisplayName(t *testing.T) {
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
			DisplayName: "Custom Display Name",
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
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "Custom Display Name", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")

	runFIDO2RegisterWithWriter(cmd, []string{"testuser"}, &buf)

	output := buf.String()
	if !strings.Contains(output, "FIDO2 Credential Registration Successful") {
		t.Errorf("expected success message, got: %s", output)
	}
}

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

func TestFIDO2AuthenticateCmd_Success(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := make([]byte, 32)
	for i := range derivedKey {
		derivedKey[i] = byte(i)
	}

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
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "Authentication successful") {
		t.Errorf("expected 'Authentication successful', got: %s", output)
	}
	if !strings.Contains(output, "Derived Key") {
		t.Errorf("expected 'Derived Key' in output, got: %s", output)
	}
}

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
// File-Based Credential Storage Tests
// =============================================================================

func TestNewFileCredentialStorage_ValidDirectory(t *testing.T) {
	stateDir := t.TempDir()

	storage, err := newFileCredentialStorage(stateDir)
	if err != nil {
		t.Fatalf("newFileCredentialStorage failed with valid directory: %v", err)
	}
	if storage == nil {
		t.Fatal("newFileCredentialStorage returned nil storage")
	}
	defer func() { _ = storage.Close() }()
}

func TestNewFileCredentialStorage_InvalidDirectory(t *testing.T) {
	// Use a path that cannot be created (nested under a file that does not exist
	// as a directory). On Linux /dev/null is a file, so /dev/null/subdir fails.
	invalidDir := "/dev/null/impossible/path"

	storage, err := newFileCredentialStorage(invalidDir)
	if err == nil {
		_ = storage.Close()
		t.Fatal("newFileCredentialStorage should fail with invalid directory")
	}
	if !errors.Is(err, ErrVirtualStorageInit) {
		t.Errorf("expected error wrapping ErrVirtualStorageInit, got: %v", err)
	}
}

func TestDefaultFIDO2HandlerFactory_VirtualWithStateDir(t *testing.T) {
	originalVirtual := os.Getenv("FIDO2_USE_VIRTUAL")
	originalStateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR")

	stateDir := t.TempDir()

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "true"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	if err := os.Setenv("FIDO2_VIRTUAL_STATE_DIR", stateDir); err != nil {
		t.Fatalf("Failed to set FIDO2_VIRTUAL_STATE_DIR: %v", err)
	}
	defer func() {
		if originalVirtual == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalVirtual)
		}
		if originalStateDir == "" {
			_ = os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
		} else {
			_ = os.Setenv("FIDO2_VIRTUAL_STATE_DIR", originalStateDir)
		}
	}()

	config := &fido2.Config{}
	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory with state dir failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory with state dir returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

func TestDefaultFIDO2HandlerFactory_VirtualWithInvalidStateDir(t *testing.T) {
	originalVirtual := os.Getenv("FIDO2_USE_VIRTUAL")
	originalStateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "true"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	if err := os.Setenv("FIDO2_VIRTUAL_STATE_DIR", "/dev/null/impossible/path"); err != nil {
		t.Fatalf("Failed to set FIDO2_VIRTUAL_STATE_DIR: %v", err)
	}
	defer func() {
		if originalVirtual == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalVirtual)
		}
		if originalStateDir == "" {
			_ = os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
		} else {
			_ = os.Setenv("FIDO2_VIRTUAL_STATE_DIR", originalStateDir)
		}
	}()

	config := &fido2.Config{}
	handler, err := defaultFIDO2HandlerFactory(config)
	if err == nil {
		_ = handler.Close()
		t.Fatal("defaultFIDO2HandlerFactory should fail with invalid state dir")
	}
	if !errors.Is(err, ErrVirtualStorageInit) {
		t.Errorf("expected error wrapping ErrVirtualStorageInit, got: %v", err)
	}
}

func TestDefaultFIDO2HandlerFactory_VirtualWithEmptyStateDir(t *testing.T) {
	// When FIDO2_VIRTUAL_STATE_DIR is empty string, the factory should
	// fall back to in-memory storage (no file storage created).
	originalVirtual := os.Getenv("FIDO2_USE_VIRTUAL")
	originalStateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "true"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	if err := os.Setenv("FIDO2_VIRTUAL_STATE_DIR", ""); err != nil {
		t.Fatalf("Failed to set FIDO2_VIRTUAL_STATE_DIR: %v", err)
	}
	defer func() {
		if originalVirtual == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalVirtual)
		}
		if originalStateDir == "" {
			_ = os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
		} else {
			_ = os.Setenv("FIDO2_VIRTUAL_STATE_DIR", originalStateDir)
		}
	}()

	config := &fido2.Config{}
	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory with empty state dir failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory with empty state dir returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}

func TestDefaultFIDO2HandlerFactory_VirtualWithoutStateDir(t *testing.T) {
	// When FIDO2_VIRTUAL_STATE_DIR is not set at all, the factory should
	// use in-memory storage (same as before the change).
	originalVirtual := os.Getenv("FIDO2_USE_VIRTUAL")
	originalStateDir := os.Getenv("FIDO2_VIRTUAL_STATE_DIR")

	if err := os.Setenv("FIDO2_USE_VIRTUAL", "true"); err != nil {
		t.Fatalf("Failed to set FIDO2_USE_VIRTUAL: %v", err)
	}
	_ = os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
	defer func() {
		if originalVirtual == "" {
			_ = os.Unsetenv("FIDO2_USE_VIRTUAL")
		} else {
			_ = os.Setenv("FIDO2_USE_VIRTUAL", originalVirtual)
		}
		if originalStateDir == "" {
			_ = os.Unsetenv("FIDO2_VIRTUAL_STATE_DIR")
		} else {
			_ = os.Setenv("FIDO2_VIRTUAL_STATE_DIR", originalStateDir)
		}
	}()

	config := &fido2.Config{}
	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		t.Fatalf("defaultFIDO2HandlerFactory without state dir failed: %v", err)
	}
	if handler == nil {
		t.Fatal("defaultFIDO2HandlerFactory without state dir returned nil handler")
	}
	defer func() { _ = handler.Close() }()
}
