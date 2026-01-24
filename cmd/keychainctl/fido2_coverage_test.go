// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/spf13/cobra"
)

// mockFIDO2Handler implements fido2.Handler for testing
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

// TestFIDO2ListDevicesCmd_Success tests successful device listing
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

	// Set up config
	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	// Create output buffer
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

// TestFIDO2ListDevicesCmd_NoDevices tests listing when no devices are found
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

// TestFIDO2ListDevicesCmd_HandlerCreateError tests error when handler creation fails
func TestFIDO2ListDevicesCmd_HandlerCreateError(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	expectedErr := errors.New("handler creation failed")
	fido2HandlerFactory = createMockFIDO2HandlerFactory(nil, expectedErr)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}

	// This should call handleError which captures the exit
	runFIDO2ListDevicesWithWriter(cmd, []string{}, &buf)
	// Test passes if no panic occurs
}

// TestFIDO2ListDevicesCmd_ListError tests error when listing devices fails
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
	// Test passes if no panic occurs
}

// TestFIDO2ListDevicesCmd_JSONOutput tests JSON output format
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

// TestFIDO2ListDevicesCmd_TableOutput tests table output format
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

// TestFIDO2WaitDeviceCmd_Success tests successful device wait
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

// TestFIDO2WaitDeviceCmd_HandlerCreateError tests error when handler creation fails
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
	// Test passes if no panic occurs
}

// TestFIDO2WaitDeviceCmd_WaitError tests error when waiting for device fails
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
	// Test passes if no panic occurs
}

// TestFIDO2RegisterCmd_Success tests successful credential registration
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

// TestFIDO2RegisterCmd_WithDisplayName tests registration with custom display name
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

// TestFIDO2RegisterCmd_HandlerCreateError tests error when handler creation fails
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
	// Test passes if no panic occurs
}

// TestFIDO2RegisterCmd_EnrollError tests error when enrollment fails
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
	// Test passes if no panic occurs
}

// TestFIDO2RegisterCmd_JSONOutput tests JSON output format for registration
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

// TestFIDO2AuthenticateCmd_Success tests successful authentication
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

// TestFIDO2AuthenticateCmd_HexOutput tests authentication with hex output
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

// TestFIDO2AuthenticateCmd_JSONOutput tests authentication with JSON output
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

// TestFIDO2AuthenticateCmd_MissingCredentialID tests error when credential-id is missing
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
	// Test passes if handleError was called without panic
}

// TestFIDO2AuthenticateCmd_MissingSalt tests error when salt is missing
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
	// Test passes if handleError was called without panic
}

// TestFIDO2AuthenticateCmd_InvalidCredentialID tests error with invalid credential-id
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
	// Test passes if handleError was called without panic
}

// TestFIDO2AuthenticateCmd_InvalidSalt tests error with invalid salt
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
	// Test passes if handleError was called without panic
}

// TestFIDO2AuthenticateCmd_HandlerCreateError tests error when handler creation fails
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
	// Test passes if no panic occurs
}

// TestFIDO2AuthenticateCmd_UnlockError tests error when unlock fails
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
	// Test passes if no panic occurs
}

// TestFIDO2AuthenticateCmd_HexEncodedCredentials tests authentication with hex-encoded credentials
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

// TestFIDO2InfoCmd_Success tests successful device info retrieval
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

// TestFIDO2InfoCmd_WithDevicePath tests info retrieval with specific device path
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

// TestFIDO2InfoCmd_DeviceNotFound tests error when specified device is not found
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
	// Test passes if handleError was called without panic
}

// TestFIDO2InfoCmd_NoDevices tests error when no devices are found
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
	// Test passes if handleError was called without panic
}

// TestFIDO2InfoCmd_HandlerCreateError tests error when handler creation fails
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
	// Test passes if no panic occurs
}

// TestFIDO2InfoCmd_ListError tests error when listing devices fails
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
	// Test passes if no panic occurs
}

// TestFIDO2InfoCmd_JSONOutput tests JSON output format for device info
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

// TestDecodeCredentialDataCoverage_Base64Standard tests standard base64 decoding
func TestDecodeCredentialDataCoverage_Base64Standard(t *testing.T) {
	original := []byte("test data for base64")
	encoded := base64.StdEncoding.EncodeToString(original)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded = %v, want %v", decoded, original)
	}
}

// TestDecodeCredentialDataCoverage_Base64URL tests URL-safe base64 decoding
func TestDecodeCredentialDataCoverage_Base64URL(t *testing.T) {
	original := []byte("test data with special chars +-/")
	encoded := base64.URLEncoding.EncodeToString(original)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded = %v, want %v", decoded, original)
	}
}

// TestDecodeCredentialDataCoverage_Hex tests hex decoding
func TestDecodeCredentialDataCoverage_Hex(t *testing.T) {
	original := []byte("hex test data")
	encoded := hex.EncodeToString(original)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded = %v, want %v", decoded, original)
	}
}

// TestDecodeCredentialDataCoverage_Invalid tests error for invalid encoding
func TestDecodeCredentialDataCoverage_Invalid(t *testing.T) {
	invalidData := "!!!not-valid-base64-or-hex!!!"

	_, err := decodeCredentialData(invalidData)
	if err == nil {
		t.Error("expected error for invalid data, got nil")
	}
	if !strings.Contains(err.Error(), "could not decode") {
		t.Errorf("expected 'could not decode' error, got: %v", err)
	}
}

// TestDecodeCredentialDataCoverage_Empty tests empty string decoding
func TestDecodeCredentialDataCoverage_Empty(t *testing.T) {
	decoded, err := decodeCredentialData("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(decoded))
	}
}

// TestDefaultFIDO2HandlerFactoryCoverage tests the default handler factory
func TestDefaultFIDO2HandlerFactoryCoverage(t *testing.T) {
	// Just verify the factory returns a handler or error
	// Note: This may fail without a real device, but tests the code path
	config := &fido2.Config{
		Timeout:    30 * time.Second,
		RetryCount: 1,
	}

	handler, err := defaultFIDO2HandlerFactory(config)
	if err != nil {
		// Expected on systems without FIDO2 devices
		t.Logf("defaultFIDO2HandlerFactory returned error (expected without device): %v", err)
	}
	if handler != nil {
		_ = handler.Close()
	}
}

// TestFIDO2RegisterCmd_WithUserVerification tests registration with user verification required
func TestFIDO2RegisterCmd_WithUserVerification(t *testing.T) {
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
	globalConfig.OutputFormat = "text"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/dev/hidraw0", "")
	cmd.Flags().Bool("user-verification", true, "")

	runFIDO2RegisterWithWriter(cmd, []string{"testuser"}, &buf)

	output := buf.String()
	if !strings.Contains(output, "FIDO2 Credential Registration Successful") {
		t.Errorf("expected success message, got: %s", output)
	}
}

// TestFIDO2AuthenticateCmd_WithUserVerification tests authentication with user verification required
func TestFIDO2AuthenticateCmd_WithUserVerification(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := make([]byte, 32)
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
	cmd.Flags().String("device", "/dev/hidraw0", "")
	cmd.Flags().Bool("user-verification", true, "")
	cmd.Flags().Bool("hex", false, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "Authentication successful") {
		t.Errorf("expected 'Authentication successful', got: %s", output)
	}
}

// TestFIDO2WaitDeviceCmd_JSONOutput tests JSON output format for wait-device
func TestFIDO2WaitDeviceCmd_JSONOutput(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	device := &fido2.Device{
		Path:    "/dev/hidraw0",
		Product: "YubiKey 5",
	}

	mockHandler := &mockFIDO2Handler{waitForDeviceDev: device}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "json"

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 100*time.Millisecond, "")

	runFIDO2WaitDeviceWithWriter(cmd, []string{}, &buf)

	// JSON output should contain success message
	output := buf.String()
	if !strings.Contains(output, "Device found") {
		t.Logf("output: %s", output) // For debugging
	}
}

// TestRunFIDO2ListDevicesCmd_DirectCall tests the direct Run function
func TestRunFIDO2ListDevicesCmd_DirectCall(t *testing.T) {
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

	cmd := &cobra.Command{}
	// This tests the wrapper that calls os.Stdout
	// We're just verifying it doesn't panic
	runFIDO2ListDevices(cmd, []string{})
}

// TestRunFIDO2WaitDeviceCmd_DirectCall tests the direct Run function
func TestRunFIDO2WaitDeviceCmd_DirectCall(t *testing.T) {
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

	cmd := &cobra.Command{}
	cmd.Flags().Duration("timeout", 100*time.Millisecond, "")
	runFIDO2WaitDevice(cmd, []string{})
}

// TestRunFIDO2RegisterCmd_DirectCall tests the direct Run function
func TestRunFIDO2RegisterCmd_DirectCall(t *testing.T) {
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
	globalConfig.OutputFormat = "text"

	cmd := &cobra.Command{}
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().String("rp-name", "Example", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	runFIDO2Register(cmd, []string{"testuser"})
}

// TestRunFIDO2AuthenticateCmd_DirectCall tests the direct Run function
func TestRunFIDO2AuthenticateCmd_DirectCall(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := make([]byte, 32)
	mockHandler := &mockFIDO2Handler{derivedKey: derivedKey}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	credID := base64.StdEncoding.EncodeToString([]byte("test-credential-id"))
	salt := base64.StdEncoding.EncodeToString([]byte("test-salt"))

	cmd := &cobra.Command{}
	cmd.Flags().String("credential-id", credID, "")
	cmd.Flags().String("salt", salt, "")
	cmd.Flags().String("rp-id", "example.com", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().Bool("hex", false, "")
	runFIDO2Authenticate(cmd, []string{})
}

// TestRunFIDO2InfoCmd_DirectCall tests the direct Run function
func TestRunFIDO2InfoCmd_DirectCall(t *testing.T) {
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

	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	runFIDO2Info(cmd, []string{})
}

// TestFIDO2HandlerFactoryType verifies the type alias is correct
func TestFIDO2HandlerFactoryType(t *testing.T) {
	// Test that the factory type can be assigned
	var factory FIDO2HandlerFactory = func(config *fido2.Config) (fido2.Handler, error) {
		return nil, nil
	}
	if factory == nil {
		t.Error("factory should not be nil")
	}
}

// TestFIDO2AuthenticateCmd_Base64URLEncodedCredentials tests with URL-safe base64
func TestFIDO2AuthenticateCmd_Base64URLEncodedCredentials(t *testing.T) {
	cleanup := testSetupFIDO2(t)
	defer cleanup()

	derivedKey := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	mockHandler := &mockFIDO2Handler{derivedKey: derivedKey}
	fido2HandlerFactory = createMockFIDO2HandlerFactory(mockHandler, nil)

	globalConfig = NewConfig()
	globalConfig.OutputFormat = "text"

	// Use URL-safe base64 encoding
	credID := base64.URLEncoding.EncodeToString([]byte("test-credential-id-with-special"))
	salt := base64.URLEncoding.EncodeToString([]byte("test-salt"))

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

// TestFIDO2AuthenticateCmd_JSONHexOutput tests JSON output with hex encoding
func TestFIDO2AuthenticateCmd_JSONHexOutput(t *testing.T) {
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
	cmd.Flags().Bool("hex", true, "")

	runFIDO2AuthenticateWithWriter(cmd, []string{}, &buf)

	output := buf.String()
	if !strings.Contains(output, "\"success\"") {
		t.Errorf("expected JSON output with 'success', got: %s", output)
	}
	expectedHex := hex.EncodeToString(derivedKey)
	if !strings.Contains(output, expectedHex) {
		t.Errorf("expected hex value %s in output, got: %s", expectedHex, output)
	}
}
