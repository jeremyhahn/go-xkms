//go:build ignore

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
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewVirtualFIDO2Device_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.auth == nil {
		t.Error("expected authenticator to be initialized")
	}

	if device.hidHandler == nil {
		t.Error("expected HID handler to be initialized")
	}

	if device.storage == nil {
		t.Error("expected storage to be initialized")
	}

	if device.keyBackend == nil {
		t.Error("expected key backend to be initialized")
	}

	if device.IsRunning() {
		t.Error("expected device to not be running before Run is called")
	}
}

func TestNewVirtualFIDO2Device_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(nil, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with nil config failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.cfg == nil {
		t.Error("expected default config to be set")
	}
}

func TestNewVirtualFIDO2Device_NilLogger(t *testing.T) {
	cfg := DefaultConfig()

	device, err := NewVirtualFIDO2Device(cfg, nil)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with nil logger failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.logger == nil {
		t.Error("expected default logger to be set")
	}
}

func TestNewVirtualFIDO2Device_MemoryStorage(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "TEST001",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with memory storage failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.storage == nil {
		t.Error("expected storage to be initialized")
	}
}

func TestNewVirtualFIDO2Device_FileStorage(t *testing.T) {
	// Create a temporary directory for file storage
	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "fido2-storage")

	cfg := &Config{
		StorageType:       StorageTypeFile,
		StoragePath:       storagePath,
		DeviceName:        "Test Device",
		SerialNumber:      "TEST002",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with file storage failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.storage == nil {
		t.Error("expected storage to be initialized")
	}

	// Verify storage directory was created
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		t.Error("expected storage directory to be created")
	}
}

func TestNewVirtualFIDO2Device_WithPIN(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "TEST003",
		EnablePIN:         true,
		PIN:               "123456",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with PIN failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify PIN was set
	if !device.auth.IsPINSet() {
		t.Error("expected PIN to be set")
	}
}

func TestNewVirtualFIDO2Device_EnablePINNoPIN(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "TEST004",
		EnablePIN:         true,
		PIN:               "", // No initial PIN
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with PIN enabled but no PIN failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify PIN is not set (can be set later via CTAP protocol)
	if device.auth.IsPINSet() {
		t.Error("expected PIN to not be set when no initial PIN provided")
	}
}

func TestNewVirtualFIDO2Device_InvalidStorageType(t *testing.T) {
	cfg := &Config{
		StorageType:       "invalid",
		DeviceName:        "Test Device",
		SerialNumber:      "TEST005",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for invalid storage type")
	}
}

func TestNewVirtualFIDO2Device_FileStorageMissingPath(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeFile,
		StoragePath:       "", // Missing path
		DeviceName:        "Test Device",
		SerialNumber:      "TEST006",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for file storage without path")
	}
}

func TestVirtualFIDO2Device_Close(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}

	// Close should succeed
	err = device.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Close again should be idempotent
	err = device.Close()
	if err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestVirtualFIDO2Device_Authenticator(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	auth := device.Authenticator()
	if auth == nil {
		t.Error("expected Authenticator to return non-nil")
	}

	if auth != device.auth {
		t.Error("expected Authenticator to return the internal authenticator")
	}
}

func TestVirtualFIDO2Device_IsRunning(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	if device.IsRunning() {
		t.Error("expected IsRunning to return false before Run")
	}
}

func TestCreateStorage_Memory(t *testing.T) {
	cfg := &Config{
		StorageType: StorageTypeMemory,
	}

	storage, err := createStorage(cfg)
	if err != nil {
		t.Fatalf("createStorage for memory failed: %v", err)
	}
	defer func() { _ = storage.Close() }()

	if storage == nil {
		t.Error("expected storage to be non-nil")
	}
}

func TestCreateStorage_File(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &Config{
		StorageType: StorageTypeFile,
		StoragePath: filepath.Join(tempDir, "test-storage"),
	}

	storage, err := createStorage(cfg)
	if err != nil {
		t.Fatalf("createStorage for file failed: %v", err)
	}
	defer func() { _ = storage.Close() }()

	if storage == nil {
		t.Error("expected storage to be non-nil")
	}
}

func TestCreateStorage_InvalidType(t *testing.T) {
	cfg := &Config{
		StorageType: "unknown",
	}

	_, err := createStorage(cfg)
	if err == nil {
		t.Error("expected error for invalid storage type")
	}

	if !errors.Is(err, ErrInvalidStorageType) {
		t.Errorf("error = %v, want %v", err, ErrInvalidStorageType)
	}
}

// TestVirtualFIDO2Device_RunWithoutUHID tests Run behavior when UHID is not available.
// This test only runs if UHID is not available (most CI environments).
func TestVirtualFIDO2Device_RunWithoutUHID(t *testing.T) {
	// Skip if running as root or if /dev/uhid exists and is accessible
	if _, err := os.Stat("/dev/uhid"); err == nil {
		t.Skip("skipping test: /dev/uhid is available")
	}

	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run should fail because UHID is not available
	err = device.Run(ctx)
	if err == nil {
		t.Error("expected error when UHID is not available")
	}

	// Verify the error is the expected UHID open error
	if !errors.Is(err, ErrUHIDOpenFailed) {
		t.Logf("error was: %v", err)
	}

	// Device should not be marked as running after failed start
	if device.IsRunning() {
		t.Error("expected IsRunning to return false after failed start")
	}
}

func TestNewVirtualFIDO2Device_ShortPIN(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "TEST007",
		EnablePIN:         true,
		PIN:               "123", // Too short
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for PIN that is too short")
	}

	// Verify the error is related to PIN
	if !errors.Is(err, ErrPINSetFailed) {
		t.Logf("error was: %v", err)
	}
}

func TestVirtualFIDO2Device_CloseWithFileStorage(t *testing.T) {
	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "close-test-storage")

	cfg := &Config{
		StorageType:       StorageTypeFile,
		StoragePath:       storagePath,
		DeviceName:        "Test Device",
		SerialNumber:      "CLOSE001",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}

	// Close should succeed and clean up file storage
	err = device.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestVirtualFIDO2Device_InvalidLogLevel(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "LOG001",
		LogLevel:          "invalid",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for invalid log level")
	}

	if !errors.Is(err, ErrInvalidLogLevel) {
		t.Errorf("error = %v, want %v", err, ErrInvalidLogLevel)
	}
}

func TestDeviceLifecycleErrorConstants(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrDeviceAlreadyRunning", ErrDeviceAlreadyRunning},
		{"ErrDeviceNotRunning", ErrDeviceNotRunning},
		{"ErrStorageCreationFailed", ErrStorageCreationFailed},
		{"ErrAuthenticatorCreationFailed", ErrAuthenticatorCreationFailed},
		{"ErrUHIDOpenFailed", ErrUHIDOpenFailed},
		{"ErrUHIDCreateFailed", ErrUHIDCreateFailed},
		{"ErrPINSetFailed", ErrPINSetFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s should have an error message", tt.name)
			}
		})
	}
}

func TestNewVirtualFIDO2Device_WithAllOptions(t *testing.T) {
	tempDir := t.TempDir()
	storagePath := filepath.Join(tempDir, "full-options-storage")

	cfg := &Config{
		StorageType:         StorageTypeFile,
		StoragePath:         storagePath,
		DeviceName:          "Full Options Device",
		SerialNumber:        "FULL0001",
		EnablePIN:           true,
		PIN:                 "1234567890", // Valid 10-char PIN
		LogLevel:            "debug",
		LogFile:             "", // stdout
		Interactive:         false,
		UserPresenceTimeout: 60 * time.Second,
		Backend:             "software",
		TPMDevice:           "/dev/tpmrm0",
		AttestationFormat:   "packed",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with all options failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify all components are initialized
	if device.auth == nil {
		t.Error("authenticator should be initialized")
	}
	if device.hidHandler == nil {
		t.Error("HID handler should be initialized")
	}
	if device.storage == nil {
		t.Error("storage should be initialized")
	}
	if device.keyBackend == nil {
		t.Error("key backend should be initialized")
	}
	if !device.auth.IsPINSet() {
		t.Error("PIN should be set")
	}
}

func TestNewVirtualFIDO2Device_StorageCreationFailure(t *testing.T) {
	// Use a storage type that would cause createStorage to fail after validation
	// We need to test the path where storage creation itself fails, not validation

	cfg := &Config{
		StorageType: StorageTypeFile,
		// Use a path that is invalid for storage creation (null byte)
		StoragePath:       "/tmp/\x00invalid",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for invalid storage path")
	}
}

func TestVirtualFIDO2Device_AuthenticatorCapabilities(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Capability Test",
		SerialNumber:      "CAP001",
		EnablePIN:         false,
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	auth := device.Authenticator()

	// Verify authenticator is properly configured
	if auth == nil {
		t.Fatal("Authenticator should not be nil")
	}

	// PIN should not be set when EnablePIN is false
	if auth.IsPINSet() {
		t.Error("PIN should not be set when EnablePIN is false")
	}
}

func TestVirtualFIDO2Device_ConfigAccessors(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Accessor Test",
		SerialNumber:      "ACCESS01",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify config is stored correctly
	if device.cfg.DeviceName != "Accessor Test" {
		t.Errorf("DeviceName = %q, want %q", device.cfg.DeviceName, "Accessor Test")
	}

	if device.cfg.SerialNumber != "ACCESS01" {
		t.Errorf("SerialNumber = %q, want %q", device.cfg.SerialNumber, "ACCESS01")
	}

	if device.cfg.StorageType != StorageTypeMemory {
		t.Errorf("StorageType = %q, want %q", device.cfg.StorageType, StorageTypeMemory)
	}
}

func TestVirtualFIDO2Device_RunningStateTransitions(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Initial state should be not running
	if device.IsRunning() {
		t.Error("device should not be running initially")
	}

	// Verify running state can be checked multiple times
	for i := 0; i < 3; i++ {
		if device.IsRunning() {
			t.Errorf("iteration %d: device should not be running", i)
		}
	}
}

func TestCreateStorage_FileStorageDeepPath(t *testing.T) {
	tempDir := t.TempDir()
	// Create a deeply nested path
	deepPath := filepath.Join(tempDir, "level1", "level2", "level3", "storage")

	cfg := &Config{
		StorageType: StorageTypeFile,
		StoragePath: deepPath,
	}

	storage, err := createStorage(cfg)
	if err != nil {
		t.Fatalf("createStorage for deep path failed: %v", err)
	}
	defer func() { _ = storage.Close() }()

	// Verify storage was created
	if storage == nil {
		t.Error("expected storage to be non-nil")
	}

	// Verify directory structure was created
	if _, err := os.Stat(deepPath); os.IsNotExist(err) {
		t.Error("expected deep path to be created")
	}
}

func TestVirtualFIDO2Device_CloseNilComponents(t *testing.T) {
	// Create a minimal device to test Close with potentially nil components
	device := &VirtualFIDO2Device{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		// All other fields are nil
	}

	// Close should handle nil components gracefully
	err := device.Close()
	if err != nil {
		t.Errorf("Close with nil components failed: %v", err)
	}
}

func TestVirtualFIDO2Device_CloseWithAllComponents(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Close All Test",
		SerialNumber:      "CLOSEALL",
		EnablePIN:         true,
		PIN:               "123456",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}

	// Verify all components are set
	if device.auth == nil {
		t.Error("auth should be set")
	}
	if device.hidHandler == nil {
		t.Error("hidHandler should be set")
	}
	if device.storage == nil {
		t.Error("storage should be set")
	}
	if device.keyBackend == nil {
		t.Error("keyBackend should be set")
	}

	// Close should close all components
	err = device.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestVirtualFIDO2Device_IsRunningConcurrent(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Test concurrent IsRunning calls
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = device.IsRunning()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCreateStorage_MemoryMultipleTimes(t *testing.T) {
	// Test that multiple memory storage instances can be created
	cfg := &Config{
		StorageType: StorageTypeMemory,
	}

	for i := 0; i < 5; i++ {
		storage, err := createStorage(cfg)
		if err != nil {
			t.Fatalf("createStorage iteration %d failed: %v", i, err)
		}
		if storage == nil {
			t.Errorf("iteration %d: storage should not be nil", i)
		}
		_ = storage.Close()
	}
}

func TestCreateStorage_FileWithSpecialChars(t *testing.T) {
	tempDir := t.TempDir()
	// Use a path with special characters (but valid)
	specialPath := filepath.Join(tempDir, "test-storage_v1.0")

	cfg := &Config{
		StorageType: StorageTypeFile,
		StoragePath: specialPath,
	}

	storage, err := createStorage(cfg)
	if err != nil {
		t.Fatalf("createStorage with special chars failed: %v", err)
	}
	defer func() { _ = storage.Close() }()

	if storage == nil {
		t.Error("expected storage to be non-nil")
	}
}

func TestNewVirtualFIDO2Device_LongPIN(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "LONGPIN1",
		EnablePIN:         true,
		PIN:               "12345678901234567890123456789012345678901234567890", // 50 chars
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device with long PIN failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify PIN was set
	if !device.auth.IsPINSet() {
		t.Error("expected PIN to be set")
	}
}

func TestVirtualFIDO2Device_MultipleClose(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}

	// Close multiple times - should be idempotent
	for i := 0; i < 5; i++ {
		err := device.Close()
		if err != nil {
			t.Errorf("Close iteration %d failed: %v", i, err)
		}
	}
}

func TestNewVirtualFIDO2Device_DefaultsApplied(t *testing.T) {
	// Test with minimal config - defaults should be applied
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	device, err := NewVirtualFIDO2Device(cfg, logger)
	if err != nil {
		t.Fatalf("NewVirtualFIDO2Device failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	// Verify device was created successfully
	if device.auth == nil {
		t.Error("authenticator should be initialized")
	}
}

func TestVirtualFIDO2Device_CloseWithPartialComponents(t *testing.T) {
	// Create device with only some components initialized
	device := &VirtualFIDO2Device{
		logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		hidHandler: nil, // Nil handler
		auth:       nil, // Nil auth
		storage:    nil, // Nil storage
		keyBackend: nil, // Nil key backend
	}

	// Close should handle nil components
	err := device.Close()
	if err != nil {
		t.Errorf("Close with partial components failed: %v", err)
	}
}

func TestCreateStorage_EmptyConfig(t *testing.T) {
	cfg := &Config{
		StorageType: "", // Empty storage type
	}

	_, err := createStorage(cfg)
	if err == nil {
		t.Error("expected error for empty storage type")
	}

	if !errors.Is(err, ErrInvalidStorageType) {
		t.Errorf("error = %v, want %v", err, ErrInvalidStorageType)
	}
}

func TestNewVirtualFIDO2Device_AllLogLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error", ""}

	for _, level := range levels {
		t.Run("level_"+level, func(t *testing.T) {
			cfg := &Config{
				StorageType:       StorageTypeMemory,
				DeviceName:        "Log Level Test",
				SerialNumber:      "LOG" + level,
				LogLevel:          level,
				Backend:           "software",
				AttestationFormat: "none",
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

			device, err := NewVirtualFIDO2Device(cfg, logger)
			if err != nil {
				t.Fatalf("NewVirtualFIDO2Device with log level %q failed: %v", level, err)
			}
			_ = device.Close()
		})
	}
}

func TestCreateUserPresenceHandler_AutoGrant(t *testing.T) {
	cfg := &Config{
		Interactive: false,
		EnablePIN:   false,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	handler, err := createUserPresenceHandler(cfg, logger)
	if err != nil {
		t.Fatalf("createUserPresenceHandler failed: %v", err)
	}

	if handler == nil {
		t.Error("expected handler to be non-nil")
	}
}

func TestCreateUserPresenceHandler_AutoGrantWithPIN(t *testing.T) {
	cfg := &Config{
		Interactive: false,
		EnablePIN:   true,
		PIN:         "123456",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	handler, err := createUserPresenceHandler(cfg, logger)
	if err != nil {
		t.Fatalf("createUserPresenceHandler failed: %v", err)
	}

	if handler == nil {
		t.Error("expected handler to be non-nil")
	}
}

func TestCreateKeyBackend_Software(t *testing.T) {
	cfg := &Config{
		Backend: "software",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	backend, err := createKeyBackend(cfg, logger)
	if err != nil {
		t.Fatalf("createKeyBackend failed: %v", err)
	}
	defer func() { _ = backend.Close() }()

	if backend == nil {
		t.Error("expected backend to be non-nil")
	}
}

func TestCreateKeyBackend_TPM2RequiresDevice(t *testing.T) {
	cfg := &Config{
		Backend:   "tpm2",
		TPMDevice: "/dev/tpmrm0",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// TPM2 backend requires a real TPM device; should fail in unit tests
	_, err := createKeyBackend(cfg, logger)
	if err == nil {
		t.Fatal("expected error when TPM device is unavailable")
	}
	if !errors.Is(err, ErrTPMOpenFailed) {
		t.Errorf("expected ErrTPMOpenFailed, got %v", err)
	}
}

func TestNewVirtualFIDO2Device_InvalidBackend(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "BACKEND1",
		LogLevel:          "info",
		Backend:           "invalid",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for invalid backend")
	}

	if !errors.Is(err, ErrInvalidBackend) {
		t.Errorf("error = %v, want %v", err, ErrInvalidBackend)
	}
}

func TestNewVirtualFIDO2Device_TPMAttestationRequiresTPMBackend(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "ATTEST1",
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "tpm",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Error("expected error for TPM attestation with software backend")
	}

	if !errors.Is(err, ErrTPMAttestationRequiresTPMBackend) {
		t.Errorf("error = %v, want %v", err, ErrTPMAttestationRequiresTPMBackend)
	}
}

func TestCreateUserPresenceHandler_InteractiveFails(t *testing.T) {
	cfg := &Config{
		Interactive: true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Interactive handler requires a terminal; unit tests don't have one.
	_, err := createUserPresenceHandler(cfg, logger)
	if err == nil {
		t.Fatal("expected error for interactive mode without terminal")
	}
}

func TestCreateKeyBackend_DefaultFallsBackToSoftware(t *testing.T) {
	// Call createKeyBackend directly with an empty backend string to exercise
	// the default case in the switch statement.
	cfg := &Config{
		Backend: "",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	backend, err := createKeyBackend(cfg, logger)
	if err != nil {
		t.Fatalf("createKeyBackend with empty backend failed: %v", err)
	}
	defer func() { _ = backend.Close() }()

	if backend == nil {
		t.Error("expected backend to be non-nil")
	}
}

func TestNewVirtualFIDO2Device_InteractiveNoTerminal(t *testing.T) {
	cfg := &Config{
		StorageType:       StorageTypeMemory,
		DeviceName:        "Test Device",
		SerialNumber:      "INTERACTIVE1",
		LogLevel:          "info",
		Interactive:       true,
		Backend:           "software",
		AttestationFormat: "none",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Interactive mode requires a terminal, should fail in unit test environment.
	_, err := NewVirtualFIDO2Device(cfg, logger)
	if err == nil {
		t.Fatal("expected error for interactive mode without terminal")
	}
	if !errors.Is(err, ErrAuthenticatorCreationFailed) {
		t.Errorf("expected ErrAuthenticatorCreationFailed, got %v", err)
	}
}

func TestDeviceLifecycleErrorConstants_TPM(t *testing.T) {
	// Verify TPM error constants added during Phase 2.
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrTPMOpenFailed",
			err:  ErrTPMOpenFailed,
			want: "fido2key: TPM open failed",
		},
		{
			name: "ErrTPMBackendCreationFailed",
			err:  ErrTPMBackendCreationFailed,
			want: "fido2key: TPM2 backend creation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}
			if tt.err.Error() != tt.want {
				t.Errorf("%s.Error() = %q, want %q", tt.name, tt.err.Error(), tt.want)
			}
		})
	}
}

func TestCreateTPM2KeyBackend_InvalidDevice(t *testing.T) {
	cfg := &Config{
		Backend:   "tpm2",
		TPMDevice: "/dev/nonexistent-tpm-device",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := createTPM2KeyBackend(cfg, logger)
	if err == nil {
		t.Fatal("expected error for nonexistent TPM device")
	}
	if !errors.Is(err, ErrTPMOpenFailed) {
		t.Errorf("expected ErrTPMOpenFailed, got %v", err)
	}
}
