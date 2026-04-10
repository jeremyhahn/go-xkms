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
	"testing"
	"time"
)

func TestStorageTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant StorageType
		expected string
	}{
		{
			name:     "memory storage type",
			constant: StorageTypeMemory,
			expected: "memory",
		},
		{
			name:     "file storage type",
			constant: StorageTypeFile,
			expected: "file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.constant) != tt.expected {
				t.Errorf("StorageType = %q, want %q", string(tt.constant), tt.expected)
			}
		})
	}
}

func TestDefaultConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "default device name",
			constant: DefaultDeviceName,
			expected: "FIDO2 Key (go-keychain)",
		},
		{
			name:     "default log level",
			constant: DefaultLogLevel,
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("constant = %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Verify default storage type
	if cfg.StorageType != StorageTypeMemory {
		t.Errorf("StorageType = %q, want %q", cfg.StorageType, StorageTypeMemory)
	}

	// Verify default device name
	if cfg.DeviceName != DefaultDeviceName {
		t.Errorf("DeviceName = %q, want %q", cfg.DeviceName, DefaultDeviceName)
	}

	// Verify serial number is generated (16 hex chars)
	if len(cfg.SerialNumber) != 16 {
		// Could also be fallback "KCFIDO2-00000000" (16 chars)
		if cfg.SerialNumber != "KCFIDO2-00000000" {
			t.Errorf("SerialNumber length = %d, want 16 (or fallback)", len(cfg.SerialNumber))
		}
	}

	// Verify PIN is disabled by default
	if cfg.EnablePIN {
		t.Error("EnablePIN should be false by default")
	}

	// Verify default log level
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}

	// Verify new default fields
	if cfg.Interactive {
		t.Error("Interactive should be false by default")
	}

	if cfg.UserPresenceTimeout != 30*time.Second {
		t.Errorf("UserPresenceTimeout = %v, want %v", cfg.UserPresenceTimeout, 30*time.Second)
	}

	if cfg.Backend != "software" {
		t.Errorf("Backend = %q, want %q", cfg.Backend, "software")
	}

	if cfg.TPMDevice != "/dev/tpmrm0" {
		t.Errorf("TPMDevice = %q, want %q", cfg.TPMDevice, "/dev/tpmrm0")
	}

	if cfg.AttestationFormat != "none" {
		t.Errorf("AttestationFormat = %q, want %q", cfg.AttestationFormat, "none")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError error
	}{
		{
			name: "valid memory storage config",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "valid file storage config",
			config: &Config{
				StorageType:       StorageTypeFile,
				StoragePath:       "/tmp/test-storage",
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "invalid storage type",
			config: &Config{
				StorageType:       "invalid",
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: ErrInvalidStorageType,
		},
		{
			name: "file storage without path",
			config: &Config{
				StorageType:       StorageTypeFile,
				StoragePath:       "",
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: ErrStoragePathRequired,
		},
		{
			name: "invalid log level",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "invalid",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: ErrInvalidLogLevel,
		},
		{
			name: "valid debug log level",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "debug",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "valid warn log level",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "warn",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "valid error log level",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "error",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "empty log level is valid",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "unknown storage type",
			config: &Config{
				StorageType:       "s3",
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "none",
			},
			expectError: ErrInvalidStorageType,
		},
		{
			name: "invalid backend",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "invalid",
				AttestationFormat: "none",
			},
			expectError: ErrInvalidBackend,
		},
		{
			name: "empty backend is invalid",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "",
				AttestationFormat: "none",
			},
			expectError: ErrInvalidBackend,
		},
		{
			name: "valid tpm2 backend",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "tpm2",
				AttestationFormat: "none",
			},
			expectError: nil,
		},
		{
			name: "invalid attestation format",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "invalid",
			},
			expectError: ErrInvalidAttestationFormat,
		},
		{
			name: "valid packed attestation format",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "packed",
			},
			expectError: nil,
		},
		{
			name: "valid tpm attestation format with tpm2 backend",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "tpm2",
				AttestationFormat: "tpm",
			},
			expectError: nil,
		},
		{
			name: "tpm attestation requires tpm2 backend",
			config: &Config{
				StorageType:       StorageTypeMemory,
				LogLevel:          "info",
				Backend:           "software",
				AttestationFormat: "tpm",
			},
			expectError: ErrTPMAttestationRequiresTPMBackend,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError == nil {
				if err != nil {
					t.Errorf("Validate() returned unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error %v, got nil", tt.expectError)
				} else if err != tt.expectError {
					t.Errorf("Validate() error = %v, want %v", err, tt.expectError)
				}
			}
		})
	}
}

func TestConfigIsValidStorageType(t *testing.T) {
	tests := []struct {
		name        string
		storageType StorageType
		expected    bool
	}{
		{
			name:        "memory is valid",
			storageType: StorageTypeMemory,
			expected:    true,
		},
		{
			name:        "file is valid",
			storageType: StorageTypeFile,
			expected:    true,
		},
		{
			name:        "empty is invalid",
			storageType: "",
			expected:    false,
		},
		{
			name:        "unknown is invalid",
			storageType: "redis",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{StorageType: tt.storageType}
			result := cfg.isValidStorageType()

			if result != tt.expected {
				t.Errorf("isValidStorageType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfigIsValidLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
		expected bool
	}{
		{
			name:     "debug is valid",
			logLevel: "debug",
			expected: true,
		},
		{
			name:     "info is valid",
			logLevel: "info",
			expected: true,
		},
		{
			name:     "warn is valid",
			logLevel: "warn",
			expected: true,
		},
		{
			name:     "error is valid",
			logLevel: "error",
			expected: true,
		},
		{
			name:     "empty is valid (defaults to info)",
			logLevel: "",
			expected: true,
		},
		{
			name:     "trace is invalid",
			logLevel: "trace",
			expected: false,
		},
		{
			name:     "fatal is invalid",
			logLevel: "fatal",
			expected: false,
		},
		{
			name:     "WARNING is invalid (case sensitive)",
			logLevel: "WARNING",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{LogLevel: tt.logLevel}
			result := cfg.isValidLogLevel()

			if result != tt.expected {
				t.Errorf("isValidLogLevel() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfigIsValidBackend(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		expected bool
	}{
		{
			name:     "software is valid",
			backend:  "software",
			expected: true,
		},
		{
			name:     "tpm2 is valid",
			backend:  "tpm2",
			expected: true,
		},
		{
			name:     "empty is invalid",
			backend:  "",
			expected: false,
		},
		{
			name:     "unknown is invalid",
			backend:  "pkcs11",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Backend: tt.backend}
			result := cfg.isValidBackend()

			if result != tt.expected {
				t.Errorf("isValidBackend() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfigIsValidAttestationFormat(t *testing.T) {
	tests := []struct {
		name              string
		attestationFormat string
		expected          bool
	}{
		{
			name:              "none is valid",
			attestationFormat: "none",
			expected:          true,
		},
		{
			name:              "packed is valid",
			attestationFormat: "packed",
			expected:          true,
		},
		{
			name:              "tpm is valid",
			attestationFormat: "tpm",
			expected:          true,
		},
		{
			name:              "empty is invalid",
			attestationFormat: "",
			expected:          false,
		},
		{
			name:              "unknown is invalid",
			attestationFormat: "android-key",
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{AttestationFormat: tt.attestationFormat}
			result := cfg.isValidAttestationFormat()

			if result != tt.expected {
				t.Errorf("isValidAttestationFormat() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	t.Run("generates 16 character hex string", func(t *testing.T) {
		serial := GenerateSerialNumber()

		// Should be 16 hex characters (8 bytes encoded)
		if len(serial) != 16 {
			// Check for fallback case
			if serial != "KCFIDO2-00000000" {
				t.Errorf("GenerateSerialNumber() length = %d, want 16 (or fallback)", len(serial))
			}
		}

		// Verify all characters are valid hex
		for _, c := range serial {
			//nolint:staticcheck // QF1001 - current form is more readable than De Morgan's law equivalent
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
				t.Errorf("GenerateSerialNumber() contains invalid character: %c", c)
			}
		}
	})

	t.Run("generates unique values", func(t *testing.T) {
		seen := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			serial := GenerateSerialNumber()
			if seen[serial] {
				t.Errorf("GenerateSerialNumber() produced duplicate: %s", serial)
			}
			seen[serial] = true
		}

		if len(seen) != iterations {
			t.Errorf("GenerateSerialNumber() produced %d unique values, want %d", len(seen), iterations)
		}
	})
}

func TestConfigWithAllFields(t *testing.T) {
	cfg := &Config{
		StorageType:         StorageTypeFile,
		StoragePath:         "/var/lib/fido2",
		DeviceName:          "Custom Device",
		SerialNumber:        "CUSTOM12345678",
		EnablePIN:           true,
		PIN:                 "123456",
		LogLevel:            "debug",
		LogFile:             "/var/log/fido2.log",
		Interactive:         true,
		UserPresenceTimeout: 60 * time.Second,
		Backend:             "software",
		TPMDevice:           "/dev/tpmrm0",
		AttestationFormat:   "packed",
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() returned unexpected error for fully populated config: %v", err)
	}
}

func TestConfigValidateStorageTypePriority(t *testing.T) {
	// Tests that storage type validation happens before storage path validation
	cfg := &Config{
		StorageType:       "invalid",
		StoragePath:       "", // Would fail for file storage, but should fail on type first
		LogLevel:          "info",
		Backend:           "software",
		AttestationFormat: "none",
	}

	err := cfg.Validate()
	if err != ErrInvalidStorageType {
		t.Errorf("Validate() error = %v, want %v (storage type should be validated first)", err, ErrInvalidStorageType)
	}
}
