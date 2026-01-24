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
	"crypto/rand"
	"encoding/hex"
	"time"
)

// StorageType represents the credential storage backend type.
type StorageType string

const (
	// StorageTypeMemory stores credentials in memory (volatile).
	StorageTypeMemory StorageType = "memory"

	// StorageTypeFile stores credentials on the filesystem (persistent).
	StorageTypeFile StorageType = "file"
)

// Default configuration values.
const (
	DefaultDeviceName = "Virtual FIDO2 Key (go-keychain)"
	DefaultPIDFile    = "/var/run/vfido2.pid"
	DefaultLogLevel   = "info"
)

// Config holds the configuration for the virtual FIDO2 device.
type Config struct {
	// Storage configuration
	StorageType StorageType
	StoragePath string // Required if StorageType is "file"

	// Device configuration
	DeviceName   string // Default: "Virtual FIDO2 Key (go-keychain)"
	SerialNumber string // Auto-generated if empty

	// PIN configuration
	EnablePIN bool
	PIN       string // Initial PIN if EnablePIN is true

	// Daemon configuration
	Daemon  bool
	PIDFile string // Default: /var/run/vfido2.pid

	// Logging
	LogLevel string // debug, info, warn, error
	LogFile  string // Empty = stdout

	// User presence mode
	Interactive         bool          // Enable interactive mode (prompt for touch/PIN)
	UserPresenceTimeout time.Duration // Timeout for user presence requests

	// Key backend configuration
	Backend           string // "software" or "tpm2"
	TPMDevice         string // TPM device path (e.g., "/dev/tpmrm0")
	AttestationFormat string // "none", "packed", or "tpm"
}

// DefaultConfig returns a new Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		StorageType:         StorageTypeMemory,
		DeviceName:          DefaultDeviceName,
		SerialNumber:        GenerateSerialNumber(),
		EnablePIN:           false,
		Daemon:              false,
		PIDFile:             DefaultPIDFile,
		LogLevel:            DefaultLogLevel,
		Interactive:         false,
		UserPresenceTimeout: 30 * time.Second,
		Backend:             "software",
		TPMDevice:           "/dev/tpmrm0",
		AttestationFormat:   "none",
	}
}

// Validate checks the configuration for errors and returns the first error found.
func (c *Config) Validate() error {
	// Validate storage type
	if !c.isValidStorageType() {
		return ErrInvalidStorageType
	}

	// File storage requires a path
	if c.StorageType == StorageTypeFile && c.StoragePath == "" {
		return ErrStoragePathRequired
	}

	// Validate log level
	if !c.isValidLogLevel() {
		return ErrInvalidLogLevel
	}

	// Interactive mode cannot be used with daemon mode
	if c.Interactive && c.Daemon {
		return ErrInteractiveDaemonConflict
	}

	// Validate backend
	if !c.isValidBackend() {
		return ErrInvalidBackend
	}

	// Validate attestation format
	if !c.isValidAttestationFormat() {
		return ErrInvalidAttestationFormat
	}

	// TPM attestation requires TPM2 backend
	if c.AttestationFormat == "tpm" && c.Backend != "tpm2" {
		return ErrTPMAttestationRequiresTPMBackend
	}

	return nil
}

// isValidStorageType checks if the storage type is supported.
func (c *Config) isValidStorageType() bool {
	switch c.StorageType {
	case StorageTypeMemory, StorageTypeFile:
		return true
	default:
		return false
	}
}

// isValidLogLevel checks if the log level is supported.
func (c *Config) isValidLogLevel() bool {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
		return true
	case "": // Empty defaults to info
		return true
	default:
		return false
	}
}

// isValidBackend checks if the backend type is supported.
func (c *Config) isValidBackend() bool {
	switch c.Backend {
	case "software", "tpm2":
		return true
	default:
		return false
	}
}

// isValidAttestationFormat checks if the attestation format is supported.
func (c *Config) isValidAttestationFormat() bool {
	switch c.AttestationFormat {
	case "none", "packed", "tpm":
		return true
	default:
		return false
	}
}

// GenerateSerialNumber creates a random 16-character hexadecimal serial number.
func GenerateSerialNumber() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a deterministic serial if crypto/rand fails
		return "VFIDO2-00000000"
	}
	return hex.EncodeToString(b)
}
