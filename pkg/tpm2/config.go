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

//go:build tpm2

package tpm2

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration parameters for TPM 2.0 backend initialization.
// It supports both hardware TPM devices and simulator connections.
type Config struct {
	// CN is the Common Name identifier for the Storage Root Key (SRK).
	// This is required and typically identifies the keychain instance.
	CN string `json:"cn" yaml:"cn"`

	// DevicePath specifies the path to the TPM character device.
	// Common values: /dev/tpmrm0 (resource manager), /dev/tpm0 (direct access)
	// Required when UseSimulator is false.
	DevicePath string `json:"device_path" yaml:"device_path"`

	// UseSimulator indicates whether to use a TPM simulator instead of hardware.
	// When true, SimulatorType, SimulatorHost and SimulatorPort must be specified.
	UseSimulator bool `json:"use_simulator" yaml:"use_simulator"`

	// SimulatorType specifies which TPM simulator to use.
	// Valid values: "embedded" (go-tpm-tools stateless), "swtpm" (TCP-based stateful)
	// Default: "swtpm" for production compatibility
	SimulatorType string `json:"simulator_type,omitempty" yaml:"simulator_type,omitempty"`

	// SimulatorHost is the hostname or IP address of the TPM simulator.
	// Required when UseSimulator is true and SimulatorType is "swtpm". Common value: "localhost"
	SimulatorHost string `json:"simulator_host,omitempty" yaml:"simulator_host,omitempty"`

	// SimulatorPort is the port number of the TPM simulator.
	// Required when UseSimulator is true and SimulatorType is "swtpm". Common value: 2321
	SimulatorPort int `json:"simulator_port,omitempty" yaml:"simulator_port,omitempty"`

	// SRKHandle is the persistent handle for the Storage Root Key.
	// Must be in the persistent handle range: 0x81000000 - 0x81FFFFFF
	// Common value: 0x81000001
	SRKHandle uint32 `json:"srk_handle" yaml:"srk_handle"`

	// Hierarchy specifies the TPM hierarchy for key operations.
	// Valid values: "owner" (default), "endorsement", "platform"
	// The owner hierarchy is most common for application keys.
	Hierarchy string `json:"hierarchy,omitempty" yaml:"hierarchy,omitempty"`

	// PlatformPolicy enables Platform Configuration Register (PCR) policy
	// for keys. When enabled, keys are bound to specific PCR values,
	// providing measured boot integration.
	PlatformPolicy bool `json:"platform_policy" yaml:"platform_policy"`

	// PCRSelection specifies which PCR banks to include in the platform policy.
	// Example: [0, 1, 2, 3, 7] for secure boot PCRs
	PCRSelection []int `json:"pcr_selection,omitempty" yaml:"pcr_selection,omitempty"`

	// EncryptSession enables AES-128/256 CFB encryption for TPM sessions.
	//
	// Security (STRONGLY RECOMMENDED for Production):
	//   - Encrypts all parameter data sent to/from the TPM
	//   - Protects against man-in-the-middle attacks on TPM bus
	//   - Prevents bus snooping of sensitive keys, PINs, and data
	//   - Required for FIPS 140-2/3 and Common Criteria EAL4+ compliance
	//   - Enabled by default in production configurations
	//
	// Performance Impact (Minimal):
	//   - Session creation: +2-5ms per session
	//   - Per-operation overhead: <1ms
	//   - Negligible compared to TPM operation time (10-100ms)
	//
	// When to Disable (Debugging Only):
	//   - Local development and testing
	//   - TPM command troubleshooting and debugging
	//   - Performance benchmarking and profiling
	//   - NEVER disable in production environments
	//
	// Compliance Requirements:
	//   - FIPS 140-2/3: Required for cryptographic module validation
	//   - Common Criteria EAL4+: Required for high assurance
	//   - PCI-DSS: Recommended for protecting cardholder data
	//   - HIPAA: Recommended for protecting health information
	//
	// Technical Details:
	//   - Uses AES-128/256 in CFB mode for symmetric encryption
	//   - Default mode: EncryptInOut (bidirectional encryption)
	//   - Sessions created via HMAC(), HMACSession(), HMACSaltedSession()
	//   - Transparent to calling code - automatically applied
	//   - Can be configured via SessionConfig for advanced control
	//
	// Default: true (recommended for all production use)
	EncryptSession bool `json:"encrypt_session" yaml:"encrypt_session"`

	// SessionConfig provides detailed configuration for TPM session encryption.
	// If nil, default session configuration is used (bidirectional encryption, AES-128).
	// Only used when EncryptSession is true.
	//
	// Recommended for production:
	//   SessionConfig: &SessionConfig{
	//       Encrypted:      true,
	//       EncryptionMode: EncryptionModeInOut,  // Bidirectional encryption
	//       AESKeySize:     128,                   // AES-128 (TPM standard)
	//   }
	//
	// For high-security environments (with performance tradeoff):
	//   SessionConfig: &SessionConfig{
	//       Encrypted:      true,
	//       EncryptionMode: EncryptionModeInOut,  // Bidirectional encryption
	//       Salted:         true,                  // Enhanced key derivation
	//       AESKeySize:     256,                   // AES-256
	//   }
	//
	// For high-performance environments:
	//   SessionConfig: &SessionConfig{
	//       Encrypted:      true,
	//       EncryptionMode: EncryptionModeInOut,
	//       AESKeySize:     128,
	//       PoolSize:       4,                     // Pre-allocate 4 sessions
	//   }
	SessionConfig *SessionConfig `json:"session_config,omitempty" yaml:"session_config,omitempty"`

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker `yaml:"-" json:"-" mapstructure:"-"`

	// Debug enables verbose logging of TPM operations.
	Debug bool `json:"debug" yaml:"debug"`
}

// DefaultConfig returns a Config with sensible defaults for hardware TPM usage.
// The returned configuration:
//   - Uses /dev/tpmrm0 (TPM resource manager)
//   - Sets SRK handle to 0x81000001 (standard persistent handle)
//   - Uses owner hierarchy (most common for applications)
//   - Disables platform policy by default
//   - Enables session encryption for security
func DefaultConfig() *Config {
	return &Config{
		CN:             "keystore-srk",
		DevicePath:     "/dev/tpmrm0",
		UseSimulator:   false,
		SRKHandle:      0x81000001,
		Hierarchy:      "owner",
		PlatformPolicy: false,
		EncryptSession: true,
		Debug:          false,
	}
}

// Validate checks the configuration for completeness and correctness.
// It returns an error if any required fields are missing or invalid.
func (c *Config) Validate() error {
	if c.CN == "" {
		return errors.New("tpm2: CN (Common Name) is required")
	}

	if c.SRKHandle == 0 {
		return errors.New("tpm2: SRKHandle is required")
	}

	if !IsPersistentHandle(c.SRKHandle) {
		return fmt.Errorf("tpm2: SRKHandle must be in persistent range (0x81000000-0x81FFFFFF), got %#x", c.SRKHandle)
	}

	if c.UseSimulator {
		// Default to SWTPM for production compatibility
		if c.SimulatorType == "" {
			c.SimulatorType = "swtpm"
		}

		// Validate simulator type
		switch c.SimulatorType {
		case "embedded", "swtpm":
			// Valid
		default:
			return fmt.Errorf("tpm2: invalid SimulatorType %q, must be 'embedded' or 'swtpm'", c.SimulatorType)
		}

		// SWTPM requires host and port
		if c.SimulatorType == "swtpm" {
			if c.SimulatorHost == "" {
				return errors.New("tpm2: SimulatorHost is required when SimulatorType is 'swtpm'")
			}
			if c.SimulatorPort == 0 {
				return errors.New("tpm2: SimulatorPort is required when SimulatorType is 'swtpm'")
			}
		}
	} else {
		if c.DevicePath == "" {
			return errors.New("tpm2: DevicePath is required when UseSimulator is false")
		}
	}

	// Validate hierarchy if specified
	if c.Hierarchy != "" {
		switch c.Hierarchy {
		case "owner", "endorsement", "platform":
			// Valid hierarchy
		default:
			return fmt.Errorf("tpm2: invalid hierarchy %q, must be 'owner', 'endorsement', or 'platform'", c.Hierarchy)
		}
	}

	return nil
}

// IsPersistentHandle returns true if the handle is in the TPM persistent handle range.
// TPM 2.0 persistent handles are in the range 0x81000000 to 0x81FFFFFF.
func IsPersistentHandle(handle uint32) bool {
	return handle >= 0x81000000 && handle <= 0x81FFFFFF
}
