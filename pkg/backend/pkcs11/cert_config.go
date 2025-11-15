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

//go:build pkcs11

package pkcs11

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
	"github.com/miekg/pkcs11"
)

// CertStorageConfig configures certificate storage for PKCS#11 backend
type CertStorageConfig struct {
	// Mode determines where certificates are stored
	// Default: CertStorageModeExternal
	Mode hardware.CertStorageMode

	// ExternalStorage provides external certificate storage
	// Required for External and Hybrid modes
	ExternalStorage storage.Backend

	// EnableHardwareStorage allows certificates to be stored in the HSM
	// Default: false (use external storage only)
	EnableHardwareStorage bool

	// MaxCertificates limits the number of certificates in hardware
	// Default: 100 (prevents token exhaustion)
	// Set to 0 for unlimited (not recommended)
	MaxCertificates int
}

// DefaultCertStorageConfig returns safe defaults for certificate storage configuration.
func DefaultCertStorageConfig() *CertStorageConfig {
	return &CertStorageConfig{
		Mode:                  hardware.CertStorageModeExternal,
		EnableHardwareStorage: false,
		MaxCertificates:       100,
	}
}

// Validate checks configuration consistency and returns an error if invalid.
func (c *CertStorageConfig) Validate() error {
	if c == nil {
		return errors.New("certificate storage config cannot be nil")
	}

	// Validate mode-specific requirements
	switch c.Mode {
	case hardware.CertStorageModeExternal:
		if c.ExternalStorage == nil {
			return errors.New("external storage required for external mode")
		}
	case hardware.CertStorageModeHybrid:
		if c.ExternalStorage == nil {
			return errors.New("external storage required for hybrid mode")
		}
		if !c.EnableHardwareStorage {
			return errors.New("hardware storage must be enabled for hybrid mode")
		}
	case hardware.CertStorageModeHardware:
		if !c.EnableHardwareStorage {
			return errors.New("hardware storage must be enabled for hardware mode")
		}
	default:
		return fmt.Errorf("unknown certificate storage mode: %s", c.Mode)
	}

	// Validate max certificates
	if c.MaxCertificates < 0 {
		return errors.New("max certificates cannot be negative")
	}

	return nil
}

// CreateCertificateStorage creates appropriate certificate storage based on configuration.
// This is a factory function that should be called by the PKCS#11 backend after
// initializing and logging into the HSM.
//
// Parameters:
//   - backend: The PKCS#11 backend instance (must be initialized and logged in)
//   - config: Certificate storage configuration (nil uses defaults)
//
// Returns the configured certificate storage or an error.
func (b *Backend) CreateCertificateStorage(config *CertStorageConfig) (storage.Backend, error) {
	if config == nil {
		config = DefaultCertStorageConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid certificate storage config: %w", err)
	}

	// Ensure backend is initialized
	if b.ctx == nil {
		return nil, fmt.Errorf("backend must be initialized before creating certificate storage")
	}

	switch config.Mode {
	case hardware.CertStorageModeExternal:
		// Use only external storage
		return config.ExternalStorage, nil

	case hardware.CertStorageModeHardware:
		// Use only hardware storage
		hwStorage, err := b.createHardwareStorage()
		if err != nil {
			return nil, err
		}
		// Wrap hardware storage to implement storage.Backend
		return hardware.NewHardwareBackendAdapter(hwStorage), nil

	case hardware.CertStorageModeHybrid:
		// Create hybrid storage that uses both hardware and external
		hwStorage, err := b.createHardwareStorage()
		if err != nil {
			return nil, fmt.Errorf("failed to create hardware storage: %w", err)
		}

		// Create hybrid storage wrapper that combines hardware and external storage
		hybridStorage, err := hardware.NewHybridCertStorageFromBackend(hwStorage, config.ExternalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create hybrid certificate storage: %w", err)
		}
		// Wrap hybrid storage to implement storage.Backend
		return hardware.NewHardwareBackendAdapter(hybridStorage), nil

	default:
		return nil, fmt.Errorf("unknown certificate storage mode: %s", config.Mode)
	}
}

// createHardwareStorage creates a PKCS#11 hardware certificate storage instance.
// This is a helper function used by CreateCertificateStorage.
func (b *Backend) createHardwareStorage() (hardware.HardwareCertStorage, error) {
	// Get the session from the backend
	// We need to use the low-level PKCS#11 context and session

	if b.p11ctx == nil {
		return nil, fmt.Errorf("PKCS#11 context not initialized")
	}

	// Find the slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return nil, fmt.Errorf("no PKCS#11 slots available")
	}

	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	// Open a session for certificate operations
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session for certificate storage: %w", err)
	}

	// Login to the session
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			// Ignore already logged in error
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				b.p11ctx.CloseSession(session)
				return nil, fmt.Errorf("failed to login for certificate storage: %w", err)
			}
		}
	}

	// Create the hardware certificate storage
	return hardware.NewPKCS11CertStorage(
		b.p11ctx,
		session,
		b.config.TokenLabel,
		slot,
	)
}
