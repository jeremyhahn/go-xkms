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

//go:build pkcs11

package pkcs11

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// CertStorageConfig configures certificate storage for PKCS#11 backend
type CertStorageConfig struct {
	Mode                  hardware.CertStorageMode
	ExternalStorage       storage.Backend
	EnableHardwareStorage bool
	MaxCertificates       int
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

	if c.MaxCertificates < 0 {
		return errors.New("max certificates cannot be negative")
	}

	return nil
}

// CreateCertificateStorage creates appropriate certificate storage based on configuration.
func (b *Backend) CreateCertificateStorage(config *CertStorageConfig) (storage.Backend, error) {
	if config == nil {
		config = DefaultCertStorageConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid certificate storage config: %w", err)
	}

	if b.pool == nil {
		return nil, fmt.Errorf("backend must be initialized before creating certificate storage")
	}

	switch config.Mode {
	case hardware.CertStorageModeExternal:
		return config.ExternalStorage, nil

	case hardware.CertStorageModeHardware:
		hwStorage, err := b.createHardwareStorage()
		if err != nil {
			return nil, err
		}
		return hardware.NewHardwareBackendAdapter(hwStorage), nil

	case hardware.CertStorageModeHybrid:
		hwStorage, err := b.createHardwareStorage()
		if err != nil {
			return nil, fmt.Errorf("failed to create hardware storage: %w", err)
		}

		hybridStorage, err := hardware.NewHybridCertStorageFromBackend(hwStorage, config.ExternalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create hybrid certificate storage: %w", err)
		}
		return hardware.NewHardwareBackendAdapter(hybridStorage), nil

	default:
		return nil, fmt.Errorf("unknown certificate storage mode: %s", config.Mode)
	}
}

// createHardwareStorage creates a PKCS#11 hardware certificate storage instance
// using the backend's shared SessionPool for all PKCS#11 operations.
//
// For YubiKey PIV, the storage is configured to elevate to CKU_SO for delete
// operations via the management key (SOPIN), since libykcs11 rejects
// C_DestroyObject under CKU_USER with CKR_USER_TYPE_INVALID.
func (b *Backend) createHardwareStorage() (hardware.HardwareCertStorage, error) {
	if b.pool == nil {
		return nil, fmt.Errorf("session pool not initialized")
	}

	if b.config.IsYubiKeyPIV() {
		return hardware.NewPKCS11CertStorageWithSO(
			b.pool,
			b.config.TokenLabel,
			b.config.SOPIN,
			b.config.PIN,
			true,
		)
	}

	return hardware.NewPKCS11CertStorage(
		b.pool,
		b.config.TokenLabel,
	)
}
