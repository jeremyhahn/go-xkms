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

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// CertStorageConfig configures certificate storage for TPM2 backend
type CertStorageConfig struct {
	// Mode determines where certificates are stored
	// Default: CertStorageModeExternal
	Mode hardware.CertStorageMode

	// ExternalStorage provides external certificate storage
	// Required for External and Hybrid modes
	ExternalStorage storage.Backend

	// EnableNVStorage allows certificates to be stored in TPM NV RAM
	// Default: false (use external storage only)
	EnableNVStorage bool

	// NVBaseIndex is the starting NV index for certificate storage
	// Default: 0x01800000 (TPM_NV_INDEX_FIRST)
	NVBaseIndex uint32

	// MaxCertSize is the maximum certificate size in bytes
	// Default: 2048 bytes
	MaxCertSize int

	// MaxCertificates limits the number of certificates in NV RAM
	// Default: 4 (TPM NV RAM is limited, typically 2-8KB total)
	MaxCertificates int

	// OwnerAuth is the owner hierarchy password for NV operations
	// Default: nil (no password)
	OwnerAuth []byte
}

// DefaultCertStorageConfig returns safe defaults for TPM2
func DefaultCertStorageConfig() *CertStorageConfig {
	return &CertStorageConfig{
		Mode:            hardware.CertStorageModeExternal,
		EnableNVStorage: false,
		NVBaseIndex:     0x01800000, // TPM_NV_INDEX_FIRST
		MaxCertSize:     2048,
		MaxCertificates: 4, // Conservative limit for NV RAM
		OwnerAuth:       nil,
	}
}

// Validate checks configuration consistency
func (c *CertStorageConfig) Validate() error {
	if c.Mode == hardware.CertStorageModeExternal && c.ExternalStorage == nil {
		return errors.New("external storage required for external mode")
	}
	if c.Mode == hardware.CertStorageModeHybrid && c.ExternalStorage == nil {
		return errors.New("external storage required for hybrid mode")
	}
	if c.MaxCertificates < 1 || c.MaxCertificates > 10 {
		return errors.New("max certificates must be between 1 and 10 for TPM2")
	}
	if c.MaxCertSize < 512 || c.MaxCertSize > 4096 {
		return errors.New("max cert size must be between 512 and 4096 bytes")
	}

	// Validate NV base index is in correct range
	if c.NVBaseIndex < 0x01000000 || c.NVBaseIndex > 0x01BFFFFF {
		return errors.New("NV base index must be in range 0x01000000-0x01BFFFFF")
	}

	return nil
}

// CreateCertificateStorage creates appropriate certificate storage based on configuration.
// This method is called by applications to instantiate the right storage backend.
//
// Parameters:
//   - config: Certificate storage configuration
//
// Returns:
//   - storage.Backend: The configured certificate storage
//   - error: Any validation or initialization error
func (ks *TPM2KeyStore) CreateCertificateStorage(config *CertStorageConfig) (storage.Backend, error) {
	if config == nil {
		config = DefaultCertStorageConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.Mode {
	case hardware.CertStorageModeExternal:
		// Use external storage only
		return config.ExternalStorage, nil

	case hardware.CertStorageModeHardware:
		// Use hardware storage only
		if !config.EnableNVStorage {
			return nil, errors.New("EnableNVStorage must be true for hardware mode")
		}

		hwConfig := &hardware.TPM2CertStorageConfig{
			BaseIndex:   config.NVBaseIndex,
			MaxCertSize: config.MaxCertSize,
			OwnerAuth:   config.OwnerAuth,
		}

		hwStorage, err := hardware.NewTPM2CertStorage(ks.tpm, hwConfig)
		if err != nil {
			return nil, err
		}
		// Wrap hardware storage to implement storage.Backend
		return hardware.NewHardwareBackendAdapter(hwStorage), nil

	case hardware.CertStorageModeHybrid:
		// Use hybrid storage (hardware + external)
		if !config.EnableNVStorage {
			return nil, errors.New("EnableNVStorage must be true for hybrid mode")
		}

		// Create hardware storage
		hwConfig := &hardware.TPM2CertStorageConfig{
			BaseIndex:   config.NVBaseIndex,
			MaxCertSize: config.MaxCertSize,
			OwnerAuth:   config.OwnerAuth,
		}

		hwStorage, err := hardware.NewTPM2CertStorage(ks.tpm, hwConfig)
		if err != nil {
			return nil, err
		}

		// Create hybrid storage wrapper
		hybridStorage, err := hardware.NewHybridCertStorageFromBackend(hwStorage, config.ExternalStorage)
		if err != nil {
			return nil, err
		}
		// Wrap hybrid storage to implement storage.Backend
		return hardware.NewHardwareBackendAdapter(hybridStorage), nil

	default:
		return nil, errors.New("unknown certificate storage mode")
	}
}
