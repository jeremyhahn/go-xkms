// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/jeremyhahn/go-xkms/pkg/storage/mocks"
)

// TestCertStorageConfig_Validate_Success proves that every valid
// configuration combination is accepted.
func TestCertStorageConfig_Validate_Success(t *testing.T) {
	external := mocks.NewMockCertStorage()

	tests := []struct {
		name   string
		config *CertStorageConfig
	}{
		{
			name: "external mode with external storage",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: external,
				MaxCertificates: 10,
			},
		},
		{
			name: "hybrid mode with external storage and hardware enabled",
			config: &CertStorageConfig{
				Mode:                  hardware.CertStorageModeHybrid,
				ExternalStorage:       external,
				EnableHardwareStorage: true,
				MaxCertificates:       10,
			},
		},
		{
			name: "hardware mode with hardware enabled",
			config: &CertStorageConfig{
				Mode:                  hardware.CertStorageModeHardware,
				EnableHardwareStorage: true,
				MaxCertificates:       10,
			},
		},
		{
			name: "default config with external storage supplied",
			config: func() *CertStorageConfig {
				cfg := DefaultCertStorageConfig()
				cfg.ExternalStorage = external
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
		})
	}
}

// TestCertStorageConfig_Validate_Errors proves that every invalid
// configuration is rejected with a typed error (errs.Message), reachable
// with errors.As, rather than an inline errors.New value (#700).
func TestCertStorageConfig_Validate_Errors(t *testing.T) {
	external := mocks.NewMockCertStorage()

	tests := []struct {
		name    string
		config  *CertStorageConfig
		wantMsg string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantMsg: "certificate storage config cannot be nil",
		},
		{
			name: "external mode missing external storage",
			config: &CertStorageConfig{
				Mode: hardware.CertStorageModeExternal,
			},
			wantMsg: "external storage required for external mode",
		},
		{
			name: "hybrid mode missing external storage",
			config: &CertStorageConfig{
				Mode:                  hardware.CertStorageModeHybrid,
				EnableHardwareStorage: true,
			},
			wantMsg: "external storage required for hybrid mode",
		},
		{
			name: "hybrid mode missing hardware storage",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeHybrid,
				ExternalStorage: external,
			},
			wantMsg: "hardware storage must be enabled for hybrid mode",
		},
		{
			name: "hardware mode missing hardware storage",
			config: &CertStorageConfig{
				Mode: hardware.CertStorageModeHardware,
			},
			wantMsg: "hardware storage must be enabled for hardware mode",
		},
		{
			name: "unknown mode",
			config: &CertStorageConfig{
				Mode: hardware.CertStorageMode("carrier-pigeon"),
			},
			wantMsg: "unknown certificate storage mode: carrier-pigeon",
		},
		{
			name: "negative max certificates",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: external,
				MaxCertificates: -1,
			},
			wantMsg: "max certificates cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if err.Error() != tt.wantMsg {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.wantMsg)
			}
			var typed *errs.Message
			if !errors.As(err, &typed) {
				t.Errorf("Validate() error = %v, want *errs.Message", err)
			}
		})
	}
}
