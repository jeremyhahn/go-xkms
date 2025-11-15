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
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// TestDefaultCertStorageConfig tests default configuration
func TestDefaultCertStorageConfig(t *testing.T) {
	config := DefaultCertStorageConfig()

	if config.Mode != hardware.CertStorageModeExternal {
		t.Errorf("Mode = %v, want CertStorageModeExternal", config.Mode)
	}

	if config.EnableNVStorage {
		t.Error("EnableNVStorage should be false by default")
	}

	if config.NVBaseIndex != 0x01800000 {
		t.Errorf("NVBaseIndex = %#x, want 0x01800000", config.NVBaseIndex)
	}

	if config.MaxCertSize != 2048 {
		t.Errorf("MaxCertSize = %d, want 2048", config.MaxCertSize)
	}

	if config.MaxCertificates != 4 {
		t.Errorf("MaxCertificates = %d, want 4", config.MaxCertificates)
	}
}

// TestCertStorageConfig_Validate tests configuration validation
func TestCertStorageConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *CertStorageConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid external mode",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: false,
		},
		{
			name: "external mode without storage",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "external storage required",
		},
		{
			name: "hybrid mode without storage",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeHybrid,
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "external storage required",
		},
		{
			name: "invalid max certificates (too low)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 0,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "max certificates must be between 1 and 10",
		},
		{
			name: "invalid max certificates (too high)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 11,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "max certificates must be between 1 and 10",
		},
		{
			name: "invalid max cert size (too small)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     511,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "max cert size must be between 512 and 4096",
		},
		{
			name: "invalid max cert size (too large)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     4097,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "max cert size must be between 512 and 4096",
		},
		{
			name: "invalid NV base index (too low)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x00FFFFFF,
			},
			wantErr: true,
			errMsg:  "NV base index must be in range",
		},
		{
			name: "invalid NV base index (too high)",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01C00000,
			},
			wantErr: true,
			errMsg:  "NV base index must be in range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if err.Error() != tt.errMsg && !containsCertConfig(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestTPM2KeyStore_CreateCertificateStorage tests storage creation
func TestTPM2KeyStore_CreateCertificateStorage(t *testing.T) {
	tests := []struct {
		name    string
		config  *CertStorageConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "external mode",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: false,
		},
		{
			name: "hardware mode enabled",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeHardware,
				EnableNVStorage: true,
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: false,
		},
		{
			name: "hardware mode without enable flag",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeHardware,
				EnableNVStorage: false,
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: true,
			errMsg:  "EnableNVStorage must be true",
		},
		{
			name: "hybrid mode enabled",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeHybrid,
				ExternalStorage: &mockCertStorage{},
				EnableNVStorage: true,
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: false,
		},
		{
			name: "nil config uses defaults",
			config: &CertStorageConfig{
				Mode:            hardware.CertStorageModeExternal,
				ExternalStorage: &mockCertStorage{},
				MaxCertificates: 4,
				MaxCertSize:     2048,
				NVBaseIndex:     0x01800000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create TPM keystore with simulator
			tpm := newMockTPM(t)
			defer tpm.Close()

			ks := &TPM2KeyStore{tpm: tpm}

			storage, err := ks.CreateCertificateStorage(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificateStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !containsCertConfig(err.Error(), tt.errMsg) {
					t.Errorf("CreateCertificateStorage() error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			}

			if err == nil && storage == nil {
				t.Error("CreateCertificateStorage() returned nil storage without error")
			}

			if err == nil && storage != nil {
				defer storage.Close()
			}
		})
	}
}

// Helper functions

// newMockTPM creates a TPM simulator for testing
func newMockTPM(t *testing.T) transport.TPMCloser {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		t.Fatalf("Failed to create TPM simulator: %v", err)
	}

	return &simulatorCloser{
		sim:       sim,
		transport: transport.FromReadWriter(sim),
	}
}

// mockCertStorage is a minimal mock for testing
type mockCertStorage struct{}

// Certificate storage methods
func (m *mockCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	return nil
}

func (m *mockCertStorage) GetCert(id string) (*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertStorage) DeleteCert(id string) error {
	return nil
}

func (m *mockCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	return nil
}

func (m *mockCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockCertStorage) ListCerts() ([]string, error) {
	return nil, nil
}

func (m *mockCertStorage) CertExists(id string) (bool, error) {
	return false, nil
}

// storage.Backend interface methods
func (m *mockCertStorage) Get(key string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertStorage) Put(key string, value []byte, opts *storage.Options) error {
	return nil
}

func (m *mockCertStorage) Delete(key string) error {
	return nil
}

func (m *mockCertStorage) List(prefix string) ([]string, error) {
	return nil, nil
}

func (m *mockCertStorage) Exists(key string) (bool, error) {
	return false, nil
}

func (m *mockCertStorage) Close() error {
	return nil
}

// containsCertConfig checks if haystack contains needle
func containsCertConfig(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
