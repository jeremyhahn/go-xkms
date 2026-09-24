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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateCertificateStorage_Modes exercises every CertStorageConfig.Mode
// branch against a real, provisioned SoftHSM2 token: external returns the
// caller's backend unchanged, hardware and hybrid both construct a working
// hardware.HardwareCertStorage-backed adapter through createHardwareStorage,
// and nil config falls back to DefaultCertStorageConfig.
func TestCreateCertificateStorage_Modes(t *testing.T) {
	b := newProvisionedBackend(t, "cert-config-modes")
	external := storage.New()

	t.Run("nil config uses defaults (external)", func(t *testing.T) {
		got, err := b.CreateCertificateStorage(nil)
		require.Error(t, err, "default config has no ExternalStorage, so Validate must reject it")
		assert.Nil(t, got)
	})

	t.Run("external", func(t *testing.T) {
		got, err := b.CreateCertificateStorage(&CertStorageConfig{
			Mode:            hardware.CertStorageModeExternal,
			ExternalStorage: external,
		})
		require.NoError(t, err)
		assert.Same(t, external, got, "external mode must return the caller's storage unchanged")
	})

	t.Run("hardware", func(t *testing.T) {
		got, err := b.CreateCertificateStorage(&CertStorageConfig{
			Mode:                  hardware.CertStorageModeHardware,
			EnableHardwareStorage: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, got)
	})

	t.Run("hybrid", func(t *testing.T) {
		got, err := b.CreateCertificateStorage(&CertStorageConfig{
			Mode:                  hardware.CertStorageModeHybrid,
			ExternalStorage:       external,
			EnableHardwareStorage: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, got)
	})

	t.Run("invalid config surfaces Validate's error", func(t *testing.T) {
		_, err := b.CreateCertificateStorage(&CertStorageConfig{Mode: hardware.CertStorageMode("bogus")})
		require.Error(t, err)
	})
}

// TestCreateCertificateStorage_UninitializedBackend verifies the guard
// clause against a Backend whose session pool was never created.
func TestCreateCertificateStorage_UninitializedBackend(t *testing.T) {
	b := &Backend{}
	_, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode:            hardware.CertStorageModeExternal,
		ExternalStorage: storage.New(),
	})
	require.Error(t, err)
}
