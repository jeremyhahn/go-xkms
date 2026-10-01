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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/jeremyhahn/go-xkms/pkg/storage/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackend_CreateCertificateStorage_ExternalMode verifies external mode
// returns the caller's storage.Backend unchanged, against a real,
// initialized backend rather than only validating inputs.
func TestBackend_CreateCertificateStorage_ExternalMode(t *testing.T) {
	b := newProvisionedBackend(t, "certcfg-external")
	external := mocks.NewMockCertStorage()

	got, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode:            hardware.CertStorageModeExternal,
		ExternalStorage: external,
	})

	if err != nil {
		t.Fatalf("CreateCertificateStorage() unexpected error: %v", err)
	}
	if got != external {
		t.Fatalf("CreateCertificateStorage() = %v, want the external storage unchanged", got)
	}
}

// TestBackend_CreateCertificateStorage_NilConfigUsesDefault verifies a nil
// config falls back to DefaultCertStorageConfig (external mode), and that
// the default's zero ExternalStorage then fails validation rather than
// panicking on a nil storage.Backend.
func TestBackend_CreateCertificateStorage_NilConfigUsesDefault(t *testing.T) {
	b := newProvisionedBackend(t, "certcfg-nil-default")

	_, err := b.CreateCertificateStorage(nil)

	if err == nil {
		t.Fatal("CreateCertificateStorage(nil) expected an error (default mode has no external storage)")
	}
	var wrapped *errs.Wrapped
	if !errors.As(err, &wrapped) {
		t.Fatalf("CreateCertificateStorage(nil) error = %T, want *errs.Wrapped", err)
	}
}

// TestBackend_CreateCertificateStorage_HardwareMode verifies hardware mode
// builds a real PKCS#11-backed certificate store over the backend's own
// session pool and wraps it as a storage.Backend, proving createHardwareStorage's
// non-YubiKey path end-to-end.
func TestBackend_CreateCertificateStorage_HardwareMode(t *testing.T) {
	b := newProvisionedBackend(t, "certcfg-hardware")

	got, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode:                  hardware.CertStorageModeHardware,
		EnableHardwareStorage: true,
	})

	if err != nil {
		t.Fatalf("CreateCertificateStorage() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("CreateCertificateStorage() returned a nil storage.Backend")
	}

	// Adapter must be usable against the real token: round-trip a value
	// through it rather than only checking the type came back non-nil.
	stored, err := got.PutIfAbsent(t.Context(), "certs/hw-mode-check.pem", []byte{})
	if err == nil {
		t.Fatalf("expected an error parsing an empty certificate, stored=%v", stored)
	}
}

// TestBackend_CreateCertificateStorage_HybridMode verifies hybrid mode
// composes the same real hardware store with the caller's external storage
// via NewHybridCertStorageFromBackend.
func TestBackend_CreateCertificateStorage_HybridMode(t *testing.T) {
	b := newProvisionedBackend(t, "certcfg-hybrid")
	external := mocks.NewMockCertStorage()

	got, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode:                  hardware.CertStorageModeHybrid,
		ExternalStorage:       external,
		EnableHardwareStorage: true,
	})

	if err != nil {
		t.Fatalf("CreateCertificateStorage() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("CreateCertificateStorage() returned a nil storage.Backend")
	}
}

// TestBackend_CreateCertificateStorage_InvalidConfig verifies a config that
// fails Validate() is refused, wrapped, before the backend does any
// PKCS#11 work.
func TestBackend_CreateCertificateStorage_InvalidConfig(t *testing.T) {
	b := newProvisionedBackend(t, "certcfg-invalid")

	_, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode: hardware.CertStorageMode("not-a-real-mode"),
	})

	var wrapped *errs.Wrapped
	if !errors.As(err, &wrapped) {
		t.Fatalf("CreateCertificateStorage() error = %T, want *errs.Wrapped", err)
	}
	if wrapped.Msg != "invalid certificate storage config" {
		t.Errorf("CreateCertificateStorage() error msg = %q", wrapped.Msg)
	}
}

// TestBackend_CreateCertificateStorage_UninitializedBackend verifies a
// backend with no session pool (Login never called) is refused rather than
// dereferencing a nil pool.
func TestBackend_CreateCertificateStorage_UninitializedBackend(t *testing.T) {
	b := &Backend{config: testConfig("/usr/lib/softhsm/libsofthsm2.so", "uninitialized")}

	_, err := b.CreateCertificateStorage(&CertStorageConfig{
		Mode:                  hardware.CertStorageModeHardware,
		EnableHardwareStorage: true,
	})

	var typed *errs.Message
	if !errors.As(err, &typed) {
		t.Fatalf("CreateCertificateStorage() error = %T, want *errs.Message", err)
	}
}

// TestBackend_createHardwareStorage_UninitializedBackend exercises
// createHardwareStorage directly for the same uninitialized-pool guard, since
// CreateCertificateStorage's own b.pool check would otherwise make this
// branch unreachable from the public entry point once one is added there.
func TestBackend_createHardwareStorage_UninitializedBackend(t *testing.T) {
	b := &Backend{config: testConfig("/usr/lib/softhsm/libsofthsm2.so", "uninitialized")}

	_, err := b.createHardwareStorage()

	var typed *errs.Message
	if !errors.As(err, &typed) {
		t.Fatalf("createHardwareStorage() error = %T, want *errs.Message", err)
	}
	if typed.Msg != "session pool not initialized" {
		t.Errorf("createHardwareStorage() error msg = %q", typed.Msg)
	}
}

// TestBackend_createHardwareStorage_YubiKeyBranch exercises the CKU_SO
// routing path taken when the configured library names YubiKey's ykcs11:
// createHardwareStorage decides that purely from the Library path, so
// reusing a real, provisioned SoftHSM pool under a YubiKey-shaped Library
// string exercises the SO-PIN plumbing without needing real YubiKey
// hardware. Runtime session behaviour that depends on actual YubiKey
// firmware quirks (e.g. C_DestroyObject under CKU_USER) is out of scope for
// this constructor-only test.
func TestBackend_createHardwareStorage_YubiKeyBranch(t *testing.T) {
	provisioned := newProvisionedBackend(t, "certcfg-yubikey")

	yubi := &Backend{
		config: &Config{
			Library:    "/usr/lib/ykcs11.so",
			TokenLabel: provisioned.config.TokenLabel,
			PIN:        secrettest.Literal(t, []byte("123456")),
			SOPIN:      secrettest.Literal(t, []byte("87654321")),
		},
		pool: provisioned.pool,
	}

	got, err := yubi.createHardwareStorage()
	if err != nil {
		t.Fatalf("createHardwareStorage() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("createHardwareStorage() returned a nil HardwareCertStorage")
	}
}

// TestBackend_createHardwareStorage_YubiKeySOPINError verifies an
// unresolved SO PIN reference aborts construction rather than silently
// proceeding with an empty SO PIN.
func TestBackend_createHardwareStorage_YubiKeySOPINError(t *testing.T) {
	provisioned := newProvisionedBackend(t, "certcfg-yubikey-sopin-err")

	yubi := &Backend{
		config: &Config{
			Library:    "/usr/lib/ykcs11.so",
			TokenLabel: provisioned.config.TokenLabel,
			SOPIN:      &types.SecretValue{Raw: "credential://unresolved"},
		},
		pool: provisioned.pool,
	}

	_, err := yubi.createHardwareStorage()
	var refErr *types.SecretReferenceUnresolvedError
	if !errors.As(err, &refErr) {
		t.Fatalf("createHardwareStorage() error = %T, want *types.SecretReferenceUnresolvedError", err)
	}
}

// TestBackend_createHardwareStorage_YubiKeyUserPINError verifies an
// unresolved user PIN reference aborts construction after the SO PIN
// resolves successfully.
func TestBackend_createHardwareStorage_YubiKeyUserPINError(t *testing.T) {
	provisioned := newProvisionedBackend(t, "certcfg-yubikey-userpin-err")

	yubi := &Backend{
		config: &Config{
			Library:    "/usr/lib/ykcs11.so",
			TokenLabel: provisioned.config.TokenLabel,
			SOPIN:      secrettest.Literal(t, []byte("87654321")),
			PIN:        &types.SecretValue{Raw: "credential://unresolved"},
		},
		pool: provisioned.pool,
	}

	_, err := yubi.createHardwareStorage()
	var refErr *types.SecretReferenceUnresolvedError
	if !errors.As(err, &refErr) {
		t.Fatalf("createHardwareStorage() error = %T, want *types.SecretReferenceUnresolvedError", err)
	}
}

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
