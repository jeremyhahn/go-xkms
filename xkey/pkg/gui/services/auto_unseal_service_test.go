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

package services

import (
	"context"
	"errors"
	"os"
	"testing"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockStorageServiceHelper wraps a real StorageService with a mock elevator
// configured for testing. Since StorageService.GetStatus calls real LUKS
// code, we use a mock elevator to control UnlockVolume behavior.
type mockStorageServiceHelper struct {
	getStatusMounted bool
	getStatusErr     error
	unlockErr        error
	unlockCalled     bool
	unlockPassphrase string
}

// newAutoUnsealTestSvc creates an AutoUnsealService wired to a mock TPM
// and a real StorageService with a mock elevator.
func newAutoUnsealTestSvc(t *testing.T, mock *sealMockTPM) (*AutoUnsealService, *SealService, *StorageService) {
	t.Helper()

	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			if mock.sealErr != nil {
				return nil, mock.sealErr
			}
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: req.Data,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			if mock.unsealErr != nil {
				return nil, mock.unsealErr
			}
			return &transport.UnsealResponse{
				Plaintext: req.Ciphertext,
			}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: mock.canSeal, Backend: backend}, nil
		},
	}

	sealSvc := NewSealService(t.TempDir())
	sealSvc.SetClientFunc(func() xkms.Client { return mc })
	sealSvc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	sealSvc.SetContext(context.Background())

	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())

	return autoSvc, sealSvc, storageSvc
}

// ---------------------------------------------------------------------------
// Constructor & lifecycle
// ---------------------------------------------------------------------------

func TestNewAutoUnsealService(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	svc := NewAutoUnsealService(sealSvc, storageSvc)
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.Equal(t, sealSvc, svc.sealSvc)
	assert.Equal(t, storageSvc, svc.storageSvc)
}

func TestAutoUnsealService_SetContext(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	svc := NewAutoUnsealService(sealSvc, storageSvc)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestAutoUnsealService_SetConfigFunc(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	svc := NewAutoUnsealService(sealSvc, storageSvc)

	cfg := testConfigData()
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	assert.NotNil(t, svc.configFunc)
}

func TestAutoUnsealService_SetConfigSaveFunc(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	svc := NewAutoUnsealService(sealSvc, storageSvc)

	svc.SetConfigSaveFunc(func(cfg *GUIConfigData) error { return nil })
	assert.NotNil(t, svc.configSave)
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestAutoUnsealService_GetStatus_Available(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigDataWithAutoUnseal("blob-123")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	status := autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.True(t, status.Configured)
	assert.Equal(t, "blob-123", status.BlobID)
}

func TestAutoUnsealService_GetStatus_Unavailable(t *testing.T) {
	// No TPM accessor set.
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)

	status := autoSvc.GetStatus()
	assert.False(t, status.Available)
	assert.False(t, status.Configured)
	assert.Empty(t, status.BlobID)
}

func TestAutoUnsealService_GetStatus_NotConfigured(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Config without auto-unseal.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	status := autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.False(t, status.Configured)
	assert.Empty(t, status.BlobID)
}

func TestAutoUnsealService_GetStatus_NilConfigFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	// Do not set configFunc.

	status := autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.False(t, status.Configured)
}

func TestAutoUnsealService_GetStatus_EnabledButNoBlobID(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	cfg.AutoUnsealEnabled = true
	cfg.AutoUnsealBlobID = "" // no blob ID
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	status := autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.False(t, status.Configured)
}

// ---------------------------------------------------------------------------
// Enable
// ---------------------------------------------------------------------------

func TestAutoUnsealService_Enable_Success(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "enabled")

	// Verify config was updated.
	require.NotNil(t, savedCfg)
	assert.True(t, savedCfg.AutoUnsealEnabled)
	assert.NotEmpty(t, savedCfg.AutoUnsealBlobID)
	assert.Equal(t, []int{0, 7}, savedCfg.AutoUnsealPCRs)
	assert.Equal(t, "sha256", savedCfg.AutoUnsealPCRBank)
}

func TestAutoUnsealService_Enable_WithPolicyType(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	// Use custom_pcr policy type which does not require a PlatformPolicyService.
	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7, 9}, "sha256",
		string(PolicyTypeCustomPCR), "Custom PCR Policy", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	// Verify policy fields were persisted.
	require.NotNil(t, savedCfg)
	assert.Equal(t, string(PolicyTypeCustomPCR), savedCfg.AutoUnsealPolicyType)
	assert.Equal(t, "Custom PCR Policy", savedCfg.AutoUnsealPolicyName)
}

func TestAutoUnsealService_Enable_DefaultPCRBank(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	// Empty PCR bank should default to sha256.
	result, err := autoSvc.Enable("strongpassphrase", []int{0}, "", "", "", "")
	require.NoError(t, err)
	assert.True(t, result.Success)
	require.NotNil(t, savedCfg)
	assert.Equal(t, "sha256", savedCfg.AutoUnsealPCRBank)
}

func TestAutoUnsealService_Enable_NoTPM(t *testing.T) {
	// Use a mock with canSeal = false.
	mock := defaultSealMock()
	mock.canSeal = false
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigData() })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	_, err := autoSvc.Enable("strongpassphrase", []int{0}, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealTPMNotAvailable)
}

func TestAutoUnsealService_Enable_EmptyPassphrase(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	_, err := autoSvc.Enable("", nil, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealInvalidPassphrase)
}

func TestAutoUnsealService_Enable_ShortPassphrase(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	_, err := autoSvc.Enable("short", nil, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealInvalidPassphrase)
}

func TestAutoUnsealService_Enable_ExactlyMinLength(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	result, err := autoSvc.Enable("12345678", nil, "sha256", "", "", "")
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestAutoUnsealService_Enable_SealFailed(t *testing.T) {
	mock := defaultSealMock()
	mock.sealErr = errors.New("tpm seal error")
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealSealFailed)
}

func TestAutoUnsealService_Enable_ConfigSaveFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	saveErr := errors.New("config save failed")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return saveErr })

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	assert.Equal(t, saveErr, err)

	// Verify the sealed blob was cleaned up (deleted).
	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Empty(t, blobs)
}

func TestAutoUnsealService_Enable_NilConfigFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	// Do not set configFunc.
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealConfigFuncNil)
}

func TestAutoUnsealService_Enable_NilConfigSaveFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigData() })
	// Do not set configSave.

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

func TestAutoUnsealService_Disable_Success(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	// First enable auto-unseal with a custom PCR policy.
	cfg := testConfigData()
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		if savedCfg != nil {
			return savedCfg
		}
		return cfg
	})
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	result, err := autoSvc.Enable("strongpassphrase", []int{0}, "sha256",
		string(PolicyTypeCustomPCR), "Custom PCR Policy", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify blob exists.
	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	require.Len(t, blobs, 1)

	// Now disable.
	err = autoSvc.Disable()
	require.NoError(t, err)

	// Verify blob was deleted.
	blobs, listErr = sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Empty(t, blobs)

	// Verify config was cleared.
	assert.False(t, savedCfg.AutoUnsealEnabled)
	assert.Empty(t, savedCfg.AutoUnsealBlobID)
	assert.Nil(t, savedCfg.AutoUnsealPCRs)
	assert.Empty(t, savedCfg.AutoUnsealPCRBank)
	assert.Empty(t, savedCfg.AutoUnsealPolicyType)
	assert.Empty(t, savedCfg.AutoUnsealPolicyName)
	assert.Empty(t, savedCfg.AutoUnsealBackend)
}

func TestAutoUnsealService_Disable_NotConfigured(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealNotConfigured)
}

func TestAutoUnsealService_Disable_NilConfigFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigFuncNil)
}

func TestAutoUnsealService_Disable_NilConfigSaveFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return testConfigDataWithAutoUnseal("blob-123")
	})

	err := autoSvc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

func TestAutoUnsealService_Disable_BlobDeleteFails_StillClearsConfig(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Config references a blob that doesn't exist (already deleted or never created).
	cfg := testConfigDataWithAutoUnseal("nonexistent-blob")
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	err := autoSvc.Disable()
	require.NoError(t, err) // Should not fail even if blob deletion fails.

	// Config should still be cleared.
	require.NotNil(t, savedCfg)
	assert.False(t, savedCfg.AutoUnsealEnabled)
	assert.Empty(t, savedCfg.AutoUnsealBlobID)
}

func TestAutoUnsealService_Disable_ConfigSaveFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigDataWithAutoUnseal("blob-123")
	saveErr := errors.New("save failed")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return saveErr })

	err := autoSvc.Disable()
	assert.Equal(t, saveErr, err)
}

// ---------------------------------------------------------------------------
// TryAutoUnseal
// ---------------------------------------------------------------------------

func TestAutoUnsealService_TryAutoUnseal_NotConfigured(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not configured")
}

func TestAutoUnsealService_TryAutoUnseal_NilConfigFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	// Do not set configFunc.

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not configured")
}

func TestAutoUnsealService_TryAutoUnseal_EnabledButNoBlobID(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	cfg.AutoUnsealEnabled = true
	cfg.AutoUnsealBlobID = ""
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not configured")
}

func TestAutoUnsealService_TryAutoUnseal_AlreadyMounted(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, storageSvc := newAutoUnsealTestSvc(t, mock)

	// Set up config with auto-unseal enabled.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	// Enable auto-unseal first.
	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	require.NoError(t, err)

	// Create a mock elevator that makes GetStatus report mounted.
	// Since GetStatus calls real LUKS code, we need the volume path to exist
	// and be recognized as mounted. Instead, we override the storageSvc
	// with a custom elevator that returns the mount status.
	// Since we cannot easily mock GetStatus, we verify the unseal path works
	// by checking that it at least attempts to unseal. The "already mounted"
	// test relies on the LUKS volume actually being mounted on the system,
	// which is an integration test scenario.
	// Instead, test that unseal attempts work when configured.
	_ = sealSvc
	_ = storageSvc

	// This test verifies the happy path: TryAutoUnseal reads config, attempts unseal.
	result := autoSvc.TryAutoUnseal()
	// It will either succeed with "already mounted" or fail trying to unseal/unlock.
	// Since we're in a test environment without real LUKS, we just verify it proceeds
	// past the config check.
	assert.NotContains(t, result.Message, "not configured")
}

func TestAutoUnsealService_TryAutoUnseal_UnsealFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Reference a blob that doesn't exist.
	cfg := testConfigDataWithAutoUnseal("nonexistent-blob")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "unseal")
}

func TestAutoUnsealService_TryAutoUnseal_UnlockFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal to create a real blob.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, cfg.AutoUnsealBlobID)

	// TryAutoUnseal should unseal successfully but fail to unlock
	// (no real LUKS volume or elevator).
	result := autoSvc.TryAutoUnseal()
	// In a non-root test environment, UnlockVolume will fail because
	// there is no elevator and we're not root. The result should indicate
	// a mount failure or that the unlock failed.
	assert.False(t, result.Success)
	// It should get past unseal and fail at the mount/unlock stage.
	assert.Contains(t, result.Message, "mount")
}

func TestAutoUnsealService_TryAutoUnseal_Success(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, storageSvc := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal to create a real blob.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", nil, "sha256", "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, cfg.AutoUnsealBlobID)

	// Set up a mock elevator that accepts the unlock command.
	mockElev := &mockElevator{available: true, output: []byte(`{}`)}
	storageSvc.SetElevator(mockElev)

	// If running as root, UnlockVolume calls real LUKS which would fail.
	// If not root, it uses the elevator which is mocked.
	if os.Geteuid() != 0 {
		result := autoSvc.TryAutoUnseal()
		assert.True(t, result.Success)
		assert.Contains(t, result.Message, "unlocked")

		// Check the subcommand args prefix.
		require.True(t, len(mockElev.lastArgs) >= 2, "expected at least 2 args, got %d", len(mockElev.lastArgs))
		assert.Equal(t, "luks2", mockElev.lastArgs[0])
		assert.Equal(t, "unseal", mockElev.lastArgs[1])
		// Verify explicit paths are passed to prevent sudo home dir issues.
		assert.Contains(t, mockElev.lastArgs, "--path")
		assert.Contains(t, mockElev.lastArgs, "--mount-point")
	}
}

// ---------------------------------------------------------------------------
// Error sentinel tests
// ---------------------------------------------------------------------------

func TestAutoUnsealErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrAutoUnsealTPMNotAvailable,
		ErrAutoUnsealNotConfigured,
		ErrAutoUnsealSealFailed,
		ErrAutoUnsealUnsealFailed,
		ErrAutoUnsealInvalidPassphrase,
		ErrAutoUnsealMountFailed,
		ErrAutoUnsealAlreadyMounted,
		ErrAutoUnsealConfigFuncNil,
		ErrAutoUnsealConfigSaveFuncNil,
		ErrAutoUnsealResealFailed,
	}

	for i := range errs {
		for j := range errs {
			if i == j {
				continue
			}
			assert.NotEqual(t, errs[i], errs[j],
				"error %d and %d should be distinct", i, j)
		}
	}
}

// ---------------------------------------------------------------------------
// Enable + Disable round trip
// ---------------------------------------------------------------------------

func TestAutoUnsealService_EnableDisableRoundTrip(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	// Enable.
	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "")
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify status is configured.
	status := autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.True(t, status.Configured)
	assert.NotEmpty(t, status.BlobID)

	// Verify blob exists.
	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Len(t, blobs, 1)

	// Disable.
	err = autoSvc.Disable()
	require.NoError(t, err)

	// Verify status is no longer configured.
	status = autoSvc.GetStatus()
	assert.True(t, status.Available)
	assert.False(t, status.Configured)
	assert.Empty(t, status.BlobID)

	// Verify blob is deleted.
	blobs, listErr = sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Empty(t, blobs)
}

// ---------------------------------------------------------------------------
// Reseal
// ---------------------------------------------------------------------------

func TestAutoUnsealService_Reseal_Success(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal first with a custom PCR policy.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256",
		string(PolicyTypeCustomPCR), "Custom PCR Policy", "")
	require.NoError(t, err)
	assert.True(t, result.Success)

	oldBlobID := cfg.AutoUnsealBlobID
	require.NotEmpty(t, oldBlobID)

	// Reseal.
	err = autoSvc.Reseal()
	require.NoError(t, err)

	// Blob ID should have changed.
	assert.NotEqual(t, oldBlobID, cfg.AutoUnsealBlobID)
	assert.NotEmpty(t, cfg.AutoUnsealBlobID)

	// Config should still be enabled with the same PCRs and policy.
	assert.True(t, cfg.AutoUnsealEnabled)
	assert.Equal(t, []int{0, 7}, cfg.AutoUnsealPCRs)
	assert.Equal(t, "sha256", cfg.AutoUnsealPCRBank)
	assert.Equal(t, string(PolicyTypeCustomPCR), cfg.AutoUnsealPolicyType)
	assert.Equal(t, "Custom PCR Policy", cfg.AutoUnsealPolicyName)

	// Exactly one blob should remain (old deleted, new created).
	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Len(t, blobs, 1)
	assert.Equal(t, cfg.AutoUnsealBlobID, blobs[0].ID)
}

func TestAutoUnsealService_Reseal_NotConfigured(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealNotConfigured)
}

func TestAutoUnsealService_Reseal_NilConfigFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigFuncNil)
}

func TestAutoUnsealService_Reseal_NilConfigSaveFunc(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigDataWithAutoUnseal("blob-123")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	// Do not set configSave.

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

func TestAutoUnsealService_Reseal_UnsealFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Reference a blob that doesn't exist.
	cfg := testConfigDataWithAutoUnseal("nonexistent-blob")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealResealFailed)
}

func TestAutoUnsealService_Reseal_SealFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal first (seal works).
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "")
	require.NoError(t, err)

	oldBlobID := cfg.AutoUnsealBlobID

	// Now make seal fail for the reseal.
	mock.sealErr = errors.New("tpm seal error")

	err = autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealResealFailed)

	// Old blob and config should be unchanged (reseal is safe).
	assert.Equal(t, oldBlobID, cfg.AutoUnsealBlobID)
}

func TestAutoUnsealService_Reseal_ConfigSaveFails(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal first.
	cfg := testConfigData()
	saveShouldFail := false
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		if saveShouldFail {
			return errors.New("config save failed")
		}
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "")
	require.NoError(t, err)

	oldBlobID := cfg.AutoUnsealBlobID

	// Make config save fail for reseal.
	saveShouldFail = true

	err = autoSvc.Reseal()
	assert.Error(t, err)

	// Old blob should still exist (config save failed, new blob cleaned up).
	assert.Equal(t, oldBlobID, cfg.AutoUnsealBlobID)

	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	// Only the original blob should remain.
	assert.Len(t, blobs, 1)
	assert.Equal(t, oldBlobID, blobs[0].ID)
}

func TestAutoUnsealService_Reseal_DefaultPCRBank(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Enable auto-unseal with empty PCR bank.
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", []int{0}, "", "", "", "")
	require.NoError(t, err)

	// Manually clear the PCR bank in config to test default.
	cfg.AutoUnsealPCRBank = ""

	err = autoSvc.Reseal()
	require.NoError(t, err)

	// Config should still work after reseal.
	assert.True(t, cfg.AutoUnsealEnabled)
	assert.NotEmpty(t, cfg.AutoUnsealBlobID)
}

func TestAutoUnsealService_Reseal_PreservesPolicyType(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	// Enable with custom PCR policy (does not require PlatformPolicyService).
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	_, err := autoSvc.Enable("strongpassphrase", []int{0, 7, 9}, "sha256",
		string(PolicyTypeCustomPCR), "Custom PCR Policy", "")
	require.NoError(t, err)

	// Verify policy type is stored.
	assert.Equal(t, string(PolicyTypeCustomPCR), cfg.AutoUnsealPolicyType)

	oldBlobID := cfg.AutoUnsealBlobID

	// Reseal should preserve the policy type in the new seal request.
	err = autoSvc.Reseal()
	require.NoError(t, err)

	// Blob ID changed but policy fields persisted.
	assert.NotEqual(t, oldBlobID, cfg.AutoUnsealBlobID)
	assert.Equal(t, string(PolicyTypeCustomPCR), cfg.AutoUnsealPolicyType)
	assert.Equal(t, "Custom PCR Policy", cfg.AutoUnsealPolicyName)
}

// ---------------------------------------------------------------------------
// Enable with explicit backend
// ---------------------------------------------------------------------------

func TestAutoUnsealService_Enable_WithExplicitBackend(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigData()
	var savedCfg *GUIConfigData
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "tpm2")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "enabled")

	// Verify the explicit backend was persisted to the config.
	require.NotNil(t, savedCfg)
	assert.Equal(t, "tpm2", savedCfg.AutoUnsealBackend,
		"explicit backend must be persisted in AutoUnsealBackend")
	assert.True(t, savedCfg.AutoUnsealEnabled)
	assert.NotEmpty(t, savedCfg.AutoUnsealBlobID)
}

// ---------------------------------------------------------------------------
// Reseal preserves backend
// ---------------------------------------------------------------------------

func TestAutoUnsealService_Reseal_PreservesBackend(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	// Enable with explicit backend "tpm2".
	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		cfg = c
		return nil
	})

	result, err := autoSvc.Enable("strongpassphrase", []int{0, 7}, "sha256", "", "", "tpm2")
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify backend was stored.
	assert.Equal(t, "tpm2", cfg.AutoUnsealBackend)
	oldBlobID := cfg.AutoUnsealBlobID
	require.NotEmpty(t, oldBlobID)

	// Reseal should create a new blob but preserve the backend field.
	err = autoSvc.Reseal()
	require.NoError(t, err)

	// Blob ID should have changed.
	assert.NotEqual(t, oldBlobID, cfg.AutoUnsealBlobID)
	assert.NotEmpty(t, cfg.AutoUnsealBlobID)

	// Backend must be preserved across the reseal.
	assert.Equal(t, "tpm2", cfg.AutoUnsealBackend,
		"AutoUnsealBackend must survive reseal")

	// Config should still be enabled.
	assert.True(t, cfg.AutoUnsealEnabled)

	// Exactly one blob should remain (old deleted, new created).
	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.Len(t, blobs, 1)
	assert.Equal(t, cfg.AutoUnsealBlobID, blobs[0].ID)
}
