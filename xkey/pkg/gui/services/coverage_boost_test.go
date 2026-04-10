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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// PIN Service coverage boost
// ===========================================================================

func TestPINService_VerifySOPIN_NotConfigured(t *testing.T) {
	svc := newTestPINService(nil)
	err := svc.VerifySOPIN("some-pin")
	assert.True(t, errors.Is(err, ErrPINServiceNotConfigured))
}

func TestPINService_VerifySOPIN_ManagerError(t *testing.T) {
	errTest := errors.New("test: so pin verify error")
	mgr := &mockPINBackendWithSOPINErr{
		mockPINBackend: mockPINBackend{strategy: pin.StrategySoftware},
		verifySOPINErr: errTest,
	}
	svc := newTestPINService(mgr)

	err := svc.VerifySOPIN("wrong-so-pin")
	assert.Equal(t, errTest, err)
}

func TestPINService_VerifySOPIN_Success(t *testing.T) {
	mgr := &mockPINBackendWithSOPINErr{
		mockPINBackend: mockPINBackend{strategy: pin.StrategySoftware},
		verifySOPINErr: nil,
	}
	svc := newTestPINService(mgr)

	err := svc.VerifySOPIN("correct-so-pin")
	assert.NoError(t, err)
}

// mockPINBackendWithSOPINErr extends mockPINBackend to add configurable
// VerifySOPIN error behavior. The base mockPINBackend always returns nil
// from VerifySOPIN, making it impossible to test the error path.
type mockPINBackendWithSOPINErr struct {
	mockPINBackend
	verifySOPINErr error
}

func (m *mockPINBackendWithSOPINErr) VerifySOPIN(_ string) error {
	return m.verifySOPINErr
}

// ===========================================================================
// Barrier Service coverage boost
// ===========================================================================

func TestBarrierService_ProbeStrategies_TPMReturnsNil(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return nil // Sealer function returns nil.
	})

	strategies := svc.ProbeStrategies()

	require.Len(t, strategies, 2, "TPM strategy entry should still appear")
	// Software strategy.
	assert.Equal(t, string(seal.StrategySoftware), strategies[0].ID)
	assert.True(t, strategies[0].Available)
	// TPM2 strategy marked as unavailable.
	assert.Equal(t, string(seal.StrategyTPM2), strategies[1].ID)
	assert.False(t, strategies[1].Available, "TPM strategy should be unavailable when sealer is nil")
	assert.True(t, strategies[1].HardwareBacked)
}

func TestBarrierService_assembleStrategy_Software(t *testing.T) {
	svc := newTestBarrierService(t)
	strategy, err := svc.assembleStrategy("software")
	require.NoError(t, err)
	assert.Equal(t, seal.StrategySoftware, strategy.ID())
}

func TestBarrierService_assembleStrategy_TPM_NilFunc(t *testing.T) {
	svc := newTestBarrierService(t)
	// tpmSealerFn is nil → TPM2 strategy unavailable.
	_, err := svc.assembleStrategy("tpm2")
	assert.Error(t, err)
	var unavail *ErrBarrierStrategyUnavailable
	assert.ErrorAs(t, err, &unavail)
}

func TestBarrierService_assembleStrategy_TPM_CanSealFalse(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: false}
	})
	_, err := svc.assembleStrategy("tpm2")
	assert.Error(t, err)
}

func TestBarrierService_assembleStrategy_TPM_Available(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return &mockSealer{canSeal: true}
	})
	strategy, err := svc.assembleStrategy("tpm2")
	require.NoError(t, err)
	assert.Equal(t, seal.StrategyTPM2, strategy.ID())
}

func TestBarrierService_assembleStrategy_UnknownStrategy(t *testing.T) {
	svc := newTestBarrierService(t)
	_, err := svc.assembleStrategy("unknown")
	assert.Error(t, err)
}

func TestBarrierService_context_NilCtx(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	// ctx is nil (SetContext not called).
	ctx := svc.context()
	assert.NotNil(t, ctx, "should fall back to context.Background()")
}

func TestBarrierService_context_SetCtx(t *testing.T) {
	svc := newTestBarrierService(t)
	expected := context.Background()
	svc.SetContext(expected)
	assert.Equal(t, expected, svc.context())
}

func TestBarrierService_Unseal_WrongPassword(t *testing.T) {
	svc := newTestBarrierService(t)

	// Initialize with a known password.
	err := svc.Initialize("correct-password", "software")
	require.NoError(t, err)

	// Seal.
	err = svc.Seal()
	require.NoError(t, err)

	// Unseal with wrong password.
	err = svc.Unseal("wrong-password", "software")
	assert.Error(t, err, "unsealing with wrong password must fail")
}

func TestBarrierService_IsUnsealed_AfterUnseal(t *testing.T) {
	svc := newTestBarrierService(t)

	// Before init, should be sealed.
	assert.False(t, svc.IsUnsealed())

	// Initialize.
	err := svc.Initialize("test-pw", "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())

	// Seal.
	require.NoError(t, svc.Seal())
	assert.False(t, svc.IsUnsealed())

	// Unseal.
	require.NoError(t, svc.Unseal("test-pw", "software"))
	assert.True(t, svc.IsUnsealed())
}

// ===========================================================================
// App Service coverage boost
// ===========================================================================

func TestAppService_SetKeyCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.keyCountFunc)

	svc.SetKeyCountFunc(func() int { return 42 })
	assert.NotNil(t, svc.keyCountFunc)
	assert.Equal(t, 42, svc.keyCountFunc())
}

func TestAppService_SetBridgeStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.bridgeStatusFunc)

	svc.SetBridgeStatusFunc(func() bool { return true })
	assert.NotNil(t, svc.bridgeStatusFunc)
	assert.True(t, svc.bridgeStatusFunc())
}

func TestAppService_SetServerAddressFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.serverAddressFn)

	svc.SetServerAddressFunc(func() string { return "10.0.0.1:9443" })
	assert.NotNil(t, svc.serverAddressFn)
	assert.Equal(t, "10.0.0.1:9443", svc.serverAddressFn())
}

func TestAppService_SetRemoteKeyCountFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.remoteKeyCountFn)

	svc.SetRemoteKeyCountFunc(func() int { return 99 })
	assert.NotNil(t, svc.remoteKeyCountFn)
	assert.Equal(t, 99, svc.remoteKeyCountFn())
}

func TestAppService_GetStatus_WithServerAddressAndRemoteKeys(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetServerConnectedFunc(func() bool { return true })
	svc.SetServerAddressFunc(func() string { return "192.168.1.100:8443" })
	svc.SetRemoteKeyCountFunc(func() int { return 15 })
	svc.SetKeyCountFunc(func() int { return 7 })
	svc.SetBridgeStatusFunc(func() bool { return true })

	status := svc.GetStatus()
	assert.True(t, status.ServerConnected)
	assert.Equal(t, "192.168.1.100:8443", status.ServerAddress)
	assert.Equal(t, 15, status.RemoteKeyCount)
	assert.Equal(t, 7, status.KeyCount)
	assert.True(t, status.BridgeRunning)
	assert.Equal(t, "xkmsd", status.Mode)
}

func TestAppService_GetStatus_AllCallbacks(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetKeyCountFunc(func() int { return 3 })
	svc.SetBridgeStatusFunc(func() bool { return false })
	svc.SetServerConnectedFunc(func() bool { return false })
	svc.SetServerAddressFunc(func() string { return "" })
	svc.SetRemoteKeyCountFunc(func() int { return 0 })
	svc.SetOATHCountFunc(func() int { return 10 })
	svc.SetFIDO2CountFunc(func() int { return 4 })
	svc.SetPIVCertCountFunc(func() int { return 1 })
	svc.SetTPMStatusFunc(func() (bool, bool, bool) { return false, false, false })
	svc.SetStorageStatusFunc(func() (bool, bool) { return false, false })
	svc.SetSealStatusFunc(func() (bool, string, bool) { return false, "", false })
	svc.SetPINStatusFunc(func() (bool, bool, string) { return false, false, "" })
	svc.SetPhoneStatusFunc(func() (bool, string) { return false, "" })

	status := svc.GetStatus()
	assert.Equal(t, 3, status.KeyCount)
	assert.False(t, status.BridgeRunning)
	assert.Equal(t, "standalone", status.Mode)
	assert.Equal(t, 10, status.OATHAccountCount)
	assert.Equal(t, 4, status.FIDO2CredCount)
	assert.Equal(t, 1, status.PIVCertCount)
}

// ===========================================================================
// Seal Service coverage boost
// ===========================================================================

func TestSealService_saveBlob_EmptyStorageDir(t *testing.T) {
	svc := NewSealService("")
	blob := &sealedBlobStorage{
		ID:    "test-blob",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed,
		"saveBlob with empty storageDir must return ErrSealStorageFailed")
}

func TestSealService_saveBlob_RelativeStorageDir(t *testing.T) {
	svc := NewSealService("relative/path")
	blob := &sealedBlobStorage{
		ID:    "test-blob",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed,
		"saveBlob with relative storageDir must return ErrSealStorageFailed")
}

func TestSealService_ListBlobs_SkipsSubdirectories(t *testing.T) {
	svc := newSealServiceWithMock(t, defaultSealMock())

	// Seal a valid blob.
	req := validSealRequest()
	_, err := svc.SealData(req)
	require.NoError(t, err)

	// Create a subdirectory inside the storage directory.
	subdir := filepath.Join(svc.storageDir, "subdir.json")
	require.NoError(t, os.MkdirAll(subdir, 0700))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Len(t, blobs, 1, "subdirectory entries should be skipped")
}

func TestSealService_ListBlobs_MixedContent(t *testing.T) {
	svc := newSealServiceWithMock(t, defaultSealMock())

	// Create valid blobs.
	for i := 0; i < 3; i++ {
		req := validSealRequest()
		req.Label = "blob-" + string(rune('a'+i))
		_, err := svc.SealData(req)
		require.NoError(t, err)
	}

	// Add noise files.
	require.NoError(t, os.WriteFile(
		filepath.Join(svc.storageDir, "README.txt"),
		[]byte("not a blob"), 0600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(svc.storageDir, "bad.json"),
		[]byte("{{{invalid"), 0600,
	))
	// Subdirectory named with .json extension.
	require.NoError(t, os.MkdirAll(
		filepath.Join(svc.storageDir, "fake-dir.json"), 0700,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Len(t, blobs, 3, "only valid sealed blobs should be returned")
}

// ===========================================================================
// Platform Policy Service coverage boost
// ===========================================================================

func TestPlatformPolicyService_validatePlatformPolicyDigests_EmptyDigests(t *testing.T) {
	svc := newPolicyServiceWithMock(t, defaultPolicyMock())

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{}, // Empty digests.
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result, "empty digests should return nil (unknown)")
}

func TestPlatformPolicyService_validatePlatformPolicyDigests_NoTPM(t *testing.T) {
	// No TPM accessor set: verifyDigests will fail, so result should be nil.
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabb"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result, "TPM unavailable should return nil (unknown)")
}

func TestPlatformPolicyService_validatePlatformPolicyDigests_Valid(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabbccdd", 7: "11223344"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	require.NotNil(t, result)
	assert.True(t, *result)
}

func TestPlatformPolicyService_validatePlatformPolicyDigests_Mismatch(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "ffffffff", 7: "11223344"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	require.NotNil(t, result)
	assert.False(t, *result)
}

func TestPlatformPolicyService_verifyDigests_InvalidStoredHex(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "zzzz_invalid_hex"},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

func TestPlatformPolicyService_GetStatus_NoTPM(t *testing.T) {
	// Create a service with a stored policy but no TPM accessor.
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)

	// Manually store a policy.
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 7: "ccdd"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Configured)
	// Valid should be false because verifyDigests fails without TPM.
	assert.False(t, status.Valid)
}

func TestPlatformPolicyService_GetPlatformPolicyAsPCRPolicy_ValidFalse(t *testing.T) {
	// Test the path where validatePlatformPolicyDigests returns false.
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Create a policy.
	_, err := svc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	// Change the PCR values so validation returns false.
	mock.pcrBanksOverride = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
				{ID: 7, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
			},
		},
	}

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.NotNil(t, policy.Valid)
	assert.False(t, *policy.Valid)
}

func TestPlatformPolicyService_GetPlatformPolicyAsPCRPolicy_NoTPM(t *testing.T) {
	// When TPM is unavailable, Valid should be nil (unknown).
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Nil(t, policy.Valid, "Valid should be nil when TPM is unavailable")
}

func TestPlatformPolicyService_savePolicy_AtomicWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "policy")
	policyPath := filepath.Join(dir, "platform.policy")
	svc := NewPlatformPolicyService(policyPath)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabb", 7: "ccdd"},
	}

	err := svc.savePolicy(def)
	require.NoError(t, err)

	// Verify file exists and is valid JSON.
	data, readErr := os.ReadFile(policyPath)
	require.NoError(t, readErr)

	var loaded PlatformPolicyDefinition
	require.NoError(t, json.Unmarshal(data, &loaded))
	assert.Equal(t, "sha256", loaded.Bank)
	assert.Equal(t, "aabb", loaded.Digests[0])

	// Verify temp file is cleaned up.
	_, statErr := os.Stat(policyPath + ".tmp")
	assert.True(t, os.IsNotExist(statErr))
}

func TestPlatformPolicyService_VerifyPolicy_EmptyDigests(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Store a policy with empty digests.
	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{},
	}
	svc.policy.Store(def)

	// verifyDigests iterates over stored digests; with empty digests,
	// all comparisons pass (nothing to compare), so result should be true.
	valid, err := svc.VerifyPolicy()
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPlatformPolicyService_CreatePolicy_TPMReturnsNilForAccessor(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "p.policy"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))

	_, err := svc.CreatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyTPMNotAvailable)
}

func TestPlatformPolicyService_UpdatePolicy_ReadPCRsError(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	// Create first.
	_, err := svc.CreatePolicy([]int{0}, "sha256")
	require.NoError(t, err)

	// Now fail ReadPCRs.
	mock.pcrBanksErr = errors.New("tpm read failure")

	_, err = svc.UpdatePolicy([]int{0}, "sha256")
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

// ===========================================================================
// OATH Service coverage boost
// ===========================================================================

func TestOATHService_GenerateTOTP_NonExistentAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.GenerateTOTP("does-not-exist-id")
	assert.Error(t, err)
}

func TestOATHService_GenerateHOTP_NonExistentAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("does-not-exist-id")
	assert.Error(t, err)
}

func TestOATHService_AddAccount_DuplicateURI(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct1, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.NotNil(t, acct1)

	// Adding the same URI should fail because the store rejects duplicate credentials.
	_, err = svc.AddAccount(uri)
	assert.Error(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
}

func TestOATHService_SetStore_DeferredInit(t *testing.T) {
	svc := NewOATHService(nil)

	// Verify operations fail without store.
	_, err := svc.GenerateTOTP("some-id")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)

	_, err = svc.GenerateHOTP("some-id")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)

	// Wire a store.
	store := oath.NewMemoryStore()
	svc.SetStore(store)

	// Now add and verify.
	uri := "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	code, err := svc.GenerateTOTP(acct.ID)
	require.NoError(t, err)
	assert.Len(t, code.Code, 6)
}

func TestOATHService_ScanQR_NoDisplay(t *testing.T) {
	// In CI without a display, ScanQR should return an error.
	// We test that it does not panic.
	svc := NewOATHService(nil)
	_, err := svc.ScanQR(0)
	assert.Error(t, err)
}

// ===========================================================================
// Setup Wizard Service coverage boost
// ===========================================================================

func TestSetupWizardService_GetStartupState_SetupComplete(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.True(t, state.SetupComplete)
	assert.Empty(t, state.EnterpriseWizardMode)
}

func TestSetupWizardService_GetStartupState_NilConfig(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData { return nil })

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.False(t, state.SetupComplete)
}

func TestSetupWizardService_GetStartupState_NoConfigFunc(t *testing.T) {
	svc := NewSetupWizardService()
	// configFunc is nil.

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.False(t, state.SetupComplete)
}

func TestSetupWizardService_GetStartupState_WithPINService(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})

	pinMgr := &wizardMockPINBackend{
		strategy:   pin.StrategySoftware,
		soPINSet:   true,
		userPINSet: false,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.True(t, state.SOPINSet)
	assert.False(t, state.UserPINSet)
}

func TestSetupWizardService_GetStartupState_EnterpriseSOProvisioning(t *testing.T) {
	// configDir is set but no HMAC file exists, and setup is not complete.
	tmpDir := t.TempDir()
	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.False(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	assert.Equal(t, "so_provisioning", state.EnterpriseWizardMode)
}

func TestSetupWizardService_GetStartupState_EnterpriseUserOnboarding(t *testing.T) {
	// Create HMAC file to simulate enterprise mode.
	tmpDir := t.TempDir()
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, os.WriteFile(hmacPath, []byte("fake-hmac"), 0600))

	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	assert.True(t, state.EnterpriseMode)
	assert.Equal(t, "user_onboarding", state.EnterpriseWizardMode)
}

func TestSetupWizardService_ApplySOProvisioning_MissingSOPIN(t *testing.T) {
	svc := NewSetupWizardService()
	_, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "",
	})
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

func TestSetupWizardService_ApplySOProvisioning_InvalidMode(t *testing.T) {
	svc := NewSetupWizardService()
	_, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "invalid_mode",
		SOPin: "123456",
	})
	assert.ErrorIs(t, err, ErrSetupInvalidDeploymentMode)
}

func TestSetupWizardService_ApplySOProvisioning_NilBarrierService(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(tmpDir)

	// PIN service is required.
	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	// Set up minimal config infrastructure.
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "123456",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier service nil -> warning.
	assert.Contains(t, result.Warnings, "barrier service unavailable")
	assert.False(t, result.SetupComplete, "SO provisioning should not mark setup complete")
}

func TestSetupWizardService_ApplySOProvisioning_NilPINService(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(t.TempDir())

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: "123456",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success, "must fail when PIN service is nil")
	assert.True(t, len(result.Errors) > 0)
}

func TestSetupWizardService_ApplyUserOnboarding_NotSOProvisioned(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir(t.TempDir()) // No HMAC file.

	_, err := svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:   "123456",
		UserPIN: "654321",
	})
	assert.ErrorIs(t, err, ErrSetupNotSOProvisioned)
}

func TestSetupWizardService_ApplyUserOnboarding_NilPINService(t *testing.T) {
	tmpDir := t.TempDir()
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, os.WriteFile(hmacPath, []byte("fake-hmac"), 0600))

	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)
	// pinSvc is nil.

	_, err := svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:   "123456",
		UserPIN: "654321",
	})
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestSetupWizardService_ApplyUserOnboarding_SOPINVerifyFailed(t *testing.T) {
	tmpDir := t.TempDir()
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, os.WriteFile(hmacPath, []byte("fake-hmac"), 0600))

	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)

	// PIN manager with a known SO PIN.
	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    "correct-pin",
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	_, err := svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:   "wrong-pin",
		UserPIN: "654321",
	})
	assert.ErrorIs(t, err, ErrSetupSOPINVerifyFailed)
}

func TestSetupWizardService_ApplyUserOnboarding_Success(t *testing.T) {
	tmpDir := t.TempDir()
	hmacPath := config.PolicyHMACPath(tmpDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacPath), 0700))
	require.NoError(t, os.WriteFile(hmacPath, []byte("fake-hmac"), 0600))

	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)
	svc.SetContext(context.Background())
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set up config functions.
	configFunc, configSave := newTestConfigPair(&GUIConfigData{SetupComplete: false})
	svc.SetConfigFunc(configFunc)
	svc.SetConfigSaveFunc(configSave)

	// Set up event emitter.
	var eventLog []*events.Event
	svc.SetEventEmitter(func(e events.Event) {
		eventLog = append(eventLog, &e)
	})

	// Set up PIN service with correct SO PIN.
	pinMgr := &wizardMockPINBackend{
		strategy: pin.StrategySoftware,
		soPIN:    "123456",
		soPINSet: true,
	}
	pinSvc := newWizardPINService(pinMgr)
	svc.SetPINService(pinSvc)

	// Set up barrier service.
	barrierDir := filepath.Join(tmpDir, "barrier-test")
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	barrierSvc.SetContext(context.Background())
	svc.SetBarrierService(barrierSvc)

	result, err := svc.ApplyUserOnboarding(&UserOnboardingChoices{
		SOPIN:           "123456",
		UserPIN:         "654321",
		BarrierPassword: "test-barrier-pw",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.SetupComplete)

	// Verify config was persisted.
	saved := configFunc()
	assert.True(t, saved.SetupComplete)
	assert.True(t, saved.BarrierInitialized)

	// Verify user onboarded event.
	onboardedEvt := lastEventOfType(&eventLog, events.EventUserOnboarded)
	require.NotNil(t, onboardedEvt)
}

func TestSetupWizardService_GetPolicy_LoadsFromConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Create a config with a policy.
	cfg := config.DefaultConfig()
	cfg.Policy = *config.DefaultPolicy()
	cfg.Policy.OrganizationName = "Test Org"
	require.NoError(t, config.Save(cfg))

	svc := NewSetupWizardService()
	svc.SetConfigDir(tmpDir)

	policyMap, err := svc.GetPolicy()
	require.NoError(t, err)
	require.NotNil(t, policyMap)

	// Verify the policy map contains the expected organization name.
	orgName, ok := policyMap["organization_name"]
	assert.True(t, ok)
	assert.Equal(t, "Test Org", orgName)
}

func TestSetupWizardService_ApplySetup_WithPINService_SOAndUser(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	pinMgr := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := newWizardPINService(pinMgr)
	tw.svc.SetPINService(pinSvc)

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		SetHierarchyAuth: true,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.True(t, result.SetupComplete)

	// PIN manager should have both PINs set.
	assert.True(t, pinMgr.soPINSet)
	assert.True(t, pinMgr.userPINSet)
	assert.Equal(t, testSOPin, pinMgr.soPIN)
	assert.Equal(t, testUserPin, pinMgr.userPIN)

	// Event payload should report PINs as set.
	completedEvt := lastEventOfType(tw.eventLog, events.EventSetupCompleted)
	require.NotNil(t, completedEvt)
	payload, ok := completedEvt.Payload.(events.SetupCompletedPayload)
	require.True(t, ok)
	assert.True(t, payload.SOPINSet)
	assert.True(t, payload.UserPINSet)
}

func TestSetupWizardService_ProbeEnvironment_StorageServiceAvailable(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetStorageService(NewStorageService())

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.NotNil(t, probe)
}

func TestSetupWizardService_ProbeEnvironment_LUKSCheck(t *testing.T) {
	svc := NewSetupWizardService()
	// LUKS availability depends on the system; just verify no panic.
	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	assert.NotNil(t, probe)
	// LUKSAvailable is system-dependent, so we don't assert its value.
}

func TestSetupWizardService_ApplySetup_AutoUnseal(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})

	// Enable auto-unseal.
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		EnableAutoUnseal: true,
	})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.True(t, result.SetupComplete)
}

func TestSetupWizardService_SetConfigDir(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir("/tmp/test-config")
	assert.Equal(t, "/tmp/test-config", svc.configDir)
}

// ===========================================================================
// Barrier Service - BestStrategy edge cases
// ===========================================================================

func TestBarrierService_BestStrategy_TPMNotAvailable(t *testing.T) {
	svc := newTestBarrierService(t)
	svc.SetTPMSealerFunc(func() types.Sealer {
		return nil // Returns nil sealer.
	})

	best, err := svc.BestStrategy()
	require.NoError(t, err)
	// TPM2 is listed but not available, so software should be best.
	assert.Equal(t, string(seal.StrategySoftware), best.ID)
}

// ===========================================================================
// Seal Service - SealData with backend field preserved
// ===========================================================================

func TestSealService_SealData_BackendFieldPreserved(t *testing.T) {
	svc := newSealServiceWithMock(t, defaultSealMock())
	req := validSealRequest()

	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Load the blob and verify the sealed data has the backend set.
	blob, err := svc.loadBlobByID(entry.ID)
	require.NoError(t, err)
	assert.Equal(t, types.BackendTypeTPM2, blob.SealedData.Backend)
}

func TestSealService_UnsealData_PasswordEmptyOnNonPasswordBlob(t *testing.T) {
	svc := newSealServiceWithMock(t, defaultSealMock())

	// Seal without password.
	original := "test-data"
	req := &SealRequest{
		Label: "no-pw",
		Data:  base64.StdEncoding.EncodeToString([]byte(original)),
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Unseal with empty password should succeed.
	b64, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)
	decoded, _ := base64.StdEncoding.DecodeString(b64)
	assert.Equal(t, original, string(decoded))
}

// ===========================================================================
// Platform Policy Service - error sentinels
// ===========================================================================

func TestPlatformPolicyServiceErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrPolicyTPMNotAvailable,
		ErrPolicyInvalidPCRs,
		ErrPolicyInvalidBank,
		ErrPolicyNotConfigured,
		ErrPolicySaveFailed,
		ErrPolicyLoadFailed,
		ErrPolicyVerifyFailed,
		ErrPolicyExportFailed,
		ErrPolicyNoClient,
		ErrPolicyInvalidName,
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

// TestYubiKeyDetectionResult_JSONFieldNames guards against the Wails
// field-name regression where the Svelte UI expected capitalized Go field
// names but the struct used lowercase JSON tags, causing the YubiKey
// detection result to silently appear as "not found" in the GUI.
func TestYubiKeyDetectionResult_JSONFieldNames(t *testing.T) {
	t.Parallel()

	result := YubiKeyDetectionResult{
		Found:       true,
		LibraryPath: "/usr/lib/x86_64-linux-gnu/libykcs11.so",
	}
	b, err := json.Marshal(result)
	require.NoError(t, err)
	s := string(b)
	assert.Contains(t, s, `"found":true`)
	assert.Contains(t, s, `"library_path":"/usr/lib/x86_64-linux-gnu/libykcs11.so"`)
	assert.NotContains(t, s, `"Found"`)
	assert.NotContains(t, s, `"LibraryPath"`)

	errResult := YubiKeyDetectionResult{Found: false, Error: "boom"}
	b2, err := json.Marshal(errResult)
	require.NoError(t, err)
	assert.Contains(t, string(b2), `"found":false`)
	assert.Contains(t, string(b2), `"error":"boom"`)
}

// TestPKCS11Service_DetectYubiKey_Filesystem exercises the real
// filesystem probe and asserts the result is consistent with whether the
// library actually exists on this host. It does not require the library
// to be present, but if it is, it must be reported as found.
func TestPKCS11Service_DetectYubiKey_Filesystem(t *testing.T) {
	t.Parallel()

	svc := &PKCS11Service{log: testLogger()}
	res := svc.DetectYubiKey()

	if _, err := os.Stat("/usr/lib/x86_64-linux-gnu/libykcs11.so"); err == nil {
		assert.True(t, res.Found, "library exists on host but DetectYubiKey returned not found")
		assert.NotEmpty(t, res.LibraryPath)
	} else {
		// Library may still exist at another known path; only assert
		// the contract: if Found is false, an error message is set.
		if !res.Found {
			assert.NotEmpty(t, res.Error)
		}
	}
}
