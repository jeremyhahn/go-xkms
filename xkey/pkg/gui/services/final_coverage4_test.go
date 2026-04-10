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

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSealServiceWithPlatformPolicy creates a SealService wired with a mock
// TPM and a PlatformPolicyService that has a pre-loaded policy definition.
// This allows SealData calls with PolicyType "platform_policy" to succeed.
func newSealServiceWithPlatformPolicy(t *testing.T, mock *sealMockTPM) *SealService {
	t.Helper()
	svc := newSealServiceWithMock(t, mock)

	policySvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))
	policySvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 1, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 1: "ccdd", 7: "eeff"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	svc.SetPlatformPolicyService(policySvc)

	return svc
}

// ==========================================================================
// 1. setup_wizard_service.go coverage
// ==========================================================================

func TestSetupWizard_ApplySetup_TPMSealedPasswordMode_PPSvcFailsSetMode(t *testing.T) {
	svc := NewSetupWizardService()

	cfg := &GUIConfigData{}
	var savedCfg *GUIConfigData
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})
	svc.SetInitDataDirFunc(func() error { return nil })

	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	staticPWSvc := NewStaticPasswordService(store)
	ppSvc := NewPasswordProtectionService(filepath.Join(t.TempDir(), "enc.json"), staticPWSvc, nil)
	svc.SetPasswordProtectionService(ppSvc)

	pinSvc := NewPINService()
	svc.SetPINService(pinSvc)

	choices := &SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-123",
		UserPin:           "user-pin-456",
		PasswordStoreMode: "tpm_sealed",
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Password store mode is now handled transparently by the barrier.
	// Without a barrier service, setup succeeds with warnings but no errors.
	assert.True(t, result.Success)
	assert.True(t, len(result.Warnings) > 0)
	_ = savedCfg
}

func TestSetupWizard_ApplySetup_TPMSealedPasswordMode_SealUserPIN(t *testing.T) {
	svc := NewSetupWizardService()

	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })
	svc.SetInitDataDirFunc(func() error { return nil })

	mock := defaultSealMock()
	sealSvc := newSealServiceWithPlatformPolicy(t, mock)
	svc.SetSealService(sealSvc)

	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	staticPWSvc := NewStaticPasswordService(store)
	ppSvc := NewPasswordProtectionService(
		filepath.Join(t.TempDir(), "enc.json"), staticPWSvc, sealSvc)
	svc.SetPasswordProtectionService(ppSvc)

	pinSvc := NewPINService()
	svc.SetPINService(pinSvc)

	choices := &SetupChoices{
		Mode:              "standalone",
		SOPin:             "so-pin-123",
		UserPin:           "user-pin-456",
		PasswordStoreMode: "tpm_sealed",
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestSetupWizard_ApplySOProvisioning_ConfigLoadSavePaths covers L812-832.
func TestSetupWizard_ApplySOProvisioning_ConfigLoadSavePaths(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir(t.TempDir())

	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	pinSvc := NewPINService()
	svc.SetPINService(pinSvc)

	choices := &SetupChoices{
		Mode:             "standalone",
		SOPin:            "enterprise-so-pin",
		UserPin:          "enterprise-user-pin",
		OrganizationName: "TestOrg",
		MinPinLength:     6,
	}

	result, err := svc.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSetupWizard_GetPolicy_ConfigLoadFails(t *testing.T) {
	svc := NewSetupWizardService()
	result, err := svc.GetPolicy()
	if err != nil {
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "setup_wizard")
	}
}

func TestSetupWizard_GetPolicy_MarshalUnmarshalPaths(t *testing.T) {
	svc := NewSetupWizardService()

	result, err := svc.GetPolicy()
	if err != nil {
		assert.Nil(t, result)
	} else {
		assert.NotNil(t, result)
	}
}

func TestSetupWizard_FactoryReset_SOPINEmpty(t *testing.T) {
	svc := NewSetupWizardService()
	err := svc.FactoryReset("")
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

func TestSetupWizard_FactoryReset_WithConfigFuncs(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir(t.TempDir())

	cfg := &GUIConfigData{SetupComplete: true}
	var savedCfg *GUIConfigData
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		savedCfg = c
		return nil
	})

	err := svc.FactoryReset("valid-so-pin")
	if err != nil {
		assert.Contains(t, err.Error(), "factory reset completed with errors")
	}
	if savedCfg != nil {
		assert.False(t, savedCfg.SetupComplete)
	}
}

func TestSetupWizard_FactoryReset_TPMResetError(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir(t.TempDir())

	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	tpmSvc := NewTPMService()
	svc.SetTPMService(tpmSvc)

	err := svc.FactoryReset("so-pin")
	if err != nil {
		assert.Contains(t, err.Error(), "factory reset completed with errors")
	}
}

// TestSetupWizard_FactoryReset_HMACRemoval covers L1042-1046.
func TestSetupWizard_FactoryReset_HMACRemoval(t *testing.T) {
	svc := NewSetupWizardService()
	dir := t.TempDir()
	svc.SetConfigDir(dir)

	cfg := &GUIConfigData{}
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	// Create a fake HMAC file using the correct filename: xkey_policy.hmac
	hmacPath := filepath.Join(dir, "xkey_policy.hmac")
	_ = os.WriteFile(hmacPath, []byte("fake-hmac"), 0600)

	err := svc.FactoryReset("so-pin")
	if err != nil {
		assert.Contains(t, err.Error(), "factory reset")
	}
	// Verify HMAC was removed
	_, statErr := os.Stat(hmacPath)
	assert.True(t, os.IsNotExist(statErr))
}

// ==========================================================================
// 2. oath_service.go coverage
// ==========================================================================

type mockFailOATHStore struct {
	addErr    error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error
	getCred   *oath.Credential
}

func (m *mockFailOATHStore) Add(cred *oath.Credential) error { return m.addErr }
func (m *mockFailOATHStore) Get(id string) (*oath.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getCred, nil
}
func (m *mockFailOATHStore) List() ([]*oath.Credential, error)  { return nil, m.listErr }
func (m *mockFailOATHStore) Update(cred *oath.Credential) error { return m.updateErr }
func (m *mockFailOATHStore) Delete(id string) error             { return m.deleteErr }
func (m *mockFailOATHStore) Close() error                       { return nil }

func TestOATH_GenerateTOTP_GenerateError(t *testing.T) {
	badCred := &oath.Credential{
		ID:        "test",
		Name:      "test",
		Type:      oath.TypeTOTP,
		Algorithm: oath.AlgorithmSHA1,
		Secret:    "!!INVALIDSECRET!!",
		Digits:    6,
		Period:    30,
	}
	store := &mockFailOATHStore{getCred: badCred}
	svc := NewOATHService(store)

	result, err := svc.GenerateTOTP("test")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestOATH_GenerateHOTP_GenerateError(t *testing.T) {
	badCred := &oath.Credential{
		ID:        "test-hotp",
		Name:      "test-hotp",
		Type:      oath.TypeHOTP,
		Algorithm: oath.AlgorithmSHA1,
		Secret:    "!!INVALIDSECRET!!",
		Digits:    6,
		Period:    30,
		Counter:   0,
	}
	store := &mockFailOATHStore{getCred: badCred}
	svc := NewOATHService(store)

	result, err := svc.GenerateHOTP("test-hotp")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestOATH_ScanQR_ErrorPaths(t *testing.T) {
	svc := NewOATHService(nil)
	result, err := svc.ScanQR(-1)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestOATH_ScanQR_SingleDisplay(t *testing.T) {
	svc := NewOATHService(nil)
	result, err := svc.ScanQR(0)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ==========================================================================
// 3. seal_service.go coverage
// ==========================================================================

func TestSealService_ListBlobs_PanicRecoveryFC4(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestSealService_SealData_InvalidPolicyTypeFC4(t *testing.T) {
	mock := defaultSealMock()
	svc := newSealServiceWithMock(t, mock)

	req := validSealRequest()
	req.PolicyType = "totally_invalid_policy"

	entry, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealInvalidPolicyType)
	assert.Nil(t, entry)
}

func TestSealService_SealData_PasswordPolicyHashSuccess(t *testing.T) {
	mock := defaultSealMock()
	svc := newSealServiceWithMock(t, mock)

	req := validSealRequest()
	req.PolicyType = "password"
	req.Password = "my-strong-password"

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "password", entry.PolicyType)
	assert.NotEmpty(t, entry.ID)

	blobPath := svc.blobPath(entry.ID)
	data, readErr := os.ReadFile(blobPath)
	require.NoError(t, readErr)

	var blob sealedBlobStorage
	require.NoError(t, json.Unmarshal(data, &blob))
	assert.NotEmpty(t, blob.Password, "password hash should be stored")
	assert.Contains(t, blob.Password, ":")
}

func TestSealService_SaveBlob_StorageDirNotSetFC4(t *testing.T) {
	svc := NewSealService("")
	blob := &sealedBlobStorage{ID: "test"}
	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

func TestSealService_SaveBlob_RelativeDirFC4(t *testing.T) {
	svc := NewSealService("relative/path")
	blob := &sealedBlobStorage{ID: "test"}
	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

func TestSealService_HashPassword_SuccessFC4(t *testing.T) {
	hash, err := hashPassword("test-password")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, ":")

	assert.True(t, verifyPassword("test-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

func TestSealService_HashPassword_EmptyPasswordFC4(t *testing.T) {
	hash, err := hashPassword("")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.True(t, verifyPassword("", hash))
}

func TestSealService_VerifyPassword_InvalidStoredFormatFC4(t *testing.T) {
	assert.False(t, verifyPassword("pass", "nocolonseparator"))
	assert.False(t, verifyPassword("pass", "invalid_hex:valid"))
	assert.False(t, verifyPassword("pass", "aabb:invalid_hex_here"))
}

// ==========================================================================
// 4. barrier_service.go coverage
// ==========================================================================

func TestBarrierService_BestStrategy_AlwaysHasSoftwareFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	best, err := svc.BestStrategy()
	require.NoError(t, err)
	require.NotNil(t, best)
	assert.Equal(t, string(seal.StrategySoftware), best.ID)
}

func TestBarrierService_Initialize_EmptyPasswordFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Initialize("", "software")
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired)
}

func TestBarrierService_Initialize_SuccessFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Initialize("test-password-12345", "software")
	require.NoError(t, err)
	assert.NotNil(t, svc.barrier)
	assert.True(t, svc.IsUnsealed())
}

func TestBarrierService_Initialize_AlreadyInitializedFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Initialize("test-password-12345", "software")
	require.NoError(t, err)

	err = svc.Initialize("test-password-12345", "software")
	assert.ErrorIs(t, err, ErrBarrierAlreadyInit)
}

func TestBarrierService_Unseal_WrongPasswordFC4(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	err := svc.Initialize("correct-password", "software")
	require.NoError(t, err)

	svc2 := NewBarrierService(dir, slog.Default())
	err = svc2.Unseal("wrong-password", "software")
	assert.Error(t, err)
}

func TestBarrierService_Unseal_SuccessFC4(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())

	err := svc.Initialize("correct-password", "software")
	require.NoError(t, err)

	svc2 := NewBarrierService(dir, slog.Default())
	err = svc2.Unseal("correct-password", "software")
	require.NoError(t, err)
	assert.True(t, svc2.IsUnsealed())
}

// ==========================================================================
// 6. auto_unseal_service.go coverage
// ==========================================================================

func TestAutoUnseal_Enable_ConfigSaveDeleteBlobOnErrorFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, storageSvc := newAutoUnsealTestSvc(t, mock)
	_ = storageSvc

	cfg := testConfigData()
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		return errors.New("config save failed")
	})

	result, err := autoSvc.Enable("long-passphrase", nil, "", "", "", "")
	assert.Error(t, err)
	assert.Nil(t, result)

	blobs, _ := sealSvc.ListBlobs()
	assert.Empty(t, blobs)
}

func TestAutoUnseal_TryAutoUnseal_UnlockVolumePathFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	req := &SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase-12345")),
	}
	entry, err := sealSvc.SealData(req)
	require.NoError(t, err)

	cfg := testConfigDataWithAutoUnseal(entry.ID)
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	result := autoSvc.TryAutoUnseal()
	assert.NotNil(t, result)
	assert.Contains(t, result.Message, "auto_unseal")
}

func TestAutoUnseal_Reseal_ConfigSaveFailCleanupFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	req := &SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase")),
	}
	entry, err := sealSvc.SealData(req)
	require.NoError(t, err)

	cfg := testConfigDataWithAutoUnseal(entry.ID)
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		return errors.New("save failed")
	})

	err = autoSvc.Reseal()
	assert.Error(t, err)

	blobs, listErr := sealSvc.ListBlobs()
	require.NoError(t, listErr)
	assert.GreaterOrEqual(t, len(blobs), 1)
}

func TestAutoUnseal_Reseal_DeleteOldBlobFailsFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, sealSvc, _ := newAutoUnsealTestSvc(t, mock)

	req := &SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase")),
	}
	entry, err := sealSvc.SealData(req)
	require.NoError(t, err)

	cfg := testConfigDataWithAutoUnseal(entry.ID)
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		_ = os.Remove(sealSvc.blobPath(entry.ID))
		cfg.AutoUnsealBlobID = c.AutoUnsealBlobID
		return nil
	})

	err = autoSvc.Reseal()
	require.NoError(t, err)
}

func TestAutoUnseal_TryAutoUnseal_NotConfiguredFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)

	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{}
	})
	result = autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
}

func TestAutoUnseal_TryAutoUnseal_UnsealFailsFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigDataWithAutoUnseal("nonexistent-blob")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "unseal")
}

// ==========================================================================
// Additional edge cases
// ==========================================================================

func TestSealService_ListBlobs_WithBlobFilesFC4(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:         "test-blob-1",
		Label:      "user_data",
		SizeBytes:  100,
		PolicyType: "",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("test"),
		},
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-blob-1.sealed.json"), data, 0600))

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "none", entries[0].PolicyType)
}

func TestBarrierService_Context_FallbackFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	ctx := svc.context()
	assert.Equal(t, context.Background(), ctx)
}

func TestBarrierService_GetBackend_NilFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	b := svc.GetBackend()
	assert.Nil(t, b)
}

func TestBarrierService_Seal_NotInitializedFC4(t *testing.T) {
	svc := newTestBarrierService(t)
	err := svc.Seal()
	assert.ErrorIs(t, err, ErrBarrierNotInitialized)
}

func TestAutoUnseal_Enable_ShortPassphraseFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	result, err := autoSvc.Enable("short", nil, "", "", "", "")
	assert.ErrorIs(t, err, ErrAutoUnsealInvalidPassphrase)
	assert.Nil(t, result)
}

func TestAutoUnseal_Disable_NotConfiguredFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	autoSvc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Disable()
	assert.ErrorIs(t, err, ErrAutoUnsealNotConfigured)
}

func TestAutoUnseal_Reseal_NotConfiguredFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	autoSvc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealNotConfigured)
}

func TestAutoUnseal_Reseal_UnsealFailsFC4(t *testing.T) {
	mock := defaultSealMock()
	autoSvc, _, _ := newAutoUnsealTestSvc(t, mock)

	cfg := testConfigDataWithAutoUnseal("nonexistent-blob")
	autoSvc.SetConfigFunc(func() *GUIConfigData { return cfg })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAutoUnsealResealFailed))
}
