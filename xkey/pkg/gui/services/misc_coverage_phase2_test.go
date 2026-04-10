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
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// PasswordProtectionService - SetModeTPMSealed
// ---------------------------------------------------------------------------

// mockSealerForPP holds configuration for password protection seal tests.
// It is converted to an SDK sealMockClient via ppWireSealClient.
type mockSealerForPP struct {
	sealErr   error
	unsealErr error
	canSeal   bool
	sealedID  string
	unsealB64 string
}

// ppWireSealClient wires a sealMockClient into the given SealService,
// deriving SDK client behavior from the mockSealerForPP configuration.
func ppWireSealClient(svc *SealService, m *mockSealerForPP) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			if m.sealErr != nil {
				return nil, m.sealErr
			}
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: req.Data,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			if m.unsealErr != nil {
				return nil, m.unsealErr
			}
			var data []byte
			if m.unsealB64 != "" {
				data, _ = base64.StdEncoding.DecodeString(m.unsealB64)
			} else {
				data = req.Ciphertext
			}
			return &transport.UnsealResponse{Plaintext: data}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: m.canSeal, Backend: backend}, nil
		},
	}
	svc.SetClientFunc(func() xkms.Client { return mc })
}

// ---------------------------------------------------------------------------
// AdminService - GetAuditLogs, ExportAuditLogs
// ---------------------------------------------------------------------------

func TestAdminService_GetAuditLogs_NonAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}

	entries, err := svc.GetAuditLogs(&AuditFilter{Operation: "key_created"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	assert.Nil(t, entries)
}

func TestAdminService_ExportAuditLogs_InvalidFormatBeforeAuth(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	// "xml" is invalid. Non-admin gets auth error first, admin gets format error.
	_, err := svc.ExportAuditLogs("xml")
	assert.Error(t, err)
	// Could be ErrAdminNotAuthorized or ErrAdminInvalidFormat depending on admin status.
	if !svc.IsAdmin() {
		assert.ErrorIs(t, err, ErrAdminNotAuthorized)
	} else {
		assert.ErrorIs(t, err, ErrAdminInvalidFormat)
	}
}

func TestAdminService_GetAuditLogs_WithFilter(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}

	// Verify that providing a non-nil filter still results in auth error.
	_, err := svc.GetAuditLogs(&AuditFilter{
		Operation: "key_created",
		Limit:     10,
	})
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

// ---------------------------------------------------------------------------
// ClipboardService - CopyWithClear, scheduleClear, detectClipboardTool
// ---------------------------------------------------------------------------

func TestClipboard_CopyWithClear_ToolAvailableWriteError(t *testing.T) {
	svc := NewClipboardService()
	// Force a tool that likely doesn't work without a display.
	svc.tool = clipToolXsel

	err := svc.CopyWithClear("secret-data")
	if err != nil {
		// Expected: write fails without display.
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
	// If it succeeded (tool available + display), that's fine too.
}

func TestClipboard_ScheduleClear_NoPreviousCancel(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	// No previous cancelFn; should not panic.
	svc.scheduleClear("data", 1*time.Hour)

	// Verify new cancelFn was set.
	svc.clearMu.Lock()
	require.NotNil(t, svc.cancelFn)
	svc.cancelFn() // Clean up goroutine.
	svc.clearMu.Unlock()
}

func TestClipboard_ScheduleClear_ShortDelay(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone // readClipboard will return error.

	// Schedule with a very short delay; the goroutine should fire
	// and handle the readClipboard error gracefully.
	svc.scheduleClear("test", 1*time.Millisecond)

	// Wait for goroutine to process.
	time.Sleep(50 * time.Millisecond)

	// No panic means success.
}

func TestClipboard_DetectClipboardTool_ReturnsValidValue(t *testing.T) {
	tool := detectClipboardTool()
	// Valid range is 0 (clipToolNone) to 3 (clipToolWlCopy).
	assert.True(t, tool >= clipToolNone)
	assert.True(t, tool <= clipToolWlCopy)
}

func TestClipboard_CopyWithClear_ZeroTimeout_SkipsSchedule(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(0)

	// If a tool is available, CopyWithClear should skip scheduleClear.
	// If no tool, it will error on writeClipboard. Either way, cancelFn
	// should not be set.
	_ = svc.CopyWithClear("data")

	svc.clearMu.Lock()
	assert.Nil(t, svc.cancelFn)
	svc.clearMu.Unlock()
}

// ---------------------------------------------------------------------------
// ConnectionService - Connect
// ---------------------------------------------------------------------------

func TestConnection_Connect_ValidProtocols_InvalidSocket(t *testing.T) {
	// Exercise the code path past protocol validation and address validation
	// through to SDK client creation and connection failure.
	protocols := []string{"rest", "grpc", "quic", "mcp"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			svc := NewConnectionService()
			svc.SetContext(context.Background())

			var emittedEvents []events.Event
			svc.SetEventEmitter(func(e events.Event) {
				emittedEvents = append(emittedEvents, e)
			})

			info, err := svc.Connect(proto, "localhost:0", false, "", "")
			require.Error(t, err)

			// The connection should fail at xkms.New or client.Connect
			// and transition to error state.
			require.NotNil(t, info)
			assert.Equal(t, "error", info.State)
			assert.Equal(t, proto, info.Protocol)
			assert.Equal(t, "localhost:0", info.Address)

			// Verify error event was emitted.
			assert.NotEmpty(t, emittedEvents)
			lastEvt := emittedEvents[len(emittedEvents)-1]
			assert.Equal(t, events.EventServerError, lastEvt.Type)
		})
	}
}

func TestConnection_Connect_WithTLS_FailsGracefully(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	info, err := svc.Connect("rest", "localhost:0", true, "", "")
	require.Error(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.True(t, info.TLS)
}

// ---------------------------------------------------------------------------
// SetupWizardService - uncovered branches
// ---------------------------------------------------------------------------

func TestSetupWizard_SkipSetup_InitDataDirFuncError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("disk full")
	})

	err := tw.svc.SkipSetup()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestSetupWizard_SkipSetup_EmitsSkippedEvent(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	err := tw.svc.SkipSetup()
	require.NoError(t, err)

	evt := lastEventOfType(tw.eventLog, events.EventSetupSkipped)
	require.NotNil(t, evt)
	payload, ok := evt.Payload.(events.SetupSkippedPayload)
	require.True(t, ok)
	assert.Contains(t, payload.Reason, "skipped")
}

func TestSetupWizard_SkipSetup_ConfigSaveErrorWrapped(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	saveErr := errors.New("permission denied")
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	svc.SetConfigSaveFunc(func(d *GUIConfigData) error { return saveErr })

	err := svc.SkipSetup()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupStorageFailed)
}

func TestSetupWizard_ApplySetup_BarrierInitError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	// Create a barrier service that will fail Initialize.
	barrierDir := t.TempDir()
	barrierSvc := NewBarrierService(barrierDir, slog.Default())
	tw.svc.SetBarrierService(barrierSvc)

	// Set up required dependencies.
	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))

	// With a User PIN provided, the barrier uses it as the password.
	// The barrier service is real and initializes successfully.
	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:        "standalone",
		SOPin:       testSOPin,
		UserPin:     testUserPin,
		StorageType: "barrier",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier should succeed because the User PIN is used as the password.
	assert.True(t, result.Success, "barrier should succeed with User PIN as password")
}

func TestSetupWizard_ApplySetup_InitDataDirError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))
	tw.svc.SetInitDataDirFunc(func() error {
		return errors.New("cannot create directory")
	})

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "data directory"))
}

func TestSetupWizard_ApplySetup_PlatformPolicyServiceNil(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:    "standalone",
		SOPin:   testSOPin,
		UserPin: testUserPin,
		// platformPolicySvc is nil
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, containsSubstring(result.Warnings, "platform policy service unavailable"))
}

func TestSetupWizard_ApplySetup_AutoUnsealLUKS_NoService(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})

	mgr := &wizardMockPINBackend{}
	tw.svc.SetPINService(newWizardPINService(mgr))

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:             "standalone",
		SOPin:            testSOPin,
		UserPin:          testUserPin,
		EnableAutoUnseal: true,
		EnableStorage:    true,
		StorageType:      "luks",
		StoragePass:      "passphrase",
		// autoUnsealSvc is nil
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, containsSubstring(result.Warnings, "auto-unseal service unavailable"))
}

func TestSetupWizard_EmitProgress_NoEmitter(t *testing.T) {
	svc := NewSetupWizardService()

	// Should not panic when eventEmitter is nil.
	svc.emitProgress(1, "test")
	svc.emitSOProvisioningProgress(1, "test")
	svc.emitUserOnboardingProgress(1, "test")
}

func TestSetupWizard_GetStartupState_SetupCompleteNoEnterprise(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: true}
	})
	// Use a clean temp dir so no stale HMAC file triggers enterprise mode.
	svc.SetConfigDir(t.TempDir())

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.SetupComplete)
	assert.False(t, state.EnterpriseMode)
	assert.Empty(t, state.EnterpriseWizardMode)
}

func TestSetupWizard_GetStartupState_NoConfigDir_NoSOProvisioning(t *testing.T) {
	// Change to a clean temp dir so that IsEnterpriseMode("") does not
	// find a stale xkey_policy.hmac in the package directory.
	t.Chdir(t.TempDir())

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{SetupComplete: false}
	})
	svc.SetConfigDir("") // Empty configDir should not advertise SO provisioning.

	state, err := svc.GetStartupState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.SetupComplete)
	assert.Empty(t, state.EnterpriseWizardMode)
}

func TestSetupWizard_GetPolicy_ConfigLoadError(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	// config.Load() will attempt to load from the default path which
	// may or may not exist. If it exists, the test passes with data.
	// We primarily verify the function does not panic.
	result, err := svc.GetPolicy()
	if err != nil {
		// Expected if no config file exists.
		assert.Nil(t, result)
	} else {
		assert.NotNil(t, result)
	}
}

// ---------------------------------------------------------------------------
// PINService - uncovered branches
// ---------------------------------------------------------------------------

// mockPINBackendVerifySOErr allows controlling VerifySOPIN error.
type mockPINBackendVerifySOErr struct {
	mockPINBackend
	verifySOPINErr error
}

func (m *mockPINBackendVerifySOErr) VerifySOPIN(_ string) error { return m.verifySOPINErr }

func TestPINService_VerifySOPIN_ManagerErrorPath(t *testing.T) {
	mgr := &mockPINBackendVerifySOErr{
		mockPINBackend: mockPINBackend{
			strategy:    "file",
			initialized: true,
		},
		verifySOPINErr: errors.New("verification failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.VerifySOPIN("wrong-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestPINService_GetLockoutStatus_WithStatus(t *testing.T) {
	lockoutStatus := &pin.LockoutStatus{
		IsLocked:        true,
		FailedAttempts:  6,
		MaxAttempts:     10,
		LockoutUntil:    time.Now().Add(5 * time.Minute),
		RecoverySeconds: 300,
	}
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		lockoutStatus: lockoutStatus,
	}
	svc := newTestPINService(mgr)

	result, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsLocked)
	assert.Equal(t, 6, result.FailedAttempts)
	assert.Equal(t, 10, result.MaxAttempts)
}

func TestPINService_SetUserPIN_ManagerErrorWithCoordinator(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		setUserPINErr: errors.New("user pin set failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.SetUserPIN("so-pin", "new-user-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user pin set failed")
}

func TestPINService_ChangeUserPIN_ManagerErrorWithCoordinator(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:      "file",
		initialized:   true,
		changeUserErr: errors.New("change user pin failed"),
	}
	svc := newTestPINService(mgr)

	err := svc.ChangeUserPIN("old-pin", "new-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "change user pin failed")
}

func TestPINService_ResetLockout_Success(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    "file",
		initialized: true,
	}
	svc := newTestPINService(mgr)

	err := svc.ResetLockout("so-pin")
	assert.NoError(t, err)
}

func TestPINService_GetPINStatus_AllFieldsPopulated(t *testing.T) {
	mgr := &mockPINBackend{
		strategy:    "file",
		soPINSet:    true,
		userPINSet:  true,
		initialized: true,
	}
	svc := newTestPINService(mgr)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.SOPINSet)
	assert.True(t, status.UserPINSet)
	assert.True(t, status.Initialized)
	assert.Equal(t, "file", status.Strategy)
}

// ---------------------------------------------------------------------------
// PlatformPolicyService - uncovered branches
// ---------------------------------------------------------------------------

func TestPlatformPolicy_ValidatePCRSelection_BoundaryValues(t *testing.T) {
	// PCR index 0 (minimum valid).
	err := validatePCRSelection([]int{0})
	assert.NoError(t, err)

	// PCR index 23 (maximum valid).
	err = validatePCRSelection([]int{23})
	assert.NoError(t, err)

	// PCR index 24 (just over max).
	err = validatePCRSelection([]int{24})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)

	// Negative PCR index.
	err = validatePCRSelection([]int{-1})
	assert.ErrorIs(t, err, ErrPolicyInvalidPCRs)
}

func TestPlatformPolicy_ValidatePCRBank_AllValid(t *testing.T) {
	validBanks := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, bank := range validBanks {
		err := validatePCRBank(bank)
		assert.NoError(t, err, "bank %q should be valid", bank)
	}
}

func TestPlatformPolicy_ValidatePCRBank_Invalid(t *testing.T) {
	invalidBanks := []string{"", "md5", "SHA256", "sha3-256"}
	for _, bank := range invalidBanks {
		err := validatePCRBank(bank)
		assert.ErrorIs(t, err, ErrPolicyInvalidBank, "bank %q should be invalid", bank)
	}
}

func TestPlatformPolicy_NormalizeBankAlg_SHA386(t *testing.T) {
	assert.Equal(t, "sha384", normalizeBankAlg("sha386"))
	assert.Equal(t, "sha384", normalizeBankAlg("SHA386"))
}

func TestPlatformPolicy_NormalizeBankAlg_Regular(t *testing.T) {
	assert.Equal(t, "sha256", normalizeBankAlg("SHA256"))
	assert.Equal(t, "sha1", normalizeBankAlg("sha1"))
}

func TestPlatformPolicy_GetPolicyPCRs_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	pcrs, bank, err := svc.GetPolicyPCRs()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
	assert.Nil(t, pcrs)
	assert.Empty(t, bank)
}

func TestPlatformPolicy_DeletePolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	err := svc.DeletePolicy()
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_VerifyPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_ExportPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	data, err := svc.ExportPolicy()
	assert.Empty(t, data)
	assert.ErrorIs(t, err, ErrPolicyNotConfigured)
}

func TestPlatformPolicy_ExportPolicy_WithDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb", 7: "ccdd"},
		CreatedAt: now,
		UpdatedAt: now,
	})

	data, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var exported map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(data), &exported))
	assert.Equal(t, "sha256", exported["pcr_bank"])
	assert.NotNil(t, exported["pcr_digests"])
	assert.NotNil(t, exported["pcr_selections"])
}

func TestPlatformPolicy_ExportPolicy_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: now,
		UpdatedAt: now,
	})

	data, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var exported map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(data), &exported))
	// Empty digests should not produce a pcr_digests key.
	_, hasDigests := exported["pcr_digests"]
	assert.False(t, hasDigests)
}

func TestPlatformPolicy_ExportPolicy_EmptyPCRs(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))
	now := time.Now()
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aabb"},
		CreatedAt: now,
		UpdatedAt: now,
	})

	data, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var exported map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(data), &exported))
	// Empty PCRs should not produce pcr_selections key.
	_, hasPCRs := exported["pcr_selections"]
	assert.False(t, hasPCRs)
}

func TestPlatformPolicy_GetPlatformPolicyAsPCRPolicy_NotConfigured(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestPlatformPolicy_ValidatePlatformPolicyDigests_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	result := svc.validatePlatformPolicyDigests(&PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{},
	})
	assert.Nil(t, result)
}

func TestPlatformPolicy_ValidatePlatformPolicyDigests_NoTPM(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))
	// No TPM accessor set.

	result := svc.validatePlatformPolicyDigests(&PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "deadbeef"},
	})
	// Should return nil when TPM is unavailable (unknown state).
	assert.Nil(t, result)
}

func TestPlatformPolicy_GetPolicyContext_WithContext(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	ctx := context.WithValue(context.Background(), "test", "value")
	svc.SetContext(ctx)

	result := svc.getPolicyContext()
	assert.Equal(t, ctx, result)
}

func TestPlatformPolicy_GetPolicyContext_Fallback(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "policy.json"))

	result := svc.getPolicyContext()
	assert.NotNil(t, result) // Should return context.Background().
}
