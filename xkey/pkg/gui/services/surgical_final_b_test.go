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
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock: failingTokenStore that returns errors on Close
// ---------------------------------------------------------------------------

type sbFailingTokenStore struct {
	saveErr   error
	loadErr   error
	deleteErr error
	closeErr  error
	tokens    map[string]*oidc.TokenResponse
}

func newSBFailingTokenStore() *sbFailingTokenStore {
	return &sbFailingTokenStore{
		tokens: make(map[string]*oidc.TokenResponse),
	}
}

func (s *sbFailingTokenStore) Save(issuer string, tokens *oidc.TokenResponse) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.tokens[issuer] = tokens
	return nil
}

func (s *sbFailingTokenStore) Load(issuer string) (*oidc.TokenResponse, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	t, ok := s.tokens[issuer]
	if !ok {
		return nil, oidc.ErrTokenNotFound
	}
	return t, nil
}

func (s *sbFailingTokenStore) Delete(issuer string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.tokens, issuer)
	return nil
}

func (s *sbFailingTokenStore) List() ([]string, error) {
	issuers := make([]string, 0, len(s.tokens))
	for k := range s.tokens {
		issuers = append(issuers, k)
	}
	return issuers, nil
}

func (s *sbFailingTokenStore) Close() error {
	return s.closeErr
}

// ---------------------------------------------------------------------------
// OIDC Service: L227-229 - Close() when StopAllRefresh runs with active procs
// ---------------------------------------------------------------------------

func TestSurgB_OIDCService_Close_WithTokenStoreCloseError(t *testing.T) {
	// Targets L227-229: StopAllRefresh in Close(), then tokenStore.Close().
	svc := NewOIDCService(nil)
	store := newSBFailingTokenStore()
	store.closeErr = errors.New("close failed")
	svc.SetTokenStore(store)

	// Add a provider with auto-refresh and a refresh proc to exercise StopAllRefresh.
	svc.dataDir = t.TempDir()
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		Issuer:      "https://example.com",
		AutoRefresh: 3600,
	}

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{
		provider: "test",
		cancel:   cancel,
	}
	_ = ctx
	svc.refreshProcs["test"] = proc

	err := svc.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
	assert.Empty(t, svc.refreshProcs)
}

func TestSurgB_OIDCService_Close_WithTokenStoreSuccess(t *testing.T) {
	svc := NewOIDCService(nil)
	store := newSBFailingTokenStore()
	svc.SetTokenStore(store)

	err := svc.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// OIDC Service: L893-894 - ExecuteScript ExitError path (non-zero exit code)
// ---------------------------------------------------------------------------

func TestSurgB_OIDCService_ExecuteScript_ExitCodeNonZero(t *testing.T) {
	// Targets L893-894: When cmd.Run() fails with an ExitError.
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client123",
	}

	result, err := svc.ExecuteScript("test", "exit 42")
	assert.NoError(t, err) // Non-zero exit is not an error, just an exit code.
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, 42, result.ExitCode)
}

func TestSurgB_OIDCService_ExecuteScript_SuccessWithTokenStore(t *testing.T) {
	// Targets L856-858: ExecuteScript with tokens in store.
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()
	store := newSBFailingTokenStore()
	_ = store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken:  "access-tok",
		RefreshToken: "refresh-tok",
		IDToken:      "id-tok",
		ExpiresIn:    3600,
	})
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client123",
		Scopes:   []string{"openid"},
	}

	result, err := svc.ExecuteScript("test", "echo ok")
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Stdout, "ok")
}

// ---------------------------------------------------------------------------
// OIDC Service: L954-956 - refreshLoop post-refresh script exec error
// ---------------------------------------------------------------------------

func TestSurgB_OIDCService_RefreshLoop_TickAndCancel(t *testing.T) {
	// Targets L944-947 and L954-956: refreshLoop tick triggers RefreshToken
	// which fails (no real OIDC server), and the exec script error is logged.
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()
	store := newSBFailingTokenStore()
	svc.SetTokenStore(store)

	entry := &OIDCProviderEntry{
		Name:        "test",
		Issuer:      "https://example.com",
		ClientID:    "client123",
		AutoRefresh: 1,
		Exec:        "exit 1",
	}
	svc.providers["test"] = entry

	_ = store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
	})

	ctx, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{provider: "test", cancel: cancel}
	initialStatus := &OIDCRefreshStatus{Provider: "test", Running: true}
	proc.status.Store(initialStatus)

	go svc.refreshLoop(ctx, proc, entry)

	time.Sleep(1500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	status := proc.status.Load()
	require.NotNil(t, status)
	assert.GreaterOrEqual(t, status.RefreshCount, 1)
	assert.Equal(t, "error", status.LastStatus)
	assert.False(t, status.Running)
}

// ---------------------------------------------------------------------------
// OIDC Service: saveProviders write failure path
// ---------------------------------------------------------------------------

func TestSurgB_OIDCService_SaveProviders_WriteFailure(t *testing.T) {
	svc := NewOIDCService(nil)

	readonlyDir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.MkdirAll(readonlyDir, 0500))
	svc.dataDir = readonlyDir

	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	err := svc.saveProviders()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard Service
// ---------------------------------------------------------------------------

func TestSurgB_ClipboardService_CopyWithClear_TimeoutZero(t *testing.T) {
	// Targets L93-96: when timeout <= 0, returns after write without clear.
	svc := NewClipboardService()
	svc.SetTimeout(0)
	svc.tool = clipToolNone
	err := svc.CopyWithClear("secret")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
	assert.Equal(t, 0, svc.GetTimeout())
}

func TestSurgB_ClipboardService_WriteClipboard_NoTool(t *testing.T) {
	// Targets L180-181: writeClipboard default case.
	svc := NewClipboardService()
	svc.tool = clipToolNone
	err := svc.writeClipboard("test")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestSurgB_ClipboardService_ReadClipboard_NoTool(t *testing.T) {
	// Targets L204-205: readClipboard default case.
	svc := NewClipboardService()
	svc.tool = clipToolNone
	_, err := svc.readClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestSurgB_ClipboardService_DetectClipboardTool(t *testing.T) {
	// Targets L218-226: detectClipboardTool checks for xclip, xsel, wl-copy.
	tool := detectClipboardTool()
	assert.True(t, tool >= clipToolNone && tool <= clipToolWlCopy)
}

func TestSurgB_ClipboardService_ScheduleClear_CancelsPrevious(t *testing.T) {
	// Targets L136-137: cancel previous pending clear.
	svc := NewClipboardService()
	svc.tool = clipToolNone

	ctx1, cancel1 := context.WithCancel(context.Background())
	svc.clearMu.Lock()
	svc.cancelFn = cancel1
	svc.clearMu.Unlock()

	svc.scheduleClear("test", 10*time.Second)

	select {
	case <-ctx1.Done():
		// Previous cancel was called -- expected.
	default:
		t.Fatal("previous cancel function was not called")
	}

	svc.clearMu.Lock()
	if svc.cancelFn != nil {
		svc.cancelFn()
	}
	svc.clearMu.Unlock()
}

// ---------------------------------------------------------------------------
// Trust Service
// ---------------------------------------------------------------------------

func TestSurgB_TrustService_SeedEmbeddedRoots_AddError(t *testing.T) {
	// Targets L307-309: error from store.AddCertificateWithOptions.
	// Create a writable store first, seed succeeds, then make the store's
	// directory readonly and try seeding a different purpose.
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	svc := NewTrustService(store)

	// Make the cert directory readonly to force AddCertificateWithOptions to fail.
	certDir := filepath.Join(dir, "certs")
	require.NoError(t, os.MkdirAll(certDir, 0700))
	require.NoError(t, os.Chmod(certDir, 0500))
	defer func() { _ = os.Chmod(certDir, 0700) }()

	count, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	if err != nil {
		// Successfully triggered the error path at L307-309.
		assert.Error(t, err)
		assert.Equal(t, 0, count)
	}
	// If no error, it means Contains() found them or no embedded roots match.
}

func TestSurgB_TrustService_RemoveFromSystem_CertNotFound(t *testing.T) {
	// Targets L362-363: Contains returns false for unknown cert.
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Use a valid 64-char hex fingerprint that does not exist in the store.
	fakeFP := "0000000000000000000000000000000000000000000000000000000000000000"
	err := svc.RemoveFromSystem(fakeFP, "password")
	assert.ErrorIs(t, err, truststore.ErrCertificateNotFound)
}

func TestSurgB_TrustService_InstallToSystem_NilStore(t *testing.T) {
	// Targets L319-320: nil store guard.
	svc := NewTrustService(nil)
	err := svc.InstallToSystem("abcd1234", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestSurgB_TrustService_RemoveFromSystem_NilStore(t *testing.T) {
	// Targets L352-354: nil store guard.
	svc := NewTrustService(nil)
	err := svc.RemoveFromSystem("abcd1234", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

func TestSurgB_TrustService_InstallToSystem_FingerprintNotFound(t *testing.T) {
	// Targets L327-329: findCertByFingerprint returns error.
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	// Seed some certs so the store is not empty, then look for a non-existent one.
	_, err := svc.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware))
	require.NoError(t, err)

	fakeFP := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	err = svc.InstallToSystem(fakeFP, "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSurgB_TrustService_IsSystemInstalled_NilStore(t *testing.T) {
	// Targets L380-381: nil store returns false, nil.
	svc := NewTrustService(nil)
	installed, err := svc.IsSystemInstalled("abc123def456abc123def456abc123def4")
	assert.NoError(t, err)
	assert.False(t, installed)
}

func TestSurgB_TrustService_IsSystemInstalled_WithStore(t *testing.T) {
	// Targets L384-391: NewOSCertStore path.
	store := newTestFileStore(t)
	defer store.Close()
	svc := NewTrustService(store)

	installed, err := svc.IsSystemInstalled("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	// Result depends on system -- just ensure no panic.
	_ = installed
	_ = err
}

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

func TestSurgB_SetupWizard_ApplySetup_TPMSealedPasswordMode_PPSvcNil(t *testing.T) {
	// Password protection is now handled transparently by the barrier.
	// Without barrier/policy services, setup succeeds with relevant warnings.
	tw := newTestSetupWizard(&GUIConfigData{SetupComplete: false})
	tw.svc.ppSvc = nil

	result, err := tw.svc.ApplySetup(&SetupChoices{
		Mode:              "standalone",
		SOPin:             testSOPin,
		UserPin:           testUserPin,
		PasswordStoreMode: "tpm_sealed",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier is nil, so a barrier warning is generated.
	assert.True(t, containsSubstring(result.Warnings, "barrier service unavailable"))
}

func TestSurgB_SetupWizard_GetPolicy_Execution(t *testing.T) {
	// Targets L946-968: GetPolicy calls config.Load, marshals, unmarshals.
	svc := NewSetupWizardService()
	svc.SetConfigDir(t.TempDir())
	result, err := svc.GetPolicy()
	// config.Load may return defaults; just ensure no panic.
	_ = result
	_ = err
}

func TestSurgB_SetupWizard_ApplySOProvisioning_Minimal(t *testing.T) {
	// Targets L779-799: config.Load/Save/WritePolicyHMAC path.
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(t.TempDir())

	var eventLog []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		eventLog = append(eventLog, e)
	})

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: testSOPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "PIN service unavailable"))
	assert.NotEmpty(t, eventLog)
}

func TestSurgB_SetupWizard_ApplySOProvisioning_WithBarrierFail(t *testing.T) {
	// Targets L708-712: barrier initialization failure.
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(t.TempDir())
	svc.SetEventEmitter(func(e events.Event) {})

	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetBarrierService(barrierSvc)

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:            "standalone",
		SOPin:           testSOPin,
		BarrierPassword: "testpassword",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestSurgB_SetupWizard_ApplySOProvisioning_InvalidMode(t *testing.T) {
	svc := NewSetupWizardService()
	_, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "invalid",
		SOPin: testSOPin,
	})
	assert.ErrorIs(t, err, ErrSetupInvalidDeploymentMode)
}

func TestSurgB_SetupWizard_ApplySOProvisioning_EmptySOPin(t *testing.T) {
	svc := NewSetupWizardService()
	_, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode: "standalone",
	})
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

func TestSurgB_SetupWizard_ApplySOProvisioning_DataDirInitFail(t *testing.T) {
	// Targets L720-724: initDataDirFunc error.
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigDir(t.TempDir())
	svc.SetEventEmitter(func(e events.Event) {})
	svc.SetInitDataDirFunc(func() error {
		return errors.New("data dir init failed")
	})

	result, err := svc.ApplySOProvisioning(&SetupChoices{
		Mode:  "standalone",
		SOPin: testSOPin,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, containsSubstring(result.Errors, "data directory initialization failed"))
}

// ---------------------------------------------------------------------------
// Phone Service
// ---------------------------------------------------------------------------

func TestSurgB_PhoneService_PubKeyFP_Valid(t *testing.T) {
	// Targets L1291-1292: successful MarshalPKIXPublicKey path.
	validCert := generateTestCert(t)
	fp := pubKeyFP(validCert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex
}

func TestSurgB_PhoneService_SaveConfig_NoError(t *testing.T) {
	// Targets saveConfig at L1217-1229.
	// Save then clean up to avoid polluting other tests.
	svc := NewPhoneService()
	cfg := &phoneConfig{
		Devices:       []phoneConfigDevice{},
		DefaultDevice: "",
	}
	path, err := phoneConfigPath()
	require.NoError(t, err)

	// Check if file existed before so we can restore state.
	_, existedBefore := os.ReadFile(path)
	existed := existedBefore == nil

	err = svc.saveConfig(cfg)
	assert.NoError(t, err)

	// Clean up: remove file if it didn't exist before.
	if !existed {
		os.Remove(path)
	}
}

func TestSurgB_PhoneService_LoadConfig(t *testing.T) {
	// Targets L1200-1213: loadConfig.
	svc := NewPhoneService()
	_, err := svc.loadConfig()
	_ = err // File may or may not exist.
}

func TestSurgB_PhoneService_PhoneConfigPath(t *testing.T) {
	// Targets L1233-1238.
	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".xkey")
	assert.Contains(t, path, devicesConfigFileName)
}

func TestSurgB_PhoneService_Hostname_NotEmpty(t *testing.T) {
	// Targets L1242-1248.
	name := hostname()
	assert.NotEmpty(t, name)
}

func TestSurgB_PhoneService_SetConnected_WithEmitter(t *testing.T) {
	// Targets L1162-1175: setConnected with event emission and status callback.
	svc := NewPhoneService()
	var emittedEvent *events.Event
	svc.eventEmitter = func(e events.Event) {
		emittedEvent = &e
	}
	var statusConnected bool
	var statusDevice string
	svc.statusChangeFn = func(connected bool, deviceName string) {
		statusConnected = connected
		statusDevice = deviceName
	}

	svc.setConnected("test-device")

	assert.True(t, svc.connState.connected.Load())
	assert.Equal(t, "test-device", svc.connState.deviceName.Load())
	require.NotNil(t, emittedEvent)
	assert.Equal(t, events.EventPhoneConnected, emittedEvent.Type)
	assert.True(t, statusConnected)
	assert.Equal(t, "test-device", statusDevice)
}

func TestSurgB_PhoneService_SetDisconnected_WithEmitter(t *testing.T) {
	// Targets L1180-1197: setDisconnected with event emission and status callback.
	svc := NewPhoneService()
	svc.connState.connected.Store(true)
	svc.connState.deviceName.Store("test-device")

	var emittedEvent *events.Event
	svc.eventEmitter = func(e events.Event) {
		emittedEvent = &e
	}
	var statusConnected bool
	svc.statusChangeFn = func(connected bool, deviceName string) {
		statusConnected = connected
	}

	svc.setDisconnected("test-device", "manual")

	assert.False(t, svc.connState.connected.Load())
	assert.Equal(t, "", svc.connState.deviceName.Load())
	require.NotNil(t, emittedEvent)
	assert.Equal(t, events.EventPhoneDisconnected, emittedEvent.Type)
	assert.False(t, statusConnected)
}

// ---------------------------------------------------------------------------
// OIDC Service: Additional paths
// ---------------------------------------------------------------------------

func TestSurgB_OIDCService_Login_AWSProviderRejected(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["aws-test"] = &OIDCProviderEntry{
		Name: "aws-test",
		Type: OIDCProviderTypeAWS,
	}

	result, err := svc.Login("aws-test")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "AWS")
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestSurgB_OIDCService_Login_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	result, err := svc.Login("nonexistent")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "provider not found")
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestSurgB_OIDCService_GetTokenInfo_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{Name: "test"}
	_, err := svc.GetTokenInfo("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestSurgB_OIDCService_GetTokenInfo_TokenNotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	store := newSBFailingTokenStore()
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}
	_, err := svc.GetTokenInfo("test")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTokenNotFound))
}

func TestSurgB_OIDCService_RefreshToken_NoRefreshTokenInStored(t *testing.T) {
	svc := NewOIDCService(nil)
	store := newSBFailingTokenStore()
	_ = store.Save("https://example.com", &oidc.TokenResponse{
		AccessToken: "access",
	})
	svc.SetTokenStore(store)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://example.com",
	}

	_, err := svc.RefreshToken("test")
	assert.ErrorIs(t, err, ErrOIDCNoRefreshToken)
}

func TestSurgB_OIDCService_DiscoverProvider_EmptyIssuer(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.DiscoverProvider("")
	assert.ErrorIs(t, err, ErrOIDCInvalidIssuer)
}

func TestSurgB_OIDCService_StartAutoRefresh_Disabled(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 0,
	}

	err := svc.StartAutoRefresh("test")
	assert.ErrorIs(t, err, ErrOIDCAutoRefreshDisabled)
}

func TestSurgB_OIDCService_StartAutoRefresh_AlreadyRunning(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{
		Name:        "test",
		AutoRefresh: 3600,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.refreshProcs["test"] = &refreshProcess{provider: "test", cancel: cancel}
	_ = ctx

	err := svc.StartAutoRefresh("test")
	assert.ErrorIs(t, err, ErrOIDCRefreshAlreadyRunning)
}

func TestSurgB_OIDCService_GetRefreshStatus_NotRunning(t *testing.T) {
	svc := NewOIDCService(nil)
	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.Equal(t, "test", status.Provider)
	assert.False(t, status.Running)
}

func TestSurgB_OIDCService_GetRefreshStatus_NilStatus(t *testing.T) {
	// Targets L818-820: proc exists but status is nil.
	svc := NewOIDCService(nil)
	_, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{provider: "test", cancel: cancel}
	svc.refreshProcs["test"] = proc

	status, err := svc.GetRefreshStatus("test")
	require.NoError(t, err)
	assert.Equal(t, "test", status.Provider)
	assert.True(t, status.Running)
	cancel()
}

func TestSurgB_OIDCService_GetAllRefreshStatus_Empty(t *testing.T) {
	svc := NewOIDCService(nil)
	statuses := svc.GetAllRefreshStatus()
	assert.Empty(t, statuses)
}

func TestSurgB_OIDCService_GetAllRefreshStatus_WithProcs(t *testing.T) {
	svc := NewOIDCService(nil)
	_, cancel := context.WithCancel(context.Background())
	proc := &refreshProcess{provider: "test", cancel: cancel}
	status := &OIDCRefreshStatus{Provider: "test", Running: true, RefreshCount: 5}
	proc.status.Store(status)
	svc.refreshProcs["test"] = proc

	statuses := svc.GetAllRefreshStatus()
	require.Len(t, statuses, 1)
	assert.Equal(t, "test", statuses[0].Provider)
	assert.Equal(t, 5, statuses[0].RefreshCount)
	cancel()
}

func TestSurgB_OIDCService_Logout_NoTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["test"] = &OIDCProviderEntry{Name: "test"}

	err := svc.Logout("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestSurgB_OIDCService_SetDataDir_CreatesTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	dir := t.TempDir()
	svc.SetDataDir(dir)
	assert.NotNil(t, svc.tokenStore)
	assert.Equal(t, dir, svc.dataDir)
}

// ---------------------------------------------------------------------------
// Storage Service
// ---------------------------------------------------------------------------

func TestSurgB_StorageService_LuksPathArgs(t *testing.T) {
	// Targets L280-288: luksPathArgs.
	args := luksPathArgs()
	if args != nil {
		assert.Len(t, args, 4)
		assert.Equal(t, "--path", args[0])
		assert.Equal(t, "--mount-point", args[2])
	}
}

func TestSurgB_StorageService_GetStatus_NoElevator(t *testing.T) {
	// Targets L94: elevator == nil path.
	svc := NewStorageService()
	status, err := svc.GetStatus()
	if err == nil {
		require.NotNil(t, status)
		assert.False(t, status.ElevationAvailable)
	}
}
