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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// sc-prefixed mocks (unique to this file to avoid conflicts)
// ---------------------------------------------------------------------------

// scMockStaticPWStore implements staticpw.Store for testing error paths.
type scMockStaticPWStore struct {
	listErr        error
	listResult     []*staticpw.StaticPassword
	listByFolderFn func(string) ([]*staticpw.StaticPassword, error)
	deleteErr      error
	addErr         error
}

func (m *scMockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	return m.addErr
}
func (m *scMockStaticPWStore) Get(_ string) (*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *scMockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listResult, nil
}
func (m *scMockStaticPWStore) Update(_ *staticpw.StaticPassword) error { return nil }
func (m *scMockStaticPWStore) Delete(_ string) error                   { return m.deleteErr }
func (m *scMockStaticPWStore) ForceDelete(_ string) error              { return nil }
func (m *scMockStaticPWStore) ListByFolder(folderPath string) ([]*staticpw.StaticPassword, error) {
	if m.listByFolderFn != nil {
		return m.listByFolderFn(folderPath)
	}
	return nil, nil
}
func (m *scMockStaticPWStore) ListFolders() ([]string, error) { return nil, nil }
func (m *scMockStaticPWStore) ListByFolderDirect(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *scMockStaticPWStore) MoveToFolder(_ string, _ string) error {
	return nil
}
func (m *scMockStaticPWStore) Close() error                { return nil }
func (m *scMockStaticPWStore) CreateFolder(_ string) error { return nil }
func (m *scMockStaticPWStore) RemoveFolder(_ string) error { return nil }

// scMockTrustStore implements truststore.TrustStore for testing error paths.
type scMockTrustStore struct {
	certsErr           error
	certs              []*x509.Certificate
	containsResult     bool
	containsErr        error
	addCertWithOptsErr error
}

func (m *scMockTrustStore) AddCertificate(_ *x509.Certificate) error { return nil }
func (m *scMockTrustStore) AddCertificateWithOptions(_ *x509.Certificate, _ *truststore.AddCertificateOptions) error {
	return m.addCertWithOptsErr
}
func (m *scMockTrustStore) AddPEM(_ []byte) (int, error)     { return 0, nil }
func (m *scMockTrustStore) RemoveCertificate(_ string) error { return nil }
func (m *scMockTrustStore) Certificates() ([]*x509.Certificate, error) {
	return m.certs, m.certsErr
}
func (m *scMockTrustStore) CertificatesByPurpose(_ truststore.CertPurpose) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *scMockTrustStore) CertPool() (*x509.CertPool, error) { return nil, nil }
func (m *scMockTrustStore) Contains(_ string) (bool, error) {
	return m.containsResult, m.containsErr
}
func (m *scMockTrustStore) Count() (int, error)                                 { return 0, nil }
func (m *scMockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) { return nil, nil }
func (m *scMockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error { return nil }
func (m *scMockTrustStore) SetSource(_ string, _ string) error                  { return nil }
func (m *scMockTrustStore) SetSystemInstalled(_ string, _ bool) error           { return nil }
func (m *scMockTrustStore) SetTags(_ string, _ []string) error                  { return nil }
func (m *scMockTrustStore) Close() error                                        { return nil }

// scMockFIDO2Storage implements StatefulCredentialStorage + ListableStorage.
type scMockFIDO2Storage struct {
	listAllErr    error
	listAllResult [][]byte
	loadErr       error
	loadResult    *authenticator.StoredCredential
}

func (m *scMockFIDO2Storage) Store(_ *authenticator.StoredCredential) error { return nil }
func (m *scMockFIDO2Storage) Load(_ []byte) (*authenticator.StoredCredential, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.loadResult, nil
}
func (m *scMockFIDO2Storage) LoadByRPID(_ string) ([]*authenticator.StoredCredential, error) {
	return nil, nil
}
func (m *scMockFIDO2Storage) Delete(_ []byte) error                                 { return nil }
func (m *scMockFIDO2Storage) Count() (int, error)                                   { return 0, nil }
func (m *scMockFIDO2Storage) CountDiscoverable() (int, error)                       { return 0, nil }
func (m *scMockFIDO2Storage) SaveState(_ *authenticator.AuthenticatorState) error   { return nil }
func (m *scMockFIDO2Storage) LoadState() (*authenticator.AuthenticatorState, error) { return nil, nil }
func (m *scMockFIDO2Storage) Close() error                                          { return nil }
func (m *scMockFIDO2Storage) ListAll() ([][]byte, error) {
	if m.listAllErr != nil {
		return nil, m.listAllErr
	}
	return m.listAllResult, nil
}

// scMockCertClient embeds transport.Client and overrides ListBackends/ListCertificates.
type scMockCertClient struct {
	transport.Client
	backendsResp *transport.ListBackendsResponse
	certsResp    *transport.ListCertificatesResponse
}

func (m *scMockCertClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return m.backendsResp, nil
}
func (m *scMockCertClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return m.certsResp, nil
}

// scMockOIDCTokenStore implements oidc.TokenStore for testing.
type scMockOIDCTokenStore struct {
	saveErr  error
	loadErr  error
	loadResp *oidc.TokenResponse
	closeErr error
}

func (m *scMockOIDCTokenStore) Save(_ string, _ *oidc.TokenResponse) error { return m.saveErr }
func (m *scMockOIDCTokenStore) Load(_ string) (*oidc.TokenResponse, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.loadResp, nil
}
func (m *scMockOIDCTokenStore) Delete(_ string) error   { return nil }
func (m *scMockOIDCTokenStore) List() ([]string, error) { return nil, nil }
func (m *scMockOIDCTokenStore) Close() error            { return m.closeErr }

// scNewPINServiceWithManager creates a PINService backed by a SoftwareBackend
// using in-memory storage. The caller can then call SetSOPIN / SetUserPIN on the service.
func scNewPINServiceWithManager(t *testing.T) *PINService {
	t.Helper()
	backend, err := pin.NewSoftwareBackend(nil, pin.DefaultHashConfig())
	require.NoError(t, err)
	svc := NewPINService()
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)
	return svc
}

// scPolicyHMACFile is the enterprise mode marker filename. Must match
// config.hmacFileName ("xkey_policy.hmac").
const scPolicyHMACFile = "xkey_policy.hmac"

// ===========================================================================
// setup_wizard_service.go tests
// ===========================================================================

// TestSC_SetupWizard_TPMSealedPW_SealFails covers L443-455: tpm_sealed mode
// where SetModeTPMSealed succeeds but SealData for user_pin fails.
func TestSC_SetupWizard_TPMSealedPW_SealFails(t *testing.T) {
	// ppSvc uses its own working sealSvc so SetModeTPMSealed succeeds.
	ppMock := defaultSealMock()
	ppSealSvc := newSealServiceWithMock(t, ppMock)
	ppStore := &scMockStaticPWStore{}
	ppStaticSvc := NewStaticPasswordService(ppStore)
	ppSvc := NewPasswordProtectionService(
		filepath.Join(t.TempDir(), "enc.json"),
		ppStaticSvc,
		ppSealSvc,
	)

	// wizard uses a separate sealSvc that always fails (for user_pin seal).
	wizMock := defaultSealMock()
	wizMock.sealErr = errors.New("seal error")
	wizSealSvc := newSealServiceWithMock(t, wizMock)

	pinSvc := scNewPINServiceWithManager(t)

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPasswordProtectionService(ppSvc)
	wiz.SetSealService(wizSealSvc)
	wiz.SetPINService(pinSvc)
	wiz.SetInitDataDirFunc(func() error { return nil })
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	choices := &SetupChoices{
		Mode:              "standalone",
		PasswordStoreMode: "tpm_sealed",
		SOPin:             "test-so-pin",
		UserPin:           "1234",
		EnableStorage:     false,
	}

	result, err := wiz.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// The user_pin seal fails, so a warning should be appended.
	assert.True(t, len(result.Warnings) > 0, "expected user_pin seal warning")
}

// TestSC_SetupWizard_AESSoftwarePW_Fails covers the aes_software password
// store mode path. Password protection is now handled transparently by the
// barrier, so the wizard succeeds with warnings rather than errors.
func TestSC_SetupWizard_AESSoftwarePW_Fails(t *testing.T) {
	ppStore := &scMockStaticPWStore{}
	ppStaticSvc := NewStaticPasswordService(ppStore)
	ppSvc := NewPasswordProtectionService(
		"/dev/null/impossible/enc.json", // unwritable path
		ppStaticSvc,
		nil,
	)

	pinSvc := scNewPINServiceWithManager(t)

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPasswordProtectionService(ppSvc)
	wiz.SetPINService(pinSvc)
	wiz.SetInitDataDirFunc(func() error { return nil })
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	choices := &SetupChoices{
		Mode:              "standalone",
		PasswordStoreMode: "aes_software",
		EnableMasterPW:    true,
		MasterPassword:    "test-master-pw",
		SOPin:             "test-so-pin",
		UserPin:           "test-user-pin",
		EnableStorage:     false,
	}

	result, err := wiz.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Barrier service is nil, so setup succeeds with warnings.
	assert.True(t, result.Success)
	assert.True(t, len(result.Warnings) > 0)
}

// TestSC_SetupWizard_AutoUnseal_EnableFails covers L504-507: auto-unseal Enable error.
func TestSC_SetupWizard_AutoUnseal_EnableFails(t *testing.T) {
	mock := &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: false}
	sealSvc := newSealServiceWithMock(t, mock)

	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigData() })
	autoSvc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	pinSvc := scNewPINServiceWithManager(t)

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetAutoUnsealService(autoSvc)
	wiz.SetPINService(pinSvc)
	wiz.SetInitDataDirFunc(func() error { return nil })
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	choices := &SetupChoices{
		Mode:             "standalone",
		SOPin:            "test-so-pin",
		UserPin:          "1234",
		EnableAutoUnseal: true,
		EnableStorage:    true,
		StorageType:      "luks",
		StoragePass:      "test-passphrase",
	}

	result, err := wiz.ApplySetup(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, len(result.Warnings) > 0)
}

// TestSC_SOProvisioning_TPMInstallAndPlatformKeyStore covers L742-756.
func TestSC_SOProvisioning_TPMInstallAndPlatformKeyStore(t *testing.T) {
	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "test-so-pin"))

	tpmSvc := &TPMService{log: slog.Default().With("component", "tpm_service")}

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetTPMService(tpmSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(t.TempDir())

	choices := &SetupChoices{Mode: "standalone", SOPin: "test-so-pin"}
	result, err := wiz.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, len(result.Warnings) >= 2, "expected TPM install warnings, got: %v", result.Warnings)
}

// TestSC_SOProvisioning_ConfigLoadFails covers L779-789.
func TestSC_SOProvisioning_ConfigLoadFails(t *testing.T) {
	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(filepath.Join(t.TempDir(), "nonexistent", "deep"))

	choices := &SetupChoices{Mode: "standalone", SOPin: "so-pin"}
	result, err := wiz.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestSC_SOProvisioning_PolicyHMACFails covers L795-799.
func TestSC_SOProvisioning_PolicyHMACFails(t *testing.T) {
	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(t.TempDir())

	choices := &SetupChoices{Mode: "standalone", SOPin: "so-pin"}
	result, err := wiz.ApplySOProvisioning(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestSC_UserOnboarding_SetUserPINFails covers L850-854: SetUserPIN failure
// when SO PIN verification passes but SetUserPIN returns an error.
func TestSC_UserOnboarding_SetUserPINFails(t *testing.T) {
	configDir := t.TempDir()
	// Write the enterprise mode marker file (must match config.hmacFileName).
	require.NoError(t, os.WriteFile(filepath.Join(configDir, scPolicyHMACFile), []byte("dummy"), 0600))

	// Create a PINService with a real manager and set the SO PIN.
	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(configDir)
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	// Use a very short user PIN that will fail validation (< 6 chars minimum).
	choices := &UserOnboardingChoices{SOPIN: "so-pin", UserPIN: "1"}
	result, err := wiz.ApplyUserOnboarding(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.True(t, len(result.Errors) > 0)
}

// TestSC_UserOnboarding_ConfigLoadFails covers L912-915: unified config load warning.
func TestSC_UserOnboarding_ConfigLoadFails(t *testing.T) {
	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(configDir, scPolicyHMACFile), []byte("d"), 0600))

	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))
	require.NoError(t, pinSvc.SetUserPIN("so-pin", "user-pin"))

	// Write an invalid YAML config file so config.Load() fails.
	config.SetConfigDir(configDir)
	defer config.ResetConfigDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "xkey.yaml"),
		[]byte("{{{{invalid yaml"),
		0600,
	))

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(configDir)
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	choices := &UserOnboardingChoices{SOPIN: "so-pin", UserPIN: "user-pin"}
	result, err := wiz.ApplyUserOnboarding(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Config load failure is a warning, not a fatal error.
	assert.True(t, result.SetupComplete)
	assert.True(t, len(result.Warnings) > 0, "expected config load warning")
}

// TestSC_UserOnboarding_ConfigSaveFails covers L921-925: unified config save failure.
func TestSC_UserOnboarding_ConfigSaveFails(t *testing.T) {
	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(configDir, scPolicyHMACFile), []byte("d"), 0600))

	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))
	require.NoError(t, pinSvc.SetUserPIN("so-pin", "user-pin"))

	// Write a valid config so config.Load() succeeds, but make the dir
	// read-only so Save() cannot create temp files.
	config.SetConfigDir(configDir)
	defer config.ResetConfigDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "xkey.yaml"),
		[]byte("log:\n  level: info\n"),
		0600,
	))
	// Make the config dir read-only so Save() cannot create temp files.
	require.NoError(t, os.Chmod(configDir, 0500))
	defer os.Chmod(configDir, 0700) //nolint:errcheck

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())
	wiz.SetPINService(pinSvc)
	wiz.SetEventEmitter(func(_ events.Event) {})
	wiz.SetConfigDir(configDir)
	wiz.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	wiz.SetConfigSaveFunc(func(_ *GUIConfigData) error { return nil })

	choices := &UserOnboardingChoices{SOPIN: "so-pin", UserPIN: "user-pin"}
	result, err := wiz.ApplyUserOnboarding(choices)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Save failure should produce errors.
	assert.False(t, result.Success)
	assert.True(t, len(result.Errors) > 0, "expected config save error")
}

// TestSC_GetPolicy_ConfigLoadError covers L948-952 and L956-958.
func TestSC_GetPolicy_ConfigLoadError(t *testing.T) {
	// Redirect config.Load() to a directory with an invalid YAML file.
	badDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(badDir, "xkey.yaml"),
		[]byte("{{{{invalid yaml content"),
		0600,
	))
	config.SetConfigDir(badDir)
	defer config.ResetConfigDir()

	wiz := NewSetupWizardService()
	wiz.SetContext(context.Background())

	result, err := wiz.GetPolicy()
	assert.Nil(t, result)
	assert.Error(t, err)
}

// ===========================================================================
// oidc_service.go tests
// ===========================================================================

// TestSC_OIDCService_SetDataDir_TokenStoreError covers L199-202.
func TestSC_OIDCService_SetDataDir_TokenStoreError(t *testing.T) {
	svc := NewOIDCService(nil)
	dir := t.TempDir()
	// Create a directory where the tokens file should be, causing file open error.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, oidcTokensFile), 0700))
	svc.SetDataDir(dir)
}

// TestSC_OIDCService_Close covers L227-229.
func TestSC_OIDCService_Close(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.tokenStore = &scMockOIDCTokenStore{}
	assert.NoError(t, svc.Close())
}

// TestSC_OIDCService_Login_DiscoveryFails covers L470-474 (subset).
func TestSC_OIDCService_Login_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	svc.providers["bad"] = &OIDCProviderEntry{
		Name: "bad", Type: OIDCProviderTypeStandard,
		Issuer: "http://127.0.0.1:1/invalid", ClientID: "c",
		RedirectURL: "http://localhost:8085/callback", Scopes: []string{"openid"},
	}

	result, err := svc.Login("bad")
	assert.NoError(t, err)
	assert.NotEmpty(t, result.Error)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestSC_OIDCService_Login_AWSType covers L452-453 AWS rejection.
func TestSC_OIDCService_Login_AWSType(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["aws"] = &OIDCProviderEntry{Name: "aws", Type: OIDCProviderTypeAWS}

	result, err := svc.Login("aws")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "AWS")
	assert.False(t, result.Success)
}

// TestSC_OIDCService_ExecuteScript_ExitCode covers L895-903.
func TestSC_OIDCService_ExecuteScript_ExitCode(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["p"] = &OIDCProviderEntry{Name: "p", Issuer: "https://x.com", ClientID: "c"}

	result, err := svc.ExecuteScript("p", "exit 42")
	require.NoError(t, err)
	assert.Equal(t, 42, result.ExitCode)
	assert.False(t, result.Success)
}

// TestSC_OIDCService_ExecuteScript_Success covers L863-865 (marshal) and normal path.
func TestSC_OIDCService_ExecuteScript_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["p"] = &OIDCProviderEntry{Name: "p", Issuer: "https://x.com", ClientID: "c"}
	svc.tokenStore = &scMockOIDCTokenStore{
		loadResp: &oidc.TokenResponse{AccessToken: "at", RefreshToken: "rt"},
	}

	result, err := svc.ExecuteScript("p", "cat > /dev/null")
	require.NoError(t, err)
	assert.True(t, result.Success)
}

// TestSC_OIDCService_SaveProviders_WriteError covers L1088-1100.
func TestSC_OIDCService_SaveProviders_WriteError(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = "/dev/null/impossible"
	svc.providers["t"] = &OIDCProviderEntry{Name: "t"}
	assert.Error(t, svc.saveProviders())
}

// TestSC_OIDCService_SaveProviders_Success covers L1088-1100 success path.
func TestSC_OIDCService_SaveProviders_Success(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()
	svc.providers["t"] = &OIDCProviderEntry{Name: "t", Issuer: "https://x.com"}
	assert.NoError(t, svc.saveProviders())
}

// TestSC_OIDCService_Refresh_DiscoveryFails covers L678-689.
func TestSC_OIDCService_Refresh_DiscoveryFails(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	svc.tokenStore = &scMockOIDCTokenStore{
		loadResp: &oidc.TokenResponse{AccessToken: "at", RefreshToken: "rt"},
	}
	svc.providers["p"] = &OIDCProviderEntry{
		Name: "p", Issuer: "http://127.0.0.1:1/invalid", ClientID: "c",
	}

	_, err := svc.RefreshToken("p")
	assert.True(t, errors.Is(err, ErrOIDCRefreshFailed))
}

// TestSC_OIDCService_PostRefreshScript covers L954-956.
func TestSC_OIDCService_PostRefreshScript(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.providers["p"] = &OIDCProviderEntry{Name: "p", Issuer: "https://x.com", ClientID: "c", Exec: "exit 1"}

	result, err := svc.ExecuteScript("p", "exit 1")
	require.NoError(t, err)
	assert.False(t, result.Success)
}

// ===========================================================================
// oath_service.go tests
// ===========================================================================

// TestSC_OATHService_ScanQR_Errors covers L235-246.
func TestSC_OATHService_ScanQR_Errors(t *testing.T) {
	svc := NewOATHService(nil)
	// ScanQR calls the real screen scanner which fails in headless CI.
	result, err := svc.ScanQR(-1)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ===========================================================================
// trust_service.go tests (non-Wails, skip L218-253)
// ===========================================================================

// TestSC_TrustService_SeedEmbeddedRoots_AddFails covers L307-309.
func TestSC_TrustService_SeedEmbeddedRoots_AddFails(t *testing.T) {
	store := &scMockTrustStore{containsResult: false, addCertWithOptsErr: errors.New("add failed")}
	svc := NewTrustService(store)
	_, _ = svc.SeedEmbeddedRoots("tls")
}

// TestSC_TrustService_InstallToSystem_RunFails covers L344-345.
func TestSC_TrustService_InstallToSystem_RunFails(t *testing.T) {
	cert := scMakeSelfSignedCert(t)
	store := &scMockTrustStore{certs: []*x509.Certificate{cert}, containsResult: true}
	svc := NewTrustService(store)
	fp := truststore.Fingerprint(cert)

	err := svc.InstallToSystem(fp, "bad-password")
	assert.Error(t, err)
}

// TestSC_TrustService_RemoveFromSystem_ContainsErr covers L344-345 error at Contains.
func TestSC_TrustService_RemoveFromSystem_ContainsErr(t *testing.T) {
	store := &scMockTrustStore{containsErr: errors.New("err")}
	svc := NewTrustService(store)
	assert.Error(t, svc.RemoveFromSystem("abc123", "pw"))
}

// TestSC_TrustService_RemoveFromSystem_NotFound covers L363.
func TestSC_TrustService_RemoveFromSystem_NotFound(t *testing.T) {
	store := &scMockTrustStore{containsResult: false}
	svc := NewTrustService(store)
	err := svc.RemoveFromSystem("abc123", "pw")
	assert.True(t, errors.Is(err, truststore.ErrCertificateNotFound))
}

// TestSC_TrustService_IsSystemInstalled covers L387-389.
func TestSC_TrustService_IsSystemInstalled(t *testing.T) {
	store := &scMockTrustStore{}
	svc := NewTrustService(store)
	result, err := svc.IsSystemInstalled("0123456789abcdef0123456789abcdef")
	if err != nil {
		assert.False(t, result)
	}
}

// ===========================================================================
// staticpw_service.go tests
// ===========================================================================

// TestSC_StaticPW_ListPasswords_StoreError covers L174-176.
func TestSC_StaticPW_ListPasswords_StoreError(t *testing.T) {
	store := &scMockStaticPWStore{listErr: errors.New("err")}
	svc := NewStaticPasswordService(store)
	_, err := svc.ListPasswords()
	assert.Error(t, err)
}

// TestSC_StaticPW_ListByFolder_Error covers L365-367.
func TestSC_StaticPW_ListByFolder_Error(t *testing.T) {
	store := &scMockStaticPWStore{
		listByFolderFn: func(_ string) ([]*staticpw.StaticPassword, error) {
			return nil, errors.New("err")
		},
	}
	svc := NewStaticPasswordService(store)
	_, err := svc.ListPasswordsByFolder("x")
	assert.Error(t, err)
}

// TestSC_StaticPW_RenameFolder_ListError covers L398-400.
func TestSC_StaticPW_RenameFolder_ListError(t *testing.T) {
	store := &scMockStaticPWStore{listErr: errors.New("err")}
	svc := NewStaticPasswordService(store)
	assert.Error(t, svc.RenameFolder("old", "new"))
}

// TestSC_StaticPW_RenameFolder_DeleteError covers L407-409.
func TestSC_StaticPW_RenameFolder_DeleteError(t *testing.T) {
	store := &scMockStaticPWStore{
		listResult: []*staticpw.StaticPassword{{Name: "pw1", FolderPath: "old", ID: "id1"}},
		deleteErr:  errors.New("err"),
	}
	svc := NewStaticPasswordService(store)
	assert.Error(t, svc.RenameFolder("old", "new"))
}

// TestSC_StaticPW_RenameFolder_AddError covers L414-416.
func TestSC_StaticPW_RenameFolder_AddError(t *testing.T) {
	store := &scMockStaticPWStore{
		listResult: []*staticpw.StaticPassword{{Name: "pw1", FolderPath: "old", ID: "id1"}},
		addErr:     errors.New("err"),
	}
	svc := NewStaticPasswordService(store)
	assert.Error(t, svc.RenameFolder("old", "new"))
}

// TestSC_StaticPW_DeleteFolder_ListError covers L433-435.
func TestSC_StaticPW_DeleteFolder_ListError(t *testing.T) {
	store := &scMockStaticPWStore{listErr: errors.New("err")}
	svc := NewStaticPasswordService(store)
	assert.Error(t, svc.DeleteFolder("folder"))
}

// TestSC_StaticPW_DeleteFolder_DeleteError covers L439-441.
func TestSC_StaticPW_DeleteFolder_DeleteError(t *testing.T) {
	store := &scMockStaticPWStore{
		listResult: []*staticpw.StaticPassword{{Name: "pw1", FolderPath: "folder", ID: "id1"}},
		deleteErr:  errors.New("err"),
	}
	svc := NewStaticPasswordService(store)
	assert.Error(t, svc.DeleteFolder("folder"))
}

// TestSC_StaticPW_SearchPasswords_ListError covers L456-458.
func TestSC_StaticPW_SearchPasswords_ListError(t *testing.T) {
	store := &scMockStaticPWStore{listErr: errors.New("err")}
	svc := NewStaticPasswordService(store)
	_, err := svc.SearchPasswords("q")
	assert.Error(t, err)
}

// ===========================================================================
// elevation_sudo.go tests
// ===========================================================================

// TestSC_SudoElevator_RunNoExecPath covers L74-77 (execPath empty).
func TestSC_SudoElevator_RunNoExecPath(t *testing.T) {
	e := &SudoElevator{log: slog.Default(), execPath: "", password: []byte("pw")}
	_, err := e.Run([]string{"test"}, nil)
	assert.True(t, errors.Is(err, ErrElevationUnavailable))
}

// TestSC_SudoElevator_RunSudoUnavailable covers L79-82.
func TestSC_SudoElevator_RunSudoUnavailable(t *testing.T) {
	e := &SudoElevator{log: slog.Default(), execPath: "/nonexistent/path", password: []byte("pw")}
	_, err := e.Run([]string{"test"}, nil)
	assert.Error(t, err)
}

// TestSC_SudoElevator_RunExitError covers L127-129 and L135-147.
func TestSC_SudoElevator_RunExitError(t *testing.T) {
	e := &SudoElevator{log: slog.Default(), execPath: "/bin/false", password: []byte("wrong")}
	_, err := e.Run([]string{}, nil)
	assert.Error(t, err)
}

// ===========================================================================
// fido2_service.go tests
// ===========================================================================

// TestSC_FIDO2Service_ListCredentials_ListAllError covers L135-142.
func TestSC_FIDO2Service_ListCredentials_ListAllError(t *testing.T) {
	storage := &scMockFIDO2Storage{listAllErr: errors.New("err")}
	svc := NewFIDO2Service(storage)
	_, err := svc.ListCredentials()
	assert.Error(t, err)
}

// TestSC_FIDO2Service_ListCredentials_LoadError covers L147-149.
func TestSC_FIDO2Service_ListCredentials_LoadError(t *testing.T) {
	storage := &scMockFIDO2Storage{
		listAllResult: [][]byte{[]byte("cred1")},
		loadErr:       errors.New("err"),
	}
	svc := NewFIDO2Service(storage)
	result, err := svc.ListCredentials()
	assert.NoError(t, err)
	assert.Empty(t, result)
}

// TestSC_FIDO2Service_GetRelyingParties_ListError covers L223-225.
func TestSC_FIDO2Service_GetRelyingParties_ListError(t *testing.T) {
	storage := &scMockFIDO2Storage{listAllErr: errors.New("err")}
	svc := NewFIDO2Service(storage)
	_, err := svc.GetRelyingParties()
	assert.Error(t, err)
}

// TestSC_FIDO2Service_StartBridge_NilClient covers L280-282.
func TestSC_FIDO2Service_StartBridge_NilClient(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	// clientFunc returns nil -> ErrFIDO2BridgeNoClient
	svc.clientFunc = func() xkms.Client { return nil }
	err := svc.StartPhoneBridge()
	assert.True(t, errors.Is(err, ErrFIDO2BridgeNoClient))
}

// TestSC_FIDO2Service_HandleBridgeRequest_NotRunning covers L349 (bridge stopped).
func TestSC_FIDO2Service_HandleBridgeRequest_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	_, err := svc.HandleBridgeRequest("test", json.RawMessage(`{}`))
	assert.True(t, errors.Is(err, ErrFIDO2BridgeStopped))
}

// ===========================================================================
// auto_unseal_service.go tests
// ===========================================================================

// TestSC_AutoUnseal_Enable_ConfigSaveDeleteBlobFails covers L186-189.
func TestSC_AutoUnseal_Enable_ConfigSaveDeleteBlobFails(t *testing.T) {
	mock := defaultSealMock()
	sealSvc := newSealServiceWithMock(t, mock)
	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigData() })
	autoSvc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return errors.New("save failed") })

	_, err := autoSvc.Enable("long-enough-passphrase", []int{0, 7}, "sha256", "none", "", "tpm2")
	assert.Error(t, err)
}

// TestSC_AutoUnseal_TryAutoUnseal_Configured covers L264-269 (already mounted path).
func TestSC_AutoUnseal_TryAutoUnseal_Configured(t *testing.T) {
	mock := defaultSealMock()
	sealSvc := newSealServiceWithMock(t, mock)
	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigDataWithAutoUnseal("blob-1") })

	result := autoSvc.TryAutoUnseal()
	assert.NotNil(t, result)
}

// TestSC_AutoUnseal_TryAutoUnseal_UnsealFails covers L284-290.
func TestSC_AutoUnseal_TryAutoUnseal_UnsealFails(t *testing.T) {
	goodMock := defaultSealMock()
	goodSealSvc := newSealServiceWithMock(t, goodMock)
	entry, err := goodSealSvc.SealData(&SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase")),
	})
	require.NoError(t, err)

	badMock := &sealMockTPM{mockTPM: *defaultMockTPM(), canSeal: true, unsealErr: errors.New("fail")}
	sealSvc := newSealServiceWithMock(t, badMock)
	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigDataWithAutoUnseal(entry.ID) })

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
}

// TestSC_AutoUnseal_Reseal_ConfigSaveDeleteFails covers L363-366.
func TestSC_AutoUnseal_Reseal_ConfigSaveDeleteFails(t *testing.T) {
	mock := defaultSealMock()
	sealSvc := newSealServiceWithMock(t, mock)
	entry, err := sealSvc.SealData(&SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase")),
	})
	require.NoError(t, err)

	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigDataWithAutoUnseal(entry.ID) })
	autoSvc.SetConfigSaveFunc(func(_ *GUIConfigData) error { return errors.New("save error") })

	assert.Error(t, autoSvc.Reseal())
}

// TestSC_AutoUnseal_Reseal_DeleteOldBlobFails covers L371-374.
func TestSC_AutoUnseal_Reseal_DeleteOldBlobFails(t *testing.T) {
	mock := defaultSealMock()
	sealSvc := newSealServiceWithMock(t, mock)
	entry, err := sealSvc.SealData(&SealRequest{
		Label: "auto-unseal-passphrase",
		Data:  base64.StdEncoding.EncodeToString([]byte("test-passphrase")),
	})
	require.NoError(t, err)

	storageSvc := NewStorageService()
	storageSvc.SetContext(context.Background())
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigDataWithAutoUnseal(entry.ID) })
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error {
		c.AutoUnsealBlobID = "non-existent-old-blob"
		return nil
	})

	assert.NoError(t, autoSvc.Reseal())
}

// ===========================================================================
// certificate_service.go tests
// ===========================================================================

// TestSC_CertService_ListAllCertificates_NoClient covers L83-87 panic recovery and L96-98.
func TestSC_CertService_ListAllCertificates_NoClient(t *testing.T) {
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	result, err := svc.ListAllCertificates()
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestSC_CertService_ListAllCertificates_NilCtx covers L96-98.
func TestSC_CertService_ListAllCertificates_NilCtx(t *testing.T) {
	svc := NewCertificateService()
	mockClient := &scMockCertClient{
		backendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{{ID: "test"}},
		},
		certsResp: &transport.ListCertificatesResponse{},
	}
	svc.SetClient(mockClient)

	result, err := svc.ListAllCertificates()
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// TestSC_CertService_ParseCertificateInfo_InvalidPEM covers L145-147.
func TestSC_CertService_ParseCertificateInfo_InvalidPEM(t *testing.T) {
	ci := &transport.CertificateInfo{
		KeyID:          "k",
		Subject:        "CN=test",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
	}
	info := parseCertificateInfo("b", ci)
	assert.Equal(t, "b", info.Backend)
}

// TestSC_CertService_ParseCertificateInfo_NilBlock covers L140-141 (nil block).
func TestSC_CertService_ParseCertificateInfo_NilBlock(t *testing.T) {
	ci := &transport.CertificateInfo{KeyID: "k", CertificatePEM: "not-pem-data"}
	info := parseCertificateInfo("b", ci)
	assert.Equal(t, "b", info.Backend)
}

// ===========================================================================
// connection_service.go tests
// ===========================================================================

// TestSC_ConnectionService_Connect_Error covers L135-137 and L144-146.
func TestSC_ConnectionService_Connect_Error(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	svc.SetEventEmitter(func(_ events.Event) {})

	info, err := svc.Connect("rest", "http://127.0.0.1:1", false, "", "")
	assert.Error(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "error", info.State)
}

// TestSC_ConnectionService_HealthCheck_NotConnected covers L196.
func TestSC_ConnectionService_HealthCheck_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	_, err := svc.HealthCheck()
	assert.True(t, errors.Is(err, ErrServerNotConnected))
}

// ===========================================================================
// auth_service.go tests
// ===========================================================================

// TestSC_AuthService_LoginSO_EnterpriseConfigLoadFails covers L152-160:
// SO login succeeds but config.Load() fails during policy verification.
func TestSC_AuthService_LoginSO_EnterpriseConfigLoadFails(t *testing.T) {
	configDir := t.TempDir()

	// Create a PINService with a real manager and set the SO PIN.
	pinSvc := scNewPINServiceWithManager(t)
	require.NoError(t, pinSvc.SetSOPIN("", "so-pin"))

	// Create the enterprise mode marker file (xkey_policy.hmac).
	require.NoError(t, os.WriteFile(filepath.Join(configDir, scPolicyHMACFile), []byte("d"), 0600))

	// Write an invalid config file so config.Load() fails.
	config.SetConfigDir(configDir)
	defer config.ResetConfigDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "xkey.yaml"),
		[]byte("{{{{invalid yaml"),
		0600,
	))

	svc := NewAuthService(pinSvc, configDir)
	svc.SetContext(context.Background())

	result := svc.LoginSO("so-pin")
	assert.True(t, result.Success)
	assert.Equal(t, string(AuthModeSOAdmin), result.Mode)
	assert.False(t, result.PolicyVerified)
	assert.Contains(t, result.Error, "config load failed")
}

// ===========================================================================
// helpers
// ===========================================================================

// scMakeSelfSignedCert generates a valid self-signed X.509 certificate
// for use in trust_service tests.
func scMakeSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sc-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}
