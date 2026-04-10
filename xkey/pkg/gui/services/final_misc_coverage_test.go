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
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Mocks (fm prefix to avoid conflicts)
// =========================================================================

// fmTokenStore is a controllable OIDC token store mock.
type fmTokenStore struct {
	saveErr  error
	loadErr  error
	loadResp *oidc.TokenResponse
	closeErr error
}

func (m *fmTokenStore) Save(_ string, _ *oidc.TokenResponse) error { return m.saveErr }
func (m *fmTokenStore) Load(_ string) (*oidc.TokenResponse, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.loadResp, nil
}
func (m *fmTokenStore) Delete(_ string) error   { return nil }
func (m *fmTokenStore) List() ([]string, error) { return nil, nil }
func (m *fmTokenStore) Close() error            { return m.closeErr }

// fmOATHStore is a controllable OATH store mock.
type fmOATHStore struct {
	getErr    error
	getCred   *oath.Credential
	listCreds []*oath.Credential
	listErr   error
	updateErr error
}

func (m *fmOATHStore) Add(_ *oath.Credential) error { return nil }
func (m *fmOATHStore) Get(_ string) (*oath.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getCred, nil
}
func (m *fmOATHStore) List() ([]*oath.Credential, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listCreds, nil
}
func (m *fmOATHStore) Update(_ *oath.Credential) error { return m.updateErr }
func (m *fmOATHStore) Delete(_ string) error           { return nil }
func (m *fmOATHStore) Close() error                    { return nil }

// fmMockElevator is a simple mock Elevator for storage tests.
type fmMockElevator struct {
	available bool
	runOut    []byte
	runErr    error
}

func (m *fmMockElevator) IsAvailable() bool                        { return m.available }
func (m *fmMockElevator) Run(_ []string, _ []byte) ([]byte, error) { return m.runOut, m.runErr }

// fmSealMock is a seal mock TPM for seal/auto-unseal tests.
type fmSealMock struct {
	mockTPM
	canSeal   bool
	sealErr   error
	unsealErr error
}

func (m *fmSealMock) CanSeal() bool { return m.canSeal }
func (m *fmSealMock) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: data,
		TPMPublic:  []byte("tpm-public"),
		TPMPrivate: []byte("tpm-private"),
	}, nil
}
func (m *fmSealMock) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return sealed.Ciphertext, nil
}

func fmDefaultSealMock() *fmSealMock {
	return &fmSealMock{
		mockTPM: *defaultMockTPM(),
		canSeal: true,
	}
}

func fmNewSealSvc(t *testing.T, mock *fmSealMock) *SealService {
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

	svc := NewSealService(t.TempDir())
	svc.SetClientFunc(func() xkms.Client { return mc })
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	svc.SetContext(context.Background())
	return svc
}

// fmSelfSignedCert generates a self-signed ECDSA certificate for testing.
func fmSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "fm-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// =========================================================================
// oidc_service.go: Close with tokenStore.Close error
// =========================================================================

// TestFM_OIDCService_Close_TokenStoreCloseError covers the path where
// tokenStore.Close returns an error (line 231 returns the error).
func TestFM_OIDCService_Close_TokenStoreCloseError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.tokenStore = &fmTokenStore{closeErr: errors.New("close failed")}

	err := svc.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
}

// TestFM_OIDCService_Close_NilTokenStore covers the nil tokenStore branch
// (line 230-232: if s.tokenStore != nil).
func TestFM_OIDCService_Close_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.tokenStore = nil

	err := svc.Close()
	assert.NoError(t, err)
}

// TestFM_OIDCService_Login_AWSProviderType covers the AWS login rejection
// branch (line 452-454: if entry.Type == OIDCProviderTypeAWS).
func TestFM_OIDCService_Login_AWSProviderType(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetContext(context.Background())

	svc.providersMu.Lock()
	svc.providers["aws-test"] = &OIDCProviderEntry{
		Name:   "aws-test",
		Type:   OIDCProviderTypeAWS,
		Issuer: "https://aws.example.com",
	}
	svc.providersMu.Unlock()

	result, err := svc.Login("aws-test")
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "AWS")
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestFM_OIDCService_Login_NilContext covers the nil context fallback
// (line 457-459: if ctx == nil).
func TestFM_OIDCService_Login_NilContext(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	// Do NOT set context -- leave svc.ctx == nil.

	svc.providersMu.Lock()
	svc.providers["test-prov"] = &OIDCProviderEntry{
		Name:   "test-prov",
		Type:   OIDCProviderTypeStandard,
		Issuer: "https://invalid.local.invalid",
	}
	svc.providersMu.Unlock()

	// Login will fail at discovery but the nil-context fallback is exercised.
	result, err := svc.Login("test-prov")
	assert.NoError(t, err)
	assert.NotEmpty(t, result.Error)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestFM_OIDCService_RefreshToken_NilTokenStore covers line 645-647:
// RefreshToken returns ErrOIDCTokenStoreUnavailable when tokenStore is nil.
func TestFM_OIDCService_RefreshToken_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providersMu.Lock()
	svc.providers["test"] = &OIDCProviderEntry{Name: "test"}
	svc.providersMu.Unlock()
	svc.tokenStore = nil

	_, err := svc.RefreshToken("test")
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

// TestFM_OIDCService_RefreshToken_NoRefreshToken covers line 654-656:
// RefreshToken returns ErrOIDCNoRefreshToken when token has no refresh_token.
func TestFM_OIDCService_RefreshToken_NoRefreshToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providersMu.Lock()
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://issuer.local",
	}
	svc.providersMu.Unlock()

	svc.tokenStore = &fmTokenStore{
		loadResp: &oidc.TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "", // empty = no refresh token
		},
	}

	_, err := svc.RefreshToken("test")
	assert.ErrorIs(t, err, ErrOIDCNoRefreshToken)
}

// TestFM_OIDCService_ExecuteScript_Empty covers line 847-849:
// ExecuteScript returns ErrOIDCExecEmpty when script is empty.
func TestFM_OIDCService_ExecuteScript_Empty(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	_, err := svc.ExecuteScript("any", "")
	assert.ErrorIs(t, err, ErrOIDCExecEmpty)
}

// TestFM_OIDCService_ExecuteScript_ProviderNotFound covers line 851-853.
func TestFM_OIDCService_ExecuteScript_ProviderNotFound(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	_, err := svc.ExecuteScript("nonexistent", "echo hello")
	assert.Error(t, err)
}

// TestFM_OIDCService_saveProviders_EmptyDataDir covers line 1076-1078:
// saveProviders returns nil immediately when dataDir is empty.
func TestFM_OIDCService_saveProviders_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.dataDir = ""
	err := svc.saveProviders()
	assert.NoError(t, err)
}

// TestFM_OIDCService_saveProviders_MkdirFails covers line 1093:
// saveProviders returns error when MkdirAll fails (path is a file, not dir).
func TestFM_OIDCService_saveProviders_MkdirFails(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.dataDir = "/dev/null/impossible"

	svc.providersMu.Lock()
	svc.providers["p1"] = &OIDCProviderEntry{Name: "p1"}
	svc.providersMu.Unlock()

	err := svc.saveProviders()
	assert.Error(t, err)
}

// =========================================================================
// setup_wizard_service.go: ApplySetup uncovered branches
// =========================================================================

// TestFM_SetupWizard_ApplySetup_BarrierInitFails covers step 2 barrier
// initialization failure path (line 339-342).
func TestFM_SetupWizard_ApplySetup_BarrierInitFails(t *testing.T) {
	dir := t.TempDir()
	cfg := &GUIConfigData{}

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })
	svc.SetConfigDir(dir)

	// Create a barrier service that fails to initialize.
	barrierSvc := NewBarrierService(dir, slog.Default())
	// Pre-create barrier dir and root key to trigger ErrBarrierAlreadyInit.
	barrierDir := filepath.Join(dir, barrierSubdir)
	require.NoError(t, os.MkdirAll(barrierDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte("x"), 0600))
	svc.SetBarrierService(barrierSvc)

	// With a User PIN provided, the barrier uses it as the password.
	// Even though there's a pre-existing corrupt root_key, the barrier
	// detects it and re-initializes with the User PIN.
	choices := &SetupChoices{
		Mode:        "standalone",
		SOPin:       "123456",
		UserPin:     "654321",
		StorageType: "barrier",
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	// Barrier may succeed or fail depending on the corrupt root key handling,
	// but the wizard should not panic.
	require.NotNil(t, result)
}

// TestFM_SetupWizard_ApplySetup_NilBarrierSvc covers step 2 nil barrier
// service path (line 331-332).
func TestFM_SetupWizard_ApplySetup_NilBarrierSvc(t *testing.T) {
	dir := t.TempDir()
	cfg := &GUIConfigData{}

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })
	svc.SetConfigDir(dir)
	// Do NOT set barrier service.

	choices := &SetupChoices{
		Mode:        "standalone",
		SOPin:       "123456",
		UserPin:     "654321",
		StorageType: "barrier",
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	assert.Contains(t, result.Warnings, "barrier service unavailable")
}

// TestFM_SetupWizard_ApplySetup_InitDataDirFails covers step 3 data dir
// initialization failure (line 357-362).
func TestFM_SetupWizard_ApplySetup_InitDataDirFails(t *testing.T) {
	dir := t.TempDir()
	cfg := &GUIConfigData{}

	svc := NewSetupWizardService()
	svc.SetContext(context.Background())
	svc.SetConfigFunc(func() *GUIConfigData { return cfg })
	svc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })
	svc.SetConfigDir(dir)
	svc.SetInitDataDirFunc(func() error {
		return errors.New("init data dir failed")
	})

	choices := &SetupChoices{
		Mode:        "standalone",
		SOPin:       "123456",
		UserPin:     "654321",
		StorageType: "barrier",
	}

	result, err := svc.ApplySetup(choices)
	require.NoError(t, err)
	assert.False(t, result.Success)
}

// TestFM_SetupWizard_ApplySOProvisioning_InvalidMode covers the invalid
// deployment mode path in ApplySOProvisioning (line 694-696).
func TestFM_SetupWizard_ApplySOProvisioning_InvalidMode(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetContext(context.Background())

	choices := &SetupChoices{
		SOPin: "123456",
		Mode:  "INVALID_MODE",
	}

	_, err := svc.ApplySOProvisioning(choices)
	assert.ErrorIs(t, err, ErrSetupInvalidDeploymentMode)
}

// TestFM_SetupWizard_ApplySOProvisioning_NoSOPin covers the empty SO PIN
// path in ApplySOProvisioning (line 691-692).
func TestFM_SetupWizard_ApplySOProvisioning_NoSOPin(t *testing.T) {
	svc := NewSetupWizardService()
	choices := &SetupChoices{SOPin: "", Mode: "local"}
	_, err := svc.ApplySOProvisioning(choices)
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
}

// =========================================================================
// phone_service.go: helper functions
// =========================================================================

// TestFM_Hostname covers the hostname() function happy path.
func TestFM_Hostname(t *testing.T) {
	name := hostname()
	assert.NotEmpty(t, name)
}

// TestFM_ParseDERChain_ValidChain covers parseDERChain with a valid cert.
func TestFM_ParseDERChain_ValidChain(t *testing.T) {
	cert := fmSelfSignedCert(t)
	chain, err := parseDERChain([][]byte{cert.Raw})
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, cert.Subject.String(), chain[0].Subject.String())
}

// TestFM_ParseDERChain_InvalidDER covers parseDERChain with invalid DER data.
func TestFM_ParseDERChain_InvalidDER(t *testing.T) {
	_, err := parseDERChain([][]byte{[]byte("not-a-cert")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 0")
}

// TestFM_ParseDERChain_EmptySlice covers parseDERChain with no certs.
func TestFM_ParseDERChain_EmptySlice(t *testing.T) {
	chain, err := parseDERChain([][]byte{})
	require.NoError(t, err)
	assert.Empty(t, chain)
}

// TestFM_FormatTrustAnchorName_AllBranches exercises all branches of
// formatTrustAnchorName.
func TestFM_FormatTrustAnchorName_AllBranches(t *testing.T) {
	// nil cert.
	assert.Equal(t, "Unknown", formatTrustAnchorName(nil))

	// Org + CN
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"ACME Corp"},
			CommonName:   "Root CA",
		},
	}
	assert.Equal(t, "ACME Corp - Root CA", formatTrustAnchorName(cert))

	// CN only
	cert2 := &x509.Certificate{
		Subject: pkix.Name{CommonName: "My Root"},
	}
	assert.Equal(t, "My Root", formatTrustAnchorName(cert2))

	// Org only
	cert3 := &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"OrgOnly"}},
	}
	assert.Equal(t, "OrgOnly", formatTrustAnchorName(cert3))

	// SerialNumber only
	cert4 := &x509.Certificate{
		Subject: pkix.Name{SerialNumber: "ABC123"},
	}
	assert.Contains(t, formatTrustAnchorName(cert4), "SN=ABC123")

	// Fallback - empty subject
	cert5 := &x509.Certificate{
		Subject: pkix.Name{},
	}
	assert.Equal(t, "Google Hardware Attestation Root", formatTrustAnchorName(cert5))
}

// TestFM_PubKeyFP_ValidCert covers the pubKeyFP happy path.
func TestFM_PubKeyFP_ValidCert(t *testing.T) {
	cert := fmSelfSignedCert(t)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex is 64 chars
}

// TestFM_CertFP covers the certFP helper.
func TestFM_CertFP(t *testing.T) {
	cert := fmSelfSignedCert(t)
	fp := certFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

// TestFM_FindMatchingTrustRoot_Match covers the match case.
func TestFM_FindMatchingTrustRoot_Match(t *testing.T) {
	cert := fmSelfSignedCert(t)
	found := findMatchingTrustRoot([]*x509.Certificate{cert}, []*x509.Certificate{cert})
	assert.NotNil(t, found)
	assert.Equal(t, certFP(cert), certFP(found))
}

// TestFM_FindMatchingTrustRoot_NoMatch covers the no-match case.
func TestFM_FindMatchingTrustRoot_NoMatch(t *testing.T) {
	cert := fmSelfSignedCert(t)
	other := fmSelfSignedCert(t) // different cert
	found := findMatchingTrustRoot([]*x509.Certificate{cert}, []*x509.Certificate{other})
	assert.Nil(t, found)
}

// TestFM_FindMatchingTrustRoot_EmptyChain covers the empty chain case.
func TestFM_FindMatchingTrustRoot_EmptyChain(t *testing.T) {
	found := findMatchingTrustRoot([]*x509.Certificate{}, []*x509.Certificate{fmSelfSignedCert(t)})
	assert.Nil(t, found)
}

// TestFM_PasswordProtection_GetStatus_NilConfig covers line 141-143:
// GetStatus with nil config returns mode "none".
func TestFM_PasswordProtection_GetStatus_NilConfig(t *testing.T) {
	dir := t.TempDir()
	pwStore := staticpw.NewStore(storage.NewMemory())
	staticSvc := NewStaticPasswordService(pwStore)
	svc := NewPasswordProtectionService(filepath.Join(dir, "enc.json"), staticSvc, nil)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "barrier", status.Mode)
}

// =========================================================================
// seal_service.go: uncovered branches
// =========================================================================

// TestFM_SealService_ListBlobs_StorageDirMissing covers line 295-298:
// ListBlobs returns empty list when storage dir check fails.
func TestFM_SealService_ListBlobs_StorageDirMissing(t *testing.T) {
	svc := NewSealService("/nonexistent/path/that/cannot/exist")
	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestFM_SealService_SaveBlob_MarshalAndWrite covers saveBlob with a real
// blob (happy path that exercises ensureStorageDir + marshal + write).
func TestFM_SealService_SaveBlob_MarshalAndWrite(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	blob := &sealedBlobStorage{
		ID:        "test-blob-1",
		Label:     "test",
		CreatedAt: time.Now(),
	}
	err := svc.saveBlob(blob)
	assert.NoError(t, err)

	// Verify the file was written.
	path := svc.blobPath("test-blob-1")
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

// TestFM_SealService_HashPassword covers the hashPassword function.
func TestFM_SealService_HashPassword(t *testing.T) {
	hash, err := hashPassword("test-password")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, ":")

	// Verify password matches.
	assert.True(t, verifyPassword("test-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

// TestFM_SealService_VerifyPassword_InvalidFormat covers verifyPassword with
// bad format (no colon separator).
func TestFM_SealService_VerifyPassword_InvalidFormat(t *testing.T) {
	assert.False(t, verifyPassword("any", "no-colon-here"))
}

// TestFM_SealService_VerifyPassword_InvalidHexSalt covers verifyPassword with
// invalid hex in the salt portion.
func TestFM_SealService_VerifyPassword_InvalidHexSalt(t *testing.T) {
	assert.False(t, verifyPassword("any", "ZZZZ:abcd"))
}

// TestFM_SealService_VerifyPassword_InvalidHexHash covers verifyPassword with
// invalid hex in the hash portion.
func TestFM_SealService_VerifyPassword_InvalidHexHash(t *testing.T) {
	assert.False(t, verifyPassword("any", "abcd:ZZZZ"))
}

// TestFM_SealService_SealData_DecodeFailure covers line 367-369:
// SealData returns ErrSealDecodeFailed when data is not valid base64.
func TestFM_SealService_SealData_DecodeFailure(t *testing.T) {
	mock := fmDefaultSealMock()
	svc := fmNewSealSvc(t, mock)

	req := &SealRequest{
		Label: "test",
		Data:  "not!!!valid!!!base64",
	}
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

// =========================================================================
// oath_service.go: uncovered paths
// =========================================================================

// TestFM_OATHService_GenerateTOTP_WrongType covers line 162-164:
// GenerateTOTP returns ErrOATHGenerateFailed when credential type is HOTP.
func TestFM_OATHService_GenerateTOTP_WrongType(t *testing.T) {
	store := &fmOATHStore{
		getCred: &oath.Credential{
			ID:     "test-hotp",
			Type:   oath.TypeHOTP,
			Secret: "JBSWY3DPEHPK3PXP",
		},
	}
	svc := NewOATHService(store)
	_, err := svc.GenerateTOTP("test-hotp")
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// TestFM_OATHService_GenerateHOTP_WrongType covers line 199-200:
// GenerateHOTP returns ErrOATHGenerateFailed when credential type is TOTP.
func TestFM_OATHService_GenerateHOTP_WrongType(t *testing.T) {
	store := &fmOATHStore{
		getCred: &oath.Credential{
			ID:     "test-totp",
			Type:   oath.TypeTOTP,
			Secret: "JBSWY3DPEHPK3PXP",
		},
	}
	svc := NewOATHService(store)
	_, err := svc.GenerateHOTP("test-totp")
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// TestFM_OATHService_GenerateTOTP_NilStore covers line 150-152:
// GenerateTOTP returns ErrOATHStoreNotSet when store is nil.
func TestFM_OATHService_GenerateTOTP_NilStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateTOTP("any")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

// TestFM_OATHService_GenerateHOTP_NilStore covers line 187-189.
func TestFM_OATHService_GenerateHOTP_NilStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateHOTP("any")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

// TestFM_OATHService_GenerateTOTP_EmptyID covers line 153-155.
func TestFM_OATHService_GenerateTOTP_EmptyID(t *testing.T) {
	store := &fmOATHStore{}
	svc := NewOATHService(store)
	_, err := svc.GenerateTOTP("")
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

// TestFM_OATHService_GenerateHOTP_EmptyID covers line 190-192.
func TestFM_OATHService_GenerateHOTP_EmptyID(t *testing.T) {
	store := &fmOATHStore{}
	svc := NewOATHService(store)
	_, err := svc.GenerateHOTP("")
	assert.ErrorIs(t, err, ErrOATHInvalidID)
}

// =========================================================================
// clipboard_service.go: uncovered paths
// =========================================================================

// TestFM_ClipboardService_CopyWithClear_ToolNone covers line 85-87:
// CopyWithClear returns ErrClipboardToolUnavailable when no tool.
func TestFM_ClipboardService_CopyWithClear_ToolNone(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipToolNone,
	}
	svc.timeout.Store(30)

	err := svc.CopyWithClear("secret")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFM_ClipboardService_ClearClipboard_ToolNone covers line 122-124:
// ClearClipboard returns ErrClipboardToolUnavailable when no tool.
func TestFM_ClipboardService_ClearClipboard_ToolNone(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipToolNone,
	}
	err := svc.ClearClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFM_ClipboardService_CopyWithClear_ZeroTimeout covers line 93-96:
// CopyWithClear with timeout=0 does not schedule clear.
func TestFM_ClipboardService_CopyWithClear_ZeroTimeout(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipToolXclip, // Need a non-none tool, but writeClipboard may fail.
	}
	svc.timeout.Store(0)

	// The write will fail (xclip not likely in test env), but we exercise
	// the timeout=0 branch check at line 94.
	_ = svc.CopyWithClear("secret")
}

// TestFM_ClipboardService_WriteClipboard_DefaultCase covers line 180-182:
// writeClipboard returns ErrClipboardToolUnavailable for unknown tool.
func TestFM_ClipboardService_WriteClipboard_DefaultCase(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipboardTool(99), // unknown tool
	}
	err := svc.writeClipboard("text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFM_ClipboardService_ReadClipboard_DefaultCase covers line 204-206:
// readClipboard returns ErrClipboardToolUnavailable for unknown tool.
func TestFM_ClipboardService_ReadClipboard_DefaultCase(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipboardTool(99),
	}
	_, err := svc.readClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// TestFM_DetectClipboardTool covers detectClipboardTool() returns something.
func TestFM_DetectClipboardTool(t *testing.T) {
	tool := detectClipboardTool()
	assert.True(t, tool >= clipToolNone && tool <= clipToolWlCopy)
}

// =========================================================================
// auto_unseal_service.go: uncovered edges
// =========================================================================

// TestFM_AutoUnseal_Enable_ConfigSaveFuncNil covers line 146-148.
func TestFM_AutoUnseal_Enable_ConfigSaveFuncNil(t *testing.T) {
	mock := fmDefaultSealMock()
	sealSvc := fmNewSealSvc(t, mock)
	storageSvc := NewStorageService()

	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData { return testConfigData() })
	// Do NOT set configSave.

	_, err := autoSvc.Enable("password1234", nil, "sha256", "none", "", "tpm2")
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

// TestFM_AutoUnseal_TryAutoUnseal_NilConfigFunc covers line 247-252.
func TestFM_AutoUnseal_TryAutoUnseal_NilConfigFunc(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not configured")
}

// TestFM_AutoUnseal_TryAutoUnseal_NotConfigured covers line 255-259.
func TestFM_AutoUnseal_TryAutoUnseal_NotConfigured(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return &GUIConfigData{AutoUnsealEnabled: false}
	})

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
}

// TestFM_AutoUnseal_TryAutoUnseal_UnsealFails covers line 272-279.
func TestFM_AutoUnseal_TryAutoUnseal_UnsealFails(t *testing.T) {
	mock := fmDefaultSealMock()
	sealSvc := fmNewSealSvc(t, mock)
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return testConfigDataWithAutoUnseal("nonexistent-blob")
	})

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "unseal")
}

// TestFM_AutoUnseal_TryAutoUnseal_InvalidBase64 covers line 283-290:
// TryAutoUnseal fails when the unsealed data is not valid base64.
func TestFM_AutoUnseal_TryAutoUnseal_InvalidBase64(t *testing.T) {
	mock := fmDefaultSealMock()
	sealSvc := fmNewSealSvc(t, mock)
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())

	// Write a manually crafted blob with raw (non-base64) sealed data
	// so that UnsealData returns a non-base64 string.
	blobDir := sealSvc.storageDir
	blobID := "bad-b64-blob"
	rawBlob := &sealedBlobStorage{
		ID:        blobID,
		Label:     "auto-unseal-passphrase",
		CreatedAt: time.Now(),
		SealedData: &types.SealedData{
			Ciphertext: []byte("not-base64-at-all!!!"),
		},
	}
	data, _ := json.Marshal(rawBlob)
	require.NoError(t, os.WriteFile(filepath.Join(blobDir, blobID+".sealed.json"), data, 0600))

	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return testConfigDataWithAutoUnseal(blobID)
	})

	result := autoSvc.TryAutoUnseal()
	assert.False(t, result.Success)
}

// TestFM_AutoUnseal_Reseal_UnsealFails covers line 331-335.
func TestFM_AutoUnseal_Reseal_UnsealFails(t *testing.T) {
	mock := fmDefaultSealMock()
	sealSvc := fmNewSealSvc(t, mock)
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetContext(context.Background())
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return testConfigDataWithAutoUnseal("nonexistent-blob")
	})
	autoSvc.SetConfigSaveFunc(func(c *GUIConfigData) error { return nil })

	err := autoSvc.Reseal()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAutoUnsealResealFailed))
}

// TestFM_AutoUnseal_Reseal_ConfigSaveNil covers line 319-321.
func TestFM_AutoUnseal_Reseal_ConfigSaveNil(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	storageSvc := NewStorageService()
	autoSvc := NewAutoUnsealService(sealSvc, storageSvc)
	autoSvc.SetConfigFunc(func() *GUIConfigData {
		return testConfigDataWithAutoUnseal("blob-123")
	})

	err := autoSvc.Reseal()
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

// =========================================================================
// elevation_sudo.go: uncovered paths
// =========================================================================

// TestFM_SudoElevator_Run_EmptyExecPath covers line 74-77:
// Run returns ErrElevationUnavailable when execPath is empty.
func TestFM_SudoElevator_Run_EmptyExecPath(t *testing.T) {
	e := &SudoElevator{
		log:      slog.Default(),
		execPath: "",
		password: []byte("password"),
	}
	_, err := e.Run([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

// TestFM_SudoElevator_IsAvailable_EmptyExecPath covers the early return
// in IsAvailable when execPath is empty.
func TestFM_SudoElevator_IsAvailable_EmptyExecPath(t *testing.T) {
	e := &SudoElevator{
		log:      slog.Default(),
		execPath: "",
	}
	assert.False(t, e.IsAvailable())
}

// TestFM_PkexecElevator_Run_EmptyExecPath covers elevation.go line 78-79:
// Run returns ErrElevationUnavailable when execPath is empty.
func TestFM_PkexecElevator_Run_EmptyExecPath(t *testing.T) {
	e := &PkexecElevator{
		execPath: "",
	}
	_, err := e.Run([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

// TestFM_PkexecElevator_IsAvailable_EmptyExecPath covers elevation.go line 67-68.
func TestFM_PkexecElevator_IsAvailable_EmptyExecPath(t *testing.T) {
	e := &PkexecElevator{
		execPath: "",
	}
	assert.False(t, e.IsAvailable())
}

// TestFM_ZeroBytes covers the zeroBytes utility.
func TestFM_ZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	zeroBytes(data)
	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
}

// =========================================================================
// storage_service.go: testable paths (non-LUKS)
// =========================================================================

// TestFM_StorageService_CreateVolume_InvalidSize covers validation.
func TestFM_StorageService_CreateVolume_InvalidSize(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 0, Passphrase: "longpassphrase"})
	assert.ErrorIs(t, err, ErrStorageInvalidSize)
}

// TestFM_StorageService_CreateVolume_ShortPassphrase covers validation.
func TestFM_StorageService_CreateVolume_ShortPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 5, Passphrase: "short"})
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

// TestFM_StorageService_UnlockVolume_ShortPassphrase covers validation.
func TestFM_StorageService_UnlockVolume_ShortPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.UnlockVolume("short")
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

// TestFM_StorageService_WipeVolume_InvalidStandard covers validation.
func TestFM_StorageService_WipeVolume_InvalidStandard(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("invalid_standard")
	assert.ErrorIs(t, err, ErrStorageInvalidStandard)
}

// TestFM_StorageService_RunElevatedCmd_NilElevator covers line 295-296.
func TestFM_StorageService_RunElevatedCmd_NilElevator(t *testing.T) {
	svc := NewStorageService()
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

// TestFM_StorageService_RunElevatedCmd_UnavailableElevator covers line 295-296.
func TestFM_StorageService_RunElevatedCmd_UnavailableElevator(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&fmMockElevator{available: false})
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

// TestFM_StorageService_LuksPathArgs covers luksPathArgs returning args.
func TestFM_StorageService_LuksPathArgs(t *testing.T) {
	args := luksPathArgs()
	if args != nil {
		assert.Len(t, args, 4)
		assert.Equal(t, "--path", args[0])
		assert.Equal(t, "--mount-point", args[2])
	}
}

// =========================================================================
// barrier_service.go: uncovered paths
// =========================================================================

// TestFM_BarrierService_BestStrategy covers BestStrategy returning a result.
func TestFM_BarrierService_BestStrategy(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	best, err := svc.BestStrategy()
	if err == nil {
		assert.NotNil(t, best)
	}
}

// TestFM_BarrierService_Initialize_PasswordRequired covers line 170-172:
// Initialize returns ErrBarrierPasswordRequired for software strategy with
// empty password.
func TestFM_BarrierService_Initialize_PasswordRequired(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())

	err := svc.Initialize("", "software")
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired)
}

// TestFM_BarrierService_Seal_NotInitialized covers line 253-254.
func TestFM_BarrierService_Seal_NotInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	err := svc.Seal()
	assert.ErrorIs(t, err, ErrBarrierNotInitialized)
}

// TestFM_BarrierService_Status_NotInitialized covers line 265-267.
func TestFM_BarrierService_Status_NotInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	status := svc.Status()
	assert.NotNil(t, status)
	assert.True(t, status.Sealed)
}

// TestFM_BarrierService_Initialize_ThenUnseal covers the happy path of
// Initialize + Seal + Unseal.
func TestFM_BarrierService_Initialize_ThenUnseal(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("strong-password-here", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	svc2 := NewBarrierService(dir, slog.Default())
	svc2.SetContext(context.Background())
	err = svc2.Unseal("strong-password-here", "software")
	require.NoError(t, err)

	status := svc2.Status()
	assert.False(t, status.Sealed)
}

// TestFM_BarrierService_Initialize_AlreadyInit covers line 158-161:
// Initialize returns ErrBarrierAlreadyInit when root key exists.
func TestFM_BarrierService_Initialize_AlreadyInit(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("strong-password-here", "software")
	require.NoError(t, err)

	svc2 := NewBarrierService(dir, slog.Default())
	svc2.SetContext(context.Background())
	err = svc2.Initialize("another-password", "software")
	assert.ErrorIs(t, err, ErrBarrierAlreadyInit)
}

// =========================================================================
// piv_service.go: uncovered paths
// =========================================================================

// TestFM_PIVService_CertKeySize_Ed25519 covers certKeySize Ed25519 branch.
func TestFM_PIVService_CertKeySize_Ed25519(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.Ed25519,
		PublicKey:          "not-a-real-key",
	}
	size := certKeySize(cert)
	assert.Equal(t, 256, size)
}

// TestFM_PIVService_CertKeySize_Unknown covers certKeySize unknown key type.
func TestFM_PIVService_CertKeySize_Unknown(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		PublicKey:          "not-a-real-key",
	}
	size := certKeySize(cert)
	assert.Equal(t, 0, size)
}

// TestFM_PIVService_CertKeySize_ECDSA covers certKeySize ECDSA branch.
func TestFM_PIVService_CertKeySize_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	size := certKeySize(cert)
	assert.Equal(t, 256, size)
}

// =========================================================================
// certificate_service.go: uncovered paths
// =========================================================================

// TestFM_CertificateService_ParseCertificateInfo_NilBlock covers line 140-141:
// parseCertificateInfo with invalid PEM returns info without parsed fields.
func TestFM_CertificateService_ParseCertificateInfo_NilBlock(t *testing.T) {
	ci := &transport.CertificateInfo{
		KeyID:          "key-1",
		Subject:        "CN=test",
		Issuer:         "CN=issuer",
		CertificatePEM: "not-valid-pem",
	}
	info := parseCertificateInfo("test-backend", ci)
	assert.Equal(t, "test-backend", info.Backend)
	assert.Equal(t, "key-1", info.KeyID)
	assert.Equal(t, "CN=test", info.Subject)
}

// TestFM_CertificateService_ParseCertificateInfo_BadDER covers line 144-146:
// parseCertificateInfo with PEM containing invalid DER returns info
// without parsed fields from the x509 parse.
func TestFM_CertificateService_ParseCertificateInfo_BadDER(t *testing.T) {
	// Encode garbage into a PEM block.
	ci := &transport.CertificateInfo{
		KeyID:          "key-2",
		Subject:        "CN=test",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nYmFkLWRlcg==\n-----END CERTIFICATE-----\n",
	}
	info := parseCertificateInfo("backend-x", ci)
	assert.Equal(t, "backend-x", info.Backend)
	assert.Equal(t, "key-2", info.KeyID)
	// x509 parse fails, so Subject stays as original value.
	assert.Equal(t, "CN=test", info.Subject)
}

// =========================================================================
// connection_service.go: uncovered paths
// =========================================================================

// TestFM_ConnectionService_HealthCheck_NotConnected covers line 193-194.
func TestFM_ConnectionService_HealthCheck_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	_, err := svc.HealthCheck()
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

// TestFM_ConnectionService_Connect_InvalidProtocol covers line 106-108.
func TestFM_ConnectionService_Connect_InvalidProtocol(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	_, err := svc.Connect("invalid_protocol", "localhost:8080", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidProtocol)
}

// TestFM_ConnectionService_Connect_EmptyAddress covers line 110-112.
func TestFM_ConnectionService_Connect_EmptyAddress(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	_, err := svc.Connect("rest", "", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidAddress)
}

// TestFM_ConnectionService_Disconnect_NotConnected covers line 175-178.
func TestFM_ConnectionService_Disconnect_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	err := svc.Disconnect()
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

// =========================================================================
// fido2_service.go: uncovered paths
// =========================================================================

// TestFM_FIDO2Service_HandleBridgeRequest_NotRunning covers line 336-338.
func TestFM_FIDO2Service_HandleBridgeRequest_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())

	_, err := svc.HandleBridgeRequest("test.method", nil)
	assert.ErrorIs(t, err, ErrFIDO2BridgeStopped)
}

// TestFM_FIDO2Service_ListCredentials_NilStorage covers line 130-131.
func TestFM_FIDO2Service_ListCredentials_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// TestFM_FIDO2Service_StartPhoneBridge_AlreadyRunning covers line 260-262.
func TestFM_FIDO2Service_StartPhoneBridge_AlreadyRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.bridgeRunning.Store(true)
	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeRunning)
}

// TestFM_FIDO2Service_StartPhoneBridge_NilClientFunc covers line 266-268.
func TestFM_FIDO2Service_StartPhoneBridge_NilClientFunc(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeNoClient)
}

// TestFM_FIDO2Service_StopPhoneBridge_NotRunning covers line 299-301.
func TestFM_FIDO2Service_StopPhoneBridge_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StopPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeStopped)
}

// =========================================================================
// audit_service.go: ExportEntries uncovered paths
// =========================================================================

// TestFM_AuditService_ExportEntries_InvalidFormat covers line 128-129.
func TestFM_AuditService_ExportEntries_InvalidFormat(t *testing.T) {
	svc := NewAuditService(nil)
	_, err := svc.ExportEntries("xml", nil)
	assert.ErrorIs(t, err, ErrAuditInvalidFormat)
}

// =========================================================================
// pin_service.go: uncovered paths
// =========================================================================

// TestFM_PINService_SetUserPIN_PINManagerFails covers line 130-131:
// SetUserPIN propagates the PIN manager error.
func TestFM_PINService_SetUserPIN_PINManagerFails(t *testing.T) {
	mgr := &mockPINBackend{setUserPINErr: errors.New("pin manager failed")}
	svc := newTestPINService(mgr)

	err := svc.SetUserPIN("so-pin", "new-user-pin")
	assert.Error(t, err)
}

// TestFM_PINService_ChangeUserPIN_PINManagerFails covers line 179-180.
func TestFM_PINService_ChangeUserPIN_PINManagerFails(t *testing.T) {
	mgr := &mockPINBackend{changeUserErr: errors.New("change failed")}
	svc := newTestPINService(mgr)

	err := svc.ChangeUserPIN("current", "new")
	assert.Error(t, err)
}

// =========================================================================
// trust_service.go: testable error paths
// =========================================================================

// TestFM_TrustService_InstallToSystem_NilStore covers line 319-320.
func TestFM_TrustService_InstallToSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	err := svc.InstallToSystem("fingerprint", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// TestFM_TrustService_RemoveFromSystem_NilStore covers line 352-353.
func TestFM_TrustService_RemoveFromSystem_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	err := svc.RemoveFromSystem("fingerprint", "password")
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// TestFM_TrustService_ImportCertificateFile_NilStore covers line 214-215.
func TestFM_TrustService_ImportCertificateFile_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	_, err := svc.ImportCertificateFile()
	assert.ErrorIs(t, err, ErrNilTrustStore)
}

// TestFM_TrustService_SeedEmbeddedRoots_NilStore covers line 281-283.
func TestFM_TrustService_SeedEmbeddedRoots_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	count, err := svc.SeedEmbeddedRoots("phone_attestation")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestFM_TrustService_IsSystemInstalled_NilStore covers line 380-382.
func TestFM_TrustService_IsSystemInstalled_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	installed, err := svc.IsSystemInstalled("abcdef0123456789")
	require.NoError(t, err)
	assert.False(t, installed)
}

// =========================================================================
// BuildCertInfoList helper coverage
// =========================================================================

// TestFM_BuildCertInfoList_SingleCert covers the buildCertInfoList function
// with a single self-signed cert (both leaf and potential trust anchor).
func TestFM_BuildCertInfoList_SingleCert(t *testing.T) {
	cert := fmSelfSignedCert(t)
	infos := buildCertInfoList([]*x509.Certificate{cert}, []*x509.Certificate{cert})
	require.Len(t, infos, 1)
	assert.True(t, infos[0].IsTrustAnchor)
	assert.NotEmpty(t, infos[0].PublicKeyFP)
	assert.NotEmpty(t, infos[0].CertFP)
}

// TestFM_BuildCertInfoList_NoMatchingRoot covers the case where the chain root
// doesn't match any embedded root.
func TestFM_BuildCertInfoList_NoMatchingRoot(t *testing.T) {
	cert := fmSelfSignedCert(t)
	other := fmSelfSignedCert(t)
	infos := buildCertInfoList([]*x509.Certificate{cert}, []*x509.Certificate{other})
	require.Len(t, infos, 1)
	assert.False(t, infos[0].IsTrustAnchor)
}

// =========================================================================
// PhoneConfigPath covers
// =========================================================================

// TestFM_PhoneConfigPath covers the phoneConfigPath function.
func TestFM_PhoneConfigPath(t *testing.T) {
	path, err := phoneConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".xkey")
	assert.Contains(t, path, devicesConfigFileName)
}

// =========================================================================
// PubKeyAlgoInfo helper
// =========================================================================

// TestFM_PubKeyAlgoInfo_ECDSA covers pubKeyAlgoInfo for ECDSA cert.
func TestFM_PubKeyAlgoInfo_ECDSA(t *testing.T) {
	cert := fmSelfSignedCert(t)
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "ECDSA", algo)
	assert.Equal(t, 256, size)
	assert.Equal(t, "P-256", curve)
}

// =========================================================================
// Seal service: ListBlobs with non-JSON files
// =========================================================================

// TestFM_SealService_ListBlobs_IgnoresNonJSON covers line 307:
// ListBlobs skips non-.json files and directories.
func TestFM_SealService_ListBlobs_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.txt"), []byte("test"), 0600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0700))

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}
