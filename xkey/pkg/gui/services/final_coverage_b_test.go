package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Mocks
// =========================================================================

// fbMockSealer implements types.Sealer for seal_service tests.
type fbMockSealer struct {
	canSeal    bool
	sealResult *xkms.SealedData
	sealErr    error
	unsealData []byte
	unsealErr  error
}

func (m *fbMockSealer) CanSeal() bool { return m.canSeal }
func (m *fbMockSealer) Seal(_ context.Context, _ []byte, _ *xkms.SealOptions) (*xkms.SealedData, error) {
	return m.sealResult, m.sealErr
}
func (m *fbMockSealer) Unseal(_ context.Context, _ *xkms.SealedData, _ *xkms.UnsealOptions) ([]byte, error) {
	return m.unsealData, m.unsealErr
}

// fbPanicTPM embeds mockTPM and panics on selected method calls.
type fbPanicTPM struct {
	mockTPM
	panicOnFixedProps bool
	panicOnEKAttrs    bool
	panicOnReadPCRs   bool
}

func (m *fbPanicTPM) FixedProperties() (*xkms.PropertiesFixed, error) {
	if m.panicOnFixedProps {
		panic("fbPanicTPM: FixedProperties panic")
	}
	return m.fixedProps, m.fixedPropsErr
}

func (m *fbPanicTPM) EKAttributes() (*xkms.KeyAttributes, error) {
	if m.panicOnEKAttrs {
		panic("fbPanicTPM: EKAttributes panic")
	}
	return m.ekAttrs, m.ekAttrsErr
}

func (m *fbPanicTPM) ReadPCRs(_ []uint) ([]xkms.PCRBank, error) {
	if m.panicOnReadPCRs {
		panic("fbPanicTPM: ReadPCRs panic")
	}
	return m.pcrBanks, m.pcrBanksErr
}

// fbMockTokenStore implements oidc.TokenStore for OIDC tests.
type fbMockTokenStore struct {
	saveErr  error
	loadResp *oidc.TokenResponse
	loadErr  error
	delErr   error
	closeErr error
}

func (m *fbMockTokenStore) Save(_ string, _ *oidc.TokenResponse) error { return m.saveErr }
func (m *fbMockTokenStore) Load(_ string) (*oidc.TokenResponse, error) {
	return m.loadResp, m.loadErr
}
func (m *fbMockTokenStore) Delete(_ string) error   { return m.delErr }
func (m *fbMockTokenStore) List() ([]string, error) { return nil, nil }
func (m *fbMockTokenStore) Close() error            { return m.closeErr }

func TestFB_OIDCService_Close_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	assert.NoError(t, svc.Close())
}

func TestFB_OIDCService_Close_WithTokenStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.SetTokenStore(&fbMockTokenStore{closeErr: nil})
	assert.NoError(t, svc.Close())
}

func TestFB_OIDCService_SaveProviders_BadDir(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.dataDir = "/dev/null/impossible"
	svc.providers["test"] = &OIDCProviderEntry{
		Name: "test", Issuer: "https://test.example.com", ClientID: "c123",
	}
	assert.Error(t, svc.saveProviders())
}

func TestFB_OIDCService_Login_AWSType(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"aws": {Name: "aws", Issuer: "https://aws.example.com", ClientID: "x", Type: OIDCProviderTypeAWS},
	}
	result, err := svc.Login("aws")
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NoError(t, err)
	assert.Contains(t, result.Error, "aws_region")
}

func TestFB_OIDCService_RefreshToken_NoStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test", Issuer: "https://test.example.com", ClientID: "x"},
	}
	result, err := svc.RefreshToken("test")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestFB_OIDCService_RefreshToken_LoadError(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test", Issuer: "https://test.example.com", ClientID: "x"},
	}
	svc.SetTokenStore(&fbMockTokenStore{loadErr: errors.New("not found")})
	result, err := svc.RefreshToken("test")
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestFB_OIDCService_RefreshToken_EmptyRefreshToken(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test", Issuer: "https://test.example.com", ClientID: "x"},
	}
	svc.SetTokenStore(&fbMockTokenStore{loadResp: &oidc.TokenResponse{RefreshToken: ""}})
	result, err := svc.RefreshToken("test")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrOIDCNoRefreshToken)
}

func TestFB_OIDCService_GetTokenInfo_NoStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test", Issuer: "https://test.example.com", ClientID: "x"},
	}
	info, err := svc.GetTokenInfo("test")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrOIDCTokenStoreUnavailable)
}

func TestFB_OIDCService_Logout_NoStore(t *testing.T) {
	svc := NewOIDCService(slog.Default())
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test", Issuer: "https://test.example.com", ClientID: "x"},
	}
	assert.ErrorIs(t, svc.Logout("test"), ErrOIDCTokenStoreUnavailable)
}

// =========================================================================
// 3. SetupWizardService (GetPolicy success path)
// =========================================================================

func TestFB_SetupWizard_GetPolicy_Success(t *testing.T) {
	svc := &SetupWizardService{}
	result, err := svc.GetPolicy()
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// =========================================================================
// 4. TrustService
// =========================================================================

func TestFB_TrustService_SeedEmbeddedRoots_AddCertError(t *testing.T) {
	store := &scMockTrustStore{containsResult: false, addCertWithOptsErr: errors.New("add cert failed")}
	svc := NewTrustService(store)
	added, err := svc.SeedEmbeddedRoots("ca")
	assert.Equal(t, 0, added)
	// "ca" is not a supported embedded root purpose, so LoadEmbeddedRoots
	// returns nil and the method returns early with no error.
	assert.NoError(t, err)
}

func TestFB_TrustService_IsSystemInstalled_NilStore(t *testing.T) {
	svc := NewTrustService(nil)
	installed, err := svc.IsSystemInstalled("abc123def456abcd")
	assert.False(t, installed)
	assert.NoError(t, err)
}

// =========================================================================
// 6. TPMService - panic-recover + NilTPM paths
// =========================================================================

func fbTPMSvcWithPanic() *TPMService {
	panicMock := &fbPanicTPM{mockTPM: *defaultMockTPM(), panicOnFixedProps: true}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return panicMock }))
	return svc
}

func fbTPMSvcNilTPM() *TPMService {
	return NewTPMService() // No accessor => getTPM returns ErrTPMNotAvailable
}

func TestFB_TPM_GetStatus_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	status, err := svc.GetStatus()
	assert.Nil(t, err)
	assert.NotNil(t, status)
	assert.False(t, status.Available)
}

func TestFB_TPM_GetStatus_NilAccessor(t *testing.T) {
	svc := fbTPMSvcNilTPM()
	status, err := svc.GetStatus()
	assert.Nil(t, err)
	assert.NotNil(t, status)
	// When the accessor is nil, getTPM fails. GetStatus returns
	// Available=false regardless of whether the device node exists.
	assert.False(t, status.Available)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

func TestFB_TPM_GetInfo_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	info, err := svc.GetInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
}

func TestFB_TPM_GetEKInfo_PanicRecover(t *testing.T) {
	m := &fbPanicTPM{mockTPM: *defaultMockTPM(), panicOnEKAttrs: true}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return m }))
	info, err := svc.GetEKInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFB_TPM_GetEKECCInfo_PanicRecover(t *testing.T) {
	m := &fbPanicTPM{mockTPM: *defaultMockTPM(), panicOnEKAttrs: true}
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return m }))
	info, err := svc.GetEKECCInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestFB_TPM_GetSharedSRKInfo_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	info, err := svc.GetSharedSRKInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
}

func TestFB_TPM_GetPlatformSRKInfo_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	info, err := svc.GetPlatformSRKInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
}

func TestFB_TPM_GetIAKInfo_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	info, err := svc.GetIAKInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
}

func TestFB_TPM_GetIDevIDInfo_PanicRecover(t *testing.T) {
	svc := fbTPMSvcWithPanic()
	info, err := svc.GetIDevIDInfo()
	assert.Nil(t, err)
	assert.NotNil(t, info)
}

func TestFB_TPM_ListKeys_NilAccessor(t *testing.T) {
	svc := fbTPMSvcNilTPM()
	keys, err := svc.ListKeys()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
	assert.Nil(t, keys)
}

func TestFB_TPM_Provision_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().Provision(&ProvisionOptions{Mode: ProvisionModeInstall}), ErrTPMNotAvailable)
}

func TestFB_TPM_Install_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().Install("test"), ErrTPMNotAvailable)
}

func TestFB_TPM_InitializePlatformKeyStore_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().InitializePlatformKeyStore("so", "user"), ErrTPMNotAvailable)
}

func TestFB_TPM_InitializePlatformKeyStoreWithDefaults_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().InitializePlatformKeyStoreWithDefaults(), ErrTPMNotAvailable)
}

func TestFB_TPM_FactoryReset_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().FactoryReset("auth"), ErrTPMNotAvailable)
}

func TestFB_TPM_ProvisionIAK_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ProvisionIAK("auth"), ErrTPMNotAvailable)
}

func TestFB_TPM_ProvisionIDevID_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ProvisionIDevID("auth"), ErrTPMNotAvailable)
}

func TestFB_TPM_GenerateQuote_NilAccessor(t *testing.T) {
	q, err := fbTPMSvcNilTPM().GenerateQuote("", []int{0}, "sha256")
	assert.Nil(t, q)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_GetEventLog_NilAccessor(t *testing.T) {
	entries, err := fbTPMSvcNilTPM().GetEventLog()
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_GetRandomBytes_NilAccessor(t *testing.T) {
	result, err := fbTPMSvcNilTPM().GetRandomBytes(32)
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_GetPCRs_NilAccessor(t *testing.T) {
	pcrs, err := fbTPMSvcNilTPM().GetPCRs("sha256")
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_GetLockoutInfo_NilAccessor(t *testing.T) {
	info, err := fbTPMSvcNilTPM().GetLockoutInfo()
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ChangeOwnerAuth_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ChangeOwnerAuth("o", "n"), ErrTPMNotAvailable)
}

func TestFB_TPM_ChangeEndorsementAuth_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ChangeEndorsementAuth("o", "n"), ErrTPMNotAvailable)
}

func TestFB_TPM_ChangeLockoutAuth_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ChangeLockoutAuth("o", "n"), ErrTPMNotAvailable)
}

func TestFB_TPM_GetNVSummary_NilAccessor(t *testing.T) {
	s, err := fbTPMSvcNilTPM().GetNVSummary()
	assert.Nil(t, s)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_DefineNVOrdinary_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().DefineNVOrdinary(0x01500001, 64, "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_DefineNVCounter_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().DefineNVCounter(0x01500002, "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_DefineNVExtend_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().DefineNVExtend(0x01500003, "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_WriteNVData_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().WriteNVData(0x01500001, "AABB", "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_ReadNVData_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ReadNVData(0x01500001, 64, "a")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_IncrementNVCounter_NilAccessor(t *testing.T) {
	v, err := fbTPMSvcNilTPM().IncrementNVCounter(0x01500002, "a")
	assert.Equal(t, uint64(0), v)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ExtendNV_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ExtendNV(0x01500003, "AABB", "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_ReadNVCounter_NilAccessor(t *testing.T) {
	v, err := fbTPMSvcNilTPM().ReadNVCounter(0x01500002, "a")
	assert.Equal(t, uint64(0), v)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ReadNVExtend_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ReadNVExtend(0x01500003, "a")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_DeleteNVIndex_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().DeleteNVIndex(0x01500001, "a"), ErrTPMNotAvailable)
}

func TestFB_TPM_ResetLockout_NilAccessor(t *testing.T) {
	assert.ErrorIs(t, fbTPMSvcNilTPM().ResetLockout("a"), ErrTPMNotAvailable)
}

func TestFB_TPM_ListPersistentHandles_NilAccessor(t *testing.T) {
	h, err := fbTPMSvcNilTPM().ListPersistentHandles()
	assert.Nil(t, h)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ListTransientHandles_NilAccessor(t *testing.T) {
	h, err := fbTPMSvcNilTPM().ListTransientHandles()
	assert.Nil(t, h)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ExportEKCert_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ExportEKCert("pem")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ImportEKCert_InvalidPEM(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().ImportEKCert("not-pem"), ErrTPMInvalidCert)
}

func TestFB_TPM_ExportEKECCCert_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ExportEKECCCert("pem")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ImportEKECCCert_InvalidPEM(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().ImportEKECCCert("not-pem"), ErrTPMInvalidCert)
}

func TestFB_TPM_ExportIAKCert_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ExportIAKCert("pem")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ImportIAKCert_InvalidPEM(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().ImportIAKCert("not-pem"), ErrTPMInvalidCert)
}

func TestFB_TPM_ExportIDevIDCert_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ExportIDevIDCert("pem")
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ImportIDevIDCert_InvalidPEM(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().ImportIDevIDCert("not-pem"), ErrTPMInvalidCert)
}

func TestFB_TPM_GenerateIDevIDCSR_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().GenerateIDevIDCSR()
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_CertifyKey_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().CertifyKey("0x81000001")
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_VerifyTPM_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().VerifyTPM()
	// VerifyTPM returns a non-nil VerificationStatus with Verified=false
	// and a nil error when the TPM is not available.
	assert.NotNil(t, r)
	assert.NoError(t, err)
	assert.False(t, r.Verified)
}

func TestFB_TPM_ImportManufacturerCA_InvalidPEM(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().ImportManufacturerCA("not-pem"), ErrTPMInvalidCACert)
}

func TestFB_TPM_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().saveHandleDescriptions(map[string]string{"0x81000001": "test"}), ErrTPMDataDirNotSet)
}

func TestFB_TPM_SetHandleDescription_NoDataDir(t *testing.T) {
	assert.ErrorIs(t, NewTPMService().SetHandleDescription("0x81000001", "desc"), ErrTPMDataDirNotSet)
}

func TestFB_TPM_SetHandleDescription_Success(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	assert.NoError(t, svc.SetHandleDescription("0x81000001", "my key"))
}

func TestFB_TPM_GetPlatformPolicy_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().GetPlatformPolicy()
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestFB_TPM_ViewKey_NilAccessor(t *testing.T) {
	r, err := fbTPMSvcNilTPM().ViewKey("test-key")
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// =========================================================================
// 7. SealService (12 stmts)
// =========================================================================

func TestFB_SealService_SealData_InvalidBase64(t *testing.T) {
	svc := NewSealService(t.TempDir())
	fbWireSealClient(svc, &fbMockSealer{canSeal: true})
	r, err := svc.SealData(&SealRequest{
		Label: "test", Data: "!!!invalid!!!"})
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

func TestFB_SealService_SealData_BackendNotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	r, err := svc.SealData(&SealRequest{
		Label: "t", Data: base64.StdEncoding.EncodeToString([]byte("s")), Backend: "missing"})
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

func TestFB_SealService_SealData_CannotSeal(t *testing.T) {
	svc := NewSealService(t.TempDir())
	fbWireSealClient(svc, &fbMockSealer{canSeal: false, sealErr: ErrSealNotSupported})
	r, err := svc.SealData(&SealRequest{
		Label: "t", Data: base64.StdEncoding.EncodeToString([]byte("s"))})
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrSealNotSupported)
}

func TestFB_SealService_SealData_SealError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	fbWireSealClient(svc, &fbMockSealer{canSeal: true, sealErr: errors.New("seal failed")})
	r, err := svc.SealData(&SealRequest{
		Label: "t", Data: base64.StdEncoding.EncodeToString([]byte("s"))})
	assert.Nil(t, r)
	assert.Error(t, err)
}

func TestFB_SealService_SaveBlob_BadDir(t *testing.T) {
	svc := NewSealService("/dev/null/impossible")
	assert.ErrorIs(t, svc.saveBlob(&sealedBlobStorage{
		BackendID: "software", ID: "id", Label: "l"}), ErrSealStorageFailed)
}

func TestFB_SealService_CanSeal_NoBackend(t *testing.T) {
	ok, err := NewSealService(t.TempDir()).CanSeal()
	assert.False(t, ok)
	assert.NoError(t, err)
}

func TestFB_SealService_UnsealData_NotFound(t *testing.T) {
	r, err := NewSealService(t.TempDir()).UnsealData("nonexistent", "")
	assert.Empty(t, r)
	assert.Error(t, err)
}

func TestFB_SealService_DeleteBlob_NotFound(t *testing.T) {
	assert.Error(t, NewSealService(t.TempDir()).DeleteBlob("nonexistent"))
}

// =========================================================================
// 8. BarrierService (9 stmts)
// =========================================================================

func TestFB_BarrierService_BestStrategy_NoStrategies(t *testing.T) {
	// Software strategy is always available in ProbeStrategies, so
	// BestStrategy always returns a result even without TPM.
	result, err := NewBarrierService(t.TempDir(), slog.Default()).BestStrategy()
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestFB_BarrierService_Initialize_NoStrategies(t *testing.T) {
	// Software strategy is always available, so Initialize succeeds
	// when given a password and a writable temp directory.
	assert.NoError(t, NewBarrierService(t.TempDir(), slog.Default()).Initialize("pw", "passphrase"))
}

func TestFB_BarrierService_Status_NotInitialized(t *testing.T) {
	status := NewBarrierService(t.TempDir(), slog.Default()).Status()
	assert.NotNil(t, status)
	assert.True(t, status.Sealed)
}

// =========================================================================
// 9. AutoUnsealService (6 stmts)
// =========================================================================

func TestFB_AutoUnseal_Enable_ConfigFuncNil(t *testing.T) {
	ss := NewSealService(t.TempDir())
	fbWireSealClient(ss, &fbMockSealer{canSeal: true})
	svc := NewAutoUnsealService(ss, NewStorageService())
	r, err := svc.Enable("passphrase-long-enough", xkms.TPMPolicyPlatform, "tpm2")
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrAutoUnsealConfigFuncNil)
}

func TestFB_AutoUnseal_Enable_ConfigSaveFuncNil(t *testing.T) {
	ss := NewSealService(t.TempDir())
	fbWireSealClient(ss, &fbMockSealer{canSeal: true})
	svc := NewAutoUnsealService(ss, NewStorageService())
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{} })
	r, err := svc.Enable("passphrase-long-enough", xkms.TPMPolicyPlatform, "tpm2")
	assert.Nil(t, r)
	assert.ErrorIs(t, err, ErrAutoUnsealConfigSaveFuncNil)
}

func TestFB_AutoUnseal_Disable_ConfigFuncNil(t *testing.T) {
	svc := NewAutoUnsealService(NewSealService(t.TempDir()), NewStorageService())
	assert.ErrorIs(t, svc.Disable(), ErrAutoUnsealConfigFuncNil)
}

func TestFB_AutoUnseal_Attempt_NotConfigured(t *testing.T) {
	svc := NewAutoUnsealService(NewSealService(t.TempDir()), NewStorageService())
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{AutoUnsealEnabled: false} })
	r := svc.TryAutoUnseal()
	assert.NotNil(t, r)
	assert.False(t, r.Success)
}

// =========================================================================
// 10. ElevationSudo (6 stmts)
// =========================================================================

func TestFB_SudoElevator_Run_EmptyExecPath(t *testing.T) {
	e := &SudoElevator{log: slog.Default(), execPath: ""}
	_, err := e.Run([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

func TestFB_ZeroBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	zeroBytes(data)
	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
}

// =========================================================================
// 11. PIVService (5 stmts)
// =========================================================================

func TestFB_PIVService_GenerateCSR_NoClient(t *testing.T) {
	r, err := NewPIVService(nil, "software").GenerateCSR("9a", &CSRSubject{CommonName: "test"})
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrPIVClientNotSet)
}

func TestFB_PIVService_DeleteCertificate_NoClient(t *testing.T) {
	assert.ErrorIs(t, NewPIVService(nil, "software").DeleteCertificate("9a"), ErrPIVClientNotSet)
}

// =========================================================================
// 12. CertificateService (4 stmts)
// =========================================================================

func TestFB_CertificateService_ListAllCertificates_NoClient(t *testing.T) {
	r, err := NewCertificateService().ListAllCertificates()
	assert.Nil(t, r)
	assert.Error(t, err)
}

func TestFB_CertificateService_ParseCertInfo_InvalidPEM(t *testing.T) {
	ci := &transport.CertificateInfo{KeyID: "k", CertificatePEM: "not-pem"}
	info := parseCertificateInfo("software", ci)
	assert.Equal(t, "k", info.KeyID)
	assert.Equal(t, "software", info.Backend)
}

// =========================================================================
// 13. ClipboardService (5 stmts)
// =========================================================================

func TestFB_ClipboardService_CopyWithClear_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	assert.ErrorIs(t, svc.CopyWithClear("s"), ErrClipboardToolUnavailable)
}

func TestFB_ClipboardService_Copy_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	assert.ErrorIs(t, svc.Copy("t"), ErrClipboardToolUnavailable)
}

func TestFB_ClipboardService_ClearClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	assert.ErrorIs(t, svc.ClearClipboard(), ErrClipboardToolUnavailable)
}

func TestFB_ClipboardService_WriteClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	assert.ErrorIs(t, svc.writeClipboard("t"), ErrClipboardToolUnavailable)
}

func TestFB_ClipboardService_ReadClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone
	r, err := svc.readClipboard()
	assert.Empty(t, r)
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// =========================================================================
// 14. FIDO2Service (3 stmts)
// =========================================================================

func TestFB_FIDO2Service_ListCredentials_NilStorage(t *testing.T) {
	creds, err := NewFIDO2Service(nil).ListCredentials()
	assert.NoError(t, err)
	assert.Empty(t, creds)
}

// =========================================================================
// 15. ConnectionService (3 stmts)
// =========================================================================

func TestFB_ConnectionService_HealthCheck_NotConnected(t *testing.T) {
	h, err := NewConnectionService().HealthCheck()
	assert.Nil(t, h)
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

func TestFB_ConnectionService_Connect_InvalidAddress(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	info, err := svc.Connect("grpc", "invalid:0", false, "", "")
	assert.Error(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "error", info.State)
}

// =========================================================================
// 16. PhoneService helpers (non-BLE)
// =========================================================================

func TestFB_PhoneService_Hostname(t *testing.T) {
	assert.NotEmpty(t, hostname())
}

func TestFB_PhoneService_PubKeyFP_ValidCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{PublicKey: key.Public()}
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars
}

// fbWireSealClient wires a sealMockClient into the given SealService,
// deriving SDK client behavior from the fbMockSealer configuration.
func fbWireSealClient(svc *SealService, m *fbMockSealer) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			if m.sealErr != nil {
				return nil, m.sealErr
			}
			ciphertext := req.Data
			if m.sealResult != nil {
				ciphertext = m.sealResult.Ciphertext
			}
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: ciphertext,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			if m.unsealErr != nil {
				return nil, m.unsealErr
			}
			data := req.Ciphertext
			if m.unsealData != nil {
				data = m.unsealData
			}
			return &transport.UnsealResponse{Plaintext: data}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: m.canSeal, Backend: backend}, nil
		},
	}
	svc.SetClientFunc(func() xkms.Client { return mc })
	svc.SetContext(context.Background())
}
