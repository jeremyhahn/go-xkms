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

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	pkcs11module "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// mustSecret seals s into a *secure.Secret for PKCS11TLSConfig.PIN test
// fixtures. Test-only: production callers resolve the PIN from config or a
// CLI flag.
func mustSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()
	sec, err := secure.NewSecret(t.Context(), []byte(s))
	if err != nil {
		t.Fatalf("secure.NewSecret: %v", err)
	}
	return sec
}

// ---------------------------------------------------------------------------
// Config validation tests
// ---------------------------------------------------------------------------

func TestNewPKCS11TLSConfig_NilConfig(t *testing.T) {
	_, _, err := NewPKCS11TLSConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !errors.Is(err, ErrPKCS11NilConfig) {
		t.Errorf("expected ErrPKCS11NilConfig, got: %v", err)
	}
}

func TestNewPKCS11TLSConfig_EmptyModulePath(t *testing.T) {
	cfg := &PKCS11TLSConfig{
		PIN: mustSecret(t, "1234"),
	}
	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty module path")
	}
	if !errors.Is(err, ErrPKCS11ModulePathRequired) {
		t.Errorf("expected ErrPKCS11ModulePathRequired, got: %v", err)
	}
}

func TestNewPKCS11TLSConfig_EmptyPIN(t *testing.T) {
	cfg := &PKCS11TLSConfig{
		ModulePath: "/usr/lib/libxkey11.so",
	}
	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty PIN")
	}
	if !errors.Is(err, ErrPKCS11PINRequired) {
		t.Errorf("expected ErrPKCS11PINRequired, got: %v", err)
	}
}

// TestNewPKCS11TLSConfig_DestroyedPIN proves a PIN secret that has already
// been destroyed surfaces the typed Open() error rather than silently
// authenticating with no PIN or panicking.
func TestNewPKCS11TLSConfig_DestroyedPIN(t *testing.T) {
	pin := mustSecret(t, "1234")
	pin.Destroy()

	cfg := &PKCS11TLSConfig{
		ModulePath: "/usr/lib/libxkey11.so",
		PIN:        pin,
	}
	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for destroyed PIN secret")
	}
	var nilSecretErr *secure.NilSecretError
	if !errors.As(err, &nilSecretErr) {
		t.Errorf("expected *secure.NilSecretError, got: %T: %v", err, err)
	}
}

func TestNewPKCS11TLSConfig_AllFieldsEmpty(t *testing.T) {
	cfg := &PKCS11TLSConfig{}
	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for config with all empty fields")
	}
	// ModulePath is checked first
	if !errors.Is(err, ErrPKCS11ModulePathRequired) {
		t.Errorf("expected ErrPKCS11ModulePathRequired, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Mock transport client for PKCS#11 module tests
// ---------------------------------------------------------------------------

// authMockClient implements transport.Client for testing the PKCS#11 module
// in the auth package. All methods return minimal valid responses.
type authMockClient struct {
	// Unserved serves the attestation Verifier API, which these tests do
	// not exercise.
	appraisaltest.Unserved
}

func (m *authMockClient) Connect(context.Context) error { return nil }
func (m *authMockClient) Close() error                  { return nil }
func (m *authMockClient) Health(context.Context) (*transport.HealthResponse, error) {
	return &transport.HealthResponse{Status: "ok"}, nil
}
func (m *authMockClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return &transport.ListBackendsResponse{}, nil
}
func (m *authMockClient) GetBackend(_ context.Context, id string) (*transport.BackendInfo, error) {
	return &transport.BackendInfo{ID: id}, nil
}
func (m *authMockClient) GenerateKey(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return &transport.GenerateKeyResponse{KeyID: req.KeyID, KeyType: req.KeyType}, nil
}
func (m *authMockClient) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return &transport.ListKeysResponse{}, nil
}
func (m *authMockClient) GetKey(context.Context, string, string) (*transport.GetKeyResponse, error) {
	return &transport.GetKeyResponse{}, nil
}
func (m *authMockClient) DeleteKey(context.Context, string, string) (*transport.DeleteKeyResponse, error) {
	return &transport.DeleteKeyResponse{Success: true}, nil
}
func (m *authMockClient) Sign(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
	return &transport.SignResponse{Signature: []byte("mock-signature")}, nil
}
func (m *authMockClient) Verify(context.Context, *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return &transport.VerifyResponse{Valid: true}, nil
}
func (m *authMockClient) Encrypt(context.Context, *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return &transport.EncryptResponse{Ciphertext: []byte("enc")}, nil
}
func (m *authMockClient) Decrypt(context.Context, *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return &transport.DecryptResponse{Plaintext: []byte("dec")}, nil
}
func (m *authMockClient) EncryptAsym(context.Context, *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return &transport.EncryptAsymResponse{Ciphertext: []byte("enc")}, nil
}
func (m *authMockClient) DeriveKey(_ context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return &transport.DeriveKeyResponse{DerivedKey: make([]byte, 32)}, nil
}
func (m *authMockClient) GetCertificate(context.Context, string, string) (*transport.GetCertificateResponse, error) {
	return &transport.GetCertificateResponse{}, nil
}
func (m *authMockClient) SaveCertificate(context.Context, *transport.SaveCertificateRequest) error {
	return nil
}
func (m *authMockClient) DeleteCertificate(context.Context, string, string) error { return nil }
func (m *authMockClient) CertificateExists(context.Context, string, string) (bool, error) {
	return false, nil
}
func (m *authMockClient) ImportKey(context.Context, *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return &transport.ImportKeyResponse{Success: true}, nil
}
func (m *authMockClient) ExportKey(context.Context, *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return &transport.ExportKeyResponse{}, nil
}
func (m *authMockClient) RotateKey(context.Context, *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return &transport.RotateKeyResponse{Success: true}, nil
}
func (m *authMockClient) GetImportParameters(context.Context, *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return &transport.GetImportParametersResponse{}, nil
}
func (m *authMockClient) WrapKey(context.Context, *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return &transport.WrapKeyResponse{}, nil
}
func (m *authMockClient) UnwrapKey(context.Context, *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return &transport.UnwrapKeyResponse{}, nil
}
func (m *authMockClient) WrapKeyByID(context.Context, *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return &transport.WrapKeyByIDResponse{}, nil
}
func (m *authMockClient) UnwrapKeyByID(context.Context, *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return &transport.UnwrapKeyByIDResponse{}, nil
}
func (m *authMockClient) ExportKeyMaterial(context.Context, *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return &transport.ExportKeyMaterialResponse{KeyMaterial: make([]byte, 32)}, nil
}
func (m *authMockClient) DeriveKeyECDH(context.Context, *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return &transport.DeriveKeyECDHResponse{DerivedKey: make([]byte, 32)}, nil
}
func (m *authMockClient) CopyKey(context.Context, *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return &transport.CopyKeyResponse{Success: true}, nil
}
func (m *authMockClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return &transport.ListCertificatesResponse{}, nil
}
func (m *authMockClient) SaveCertificateChain(context.Context, *transport.SaveCertificateChainRequest) error {
	return nil
}
func (m *authMockClient) GetCertificateChain(context.Context, string, string) (*transport.GetCertificateChainResponse, error) {
	return &transport.GetCertificateChainResponse{}, nil
}
func (m *authMockClient) GetTLSCertificate(context.Context, string, string) (*transport.GetTLSCertificateResponse, error) {
	return &transport.GetTLSCertificateResponse{}, nil
}
func (m *authMockClient) Seal(context.Context, *transport.SealRequest) (*transport.SealResponse, error) {
	return &transport.SealResponse{}, nil
}
func (m *authMockClient) Unseal(context.Context, *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return &transport.UnsealResponse{}, nil
}
func (m *authMockClient) CanSeal(context.Context, string) (*transport.CanSealResponse, error) {
	return &transport.CanSealResponse{}, nil
}
func (m *authMockClient) AttestKey(context.Context, *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return &transport.AttestKeyResponse{}, nil
}
func (m *authMockClient) BeginRegistration(context.Context, *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return &transport.BeginRegistrationResponse{}, nil
}
func (m *authMockClient) FinishRegistration(context.Context, *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return &transport.FinishRegistrationResponse{Success: true}, nil
}
func (m *authMockClient) BeginAuthentication(context.Context, *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return &transport.BeginAuthenticationResponse{}, nil
}
func (m *authMockClient) FinishAuthentication(context.Context, *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return &transport.FinishAuthenticationResponse{Success: true}, nil
}
func (m *authMockClient) GetCABundle(context.Context, *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return &transport.GetCABundleResponse{}, nil
}
func (m *authMockClient) GetCACertificate(context.Context, *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return &transport.GetCACertificateResponse{}, nil
}
func (m *authMockClient) SignCSR(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return &transport.SignCSRResponse{}, nil
}
func (m *authMockClient) IssueCertificate(context.Context, *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return &transport.IssueCertificateResponse{}, nil
}
func (m *authMockClient) RevokeCertificate(context.Context, *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return &transport.RevokeCertificateResponse{}, nil
}
func (m *authMockClient) GenerateCRL(context.Context, *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return &transport.GenerateCRLResponse{}, nil
}
func (m *authMockClient) IsRevoked(context.Context, *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return &transport.IsRevokedResponse{}, nil
}
func (m *authMockClient) ListPIVSlots(context.Context, *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return &transport.ListPIVSlotsResponse{}, nil
}
func (m *authMockClient) GetPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}
func (m *authMockClient) StorePIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	return nil
}
func (m *authMockClient) DeletePIVCertificate(context.Context, *transport.DeletePIVCertificateRequest) error {
	return nil
}
func (m *authMockClient) GeneratePIVKey(context.Context, *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return &transport.GeneratePIVKeyResponse{}, nil
}
func (m *authMockClient) ImportPIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	return nil
}
func (m *authMockClient) ExportPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}
func (m *authMockClient) GeneratePIVCSR(context.Context, *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return &transport.GeneratePIVCSRResponse{}, nil
}

func (m *authMockClient) BarrierSeal(context.Context) error {
	return nil
}

func (m *authMockClient) BootstrapListenerKeys(context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return &transport.BootstrapListenerKeysResponse{}, nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *authMockClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// PIN operations stub implementations
func (m *authMockClient) SetSOPIN(context.Context, *transport.SetSOPINRequest) error {
	return nil
}
func (m *authMockClient) SetUserPIN(context.Context, *transport.SetUserPINRequest) error {
	return nil
}
func (m *authMockClient) ChangeSOPIN(context.Context, *transport.ChangeSOPINRequest) error {
	return nil
}
func (m *authMockClient) ChangeUserPIN(context.Context, *transport.ChangeUserPINRequest) error {
	return nil
}
func (m *authMockClient) VerifySOPIN(context.Context, *transport.VerifySOPINRequest) error {
	return nil
}
func (m *authMockClient) VerifyUserPIN(context.Context, *transport.VerifyUserPINRequest) error {
	return nil
}
func (m *authMockClient) GetLockoutStatus(context.Context) (*transport.LockoutStatusResponse, error) {
	return &transport.LockoutStatusResponse{}, nil
}
func (m *authMockClient) ResetLockout(context.Context, *transport.ResetLockoutRequest) error {
	return nil
}

// Password operations stub implementations
func (m *authMockClient) PasswordAdd(context.Context, *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return &transport.PasswordAddResponse{}, nil
}
func (m *authMockClient) PasswordGet(context.Context, *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return &transport.PasswordGetResponse{}, nil
}
func (m *authMockClient) PasswordList(context.Context, *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return &transport.PasswordListResponse{}, nil
}
func (m *authMockClient) PasswordUpdate(context.Context, *transport.PasswordUpdateRequest) error {
	return nil
}
func (m *authMockClient) PasswordDelete(context.Context, *transport.PasswordDeleteRequest) error {
	return nil
}
func (m *authMockClient) PasswordStoreUnlock(context.Context, *transport.PasswordStoreUnlockRequest) error {
	return nil
}
func (m *authMockClient) PasswordStoreLock(context.Context) error {
	return nil
}
func (m *authMockClient) PasswordStoreStatus(context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return &transport.PasswordStoreStatusResponse{}, nil
}
func (m *authMockClient) PasswordStoreSetAccessMode(context.Context, *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}
func (m *authMockClient) PasswordGenerate(context.Context, *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return &transport.PasswordGenerateResponse{}, nil
}

// Platform store operations stub implementations
func (m *authMockClient) SealStorePut(context.Context, *transport.SealStorePutRequest) error {
	return nil
}
func (m *authMockClient) SealStoreGet(context.Context, *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return &transport.SealStoreGetResponse{}, nil
}
func (m *authMockClient) SealStoreDelete(context.Context, *transport.SealStoreDeleteRequest) error {
	return nil
}
func (m *authMockClient) SealStoreList(context.Context) (*transport.SealStoreListResponse, error) {
	return &transport.SealStoreListResponse{}, nil
}
func (m *authMockClient) SealStoreReseal(context.Context, *transport.SealStoreResealRequest) error {
	return nil
}
func (m *authMockClient) SealStoreStatus(context.Context) (*transport.SealStoreStatusResponse, error) {
	return &transport.SealStoreStatusResponse{}, nil
}

func (m *authMockClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return &transport.ListKeyVersionsResponse{}, nil
}

func (m *authMockClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *authMockClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *authMockClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *authMockClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return &transport.AllKeyVersionsResponse{}, nil
}

func (m *authMockClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return &transport.AllKeyVersionsResponse{}, nil
}

func (m *authMockClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return &transport.RotateScopeKeysResponse{}, nil
}

func (m *authMockClient) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

func (m *authMockClient) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

func (m *authMockClient) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return &transport.TPMPolicyListResponse{}, nil
}

func (m *authMockClient) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

func (m *authMockClient) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

func (m *authMockClient) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return &transport.TPMPolicyVerifyResponse{}, nil
}

func (m *authMockClient) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (m *authMockClient) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return &transport.TPMPolicyObjectsResponse{}, nil
}

func (m *authMockClient) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

func (m *authMockClient) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return &transport.TPMPolicy{}, nil
}

// OIDC credential operations are not exercised by this double.
func (*authMockClient) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*authMockClient) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*authMockClient) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*authMockClient) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*authMockClient) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*authMockClient) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*authMockClient) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*authMockClient) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*authMockClient) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (m *authMockClient) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return &transport.TPMObjectPolicyResponse{}, nil
}

func (m *authMockClient) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return &transport.TPMAuthorityRotateResponse{}, nil
}

func (m *authMockClient) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return &transport.TenantTPMModeResponse{}, nil
}

func (m *authMockClient) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return &transport.TenantTPMModeResponse{}, nil
}

func (m *authMockClient) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return &transport.TenantVTPMStatusResponse{}, nil
}

func (m *authMockClient) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return &transport.TenantVTPMStatusResponse{}, nil
}

func (m *authMockClient) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return &transport.TenantVTPMStatusResponse{}, nil
}

// ---------------------------------------------------------------------------
// PKCS#11 module test helpers
// ---------------------------------------------------------------------------

// setupPKCS11Module creates a fresh PKCS#11 module with mock transport client,
// initialized token, and a logged-in user session. Returns the module, session
// handle, and a cleanup function.
func setupPKCS11Module(t *testing.T) (*pkcs11module.Module, pkcs11module.SessionHandle, func()) {
	t.Helper()

	pkcs11module.ResetGlobalModule()

	moduleCfg := pkcs11module.DefaultConfig()
	moduleCfg.AutoInitToken = true
	moduleCfg.UserPIN = "1234"
	moduleCfg.SOPIN = "1234"
	moduleCfg.TokenLabel = "test-tls"

	mod, err := pkcs11module.New(
		pkcs11module.WithClient(&authMockClient{}),
		pkcs11module.WithConfig(moduleCfg),
	)
	if err != nil {
		t.Fatalf("pkcs11module.New failed: %v", err)
	}

	rv := mod.Initialize(moduleCfg)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("Initialize failed: %s", rv)
	}

	session, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		mod.Finalize()
		t.Fatalf("OpenSession failed: %s", rv)
	}

	rv = mod.Login(session, pkcs11module.CKU_USER, []byte("1234"))
	if rv != pkcs11module.CKR_OK {
		mod.CloseSession(session)
		mod.Finalize()
		t.Fatalf("Login failed: %s", rv)
	}

	cleanup := func() {
		mod.Logout(session)
		mod.CloseSession(session)
		mod.Finalize()
		pkcs11module.ResetGlobalModule()
	}

	return mod, session, cleanup
}

// createSelfSignedCert generates a self-signed certificate and returns the
// DER bytes, the private key, and an ID suitable for PKCS#11 storage.
func createSelfSignedCert(t *testing.T) ([]byte, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test PKCS11 TLS",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certID := []byte("test-cert-id-01")
	return certDER, privKey, certID
}

// importCert imports only a certificate into the PKCS#11 token.
// Returns the certificate object handle.
func importCert(t *testing.T, mod *pkcs11module.Module, session pkcs11module.SessionHandle,
	certDER []byte, certID []byte) pkcs11module.ObjectHandle {
	t.Helper()

	// PKCS#11 v3.2 Table 13 requires CKA_SUBJECT on an X.509 certificate
	// created with C_CreateObject, so it is taken from the certificate itself
	// rather than invented — the two must agree for a search by subject to
	// find this object.
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error: %v", err)
	}

	certTemplate := []pkcs11module.Attribute{
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CLASS, uint32(pkcs11module.CKO_CERTIFICATE)),
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CERTIFICATE_TYPE, pkcs11module.CKC_X_509),
		pkcs11module.NewAttribute(pkcs11module.CKA_VALUE, certDER),
		pkcs11module.NewAttribute(pkcs11module.CKA_SUBJECT, parsed.RawSubject),
		pkcs11module.NewAttribute(pkcs11module.CKA_ID, certID),
		pkcs11module.NewStringAttribute(pkcs11module.CKA_LABEL, "test-tls-cert"),
		{Type: pkcs11module.CKA_TOKEN, Value: []byte{1}},
	}

	certHandle, rv := mod.CreateObject(session, certTemplate)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("CreateObject(cert) failed: %s", rv)
	}

	return certHandle
}

// importCertAndKey imports a certificate and private key into the PKCS#11 token.
// privKey must not be nil.
func importCertAndKey(t *testing.T, mod *pkcs11module.Module, session pkcs11module.SessionHandle,
	certDER []byte, privKey *ecdsa.PrivateKey, certID []byte) (pkcs11module.ObjectHandle, pkcs11module.ObjectHandle) {
	t.Helper()

	certHandle := importCert(t, mod, session, certDER, certID)

	// Import private key - use raw key bytes
	privKeyBytes := privKey.D.Bytes() //nolint:staticcheck // PKCS#11 CKA_VALUE requires raw private scalar
	keyTemplate := []pkcs11module.Attribute{
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CLASS, uint32(pkcs11module.CKO_PRIVATE_KEY)),
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_KEY_TYPE, uint32(pkcs11module.CKK_EC)),
		pkcs11module.NewAttribute(pkcs11module.CKA_VALUE, privKeyBytes),
		pkcs11module.NewAttribute(pkcs11module.CKA_ID, certID),
		pkcs11module.NewStringAttribute(pkcs11module.CKA_LABEL, "test-tls-key"),
		{Type: pkcs11module.CKA_TOKEN, Value: []byte{1}},
		{Type: pkcs11module.CKA_SIGN, Value: []byte{1}},
		// This fixture's key exists only as its own CKA_VALUE: it is imported
		// raw rather than generated in the token, so the module has no backend
		// copy to fall back on. The module refuses to persist such a key while
		// it also claims protection, because withholding CKA_VALUE on reload
		// would silently destroy the only copy. Declare it unprotected, which
		// is the truth for a throwaway test key.
		{Type: pkcs11module.CKA_SENSITIVE, Value: []byte{0}},
		{Type: pkcs11module.CKA_EXTRACTABLE, Value: []byte{1}},
	}

	keyHandle, rv := mod.CreateObject(session, keyTemplate)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("CreateObject(key) failed: %s", rv)
	}

	return certHandle, keyHandle
}

// ---------------------------------------------------------------------------
// findCertificate / findPrivateKey integration tests
// ---------------------------------------------------------------------------

func TestFindCertificate_Success(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	importCertAndKey(t, mod, session, certDER, privKey, certID)

	// Test findCertificate
	foundCertDER, foundCertID, err := findCertificate(mod, session, "")
	if err != nil {
		t.Fatalf("findCertificate() error: %v", err)
	}
	if len(foundCertDER) == 0 {
		t.Fatal("findCertificate() returned empty DER bytes")
	}
	if len(foundCertID) == 0 {
		t.Fatal("findCertificate() returned empty cert ID")
	}

	// Verify the found cert is parseable
	cert, err := x509.ParseCertificate(foundCertDER)
	if err != nil {
		t.Fatalf("failed to parse found certificate: %v", err)
	}
	if cert.Subject.CommonName != "Test PKCS11 TLS" {
		t.Errorf("certificate CN = %q, want %q", cert.Subject.CommonName, "Test PKCS11 TLS")
	}
}

func TestFindCertificate_WithLabel(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, _, certID := createSelfSignedCert(t)
	importCert(t, mod, session, certDER, certID)

	// Find by label
	foundCertDER, _, err := findCertificate(mod, session, "test-tls-cert")
	if err != nil {
		t.Fatalf("findCertificate(label) error: %v", err)
	}
	if len(foundCertDER) == 0 {
		t.Fatal("findCertificate(label) returned empty DER bytes")
	}
}

func TestFindCertificate_EmptyToken(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	// Token is empty - no certificates
	_, _, err := findCertificate(mod, session, "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrPKCS11NoCertFound) {
		t.Errorf("expected ErrPKCS11NoCertFound, got: %v", err)
	}
}

func TestFindCertificate_NonexistentLabel(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, _, certID := createSelfSignedCert(t)
	importCert(t, mod, session, certDER, certID)

	// Find by non-existent label
	_, _, err := findCertificate(mod, session, "nonexistent-label")
	if err == nil {
		t.Fatal("expected error for non-existent label")
	}
	if !errors.Is(err, ErrPKCS11NoCertFound) {
		t.Errorf("expected ErrPKCS11NoCertFound, got: %v", err)
	}
}

func TestFindPrivateKey_EmptyToken(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	// Token is empty - no keys
	_, err := findPrivateKey(mod, session, []byte("nonexistent-id"))
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrPKCS11NoKeyFound) {
		t.Errorf("expected ErrPKCS11NoKeyFound, got: %v", err)
	}
}

func TestFindPrivateKey_NilCertID(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	// Test with nil certID - searches for any private key
	_, err := findPrivateKey(mod, session, nil)
	if err == nil {
		t.Fatal("expected error for nil certID on empty token")
	}
	if !errors.Is(err, ErrPKCS11NoKeyFound) {
		t.Errorf("expected ErrPKCS11NoKeyFound, got: %v", err)
	}
}

func TestFindPrivateKey_WithMatchingKey(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	importCertAndKey(t, mod, session, certDER, privKey, certID)

	// Should find the key by its CKA_ID
	keyHandle, err := findPrivateKey(mod, session, certID)
	if err != nil {
		t.Fatalf("findPrivateKey() error: %v", err)
	}
	if keyHandle == pkcs11module.ObjectHandle(pkcs11module.InvalidHandle) {
		t.Fatal("findPrivateKey() returned invalid handle")
	}
}

func TestFindPrivateKey_NoMatchingID(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	importCertAndKey(t, mod, session, certDER, privKey, certID)

	// Search with an ID that does not match the imported key
	_, err := findPrivateKey(mod, session, []byte("wrong-id"))
	if err == nil {
		t.Fatal("expected error for non-matching CKA_ID")
	}
	if !errors.Is(err, ErrPKCS11NoKeyFound) {
		t.Errorf("expected ErrPKCS11NoKeyFound, got: %v", err)
	}
}

// TestFindObject_FailedSearchInitLeavesSessionUsable leaves a search active on
// the session, as a C_FindObjectsInit that fails part way through does on some
// tokens, and proves the certificate and key lookups report that failure and
// finalize the stale search, so the next lookup on the session succeeds
// instead of failing CKR_OPERATION_ACTIVE forever.
func TestFindObject_FailedSearchInitLeavesSessionUsable(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	importCertAndKey(t, mod, session, certDER, privKey, certID)

	searches := map[string]func() error{
		"certificate": func() error {
			_, _, err := findCertificate(mod, session, "")
			return err
		},
		"private key": func() error {
			_, err := findPrivateKey(mod, session, certID)
			return err
		},
	}

	for name, search := range searches {
		t.Run(name, func(t *testing.T) {
			if rv := mod.FindObjectsInit(session, nil); rv != pkcs11module.CKR_OK {
				t.Fatalf("leave a stale search on the session: rv = %v", rv)
			}

			var tlsErr *PKCS11TLSError
			if err := search(); !errors.As(err, &tlsErr) || tlsErr.Code != pkcs11module.CKR_OPERATION_ACTIVE {
				t.Fatalf("lookup error = %v, want the failed Init's CKR_OPERATION_ACTIVE", err)
			}

			if err := search(); err != nil {
				t.Fatalf("the failed search must not leave the session searching: %v", err)
			}
		})
	}
}

// TestFindObject_FinalFailureIsJoined proves a C_FindObjectsFinal failure is
// reported alongside the lookup's own failure rather than discarded.
func TestFindObject_FinalFailureIsJoined(t *testing.T) {
	mod, _, cleanup := setupPKCS11Module(t)
	defer cleanup()

	invalid := pkcs11module.SessionHandle(0xdead)

	_, _, err := findCertificate(mod, invalid, "")
	if !errors.Is(err, ErrPKCS11NoCertFound) || !errors.Is(err, ErrPKCS11FindObjectsFinal) {
		t.Fatalf("findCertificate() error = %v, want both the Init and the Final failure", err)
	}

	_, err = findPrivateKey(mod, invalid, nil)
	if !errors.Is(err, ErrPKCS11NoKeyFound) || !errors.Is(err, ErrPKCS11FindObjectsFinal) {
		t.Fatalf("findPrivateKey() error = %v, want both the Init and the Final failure", err)
	}
}

// ---------------------------------------------------------------------------
// pkcs11Signer.Sign() integration tests
// ---------------------------------------------------------------------------

func TestPKCS11Signer_Sign_ECDSA(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	_, keyHandle := importCertAndKey(t, mod, session, certDER, privKey, certID)

	signer := &pkcs11Signer{
		module:    mod,
		session:   session,
		keyHandle: keyHandle,
		publicKey: &privKey.PublicKey,
	}

	// Sign a digest
	digest := sha256.Sum256([]byte("test data"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("Sign() returned empty signature")
	}
}

func TestPKCS11Signer_Sign_InvalidKeyHandle(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := &pkcs11Signer{
		module:    mod,
		session:   session,
		keyHandle: pkcs11module.ObjectHandle(0xDEADBEEF),
		publicKey: &key.PublicKey,
	}

	digest := sha256.Sum256([]byte("test data"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for invalid key handle")
	}
	// Should get a SignInit error
	var tlsErr *PKCS11TLSError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *PKCS11TLSError, got %T: %v", err, err)
	}
	if tlsErr.Op != "SignInit" {
		t.Errorf("expected op 'SignInit', got %q", tlsErr.Op)
	}
}

func TestPKCS11Signer_Sign_UnsupportedKeyType(t *testing.T) {
	mod, session, cleanup := setupPKCS11Module(t)
	defer cleanup()

	// Use a nil public key to trigger unsupported key type in selectMechanism
	signer := &pkcs11Signer{
		module:    mod,
		session:   session,
		keyHandle: pkcs11module.ObjectHandle(1),
		publicKey: nil,
	}

	digest := sha256.Sum256([]byte("test data"))
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !errors.Is(err, ErrPKCS11UnsupportedKeyType) {
		t.Errorf("expected ErrPKCS11UnsupportedKeyType, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewPKCS11TLSConfig end-to-end tests with injected in-memory module
// ---------------------------------------------------------------------------

func TestNewPKCS11TLSConfig_FullFlow_Success(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	// Re-open a fresh session for object import (setupPKCS11Module's session
	// will be closed by modCleanup; NewPKCS11TLSConfig opens its own).
	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}
	defer cleanup()

	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate in TLS config")
	}
	if tlsCfg.Certificates[0].Leaf == nil {
		t.Fatal("expected Leaf certificate to be set")
	}
	if tlsCfg.Certificates[0].Leaf.Subject.CommonName != "Test PKCS11 TLS" {
		t.Errorf("Leaf CN = %q, want %q",
			tlsCfg.Certificates[0].Leaf.Subject.CommonName, "Test PKCS11 TLS")
	}
	if tlsCfg.Certificates[0].PrivateKey == nil {
		t.Fatal("expected PrivateKey to be set")
	}
	if _, ok := tlsCfg.Certificates[0].PrivateKey.(crypto.Signer); !ok {
		t.Fatal("PrivateKey should implement crypto.Signer")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d", tlsCfg.MinVersion, tls.VersionTLS13)
	}
}

func TestNewPKCS11TLSConfig_FullFlow_WithCACerts(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	caCertPool := x509.NewCertPool()
	cfg := &PKCS11TLSConfig{
		Module:  mod,
		PIN:     mustSecret(t, "1234"),
		CACerts: caCertPool,
	}

	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}
	defer cleanup()

	if tlsCfg.RootCAs != caCertPool {
		t.Error("expected RootCAs to be set to provided CA pool")
	}
}

func TestNewPKCS11TLSConfig_FullFlow_WithCertLabel(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	cfg := &PKCS11TLSConfig{
		Module:    mod,
		PIN:       mustSecret(t, "1234"),
		CertLabel: "test-tls-cert",
	}

	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}
	defer cleanup()

	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected certificate in TLS config")
	}
}

func TestNewPKCS11TLSConfig_FullFlow_NoCert(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	// Token is empty — no certificate imported.
	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrPKCS11NoCertFound) {
		t.Errorf("expected ErrPKCS11NoCertFound, got: %v", err)
	}
}

func TestNewPKCS11TLSConfig_FullFlow_CertButNoKey(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, _, certID := createSelfSignedCert(t)

	// Import certificate only, no private key.
	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCert(t, mod, importSession, certDER, certID)
	mod.CloseSession(importSession)

	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing private key")
	}
	if !errors.Is(err, ErrPKCS11NoKeyFound) {
		t.Errorf("expected ErrPKCS11NoKeyFound, got: %v", err)
	}
}

func TestNewPKCS11TLSConfig_FullFlow_SignerWorks(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}
	defer cleanup()

	// Extract the signer and verify it can sign.
	signer, ok := tlsCfg.Certificates[0].PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("PrivateKey should implement crypto.Signer")
	}

	digest := sha256.Sum256([]byte("hello pkcs11"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("Sign() returned empty signature")
	}
}

func TestNewPKCS11TLSConfig_FullFlow_CleanupIdempotent(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	_, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}

	// Calling cleanup multiple times must not panic.
	cleanup()
	cleanup()
}

func TestNewPKCS11TLSConfig_ModulePathRequired_WithoutModule(t *testing.T) {
	cfg := &PKCS11TLSConfig{
		PIN: mustSecret(t, "1234"),
		// Module is nil and ModulePath is empty
	}
	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing module path")
	}
	if !errors.Is(err, ErrPKCS11ModulePathRequired) {
		t.Errorf("expected ErrPKCS11ModulePathRequired, got: %v", err)
	}
}

func TestNewPKCS11TLSConfig_ModulePathSkipped_WithModule(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t)
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)

	importSession, rv := mod.OpenSession(0,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import failed: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	// ModulePath is empty but Module is set — should succeed.
	cfg := &PKCS11TLSConfig{
		Module: mod,
		PIN:    mustSecret(t, "1234"),
	}

	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig() error: %v", err)
	}
	defer cleanup()

	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected certificate in TLS config")
	}
}

func TestNewPKCS11TLSConfig_InitializeError_NoModule(t *testing.T) {
	pkcs11module.ResetGlobalModule()
	defer pkcs11module.ResetGlobalModule()

	cfg := &PKCS11TLSConfig{
		ModulePath: "memory",
		PIN:        mustSecret(t, "1234"),
	}

	_, _, err := NewPKCS11TLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error from NewPKCS11TLSConfig")
	}
	if !errors.Is(err, ErrPKCS11ModuleInit) {
		t.Errorf("expected ErrPKCS11ModuleInit, got: %v", err)
	}
	var tlsErr *PKCS11TLSError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *PKCS11TLSError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Mechanism selection tests
// ---------------------------------------------------------------------------

func TestSelectMechanism_RSA_SHA256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_RSA_PKCS {
		t.Errorf("expected CKM_RSA_PKCS, got %s", mech.Type)
	}
}

func TestSelectMechanism_RSA_SHA384(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA384)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_RSA_PKCS {
		t.Errorf("expected CKM_RSA_PKCS for pre-hashed RSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_RSA_SHA512(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA512)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_RSA_PKCS {
		t.Errorf("expected CKM_RSA_PKCS for pre-hashed RSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_RSA_PSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	mech, err := SelectMechanism(&key.PublicKey, pssOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_RSA_PKCS_PSS {
		t.Errorf("expected CKM_RSA_PKCS_PSS, got %s", mech.Type)
	}
}

func TestSelectMechanism_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_ECDSA {
		t.Errorf("expected CKM_ECDSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA384)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_ECDSA {
		t.Errorf("expected CKM_ECDSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	mech, err := SelectMechanism(&key.PublicKey, crypto.SHA512)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_ECDSA {
		t.Errorf("expected CKM_ECDSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	mech, err := SelectMechanism(pub, crypto.Hash(0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mech.Type != pkcs11module.CKM_EDDSA {
		t.Errorf("expected CKM_EDDSA, got %s", mech.Type)
	}
}

func TestSelectMechanism_UnsupportedKeyType(t *testing.T) {
	// Use a nil key to trigger the unsupported path.
	_, err := SelectMechanism(nil, crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for nil/unsupported key type")
	}
	if !errors.Is(err, ErrPKCS11UnsupportedKeyType) {
		t.Errorf("expected ErrPKCS11UnsupportedKeyType, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// pkcs11Signer interface compliance tests
// ---------------------------------------------------------------------------

func TestPKCS11Signer_Public_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	signer := &pkcs11Signer{
		publicKey: &key.PublicKey,
	}

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public() did not return *rsa.PublicKey")
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Error("Public() returned different RSA key")
	}
}

func TestPKCS11Signer_Public_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := &pkcs11Signer{
		publicKey: &key.PublicKey,
	}

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public() did not return *ecdsa.PublicKey")
	}
	if !ecPub.Equal(&key.PublicKey) {
		t.Error("Public() returned different ECDSA key")
	}
}

func TestPKCS11Signer_Public_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	signer := &pkcs11Signer{
		publicKey: pub,
	}

	got := signer.Public()
	if got == nil {
		t.Fatal("Public() returned nil")
	}

	edPub, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public() did not return ed25519.PublicKey")
	}
	if !edPub.Equal(pub) {
		t.Error("Public() returned different Ed25519 key")
	}
}

func TestPKCS11Signer_ImplementsCryptoSigner(t *testing.T) {
	var _ crypto.Signer = (*pkcs11Signer)(nil)
}

// ---------------------------------------------------------------------------
// PKCS11TLSError tests
// ---------------------------------------------------------------------------

func TestPKCS11TLSError_Error(t *testing.T) {
	err := &PKCS11TLSError{
		Op:   "SignInit",
		Code: pkcs11module.CKR_KEY_HANDLE_INVALID,
		Err:  ErrPKCS11SignInit,
	}

	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}

	// Verify the error message contains the operation name.
	if !containsSubstring(msg, "SignInit") {
		t.Errorf("error message should contain 'SignInit', got: %s", msg)
	}
	// Verify the error message contains the CKR code string.
	if !containsSubstring(msg, "CKR_KEY_HANDLE_INVALID") {
		t.Errorf("error message should contain 'CKR_KEY_HANDLE_INVALID', got: %s", msg)
	}
}

func TestPKCS11TLSError_Unwrap(t *testing.T) {
	tlsErr := &PKCS11TLSError{
		Op:   "Sign",
		Code: pkcs11module.CKR_GENERAL_ERROR,
		Err:  ErrPKCS11Sign,
	}

	if !errors.Is(tlsErr, ErrPKCS11Sign) {
		t.Error("Unwrap should allow errors.Is to match the underlying error")
	}
}

func TestPKCS11TLSError_UnwrapNil(t *testing.T) {
	tlsErr := &PKCS11TLSError{
		Op:   "Test",
		Code: pkcs11module.CKR_OK,
	}

	if tlsErr.Unwrap() != nil {
		t.Error("Unwrap should return nil when Err is nil")
	}
}

// ---------------------------------------------------------------------------
// keyTypeForPublicKey tests
// ---------------------------------------------------------------------------

func TestKeyTypeForPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kt, err := keyTypeForPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kt != uint32(pkcs11module.CKK_RSA) {
		t.Errorf("expected CKK_RSA (%d), got %d", pkcs11module.CKK_RSA, kt)
	}
}

func TestKeyTypeForPublicKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	kt, err := keyTypeForPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kt != uint32(pkcs11module.CKK_EC) {
		t.Errorf("expected CKK_EC (%d), got %d", pkcs11module.CKK_EC, kt)
	}
}

func TestKeyTypeForPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	kt, err := keyTypeForPublicKey(pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kt != uint32(pkcs11module.CKK_EC_EDWARDS) {
		t.Errorf("expected CKK_EC_EDWARDS (%d), got %d", pkcs11module.CKK_EC_EDWARDS, kt)
	}
}

func TestKeyTypeForPublicKey_Unsupported(t *testing.T) {
	_, err := keyTypeForPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !errors.Is(err, ErrPKCS11UnsupportedKeyType) {
		t.Errorf("expected ErrPKCS11UnsupportedKeyType, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// curveByteSize tests
// ---------------------------------------------------------------------------

func TestCurveByteSize_P256(t *testing.T) {
	size := curveByteSize(elliptic.P256())
	if size != 32 {
		t.Errorf("expected 32 for P-256, got %d", size)
	}
}

func TestCurveByteSize_P384(t *testing.T) {
	size := curveByteSize(elliptic.P384())
	if size != 48 {
		t.Errorf("expected 48 for P-384, got %d", size)
	}
}

func TestCurveByteSize_P521(t *testing.T) {
	size := curveByteSize(elliptic.P521())
	if size != 66 {
		t.Errorf("expected 66 for P-521, got %d", size)
	}
}

// ---------------------------------------------------------------------------
// Byte encoding utility tests
// ---------------------------------------------------------------------------

func TestUint32ToBytes(t *testing.T) {
	b := uint32ToBytes(42)
	if len(b) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(b))
	}
	got := bytesToUint32(b)
	if got != 42 {
		t.Errorf("roundtrip failed: expected 42, got %d", got)
	}
}

func TestBytesToUint32_TooShort(t *testing.T) {
	got := bytesToUint32([]byte{1, 2})
	if got != 0 {
		t.Errorf("expected 0 for short slice, got %d", got)
	}
}

func TestBytesToUint32_Empty(t *testing.T) {
	got := bytesToUint32(nil)
	if got != 0 {
		t.Errorf("expected 0 for nil slice, got %d", got)
	}
}

func TestUint32ToBytes_Zero(t *testing.T) {
	b := uint32ToBytes(0)
	got := bytesToUint32(b)
	if got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestUint32ToBytes_MaxValue(t *testing.T) {
	b := uint32ToBytes(0xFFFFFFFF)
	got := bytesToUint32(b)
	if got != 0xFFFFFFFF {
		t.Errorf("expected 0xFFFFFFFF, got 0x%X", got)
	}
}

// ---------------------------------------------------------------------------
// matchesAttributeValue tests
// ---------------------------------------------------------------------------

func TestMatchesAttributeValue_Equal(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	if !matchesAttributeValue(a, b) {
		t.Error("expected equal slices to match")
	}
}

func TestMatchesAttributeValue_NotEqual(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{4, 5, 6}
	if matchesAttributeValue(a, b) {
		t.Error("expected different slices to not match")
	}
}

func TestMatchesAttributeValue_NilSlices(t *testing.T) {
	if !matchesAttributeValue(nil, nil) {
		t.Error("expected nil slices to match")
	}
}

func TestMatchesAttributeValue_EmptySlices(t *testing.T) {
	if !matchesAttributeValue([]byte{}, []byte{}) {
		t.Error("expected empty slices to match")
	}
}

func TestMatchesAttributeValue_DifferentLengths(t *testing.T) {
	a := []byte{1, 2}
	b := []byte{1, 2, 3}
	if matchesAttributeValue(a, b) {
		t.Error("expected different length slices to not match")
	}
}

// ---------------------------------------------------------------------------
// PKCS11TLSConfig default field tests
// ---------------------------------------------------------------------------

func TestPKCS11TLSConfig_DefaultSlotID(t *testing.T) {
	cfg := &PKCS11TLSConfig{
		ModulePath: "/usr/lib/libpkcs11.so",
		PIN:        mustSecret(t, "1234"),
	}
	if cfg.SlotID != 0 {
		t.Errorf("default SlotID should be 0, got %d", cfg.SlotID)
	}
}

func TestPKCS11TLSConfig_CertLabelEmpty(t *testing.T) {
	cfg := &PKCS11TLSConfig{
		ModulePath: "/usr/lib/libpkcs11.so",
		PIN:        mustSecret(t, "1234"),
	}
	if cfg.CertLabel != "" {
		t.Errorf("default CertLabel should be empty, got %q", cfg.CertLabel)
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestPKCS11ErrorsAreDistinct(t *testing.T) {
	errs := []error{
		ErrPKCS11ModulePathRequired,
		ErrPKCS11PINRequired,
		ErrPKCS11OpenSession,
		ErrPKCS11Login,
		ErrPKCS11NoCertFound,
		ErrPKCS11NoKeyFound,
		ErrPKCS11CertParse,
		ErrPKCS11SignInit,
		ErrPKCS11Sign,
		ErrPKCS11UnsupportedKeyType,
		ErrPKCS11NilConfig,
		ErrPKCS11ModuleInit,
	}

	seen := make(map[string]bool, len(errs))
	for _, e := range errs {
		msg := e.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %s", msg)
		}
		seen[msg] = true
	}
}

func TestPKCS11ErrorsNotNil(t *testing.T) {
	errs := []error{
		ErrPKCS11ModulePathRequired,
		ErrPKCS11PINRequired,
		ErrPKCS11OpenSession,
		ErrPKCS11Login,
		ErrPKCS11NoCertFound,
		ErrPKCS11NoKeyFound,
		ErrPKCS11CertParse,
		ErrPKCS11SignInit,
		ErrPKCS11Sign,
		ErrPKCS11UnsupportedKeyType,
		ErrPKCS11NilConfig,
		ErrPKCS11ModuleInit,
	}

	for _, e := range errs {
		if e == nil {
			t.Error("found nil error in error list")
		}
	}
}

// ---------------------------------------------------------------------------
// mechanismDispatch edge case tests
// ---------------------------------------------------------------------------

func TestMechanismDispatch_RSA_DefaultHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// With default hash (SHA-256), should still return CKM_RSA_PKCS.
	mech, ok := mechanismDispatch(&key.PublicKey, crypto.SHA256)
	if !ok {
		t.Fatal("expected mechanism dispatch to succeed for RSA")
	}
	if mech.Type != pkcs11module.CKM_RSA_PKCS {
		t.Errorf("expected CKM_RSA_PKCS, got %s", mech.Type)
	}
}

func TestMechanismDispatch_Nil(t *testing.T) {
	_, ok := mechanismDispatch(nil, crypto.SHA256)
	if ok {
		t.Error("expected mechanism dispatch to fail for nil key")
	}
}

// ---------------------------------------------------------------------------
// selectRSAMechanism tests
// ---------------------------------------------------------------------------

func TestSelectRSAMechanism_PKCS1v15(t *testing.T) {
	mech := selectRSAMechanism(crypto.SHA256)
	if mech.Type != pkcs11module.CKM_RSA_PKCS {
		t.Errorf("expected CKM_RSA_PKCS, got %s", mech.Type)
	}
}

func TestSelectRSAMechanism_PSS(t *testing.T) {
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	mech := selectRSAMechanism(pssOpts)
	if mech.Type != pkcs11module.CKM_RSA_PKCS_PSS {
		t.Errorf("expected CKM_RSA_PKCS_PSS, got %s", mech.Type)
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestInitOwnedToken_ProvisionsLoginableToken proves the []byte provisioning
// sequence leaves a token whose user PIN works for the C_Login that follows.
func TestInitOwnedToken_ProvisionsLoginableToken(t *testing.T) {
	pkcs11module.ResetGlobalModule()
	defer pkcs11module.ResetGlobalModule()

	moduleCfg := pkcs11module.DefaultConfig()
	moduleCfg.AutoInitToken = false
	mod, err := pkcs11module.New(pkcs11module.WithClient(&authMockClient{}), pkcs11module.WithConfig(moduleCfg))
	if err != nil {
		t.Fatalf("pkcs11module.New: %v", err)
	}
	if rv := mod.Initialize(moduleCfg); rv != pkcs11module.CKR_OK {
		t.Fatalf("Initialize: %s", rv)
	}
	defer mod.Finalize()

	pin := []byte("1234")
	if tlsErr := initOwnedToken(mod, 0, pin, pkcs11TLSTokenLabel); tlsErr != nil {
		t.Fatalf("initOwnedToken: %v", tlsErr)
	}

	session, rv := mod.OpenSession(0, pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession: %s", rv)
	}
	defer mod.CloseSession(session)
	if rv := mod.Login(session, pkcs11module.CKU_USER, pin); rv != pkcs11module.CKR_OK {
		t.Fatalf("user Login after provisioning: %s", rv)
	}
	mod.Logout(session)
}

// TestInitOwnedToken_InvalidSlot proves a provisioning failure is reported as
// a typed module-initialization error naming the failing step.
func TestInitOwnedToken_InvalidSlot(t *testing.T) {
	pkcs11module.ResetGlobalModule()
	defer pkcs11module.ResetGlobalModule()

	moduleCfg := pkcs11module.DefaultConfig()
	mod, err := pkcs11module.New(pkcs11module.WithClient(&authMockClient{}), pkcs11module.WithConfig(moduleCfg))
	if err != nil {
		t.Fatalf("pkcs11module.New: %v", err)
	}
	if rv := mod.Initialize(moduleCfg); rv != pkcs11module.CKR_OK {
		t.Fatalf("Initialize: %s", rv)
	}
	defer mod.Finalize()

	tlsErr := initOwnedToken(mod, 9999, []byte("1234"), pkcs11TLSTokenLabel)
	if tlsErr == nil {
		t.Fatal("expected error for an invalid slot")
	}
	if tlsErr.Op != "GetTokenInfo" || !errors.Is(tlsErr, ErrPKCS11ModuleInit) {
		t.Errorf("got %v, want GetTokenInfo / ErrPKCS11ModuleInit", tlsErr)
	}
}

// TestInitOwnedToken_LeavesAnInitializedTokenAlone proves a token the module
// restored already initialized is not re-initialized: its user PIN still logs
// in and an object an operator put on it survives, even though the PIN offered
// here is different from the one the token was provisioned with.
func TestInitOwnedToken_LeavesAnInitializedTokenAlone(t *testing.T) {
	mod, _, modCleanup := setupPKCS11Module(t) // initialized, user PIN "1234"
	defer modCleanup()

	certDER, privKey, certID := createSelfSignedCert(t)
	importSession, rv := mod.OpenSession(0, pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		t.Fatalf("OpenSession for import: %s", rv)
	}
	importCertAndKey(t, mod, importSession, certDER, privKey, certID)
	mod.CloseSession(importSession)

	if tlsErr := initOwnedToken(mod, 0, []byte("a-different-pin"), pkcs11TLSTokenLabel); tlsErr != nil {
		t.Fatalf("initOwnedToken on an initialized token: %v", tlsErr)
	}

	// The original user PIN still works, and the certificate is still there.
	cfg := &PKCS11TLSConfig{Module: mod, PIN: mustSecret(t, "1234")}
	tlsCfg, cleanup, err := NewPKCS11TLSConfig(cfg)
	if err != nil {
		t.Fatalf("NewPKCS11TLSConfig after initOwnedToken: %v", err)
	}
	defer cleanup()
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("the certificate on the token did not survive")
	}
}

func (*authMockClient) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*authMockClient) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*authMockClient) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*authMockClient) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*authMockClient) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
func (*authMockClient) SignCoRIM(context.Context, *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	return nil, nil
}

func (*authMockClient) SignImage(context.Context, *transport.SignImageRequest) (*transport.SignedImage, error) {
	return nil, nil
}
