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
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClient implements the subset of transport.Client that KeyService uses.
// Methods not used by KeyService panic to detect accidental usage.
type mockClient struct {
	listBackendsFn func(ctx context.Context) (*transport.ListBackendsResponse, error)
	getBackendFn   func(ctx context.Context, id string) (*transport.BackendInfo, error)
	listKeysFn     func(ctx context.Context, backend string) (*transport.ListKeysResponse, error)
	getKeyFn       func(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error)
	generateKeyFn  func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)
	deleteKeyFn    func(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error)
	signFn         func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)
	verifyFn       func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)
	encryptFn      func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)
	decryptFn      func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)
	importKeyFn    func(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error)
	exportKeyFn    func(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error)
	rotateKeyFn    func(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error)
	attestKeyFn    func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error)
}

func (m *mockClient) Connect(context.Context) error { panic("not implemented") }
func (m *mockClient) Close() error                  { panic("not implemented") }
func (m *mockClient) Health(context.Context) (*transport.HealthResponse, error) {
	panic("not implemented")
}

func (m *mockClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return m.listBackendsFn(ctx)
}
func (m *mockClient) GetBackend(ctx context.Context, id string) (*transport.BackendInfo, error) {
	return m.getBackendFn(ctx, id)
}
func (m *mockClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return m.listKeysFn(ctx, backend)
}
func (m *mockClient) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	return m.getKeyFn(ctx, backend, keyID)
}
func (m *mockClient) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return m.generateKeyFn(ctx, req)
}
func (m *mockClient) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	return m.deleteKeyFn(ctx, backend, keyID)
}
func (m *mockClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return m.signFn(ctx, req)
}
func (m *mockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return m.verifyFn(ctx, req)
}
func (m *mockClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return m.encryptFn(ctx, req)
}
func (m *mockClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return m.decryptFn(ctx, req)
}
func (m *mockClient) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return m.importKeyFn(ctx, req)
}
func (m *mockClient) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return m.exportKeyFn(ctx, req)
}
func (m *mockClient) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return m.rotateKeyFn(ctx, req)
}
func (m *mockClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return m.attestKeyFn(ctx, req)
}

// Stubs for interfaces not used by KeyService.
func (m *mockClient) EncryptAsym(context.Context, *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	panic("not implemented")
}
func (m *mockClient) DeriveKey(context.Context, *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) DeriveKeyECDH(context.Context, *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetImportParameters(context.Context, *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	panic("not implemented")
}
func (m *mockClient) CopyKey(context.Context, *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) ExportKeyMaterial(context.Context, *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	panic("not implemented")
}
func (m *mockClient) WrapKey(context.Context, *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) UnwrapKey(context.Context, *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) WrapKeyByID(context.Context, *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	panic("not implemented")
}
func (m *mockClient) UnwrapKeyByID(context.Context, *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetCertificate(context.Context, string, string) (*transport.GetCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SaveCertificate(context.Context, *transport.SaveCertificateRequest) error {
	panic("not implemented")
}
func (m *mockClient) DeleteCertificate(context.Context, string, string) error {
	panic("not implemented")
}
func (m *mockClient) CertificateExists(context.Context, string, string) (bool, error) {
	panic("not implemented")
}
func (m *mockClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SaveCertificateChain(context.Context, *transport.SaveCertificateChainRequest) error {
	panic("not implemented")
}
func (m *mockClient) GetCertificateChain(context.Context, string, string) (*transport.GetCertificateChainResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetTLSCertificate(context.Context, string, string) (*transport.GetTLSCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) Seal(context.Context, *transport.SealRequest) (*transport.SealResponse, error) {
	panic("not implemented")
}
func (m *mockClient) Unseal(context.Context, *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	panic("not implemented")
}
func (m *mockClient) CanSeal(context.Context, string) (*transport.CanSealResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierInitialize(context.Context, *transport.BarrierInitializeRequest) error {
	panic("not implemented")
}
func (m *mockClient) BarrierUnseal(context.Context, *transport.BarrierUnsealRequest) error {
	panic("not implemented")
}
func (m *mockClient) BarrierSeal(context.Context) error { panic("not implemented") }
func (m *mockClient) BarrierStatus(context.Context) (*transport.BarrierStatusResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierInitializeShamir(context.Context, *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierUnsealWithShare(context.Context, *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierUnsealWithShares(context.Context, *transport.BarrierUnsealSharesRequest) error {
	panic("not implemented")
}
func (m *mockClient) BarrierShamirListShares(context.Context) (*transport.BarrierShamirSharesResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierShamirDeleteShare(context.Context, *transport.BarrierShamirDeleteShareRequest) error {
	panic("not implemented")
}
func (m *mockClient) BarrierShamirDeleteAllShares(context.Context) error {
	panic("not implemented")
}
func (m *mockClient) BarrierShamirVerify(context.Context) error { panic("not implemented") }
func (m *mockClient) BarrierRekey(context.Context, *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierGenerateRecoveryKeys(context.Context, *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierRecoverWithKeys(context.Context, *transport.BarrierRecoverWithKeysRequest) error {
	panic("not implemented")
}
func (m *mockClient) BarrierDeleteRecoveryKeys(context.Context) error { panic("not implemented") }
func (m *mockClient) BarrierHasRecoveryKeys(context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BarrierGenerateRootToken(context.Context, *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	panic("not implemented")
}
func (m *mockClient) ListPIVSlots(context.Context, *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) StorePIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	panic("not implemented")
}
func (m *mockClient) DeletePIVCertificate(context.Context, *transport.DeletePIVCertificateRequest) error {
	panic("not implemented")
}
func (m *mockClient) GeneratePIVKey(context.Context, *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) ImportPIVCertificate(context.Context, *transport.StorePIVCertificateRequest) error {
	panic("not implemented")
}
func (m *mockClient) ExportPIVCertificate(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GeneratePIVCSR(context.Context, *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BeginRegistration(context.Context, *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	panic("not implemented")
}
func (m *mockClient) FinishRegistration(context.Context, *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	panic("not implemented")
}
func (m *mockClient) BeginAuthentication(context.Context, *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	panic("not implemented")
}
func (m *mockClient) FinishAuthentication(context.Context, *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetCABundle(context.Context, *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetCACertificate(context.Context, *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SignCSR(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	panic("not implemented")
}
func (m *mockClient) IssueCertificate(context.Context, *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) RevokeCertificate(context.Context, *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GenerateCRL(context.Context, *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	panic("not implemented")
}
func (m *mockClient) IsRevoked(context.Context, *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	panic("not implemented")
}

// TCGCAService stub implementations
func (m *mockClient) IssueEKCertificate(context.Context, *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}
func (m *mockClient) IssueAKCertificate(context.Context, *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}
func (m *mockClient) SignTCGCSR(context.Context, *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}
func (m *mockClient) EnrollDevice(context.Context, *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

func (m *mockClient) SetSOPIN(context.Context, *transport.SetSOPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) SetUserPIN(context.Context, *transport.SetUserPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) ChangeSOPIN(context.Context, *transport.ChangeSOPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) ChangeUserPIN(context.Context, *transport.ChangeUserPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) VerifySOPIN(context.Context, *transport.VerifySOPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) VerifyUserPIN(context.Context, *transport.VerifyUserPINRequest) error {
	panic("not implemented")
}
func (m *mockClient) GetLockoutStatus(context.Context) (*transport.LockoutStatusResponse, error) {
	panic("not implemented")
}
func (m *mockClient) ResetLockout(context.Context, *transport.ResetLockoutRequest) error {
	panic("not implemented")
}
func (m *mockClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	panic("not implemented")
}
func (m *mockClient) GetUser(context.Context, string) (*transport.GetUserResponse, error) {
	panic("not implemented")
}
func (m *mockClient) DeleteUser(context.Context, string) error { panic("not implemented") }
func (m *mockClient) EnableUser(context.Context, string) error { panic("not implemented") }
func (m *mockClient) DisableUser(context.Context, string) error {
	panic("not implemented")
}
func (m *mockClient) ListUserCredentials(context.Context, string) (*transport.ListUserCredentialsResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PasswordAdd(context.Context, *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PasswordGet(context.Context, *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PasswordList(context.Context, *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PasswordUpdate(context.Context, *transport.PasswordUpdateRequest) error {
	panic("not implemented")
}
func (m *mockClient) PasswordDelete(context.Context, *transport.PasswordDeleteRequest) error {
	panic("not implemented")
}
func (m *mockClient) PasswordStoreUnlock(context.Context, *transport.PasswordStoreUnlockRequest) error {
	panic("not implemented")
}
func (m *mockClient) PasswordStoreLock(context.Context) error { panic("not implemented") }
func (m *mockClient) PasswordStoreStatus(context.Context) (*transport.PasswordStoreStatusResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PasswordStoreSetAccessMode(context.Context, *transport.PasswordStoreSetAccessModeRequest) error {
	panic("not implemented")
}
func (m *mockClient) PasswordGenerate(context.Context, *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SealStorePut(context.Context, *transport.SealStorePutRequest) error {
	panic("not implemented")
}
func (m *mockClient) SealStoreGet(context.Context, *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SealStoreDelete(context.Context, *transport.SealStoreDeleteRequest) error {
	panic("not implemented")
}
func (m *mockClient) SealStoreList(context.Context) (*transport.SealStoreListResponse, error) {
	panic("not implemented")
}
func (m *mockClient) SealStoreReseal(context.Context, *transport.SealStoreResealRequest) error {
	panic("not implemented")
}
func (m *mockClient) SealStoreStatus(context.Context) (*transport.SealStoreStatusResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyCreate(context.Context, *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyGet(context.Context, *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyList(context.Context) (*transport.PolicyListResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyDelete(context.Context, *transport.PolicyDeleteRequest) error {
	panic("not implemented")
}
func (m *mockClient) PolicyRefresh(context.Context, *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyVerify(context.Context, *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	panic("not implemented")
}
func (m *mockClient) PolicyExport(context.Context, *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	panic("not implemented")
}

// Custodian group operations
func (m *mockClient) CreateCustodianGroup(context.Context, *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}
func (m *mockClient) GetCustodianGroup(context.Context, string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}
func (m *mockClient) ListCustodianGroups(context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}
func (m *mockClient) DeleteCustodianGroup(context.Context, string) error {
	return nil
}
func (m *mockClient) AddCustodianMember(context.Context, *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}
func (m *mockClient) RemoveCustodianMember(context.Context, *transport.RemoveCustodianMemberRequest) error {
	return nil
}

// Share operations
func (m *mockClient) DistributeShares(context.Context, *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}
func (m *mockClient) SubmitShare(context.Context, *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}
func (m *mockClient) ListShares(context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}
func (m *mockClient) GetShareCollectionStatus(context.Context, string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

// Tenant operations
func (m *mockClient) CreateTenant(context.Context, *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}
func (m *mockClient) GetTenant(context.Context, string) (*transport.GetTenantResponse, error) {
	return nil, nil
}
func (m *mockClient) ListTenants(context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}
func (m *mockClient) DeleteTenant(context.Context, string) error {
	return nil
}
func (m *mockClient) TenantBarrierInit(context.Context, *transport.TenantBarrierInitRequest) error {
	return nil
}
func (m *mockClient) TenantBarrierUnseal(context.Context, *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService stub implementations
func (m *mockClient) GetInitStatus(context.Context) (*transport.InitStatusResponse, error) {
	return nil, nil
}
func (m *mockClient) ClaimCertBegin(context.Context, *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, nil
}
func (m *mockClient) ClaimCertComplete(context.Context, *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, nil
}
func (m *mockClient) ClaimShare(context.Context, *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, nil
}
func (m *mockClient) SignCSRInit(context.Context, *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockClient) SubmitCredential(context.Context, *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}
func (m *mockClient) GetCredentialStrategy(context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

// Compile-time check that mockClient satisfies the Client interface.
var _ transport.Client = (*mockClient)(nil)

// newTestKeyService creates a KeyService with a mock client and audit logger.
func newTestKeyService(mc *mockClient) *KeyService {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetClientFunc(func() xkms.Client { return mc })
	auditStore, err := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	if err != nil {
		panic("failed to create audit store: " + err.Error())
	}
	svc.SetAuditLogger(auditStore)
	return svc
}

// --- Existing no-client and validation tests ---

func TestKeyServiceNoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	t.Run("ListBackends", func(t *testing.T) {
		_, err := svc.ListBackends("server")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("GetBackend", func(t *testing.T) {
		_, err := svc.GetBackend("server", "test")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("ListKeys", func(t *testing.T) {
		_, err := svc.ListKeys("server", "test")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("ListAllKeys", func(t *testing.T) {
		_, err := svc.ListAllKeys("server")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("GetKey", func(t *testing.T) {
		_, err := svc.GetKey("server", "test", "key1")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("GenerateKey", func(t *testing.T) {
		_, err := svc.GenerateKey("server", &GenerateKeyParams{
			KeyID:   "key1",
			Backend: "test",
		})
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := svc.DeleteKey("server", "test", "key1")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("SignData", func(t *testing.T) {
		_, err := svc.SignData("server", "test", "key1", "SHA-256", "dGVzdA==")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("VerifySignature", func(t *testing.T) {
		_, err := svc.VerifySignature("server", "test", "key1", "SHA-256", "dGVzdA==", "c2ln")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("EncryptData", func(t *testing.T) {
		_, err := svc.EncryptData("server", "test", "key1", "AES-GCM", "dGVzdA==")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("DecryptData", func(t *testing.T) {
		_, err := svc.DecryptData("server", "test", "key1", "AES-GCM", "dGVzdA==")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("ImportKey", func(t *testing.T) {
		_, err := svc.ImportKey("server", &ImportKeyParams{
			KeyID:   "key1",
			Backend: "test",
			KeyData: "dGVzdA==",
			Format:  "raw",
		})
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("ExportKey", func(t *testing.T) {
		_, err := svc.ExportKey("server", "test", "key1", "raw")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("RotateKey", func(t *testing.T) {
		_, err := svc.RotateKey("server", "test", "key1")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})

	t.Run("AttestKey", func(t *testing.T) {
		_, err := svc.AttestKey("server", "test", "key1", "")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})
}

func TestKeyServiceInvalidGenerateRequest(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetClientFunc(func() xkms.Client { return nil })

	t.Run("nil request", func(t *testing.T) {
		_, err := svc.GenerateKey("server", nil)
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})

	t.Run("empty key ID", func(t *testing.T) {
		_, err := svc.GenerateKey("server", &GenerateKeyParams{
			KeyID:   "",
			Backend: "test",
		})
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})

	t.Run("empty backend", func(t *testing.T) {
		_, err := svc.GenerateKey("server", &GenerateKeyParams{
			KeyID:   "key1",
			Backend: "",
		})
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})

	t.Run("nil ImportKey request", func(t *testing.T) {
		_, err := svc.ImportKey("server", nil)
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})

	t.Run("ImportKey empty key ID", func(t *testing.T) {
		_, err := svc.ImportKey("server", &ImportKeyParams{
			KeyID:   "",
			Backend: "test",
		})
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})

	t.Run("ImportKey empty backend", func(t *testing.T) {
		_, err := svc.ImportKey("server", &ImportKeyParams{
			KeyID:   "key1",
			Backend: "",
		})
		assert.True(t, errors.Is(err, ErrKeyInvalidRequest))
	})
}

func TestKeyServiceGetKeyCountNoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	count := svc.GetKeyCount("server")
	assert.Equal(t, 0, count)
}

func TestKeyServiceSetClientFunc(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	called := false
	svc.SetClientFunc(func() xkms.Client {
		called = true
		return nil
	})

	_, err := svc.ListBackends("server")
	assert.True(t, called)
	assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
}

// --- SetAuditLogger ---

func TestKeyServiceSetAuditLogger(t *testing.T) {
	svc := NewKeyService()
	assert.Nil(t, svc.auditLogger)

	logger := audit.NewSlogLogger(slog.Default())
	svc.SetAuditLogger(logger)
	assert.NotNil(t, svc.auditLogger)
}

// --- convertBackendInfo ---

func TestConvertBackendInfo(t *testing.T) {
	t.Run("hardware_backed_true_from_source", func(t *testing.T) {
		b := &transport.BackendInfo{
			ID:             "hw-backend",
			Type:           "custom",
			HardwareBacked: true,
			Capabilities: transport.BackendCapabilities{
				Keys:    true,
				Signing: true,
			},
		}
		result := convertBackendInfo(b)
		assert.Equal(t, "hw-backend", result.ID)
		assert.Equal(t, "custom", result.Type)
		assert.True(t, result.HardwareBacked)
		assert.True(t, result.Capabilities.Keys)
		assert.True(t, result.Capabilities.Signing)
	})

	t.Run("hardware_backed_inferred_tpm2", func(t *testing.T) {
		b := &transport.BackendInfo{ID: "my-tpm", Type: "tpm2-device", HardwareBacked: false}
		result := convertBackendInfo(b)
		assert.True(t, result.HardwareBacked)
	})

	t.Run("hardware_backed_inferred_pkcs11", func(t *testing.T) {
		b := &transport.BackendInfo{ID: "hsm", Type: "PKCS11-Token", HardwareBacked: false}
		result := convertBackendInfo(b)
		assert.True(t, result.HardwareBacked)
	})

	t.Run("hardware_backed_inferred_phone", func(t *testing.T) {
		b := &transport.BackendInfo{ID: "phone1", Type: "phone-ble", HardwareBacked: false}
		result := convertBackendInfo(b)
		assert.True(t, result.HardwareBacked)
	})

	t.Run("software_backend_not_hardware", func(t *testing.T) {
		b := &transport.BackendInfo{ID: "sw", Type: "software", HardwareBacked: false}
		result := convertBackendInfo(b)
		assert.False(t, result.HardwareBacked)
	})

	t.Run("zero_capabilities", func(t *testing.T) {
		b := &transport.BackendInfo{ID: "test", Type: "test"}
		result := convertBackendInfo(b)
		assert.False(t, result.Capabilities.Keys)
		assert.False(t, result.Capabilities.Signing)
	})
}

// --- convertKeyInfo ---

func TestConvertKeyInfo(t *testing.T) {
	k := &transport.KeyInfo{
		KeyID:        "my-key",
		KeyType:      "ECDSA",
		Algorithm:    "ES256",
		Backend:      "software",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}
	result := convertKeyInfo(k)
	assert.Equal(t, "my-key", result.KeyID)
	assert.Equal(t, "ECDSA", result.KeyType)
	assert.Equal(t, "ES256", result.Algorithm)
	assert.Equal(t, "software", result.Backend)
	assert.Contains(t, result.PublicKeyPEM, "BEGIN PUBLIC KEY")
}

func TestConvertKeyInfoEmpty(t *testing.T) {
	k := &transport.KeyInfo{}
	result := convertKeyInfo(k)
	assert.Empty(t, result.KeyID)
	assert.Empty(t, result.KeyType)
	assert.Empty(t, result.Algorithm)
	assert.Empty(t, result.Backend)
	assert.Empty(t, result.PublicKeyPEM)
}

// --- ListBackends with mock ---

func TestKeyServiceListBackendsSuccess(t *testing.T) {
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return &transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{
					{ID: "sw", Type: "software", HardwareBacked: false},
					{ID: "hw", Type: "tpm2", HardwareBacked: true},
				},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	backends, err := svc.ListBackends("server")
	require.NoError(t, err)
	require.Len(t, backends, 2)
	assert.Equal(t, "sw", backends[0].ID)
	assert.False(t, backends[0].HardwareBacked)
	assert.Equal(t, "hw", backends[1].ID)
	assert.True(t, backends[1].HardwareBacked)
}

func TestKeyServiceListBackendsClientError(t *testing.T) {
	errRemote := errors.New("remote error")
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return nil, errRemote
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.ListBackends("server")
	assert.True(t, errors.Is(err, errRemote))
}

// --- GetBackend with mock ---

func TestKeyServiceGetBackendSuccess(t *testing.T) {
	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "pkcs11-hsm",
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	info, err := svc.GetBackend("server", "hsm1")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "hsm1", info.ID)
	assert.True(t, info.HardwareBacked) // inferred from "pkcs11" substring
}

func TestKeyServiceGetBackendError(t *testing.T) {
	errRemote := errors.New("backend not found")
	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return nil, errRemote
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.GetBackend("server", "missing")
	assert.True(t, errors.Is(err, errRemote))
}

// --- ListKeys with mock ---

func TestKeyServiceListKeysSuccess(t *testing.T) {
	mc := &mockClient{
		listKeysFn: func(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
			return &transport.ListKeysResponse{
				Keys: []transport.KeyInfo{
					{KeyID: "k1", KeyType: "ECDSA", Algorithm: "ES256", Backend: backend},
					{KeyID: "k2", KeyType: "RSA", Algorithm: "RS256", Backend: backend},
				},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	keys, err := svc.ListKeys("server", "software")
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "k1", keys[0].KeyID)
	assert.Equal(t, "software", keys[0].Backend)
}

func TestKeyServiceListKeysError(t *testing.T) {
	errRemote := errors.New("unavailable")
	mc := &mockClient{
		listKeysFn: func(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
			return nil, errRemote
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.ListKeys("server", "software")
	assert.True(t, errors.Is(err, errRemote))
}

// --- ListAllKeys with mock ---

func TestKeyServiceListAllKeysSuccess(t *testing.T) {
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return &transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{
					{ID: "sw", Type: "software"},
					{ID: "hw", Type: "tpm2", HardwareBacked: true},
				},
			}, nil
		},
		listKeysFn: func(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
			return &transport.ListKeysResponse{
				Keys: []transport.KeyInfo{
					{KeyID: backend + "-key1", Backend: backend},
				},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	keys, err := svc.ListAllKeys("server")
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "sw-key1", keys[0].KeyID)
	assert.Equal(t, "hw-key1", keys[1].KeyID)
}

func TestKeyServiceListAllKeysPartialFailure(t *testing.T) {
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return &transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{
					{ID: "good", Type: "software"},
					{ID: "bad", Type: "tpm2"},
				},
			}, nil
		},
		listKeysFn: func(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
			if backend == "bad" {
				return nil, errors.New("tpm error")
			}
			return &transport.ListKeysResponse{
				Keys: []transport.KeyInfo{{KeyID: "good-key", Backend: backend}},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	keys, err := svc.ListAllKeys("server")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "good-key", keys[0].KeyID)
}

// --- GetKey with mock ---

func TestKeyServiceGetKeySuccess(t *testing.T) {
	mc := &mockClient{
		getKeyFn: func(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:   keyID,
					KeyType: "ECDSA",
					Backend: backend,
				},
				PublicKeyPEM: "PEM-data",
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	info, err := svc.GetKey("server", "software", "mykey")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "mykey", info.KeyID)
	assert.Equal(t, "PEM-data", info.PublicKeyPEM)
}

func TestKeyServiceGetKeyNoPublicKeyOverride(t *testing.T) {
	mc := &mockClient{
		getKeyFn: func(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
			return &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:        keyID,
					PublicKeyPEM: "embedded-pem",
				},
				PublicKeyPEM: "", // empty, should not override
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	info, err := svc.GetKey("server", "sw", "k1")
	require.NoError(t, err)
	assert.Equal(t, "embedded-pem", info.PublicKeyPEM)
}

func TestKeyServiceGetKeyError(t *testing.T) {
	errNotFound := errors.New("key not found")
	mc := &mockClient{
		getKeyFn: func(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
			return nil, errNotFound
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.GetKey("server", "sw", "missing")
	assert.True(t, errors.Is(err, errNotFound))
}

// --- GenerateKey with mock ---

func TestKeyServiceGenerateKeySuccess(t *testing.T) {
	mc := &mockClient{
		generateKeyFn: func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			assert.Equal(t, "test-key", req.KeyID)
			assert.Equal(t, "software", req.Backend)
			assert.Equal(t, "ECDSA", req.KeyType)
			return &transport.GenerateKeyResponse{
				KeyID:        req.KeyID,
				KeyType:      req.KeyType,
				PublicKeyPEM: "generated-pem",
				Message:      "key generated",
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.GenerateKey("server", &GenerateKeyParams{
		KeyID:   "test-key",
		Backend: "software",
		KeyType: "ECDSA",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-key", result.KeyID)
	assert.Equal(t, "ECDSA", result.KeyType)
	assert.Equal(t, "generated-pem", result.PublicKeyPEM)
	assert.Equal(t, "key generated", result.Message)
}

func TestKeyServiceGenerateKeyClientError(t *testing.T) {
	errGen := errors.New("generation failed")
	mc := &mockClient{
		generateKeyFn: func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			return nil, errGen
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.GenerateKey("server", &GenerateKeyParams{KeyID: "k", Backend: "b"})
	assert.True(t, errors.Is(err, errGen))
}

// --- DeleteKey with mock ---

func TestKeyServiceDeleteKeySuccess(t *testing.T) {
	mc := &mockClient{
		deleteKeyFn: func(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
			return &transport.DeleteKeyResponse{Success: true}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.DeleteKey("server", "software", "key1")
	assert.NoError(t, err)
}

func TestKeyServiceDeleteKeyError(t *testing.T) {
	errDel := errors.New("delete failed")
	mc := &mockClient{
		deleteKeyFn: func(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
			return nil, errDel
		},
	}
	svc := newTestKeyService(mc)

	err := svc.DeleteKey("server", "software", "key1")
	assert.True(t, errors.Is(err, errDel))
}

// --- SignData with mock ---

func TestKeyServiceSignDataSuccess(t *testing.T) {
	inputData := base64.StdEncoding.EncodeToString([]byte("hello"))
	expectedSig := []byte("signature-bytes")

	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			assert.Equal(t, "software", req.Backend)
			assert.Equal(t, "key1", req.KeyID)
			assert.Equal(t, "SHA-256", req.Hash)
			assert.Equal(t, []byte("hello"), req.Data)
			return &transport.SignResponse{Signature: expectedSig}, nil
		},
	}
	svc := newTestKeyService(mc)

	sig, err := svc.SignData("server", "software", "key1", "SHA-256", inputData)
	require.NoError(t, err)
	decoded, decErr := base64.StdEncoding.DecodeString(sig)
	require.NoError(t, decErr)
	assert.Equal(t, expectedSig, decoded)
}

func TestKeyServiceSignDataInvalidBase64(t *testing.T) {
	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			t.Fatal("sign should not be called")
			return nil, nil
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.SignData("server", "sw", "k", "SHA-256", "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestKeyServiceSignDataClientError(t *testing.T) {
	errSign := errors.New("sign error")
	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			return nil, errSign
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.SignData("server", "sw", "k", "SHA-256", base64.StdEncoding.EncodeToString([]byte("data")))
	assert.True(t, errors.Is(err, errSign))
}

// --- VerifySignature with mock ---

func TestKeyServiceVerifySignatureSuccess(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte("data"))
	sig := base64.StdEncoding.EncodeToString([]byte("sig"))

	mc := &mockClient{
		verifyFn: func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			assert.Equal(t, []byte("data"), req.Data)
			assert.Equal(t, []byte("sig"), req.Signature)
			return &transport.VerifyResponse{Valid: true}, nil
		},
	}
	svc := newTestKeyService(mc)

	valid, err := svc.VerifySignature("server", "sw", "k", "SHA-256", data, sig)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestKeyServiceVerifySignatureInvalidData(t *testing.T) {
	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.VerifySignature("server", "sw", "k", "SHA-256", "bad!!!", base64.StdEncoding.EncodeToString([]byte("sig")))
	assert.Error(t, err)
}

func TestKeyServiceVerifySignatureInvalidSig(t *testing.T) {
	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.VerifySignature("server", "sw", "k", "SHA-256", base64.StdEncoding.EncodeToString([]byte("data")), "bad!!!")
	assert.Error(t, err)
}

func TestKeyServiceVerifySignatureClientError(t *testing.T) {
	errVerify := errors.New("verify failed")
	mc := &mockClient{
		verifyFn: func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			return nil, errVerify
		},
	}
	svc := newTestKeyService(mc)

	data := base64.StdEncoding.EncodeToString([]byte("d"))
	sig := base64.StdEncoding.EncodeToString([]byte("s"))
	_, err := svc.VerifySignature("server", "sw", "k", "SHA-256", data, sig)
	assert.True(t, errors.Is(err, errVerify))
}

// --- EncryptData with mock ---

func TestKeyServiceEncryptDataSuccess(t *testing.T) {
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret"))
	ciphertext := []byte("encrypted-data")

	mc := &mockClient{
		encryptFn: func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
			assert.Equal(t, []byte("secret"), req.Plaintext)
			return &transport.EncryptResponse{Ciphertext: ciphertext}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.EncryptData("server", "sw", "k", "AES-GCM", plaintext)
	require.NoError(t, err)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, ciphertext, decoded)
}

func TestKeyServiceEncryptDataInvalidBase64(t *testing.T) {
	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.EncryptData("server", "sw", "k", "AES-GCM", "not-base64!!!")
	assert.Error(t, err)
}

func TestKeyServiceEncryptDataClientError(t *testing.T) {
	errEnc := errors.New("encrypt failed")
	mc := &mockClient{
		encryptFn: func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
			return nil, errEnc
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.EncryptData("server", "sw", "k", "AES-GCM", base64.StdEncoding.EncodeToString([]byte("d")))
	assert.True(t, errors.Is(err, errEnc))
}

// --- DecryptData with mock ---

func TestKeyServiceDecryptDataSuccess(t *testing.T) {
	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	plaintext := []byte("decrypted")

	mc := &mockClient{
		decryptFn: func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			assert.Equal(t, []byte("encrypted"), req.Ciphertext)
			return &transport.DecryptResponse{Plaintext: plaintext}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.DecryptData("server", "sw", "k", "AES-GCM", ciphertext)
	require.NoError(t, err)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, plaintext, decoded)
}

func TestKeyServiceDecryptDataInvalidBase64(t *testing.T) {
	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.DecryptData("server", "sw", "k", "AES-GCM", "bad-base64!!!")
	assert.Error(t, err)
}

func TestKeyServiceDecryptDataClientError(t *testing.T) {
	errDec := errors.New("decrypt failed")
	mc := &mockClient{
		decryptFn: func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			return nil, errDec
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.DecryptData("server", "sw", "k", "AES-GCM", base64.StdEncoding.EncodeToString([]byte("c")))
	assert.True(t, errors.Is(err, errDec))
}

// --- ImportKey with mock ---

func TestKeyServiceImportKeySuccess(t *testing.T) {
	keyData := base64.StdEncoding.EncodeToString([]byte("raw-key-material"))

	mc := &mockClient{
		importKeyFn: func(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
			assert.Equal(t, "software", req.Backend)
			assert.Equal(t, "imported-key", req.KeyID)
			assert.Equal(t, []byte("raw-key-material"), req.WrappedKeyMaterial)
			assert.Equal(t, "pkcs8", req.Algorithm)
			return &transport.ImportKeyResponse{
				KeyID:        req.KeyID,
				PublicKeyPEM: "import-pem",
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	info, err := svc.ImportKey("server", &ImportKeyParams{
		KeyID:   "imported-key",
		Backend: "software",
		KeyType: "ECDSA",
		KeyData: keyData,
		Format:  "pkcs8",
	})
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "imported-key", info.KeyID)
	assert.Equal(t, "software", info.Backend)
	assert.Equal(t, "import-pem", info.PublicKeyPEM)
}

func TestKeyServiceImportKeyInvalidBase64(t *testing.T) {
	mc := &mockClient{
		importKeyFn: func(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
			t.Fatal("import should not be called")
			return nil, nil
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.ImportKey("server", &ImportKeyParams{
		KeyID:   "k",
		Backend: "b",
		KeyData: "not-valid-base64!!!",
	})
	assert.Error(t, err)
}

func TestKeyServiceImportKeyClientError(t *testing.T) {
	errImport := errors.New("import failed")
	mc := &mockClient{
		importKeyFn: func(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
			return nil, errImport
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.ImportKey("server", &ImportKeyParams{
		KeyID:   "k",
		Backend: "b",
		KeyData: base64.StdEncoding.EncodeToString([]byte("data")),
	})
	assert.True(t, errors.Is(err, errImport))
}

// --- ExportKey with mock ---

func TestKeyServiceExportKeySuccess(t *testing.T) {
	wrappedMaterial := []byte("wrapped-key-bytes")

	mc := &mockClient{
		exportKeyFn: func(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
			assert.Equal(t, "software", req.Backend)
			assert.Equal(t, "export-key", req.KeyID)
			assert.Equal(t, "pkcs8", req.Algorithm)
			return &transport.ExportKeyResponse{
				WrappedKeyMaterial: wrappedMaterial,
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.ExportKey("server", "software", "export-key", "pkcs8")
	require.NoError(t, err)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, wrappedMaterial, decoded)
}

func TestKeyServiceExportKeyClientError(t *testing.T) {
	errExport := errors.New("export failed")
	mc := &mockClient{
		exportKeyFn: func(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
			return nil, errExport
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.ExportKey("server", "sw", "k", "raw")
	assert.True(t, errors.Is(err, errExport))
}

// --- RotateKey with mock ---

func TestKeyServiceRotateKeySuccess(t *testing.T) {
	mc := &mockClient{
		rotateKeyFn: func(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
			assert.Equal(t, "software", req.Backend)
			assert.Equal(t, "rotate-key", req.KeyID)
			return &transport.RotateKeyResponse{
				KeyID:        req.KeyID,
				PublicKeyPEM: "rotated-pem",
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	info, err := svc.RotateKey("server", "software", "rotate-key")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "rotate-key", info.KeyID)
	assert.Equal(t, "software", info.Backend)
	assert.Equal(t, "rotated-pem", info.PublicKeyPEM)
}

func TestKeyServiceRotateKeyClientError(t *testing.T) {
	errRotate := errors.New("rotate failed")
	mc := &mockClient{
		rotateKeyFn: func(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
			return nil, errRotate
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.RotateKey("server", "sw", "k")
	assert.True(t, errors.Is(err, errRotate))
}

// --- AttestKey with mock ---

func TestKeyServiceAttestKeySuccess(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce-value"))
	certChain := [][]byte{[]byte("cert1"), []byte("cert2")}
	attestData := []byte("attestation-data")
	sigData := []byte("signature-data")

	mc := &mockClient{
		attestKeyFn: func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
			assert.Equal(t, "tpm2", req.Backend)
			assert.Equal(t, "attest-key", req.KeyID)
			assert.Equal(t, []byte("nonce-value"), req.Nonce)
			return &transport.AttestKeyResponse{
				Format:           "tpm",
				CertificateChain: certChain,
				AttestationData:  attestData,
				Signature:        sigData,
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.AttestKey("server", "tpm2", "attest-key", nonce)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tpm", result.Format)
	require.Len(t, result.CertificateChain, 2)
	assert.Equal(t, base64.StdEncoding.EncodeToString(certChain[0]), result.CertificateChain[0])
	assert.Equal(t, base64.StdEncoding.EncodeToString(certChain[1]), result.CertificateChain[1])
	assert.Equal(t, base64.StdEncoding.EncodeToString(attestData), result.AttestationData)
	assert.Equal(t, base64.StdEncoding.EncodeToString(sigData), result.Signature)
}

func TestKeyServiceAttestKeyEmptyNonce(t *testing.T) {
	mc := &mockClient{
		attestKeyFn: func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
			assert.Nil(t, req.Nonce)
			return &transport.AttestKeyResponse{
				Format:           "tpm",
				CertificateChain: [][]byte{},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	result, err := svc.AttestKey("server", "tpm2", "k", "")
	require.NoError(t, err)
	assert.Equal(t, "tpm", result.Format)
	assert.Empty(t, result.CertificateChain)
}

func TestKeyServiceAttestKeyInvalidNonce(t *testing.T) {
	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.AttestKey("server", "tpm2", "k", "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestKeyServiceAttestKeyClientError(t *testing.T) {
	errAttest := errors.New("attest failed")
	mc := &mockClient{
		attestKeyFn: func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
			return nil, errAttest
		},
	}
	svc := newTestKeyService(mc)

	_, err := svc.AttestKey("server", "tpm2", "k", "")
	assert.True(t, errors.Is(err, errAttest))
}

// --- GetKeyCount with mock ---

func TestKeyServiceGetKeyCountWithKeys(t *testing.T) {
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return &transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{{ID: "sw", Type: "software"}},
			}, nil
		},
		listKeysFn: func(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
			return &transport.ListKeysResponse{
				Keys: []transport.KeyInfo{
					{KeyID: "k1"},
					{KeyID: "k2"},
					{KeyID: "k3"},
				},
			}, nil
		},
	}
	svc := newTestKeyService(mc)

	count := svc.GetKeyCount("server")
	assert.Equal(t, 3, count)
}

// --- Operations without audit logger ---

func TestKeyServiceOperationsWithoutAuditLogger(t *testing.T) {
	mc := &mockClient{
		generateKeyFn: func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			return &transport.GenerateKeyResponse{KeyID: req.KeyID}, nil
		},
		deleteKeyFn: func(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
			return &transport.DeleteKeyResponse{Success: true}, nil
		},
	}
	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetClientFunc(func() xkms.Client { return mc })
	// No audit logger set

	t.Run("GenerateKey without logger", func(t *testing.T) {
		result, err := svc.GenerateKey("server", &GenerateKeyParams{KeyID: "k", Backend: "b"})
		require.NoError(t, err)
		assert.Equal(t, "k", result.KeyID)
	})

	t.Run("DeleteKey without logger", func(t *testing.T) {
		err := svc.DeleteKey("server", "b", "k")
		assert.NoError(t, err)
	})
}

// --- Local client tests ---

func TestKeyServiceLocalClient(t *testing.T) {
	mc := &mockClient{
		listBackendsFn: func(ctx context.Context) (*transport.ListBackendsResponse, error) {
			return &transport.ListBackendsResponse{
				Backends: []transport.BackendInfo{
					{ID: "software", Type: "software"},
				},
			}, nil
		},
	}
	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetLocalClient(mc)

	t.Run("ListBackends_local", func(t *testing.T) {
		backends, err := svc.ListBackends("local")
		require.NoError(t, err)
		require.Len(t, backends, 1)
		assert.Equal(t, "software", backends[0].ID)
	})

	t.Run("ListBackends_server_no_client", func(t *testing.T) {
		_, err := svc.ListBackends("server")
		assert.True(t, errors.Is(err, ErrKeyServiceNoClient))
	})
}

func TestKeyServiceNoLocalClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	_, err := svc.ListBackends("local")
	assert.True(t, errors.Is(err, ErrKeyServiceNoLocalClient))
}

func TestKeyServiceSetLocalClient(t *testing.T) {
	svc := NewKeyService()
	assert.Nil(t, svc.localClient)

	mc := &mockClient{}
	svc.SetLocalClient(mc)
	assert.NotNil(t, svc.localClient)
}

// --- EncryptFile tests ---

func TestKeyServiceEncryptFileSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plaintext.bin")
	outputPath := filepath.Join(tmpDir, "ciphertext.enc")

	require.NoError(t, os.WriteFile(inputPath, []byte("hello world"), 0600))

	mc := &mockClient{
		encryptFn: func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
			assert.Equal(t, []byte("hello world"), req.Plaintext)
			return &transport.EncryptResponse{Ciphertext: []byte("encrypted-output")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.EncryptFile("server", "sw", "k1", inputPath, outputPath, "base64")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	decoded, decErr := base64.StdEncoding.DecodeString(string(outputData))
	require.NoError(t, decErr)
	assert.Equal(t, []byte("encrypted-output"), decoded)
}

func TestKeyServiceEncryptFileHex(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plaintext.bin")
	outputPath := filepath.Join(tmpDir, "ciphertext.hex")

	require.NoError(t, os.WriteFile(inputPath, []byte("hello world"), 0600))

	mc := &mockClient{
		encryptFn: func(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
			assert.Equal(t, []byte("hello world"), req.Plaintext)
			return &transport.EncryptResponse{Ciphertext: []byte("encrypted-output")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.EncryptFile("server", "sw", "k1", inputPath, outputPath, "hex")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	decoded, decErr := hex.DecodeString(string(outputData))
	require.NoError(t, decErr)
	assert.Equal(t, []byte("encrypted-output"), decoded)
}

func TestKeyServiceEncryptFileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.bin")
	outputPath := filepath.Join(tmpDir, "output.enc")

	mc := &mockClient{}
	svc := newTestKeyService(mc)

	err := svc.EncryptFile("server", "sw", "k1", nonExistent, outputPath, "base64")
	assert.True(t, errors.Is(err, ErrFileReadFailed))
}

// --- DecryptFile tests ---

func TestKeyServiceDecryptFileSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "ciphertext.enc")
	outputPath := filepath.Join(tmpDir, "plaintext.bin")

	// The input file contains base64-encoded ciphertext.
	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	require.NoError(t, os.WriteFile(inputPath, []byte(ciphertextB64), 0600))

	mc := &mockClient{
		decryptFn: func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			assert.Equal(t, []byte("encrypted-data"), req.Ciphertext)
			return &transport.DecryptResponse{Plaintext: []byte("decrypted-result")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.DecryptFile("server", "sw", "k1", inputPath, outputPath, "base64")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("decrypted-result"), outputData)
}

func TestKeyServiceDecryptFileHex(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "ciphertext.hex")
	outputPath := filepath.Join(tmpDir, "plaintext.bin")

	// The input file contains hex-encoded ciphertext.
	ciphertextHex := hex.EncodeToString([]byte("encrypted-data"))
	require.NoError(t, os.WriteFile(inputPath, []byte(ciphertextHex), 0600))

	mc := &mockClient{
		decryptFn: func(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
			assert.Equal(t, []byte("encrypted-data"), req.Ciphertext)
			return &transport.DecryptResponse{Plaintext: []byte("decrypted-result")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.DecryptFile("server", "sw", "k1", inputPath, outputPath, "hex")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("decrypted-result"), outputData)
}

func TestKeyServiceDecryptFileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.enc")
	outputPath := filepath.Join(tmpDir, "output.bin")

	mc := &mockClient{}
	svc := newTestKeyService(mc)

	err := svc.DecryptFile("server", "sw", "k1", nonExistent, outputPath, "base64")
	assert.True(t, errors.Is(err, ErrFileReadFailed))
}

// --- SignFile tests ---

func TestKeyServiceSignFileSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "data.bin")
	outputPath := filepath.Join(tmpDir, "data.sig")

	require.NoError(t, os.WriteFile(inputPath, []byte("sign this data"), 0600))

	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			assert.Equal(t, []byte("sign this data"), req.Data)
			assert.Equal(t, "SHA-256", req.Hash)
			return &transport.SignResponse{Signature: []byte("the-signature")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.SignFile("server", "sw", "k1", "SHA-256", inputPath, outputPath, "base64")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	decoded, decErr := base64.StdEncoding.DecodeString(string(outputData))
	require.NoError(t, decErr)
	assert.Equal(t, []byte("the-signature"), decoded)
}

func TestKeyServiceSignFileHex(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "data.bin")
	outputPath := filepath.Join(tmpDir, "data.sig.hex")

	require.NoError(t, os.WriteFile(inputPath, []byte("sign this data"), 0600))

	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			assert.Equal(t, []byte("sign this data"), req.Data)
			return &transport.SignResponse{Signature: []byte("the-signature")}, nil
		},
	}
	svc := newTestKeyService(mc)

	err := svc.SignFile("server", "sw", "k1", "SHA-256", inputPath, outputPath, "hex")
	require.NoError(t, err)

	outputData, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	decoded, decErr := hex.DecodeString(string(outputData))
	require.NoError(t, decErr)
	assert.Equal(t, []byte("the-signature"), decoded)
}

func TestKeyServiceSignFileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.bin")
	outputPath := filepath.Join(tmpDir, "output.sig")

	mc := &mockClient{}
	svc := newTestKeyService(mc)

	err := svc.SignFile("server", "sw", "k1", "SHA-256", nonExistent, outputPath, "base64")
	assert.True(t, errors.Is(err, ErrFileReadFailed))
}

// --- VerifyFileSignature tests ---

func TestKeyServiceVerifyFileSignatureSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")
	sigPath := filepath.Join(tmpDir, "data.sig")

	require.NoError(t, os.WriteFile(dataPath, []byte("verify this data"), 0600))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("valid-signature"))
	require.NoError(t, os.WriteFile(sigPath, []byte(sigB64), 0600))

	mc := &mockClient{
		verifyFn: func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			assert.Equal(t, []byte("verify this data"), req.Data)
			assert.Equal(t, []byte("valid-signature"), req.Signature)
			return &transport.VerifyResponse{Valid: true}, nil
		},
	}
	svc := newTestKeyService(mc)

	valid, err := svc.VerifyFileSignature("server", "sw", "k1", "SHA-256", dataPath, sigPath, "base64")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestKeyServiceVerifyFileSignatureInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")
	sigPath := filepath.Join(tmpDir, "data.sig")

	require.NoError(t, os.WriteFile(dataPath, []byte("some data"), 0600))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("bad-signature"))
	require.NoError(t, os.WriteFile(sigPath, []byte(sigB64), 0600))

	mc := &mockClient{
		verifyFn: func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			assert.Equal(t, []byte("some data"), req.Data)
			assert.Equal(t, []byte("bad-signature"), req.Signature)
			return &transport.VerifyResponse{Valid: false}, nil
		},
	}
	svc := newTestKeyService(mc)

	valid, err := svc.VerifyFileSignature("server", "sw", "k1", "SHA-256", dataPath, sigPath, "base64")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestKeyServiceVerifyFileSignatureHex(t *testing.T) {
	tmpDir := t.TempDir()
	dataPath := filepath.Join(tmpDir, "data.bin")
	sigPath := filepath.Join(tmpDir, "data.sig.hex")

	require.NoError(t, os.WriteFile(dataPath, []byte("verify hex data"), 0600))
	sigHex := hex.EncodeToString([]byte("hex-signature"))
	require.NoError(t, os.WriteFile(sigPath, []byte(sigHex), 0600))

	mc := &mockClient{
		verifyFn: func(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
			assert.Equal(t, []byte("verify hex data"), req.Data)
			assert.Equal(t, []byte("hex-signature"), req.Signature)
			return &transport.VerifyResponse{Valid: true}, nil
		},
	}
	svc := newTestKeyService(mc)

	valid, err := svc.VerifyFileSignature("server", "sw", "k1", "SHA-256", dataPath, sigPath, "hex")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestKeyServiceVerifyFileSignatureReadError(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.bin")
	sigPath := filepath.Join(tmpDir, "data.sig")

	// Even if sig file exists, reading data should fail first.
	require.NoError(t, os.WriteFile(sigPath, []byte("sig"), 0600))

	mc := &mockClient{}
	svc := newTestKeyService(mc)

	_, err := svc.VerifyFileSignature("server", "sw", "k1", "SHA-256", nonExistent, sigPath, "base64")
	assert.True(t, errors.Is(err, ErrFileReadFailed))
}

func TestKeyService_ListRegisteredBackends_WithRegistry(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()

	sw := &backendregistry.RegisteredBackend{
		ID:       "software",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategorySoftware,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	sw.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(sw))

	tpm := &backendregistry.RegisteredBackend{
		ID:       "tpm2",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryTPM2,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	tpm.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(tpm))

	p11 := &backendregistry.RegisteredBackend{
		ID:       "pkcs11",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryPKCS11,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	p11.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(p11))

	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetRegistry(reg)

	result, err := svc.ListRegisteredBackends()
	require.NoError(t, err)
	require.Len(t, result, 3)

	// Verify hardware_backed flag is correct for each.
	byID := make(map[string]RemoteBackendInfo, len(result))
	for _, r := range result {
		byID[r.ID] = r
	}
	assert.False(t, byID["software"].HardwareBacked)
	assert.True(t, byID["tpm2"].HardwareBacked)
	assert.True(t, byID["pkcs11"].HardwareBacked)

	// Verify Type matches category string.
	assert.Equal(t, "software", byID["software"].Type)
	assert.Equal(t, "tpm2", byID["tpm2"].Type)
	assert.Equal(t, "pkcs11", byID["pkcs11"].Type)

	// Verify capabilities are populated for all backends (all have CapSigning + CapEncryption).
	for _, id := range []string{"software", "tpm2", "pkcs11"} {
		caps := byID[id].Capabilities
		assert.True(t, caps.Signing, "%s should have Signing", id)
		assert.True(t, caps.Decryption, "%s should have Decryption", id)
		assert.True(t, caps.Keys, "%s should have Keys", id)
	}
}

func TestKeyService_ListRegisteredBackends_NilRegistry(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	// registry is not set

	result, err := svc.ListRegisteredBackends()
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrKeyServiceNoRegistry))
}

func TestKeyService_ListRegisteredBackends_FiltersOffline(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()

	ready := &backendregistry.RegisteredBackend{
		ID:       "software",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategorySoftware,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	ready.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(ready))

	offline := &backendregistry.RegisteredBackend{
		ID:       "tpm2-offline",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryTPM2,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	offline.SetState(backendregistry.StateOffline)
	require.NoError(t, reg.Register(offline))

	errBackend := &backendregistry.RegisteredBackend{
		ID:       "pkcs11-error",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryPKCS11,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
	}
	errBackend.SetState(backendregistry.StateError)
	require.NoError(t, reg.Register(errBackend))

	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetRegistry(reg)

	result, err := svc.ListRegisteredBackends()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "software", result[0].ID)
}

func TestKeyService_ListRegisteredBackends_FiltersNonKeyBackends(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()

	// Backend with only FIDO2 capability (no signing or encryption).
	fido := &backendregistry.RegisteredBackend{
		ID:       "fido2-only",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryPhone,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapFIDO2: true,
		},
	}
	fido.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(fido))

	// Backend with signing capability should be included.
	sw := &backendregistry.RegisteredBackend{
		ID:       "software",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategorySoftware,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning: true,
		},
	}
	sw.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(sw))

	svc := NewKeyService()
	svc.SetContext(context.Background())
	svc.SetRegistry(reg)

	result, err := svc.ListRegisteredBackends()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "software", result[0].ID)
}

func TestConvertRegistryCapabilities_Signing(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning: true,
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Signing)
	assert.True(t, result.Keys)
	assert.False(t, result.Decryption)
	assert.False(t, result.Attestation)
	assert.False(t, result.Sealing)
}

func TestConvertRegistryCapabilities_Encryption(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapEncryption: true,
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Decryption)
	assert.True(t, result.Keys)
	assert.False(t, result.Signing)
	assert.False(t, result.Attestation)
	assert.False(t, result.Sealing)
}

func TestConvertRegistryCapabilities_Attestation(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapAttestation: true,
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Attestation)
	assert.False(t, result.Keys)
	assert.False(t, result.Signing)
	assert.False(t, result.Decryption)
	assert.False(t, result.Sealing)
}

func TestConvertRegistryCapabilities_Sealing(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSealing: true,
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Sealing)
	assert.False(t, result.Keys)
	assert.False(t, result.Signing)
	assert.False(t, result.Decryption)
	assert.False(t, result.Attestation)
}

func TestConvertRegistryCapabilities_Combined(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning:     true,
		backendregistry.CapEncryption:  true,
		backendregistry.CapAttestation: true,
		backendregistry.CapSealing:     true,
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Signing)
	assert.True(t, result.Decryption)
	assert.True(t, result.Keys)
	assert.True(t, result.Attestation)
	assert.True(t, result.Sealing)
}

func TestConvertRegistryCapabilities_DisabledCapability(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning:    true,
		backendregistry.CapEncryption: false, // explicitly disabled
	}
	result := convertRegistryCapabilities(caps)
	assert.True(t, result.Signing)
	assert.True(t, result.Keys)
	assert.False(t, result.Decryption, "disabled capability should not be set")
}

func TestConvertRegistryCapabilities_EmptyMap(t *testing.T) {
	caps := map[backendregistry.Capability]bool{}
	result := convertRegistryCapabilities(caps)
	assert.Equal(t, transport.BackendCapabilities{}, result)
}

func TestConvertRegistryCapabilities_NilMap(t *testing.T) {
	result := convertRegistryCapabilities(nil)
	assert.Equal(t, transport.BackendCapabilities{}, result)
}

func TestConvertRegistryCapabilities_UnknownCapability(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapFIDO2: true, // not mapped
		backendregistry.CapPIV:   true, // not mapped
	}
	result := convertRegistryCapabilities(caps)
	// Unknown capabilities should be silently ignored.
	assert.Equal(t, transport.BackendCapabilities{}, result)
}
