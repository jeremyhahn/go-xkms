// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package quic

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDisconnected returns a Transport that is not connected.
func newDisconnected(t *testing.T) *Transport {
	t.Helper()
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	return tr
}

// --- NotConnected tests for every method ---

func TestAttestKey_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).AttestKey(context.Background(), &transport.AttestKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestWrapKeyByID_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnwrapKeyByID_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportKeyMaterial_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListCertificates_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListCertificates(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSaveCertificateChain_NotConnected(t *testing.T) {
	err := newDisconnected(t).SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCertificateChain_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetCertificateChain(context.Background(), "software", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetTLSCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetTLSCertificate(context.Background(), "software", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEncryptAsym_NotConnected_Coverage(t *testing.T) {
	_, err := newDisconnected(t).EncryptAsym(context.Background(), &transport.EncryptAsymRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Barrier ---

func TestBarrierInitializeShamir_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnsealWithShare_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnsealWithShares_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirListShares_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierShamirListShares(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirDeleteShare_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirDeleteAllShares_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierShamirDeleteAllShares(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierShamirVerify_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierShamirVerify(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierRekey_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierGenerateRecoveryKeys_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierRecoverWithKeys_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierDeleteRecoveryKeys_NotConnected(t *testing.T) {
	err := newDisconnected(t).BarrierDeleteRecoveryKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierHasRecoveryKeys_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierHasRecoveryKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierGenerateRootToken_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- PIN ---

func TestSetSOPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSetUserPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestChangeSOPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestChangeUserPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerifySOPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerifyUserPIN_NotConnected(t *testing.T) {
	err := newDisconnected(t).VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetLockoutStatus_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetLockoutStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestResetLockout_NotConnected(t *testing.T) {
	err := newDisconnected(t).ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- CA ---

func TestGetCABundle_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCACertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSignCSR_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).SignCSR(context.Background(), &transport.SignCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSignCSRInit_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestIssueCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).IssueCertificate(context.Background(), &transport.IssueCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRevokeCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateCRL_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestIsRevoked_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).IsRevoked(context.Background(), &transport.IsRevokedRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- TCG CA ---

func TestIssueEKCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestIssueAKCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSignTCGCSR_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEnrollDevice_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- PIV ---

func TestListPIVSlots_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetPIVCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestStorePIVCertificate_NotConnected(t *testing.T) {
	err := newDisconnected(t).StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeletePIVCertificate_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGeneratePIVKey_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestImportPIVCertificate_NotConnected(t *testing.T) {
	err := newDisconnected(t).ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportPIVCertificate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGeneratePIVCSR_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Users (not supported for gRPC, return ErrNotSupported) ---

func TestListUsers_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestGetUser_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).GetUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestDeleteUser_NotSupported(t *testing.T) {
	err := newDisconnected(t).DeleteUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestEnableUser_NotSupported(t *testing.T) {
	err := newDisconnected(t).EnableUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestDisableUser_NotSupported(t *testing.T) {
	err := newDisconnected(t).DisableUser(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestListUserCredentials_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).ListUserCredentials(context.Background(), "admin")
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- WebAuthn (not supported) ---

func TestBeginRegistration_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestFinishRegistration_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestBeginAuthentication_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestFinishAuthentication_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- SealStore (not supported) ---

func TestSealStorePut_NotSupported(t *testing.T) {
	err := newDisconnected(t).SealStorePut(context.Background(), &transport.SealStorePutRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreGet_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).SealStoreGet(context.Background(), &transport.SealStoreGetRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreDelete_NotSupported(t *testing.T) {
	err := newDisconnected(t).SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreList_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).SealStoreList(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreReseal_NotSupported(t *testing.T) {
	err := newDisconnected(t).SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSealStoreStatus_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).SealStoreStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- Policy (not supported) ---

func TestPolicyCreate_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyCreate(context.Background(), &transport.PolicyCreateRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyGet_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyGet(context.Background(), &transport.PolicyGetRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyList_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyList(context.Background())
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyDelete_NotSupported(t *testing.T) {
	err := newDisconnected(t).PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyRefresh_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyVerify_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestPolicyExport_NotSupported(t *testing.T) {
	_, err := newDisconnected(t).PolicyExport(context.Background(), &transport.PolicyExportRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- Password ---

func TestPasswordAdd_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordGet_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PasswordGet(context.Background(), &transport.PasswordGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordList_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PasswordList(context.Background(), &transport.PasswordListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordUpdate_NotConnected(t *testing.T) {
	err := newDisconnected(t).PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordDelete_NotConnected(t *testing.T) {
	err := newDisconnected(t).PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreUnlock_NotConnected(t *testing.T) {
	err := newDisconnected(t).PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreLock_NotConnected(t *testing.T) {
	err := newDisconnected(t).PasswordStoreLock(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreStatus_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PasswordStoreStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordStoreSetAccessMode_NotConnected(t *testing.T) {
	err := newDisconnected(t).PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordGenerate_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Init Ceremony ---

func TestGetInitStatus_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetInitStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimCertBegin_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimCertComplete_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimShare_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}


// --- Credentials ---

func TestSubmitCredential_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCredentialStrategy_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetCredentialStrategy(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Custodian ---

func TestCreateCustodianGroup_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCustodianGroup_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetCustodianGroup(context.Background(), "g1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListCustodianGroups_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListCustodianGroups(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteCustodianGroup_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeleteCustodianGroup(context.Background(), "g1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestAddCustodianMember_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRemoveCustodianMember_NotConnected(t *testing.T) {
	err := newDisconnected(t).RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDistributeShares_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).DistributeShares(context.Background(), &transport.DistributeSharesRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Shares ---

func TestSubmitShare_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).SubmitShare(context.Background(), &transport.SubmitShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListShares_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListShares(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetShareCollectionStatus_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetShareCollectionStatus(context.Background(), "g1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Tenants ---

func TestCreateTenant_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).CreateTenant(context.Background(), &transport.CreateTenantRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetTenant_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetTenant(context.Background(), "t1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListTenants_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListTenants(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteTenant_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeleteTenant(context.Background(), "t1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestTenantBarrierInit_NotConnected(t *testing.T) {
	err := newDisconnected(t).TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestTenantBarrierUnseal_NotConnected(t *testing.T) {
	err := newDisconnected(t).TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}
