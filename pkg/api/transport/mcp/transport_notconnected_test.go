// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllMethods_NotConnected verifies that every transport method correctly
// returns ErrNotConnected when the transport has not been connected.
func TestAllMethods_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	ctx := context.Background()

	// Key service
	_, err = tr.GetBackend(ctx, "sw")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GenerateKey(ctx, &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListKeys(ctx, "sw")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetKey(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.DeleteKey(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.Sign(ctx, &transport.SignRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.Verify(ctx, &transport.VerifyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.Encrypt(ctx, &transport.EncryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.Decrypt(ctx, &transport.DecryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.DeriveKey(ctx, &transport.DeriveKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.AttestKey(ctx, &transport.AttestKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// Certificate service
	_, err = tr.GetCertificate(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.SaveCertificate(ctx, &transport.SaveCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DeleteCertificate(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.CertificateExists(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ImportKey(ctx, &transport.ImportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ExportKey(ctx, &transport.ExportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.RotateKey(ctx, &transport.RotateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.WrapKey(ctx, &transport.WrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.CopyKey(ctx, &transport.CopyKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListCertificates(ctx, "sw")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetCertificateChain(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetTLSCertificate(ctx, "sw", "k1")
	assert.ErrorIs(t, err, ErrNotConnected)

	// Seal service
	_, err = tr.Seal(ctx, &transport.SealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.Unseal(ctx, &transport.UnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.CanSeal(ctx, "sw")
	assert.ErrorIs(t, err, ErrNotConnected)

	// User service
	_, err = tr.ListUsers(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetUser(ctx, "admin")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DeleteUser(ctx, "admin")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.EnableUser(ctx, "admin")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DisableUser(ctx, "admin")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListUserCredentials(ctx, "admin")
	assert.ErrorIs(t, err, ErrNotConnected)

	// CA service
	_, err = tr.GetCABundle(ctx, &transport.GetCABundleRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.SignCSR(ctx, &transport.SignCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.IssueCertificate(ctx, &transport.IssueCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.IsRevoked(ctx, &transport.IsRevokedRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// PIV service
	_, err = tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// Barrier service
	err = tr.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierSeal(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierUnsealWithShares(ctx, &transport.BarrierUnsealSharesRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierShamirListShares(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierShamirDeleteShare(ctx, &transport.BarrierShamirDeleteShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierShamirDeleteAllShares(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierShamirVerify(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierRekey(ctx, &transport.BarrierRekeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.BarrierDeleteRecoveryKeys(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierHasRecoveryKeys(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// PIN service
	err = tr.SetSOPIN(ctx, &transport.SetSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.SetUserPIN(ctx, &transport.SetUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.VerifySOPIN(ctx, &transport.VerifySOPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetLockoutStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.ResetLockout(ctx, &transport.ResetLockoutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// Password service
	_, err = tr.PasswordAdd(ctx, &transport.PasswordAddRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.PasswordGet(ctx, &transport.PasswordGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.PasswordList(ctx, &transport.PasswordListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.PasswordDelete(ctx, &transport.PasswordDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.PasswordStoreLock(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.PasswordStoreStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// Custodian/Share/Tenant service
	_, err = tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetCustodianGroup(ctx, "g1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListCustodianGroups(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DeleteCustodianGroup(ctx, "g1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.DistributeShares(ctx, &transport.DistributeSharesRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.SubmitShare(ctx, &transport.SubmitShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListShares(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetShareCollectionStatus(ctx, "g1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.CreateTenant(ctx, &transport.CreateTenantRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetTenant(ctx, "t1")
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ListTenants(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.DeleteTenant(ctx, "t1")
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	err = tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	// Init ceremony
	_, err = tr.GetInitStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ClaimCertBegin(ctx, &transport.ClaimCertBeginRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ClaimCertComplete(ctx, &transport.ClaimCertCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.ClaimShare(ctx, &transport.ClaimShareRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.SignCSRInit(ctx, &transport.SignCSRInitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.SubmitCredential(ctx, &transport.CredentialSubmitRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)

	_, err = tr.GetCredentialStrategy(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
}
