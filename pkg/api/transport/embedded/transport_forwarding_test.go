// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package embedded

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errOf drops the result of a (value, error) call so every forwarding method
// fits one call signature in the table below.
func errOf[T any](_ T, err error) error {
	return err
}

// forwardingCalls returns one call per Transport method that guards on the
// connection and forwards to the service, keyed by method name.
func forwardingCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"ListKeys":             func() error { return errOf(tr.ListKeys(ctx, "software")) },
		"GetKey":               func() error { return errOf(tr.GetKey(ctx, "software", "k")) },
		"Sign":                 func() error { return errOf(tr.Sign(ctx, &transport.SignRequest{})) },
		"Verify":               func() error { return errOf(tr.Verify(ctx, &transport.VerifyRequest{})) },
		"Encrypt":              func() error { return errOf(tr.Encrypt(ctx, &transport.EncryptRequest{})) },
		"Decrypt":              func() error { return errOf(tr.Decrypt(ctx, &transport.DecryptRequest{})) },
		"EncryptAsym":          func() error { return errOf(tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{})) },
		"DeriveKey":            func() error { return errOf(tr.DeriveKey(ctx, &transport.DeriveKeyRequest{})) },
		"GetCertificate":       func() error { return errOf(tr.GetCertificate(ctx, "software", "k")) },
		"SaveCertificate":      func() error { return tr.SaveCertificate(ctx, &transport.SaveCertificateRequest{}) },
		"DeleteCertificate":    func() error { return tr.DeleteCertificate(ctx, "software", "k") },
		"CertificateExists":    func() error { return errOf(tr.CertificateExists(ctx, "software", "k")) },
		"ImportKey":            func() error { return errOf(tr.ImportKey(ctx, &transport.ImportKeyRequest{})) },
		"ExportKey":            func() error { return errOf(tr.ExportKey(ctx, &transport.ExportKeyRequest{})) },
		"RotateKey":            func() error { return errOf(tr.RotateKey(ctx, &transport.RotateKeyRequest{})) },
		"GetImportParameters":  func() error { return errOf(tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{})) },
		"WrapKey":              func() error { return errOf(tr.WrapKey(ctx, &transport.WrapKeyRequest{})) },
		"UnwrapKey":            func() error { return errOf(tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{})) },
		"CopyKey":              func() error { return errOf(tr.CopyKey(ctx, &transport.CopyKeyRequest{})) },
		"ListCertificates":     func() error { return errOf(tr.ListCertificates(ctx, "software")) },
		"SaveCertificateChain": func() error { return tr.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{}) },
		"GetCertificateChain":  func() error { return errOf(tr.GetCertificateChain(ctx, "software", "k")) },
		"GetTLSCertificate":    func() error { return errOf(tr.GetTLSCertificate(ctx, "software", "k")) },
		"Seal":                 func() error { return errOf(tr.Seal(ctx, &transport.SealRequest{})) },
		"Unseal":               func() error { return errOf(tr.Unseal(ctx, &transport.UnsealRequest{})) },
		"CanSeal":              func() error { return errOf(tr.CanSeal(ctx, "software")) },
		"AttestKey":            func() error { return errOf(tr.AttestKey(ctx, &transport.AttestKeyRequest{})) },
		"BeginRegistration":    func() error { return errOf(tr.BeginRegistration(ctx, &transport.BeginRegistrationRequest{})) },
		"FinishRegistration":   func() error { return errOf(tr.FinishRegistration(ctx, &transport.FinishRegistrationRequest{})) },
		"BeginAuthentication":  func() error { return errOf(tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{})) },
		"FinishAuthentication": func() error { return errOf(tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{})) },
		"GetInvite":            func() error { return errOf(tr.GetInvite(ctx, &transport.GetInviteRequest{})) },
		"BeginInviteRegistration": func() error {
			return errOf(tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{}))
		},
		"FinishInviteRegistration": func() error {
			return errOf(tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{}))
		},
		"ActivateInvitePIV":     func() error { return errOf(tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{})) },
		"ExportKeyMaterial":     func() error { return errOf(tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{})) },
		"WrapKeyByID":           func() error { return errOf(tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{})) },
		"UnwrapKeyByID":         func() error { return errOf(tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{})) },
		"DeriveKeyECDH":         func() error { return errOf(tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{})) },
		"GetCABundle":           func() error { return errOf(tr.GetCABundle(ctx, &transport.GetCABundleRequest{})) },
		"GetCACertificate":      func() error { return errOf(tr.GetCACertificate(ctx, &transport.GetCACertificateRequest{})) },
		"SignCSR":               func() error { return errOf(tr.SignCSR(ctx, &transport.SignCSRRequest{})) },
		"IssueCertificate":      func() error { return errOf(tr.IssueCertificate(ctx, &transport.IssueCertificateRequest{})) },
		"RevokeCertificate":     func() error { return errOf(tr.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{})) },
		"GenerateCRL":           func() error { return errOf(tr.GenerateCRL(ctx, &transport.GenerateCRLRequest{})) },
		"IsRevoked":             func() error { return errOf(tr.IsRevoked(ctx, &transport.IsRevokedRequest{})) },
		"IssueEKCertificate":    func() error { return errOf(tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{})) },
		"IssueAKCertificate":    func() error { return errOf(tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{})) },
		"SignTCGCSR":            func() error { return errOf(tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{})) },
		"EnrollDevice":          func() error { return errOf(tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{})) },
		"IssueLAKCertificate":   func() error { return errOf(tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{})) },
		"ListPIVSlots":          func() error { return errOf(tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{})) },
		"GetPIVCertificate":     func() error { return errOf(tr.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{})) },
		"StorePIVCertificate":   func() error { return tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) },
		"DeletePIVCertificate":  func() error { return tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{}) },
		"GeneratePIVKey":        func() error { return errOf(tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{})) },
		"ImportPIVCertificate":  func() error { return tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) },
		"ExportPIVCertificate":  func() error { return errOf(tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{})) },
		"GeneratePIVCSR":        func() error { return errOf(tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{})) },
		"BootstrapListenerKeys": func() error { return errOf(tr.BootstrapListenerKeys(ctx)) },
		"SetSOPIN":              func() error { return tr.SetSOPIN(ctx, &transport.SetSOPINRequest{}) },
		"SetUserPIN":            func() error { return tr.SetUserPIN(ctx, &transport.SetUserPINRequest{}) },
		"ChangeSOPIN":           func() error { return tr.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{}) },
		"ChangeUserPIN":         func() error { return tr.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{}) },
		"VerifySOPIN":           func() error { return tr.VerifySOPIN(ctx, &transport.VerifySOPINRequest{}) },
		"VerifyUserPIN":         func() error { return tr.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{}) },
		"GetLockoutStatus":      func() error { return errOf(tr.GetLockoutStatus(ctx)) },
		"ResetLockout":          func() error { return tr.ResetLockout(ctx, &transport.ResetLockoutRequest{}) },
		"PasswordAdd":           func() error { return errOf(tr.PasswordAdd(ctx, &transport.PasswordAddRequest{})) },
		"PasswordGet":           func() error { return errOf(tr.PasswordGet(ctx, &transport.PasswordGetRequest{})) },
		"PasswordList":          func() error { return errOf(tr.PasswordList(ctx, &transport.PasswordListRequest{})) },
		"PasswordUpdate":        func() error { return tr.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{}) },
		"PasswordDelete":        func() error { return tr.PasswordDelete(ctx, &transport.PasswordDeleteRequest{}) },
		"PasswordStoreUnlock":   func() error { return tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{}) },
		"PasswordStoreLock":     func() error { return tr.PasswordStoreLock(ctx) },
		"PasswordStoreStatus":   func() error { return errOf(tr.PasswordStoreStatus(ctx)) },
		"PasswordStoreSetAccessMode": func() error {
			return tr.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{})
		},
		"PasswordGenerate":         func() error { return errOf(tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{})) },
		"SealStorePut":             func() error { return tr.SealStorePut(ctx, &transport.SealStorePutRequest{}) },
		"SealStoreGet":             func() error { return errOf(tr.SealStoreGet(ctx, &transport.SealStoreGetRequest{})) },
		"SealStoreDelete":          func() error { return tr.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{}) },
		"SealStoreList":            func() error { return errOf(tr.SealStoreList(ctx)) },
		"SealStoreReseal":          func() error { return tr.SealStoreReseal(ctx, &transport.SealStoreResealRequest{}) },
		"SealStoreStatus":          func() error { return errOf(tr.SealStoreStatus(ctx)) },
		"ListKeyVersions":          func() error { return errOf(tr.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{})) },
		"EnableKeyVersion":         func() error { return errOf(tr.EnableKeyVersion(ctx, &transport.KeyVersionRequest{})) },
		"DisableKeyVersion":        func() error { return errOf(tr.DisableKeyVersion(ctx, &transport.KeyVersionRequest{})) },
		"RetireKeyVersion":         func() error { return errOf(tr.RetireKeyVersion(ctx, &transport.KeyVersionRequest{})) },
		"EnableAllKeyVersions":     func() error { return errOf(tr.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{})) },
		"DisableAllKeyVersions":    func() error { return errOf(tr.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{})) },
		"RotateScopeKeys":          func() error { return errOf(tr.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})) },
		"TPMPolicyCreate":          func() error { return errOf(tr.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{})) },
		"TPMPolicyGet":             func() error { return errOf(tr.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{})) },
		"TPMPolicyList":            func() error { return errOf(tr.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})) },
		"TPMPolicyUpdate":          func() error { return errOf(tr.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{})) },
		"TPMPolicyRevoke":          func() error { return errOf(tr.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{})) },
		"TPMPolicyVerify":          func() error { return errOf(tr.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{})) },
		"TPMPolicyDelete":          func() error { return tr.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{}) },
		"TPMPolicyObjects":         func() error { return errOf(tr.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{})) },
		"TPMPolicySetAutoUnseal":   func() error { return errOf(tr.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{})) },
		"TPMPolicySetDescription":  func() error { return errOf(tr.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{})) },
		"TPMObjectPolicy":          func() error { return errOf(tr.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{})) },
		"TPMPolicyRotateAuthority": func() error { return errOf(tr.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})) },
		"GetTenantTPMMode":         func() error { return errOf(tr.GetTenantTPMMode(ctx, "t1")) },
		"SetTenantTPMMode":         func() error { return errOf(tr.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{})) },
		"TenantVTPMStatus":         func() error { return errOf(tr.TenantVTPMStatus(ctx, "t1")) },
		"TenantVTPMStart":          func() error { return errOf(tr.TenantVTPMStart(ctx, "t1")) },
		"TenantVTPMStop":           func() error { return errOf(tr.TenantVTPMStop(ctx, "t1")) },
		"CreateTenant":             func() error { return errOf(tr.CreateTenant(ctx, &transport.CreateTenantRequest{})) },
		"GetTenant":                func() error { return errOf(tr.GetTenant(ctx, "t1")) },
		"ListTenants":              func() error { return errOf(tr.ListTenants(ctx)) },
		"DeleteTenant":             func() error { return tr.DeleteTenant(ctx, "t1") },
		"SubmitCredential":         func() error { return errOf(tr.SubmitCredential(ctx, &transport.CredentialSubmitRequest{})) },
		"GetCredentialStrategy":    func() error { return errOf(tr.GetCredentialStrategy(ctx)) },
	}
}

// TestForwarding_Connected pins that a connected transport hands each call to
// the service and returns its success unchanged.
func TestForwarding_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	for name, call := range forwardingCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, call())
		})
	}
}

// TestForwarding_ServiceError pins that a service failure reaches the caller
// unwrapped, so errors.Is on the service's typed error keeps working.
func TestForwarding_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	for name, call := range forwardingCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), errMock)
		})
	}
}

// TestForwarding_NotConnected pins that every call is refused with
// ErrNotConnected before a service is attached, instead of dereferencing a
// nil service.
func TestForwarding_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	for name, call := range forwardingCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}

// TestForwarding_AfterClose pins that Close drops the connection: a closed
// transport refuses calls even though its service is still set.
func TestForwarding_AfterClose(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	for name, call := range forwardingCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
