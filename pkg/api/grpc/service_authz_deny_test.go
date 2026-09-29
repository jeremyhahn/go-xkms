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

package grpc

import (
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// denyingRBAC always denies every request with a fixed reason. It satisfies
// the qrdb RBACClient interface so it can back an enabled *auth.Authorizer.
type denyingRBAC struct{}

func (d *denyingRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, _, _ string) error {
	return errors.New("denied by test")
}

func (d *denyingRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// newDeniedService creates a Service with a denying authorizer for testing
// authorization error paths.
func newDeniedService() *Service {
	return NewService(auth.NewAuthorizer(&denyingRBAC{}), nil, nil)
}

// deniedCtx returns a context carrying an authenticated identity so the
// enabled authorizer reaches a genuine permission denial (rather than an
// unauthenticated rejection for a missing identity).
func deniedCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "denied-subject",
		Roles:   []string{"guest"},
	})
}

// TestAuthzDeny_ServiceMethods tests the authorization denial path for all
// service methods that call s.authorize(). This covers the common pattern
// of returning a PermissionDenied error when authorization fails.
func TestAuthzDeny_ServiceMethods(t *testing.T) {
	// Need xkms initialized for methods that check backend before authorization.
	xkms.Reset()
	setupXKMSForTest(t)
	defer xkms.Reset()

	svc := newDeniedService()
	ctx := deniedCtx()

	tests := []struct {
		name string
		fn   func() error
	}{
		// service.go methods
		{"ListBackends", func() error { _, err := svc.ListBackends(ctx, &pb.ListBackendsRequest{}); return err }},
		{"GetBackendInfo", func() error {
			_, err := svc.GetBackendInfo(ctx, &pb.GetBackendInfoRequest{Name: "test"})
			return err
		}},
		{"GenerateKey", func() error {
			_, err := svc.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "k", Backend: "test", Algorithm: "ECDSA", KeyType: "signing"})
			return err
		}},
		{"ListKeys", func() error { _, err := svc.ListKeys(ctx, &pb.ListKeysRequest{Backend: "test"}); return err }},
		{"GetKey", func() error { _, err := svc.GetKey(ctx, &pb.GetKeyRequest{KeyId: "k", Backend: "test"}); return err }},
		{"Sign", func() error {
			_, err := svc.Sign(ctx, &pb.SignRequest{KeyId: "k", Backend: "test", Data: []byte("d")})
			return err
		}},
		{"Verify", func() error {
			_, err := svc.Verify(ctx, &pb.VerifyRequest{KeyId: "k", Backend: "test", Data: []byte("d"), Signature: []byte("s")})
			return err
		}},
		{"DeleteKey", func() error {
			_, err := svc.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: "k", Backend: "test"})
			return err
		}},
		{"RotateKey", func() error {
			_, err := svc.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "k", Backend: "test"})
			return err
		}},
		{"Encrypt", func() error {
			_, err := svc.Encrypt(ctx, &pb.EncryptRequest{KeyId: "k", Backend: "test", Plaintext: []byte("d")})
			return err
		}},
		// Decrypt authz called after key lookup, skipped
		// SaveCert validates PEM before authz, skipped
		{"GetCert", func() error { _, err := svc.GetCert(ctx, &pb.GetCertRequest{KeyId: "k"}); return err }},
		{"DeleteCert", func() error { _, err := svc.DeleteCert(ctx, &pb.DeleteCertRequest{KeyId: "k"}); return err }},
		{"ListCerts", func() error { _, err := svc.ListCerts(ctx, &pb.ListCertsRequest{}); return err }},
		{"CertExists", func() error { _, err := svc.CertExists(ctx, &pb.CertExistsRequest{KeyId: "k"}); return err }},
		// SaveCertChain validates PEM before authz, skipped
		{"GetCertChain", func() error { _, err := svc.GetCertChain(ctx, &pb.GetCertChainRequest{KeyId: "k"}); return err }},
		{"GetTLSCertificate", func() error {
			_, err := svc.GetTLSCertificate(ctx, &pb.GetTLSCertificateRequest{KeyId: "k", Backend: "test"})
			return err
		}},
		{"GetImportParameters", func() error {
			_, err := svc.GetImportParameters(ctx, &pb.GetImportParametersRequest{KeyId: "k", Backend: "test", WrappingAlgorithm: "a", KeyType: "RSA"})
			return err
		}},
		// WrapKey authz is tested after public key parsing, too complex for this test
		// UnwrapKey authz is tested after public key parsing, too complex for this test
		{"ImportKey", func() error {
			_, err := svc.ImportKey(ctx, &pb.ImportKeyRequest{KeyId: "k", Backend: "test", WrappedKey: []byte("d"), Algorithm: "a", KeyType: "RSA"})
			return err
		}},
		{"ExportKey", func() error {
			_, err := svc.ExportKey(ctx, &pb.ExportKeyRequest{KeyId: "k", Backend: "test", WrappingAlgorithm: "RSA_AES_KEY_WRAP_SHA_256"})
			return err
		}},
		{"ExportKeyMaterial", func() error {
			_, err := svc.ExportKeyMaterial(ctx, &pb.ExportKeyMaterialRequest{KeyId: "k", Backend: "test"})
			return err
		}},
		{"WrapKeyByID", func() error {
			_, err := svc.WrapKeyByID(ctx, &pb.WrapKeyByIDRequest{
				WrappingKeyId: "k", WrappingKeyBackend: "test", TargetKeyId: "k2", TargetKeyBackend: "test", Algorithm: "a",
			})
			return err
		}},
		{"UnwrapKeyByID", func() error {
			_, err := svc.UnwrapKeyByID(ctx, &pb.UnwrapKeyByIDRequest{
				WrappedKey: []byte("d"), UnwrappingKeyId: "k", UnwrappingKeyBackend: "test",
				Algorithm: "a", TargetKeyId: "k2", TargetKeyBackend: "test",
			})
			return err
		}},
		{"CopyKey", func() error {
			_, err := svc.CopyKey(ctx, &pb.CopyKeyRequest{
				SourceBackend: "test", SourceKeyId: "k", DestBackend: "test", DestKeyId: "k2", WrappingAlgorithm: "a",
			})
			return err
		}},
		{"EncryptAsym", func() error {
			_, err := svc.EncryptAsym(ctx, &pb.EncryptAsymRequest{KeyId: "k", Backend: "test", Plaintext: []byte("d")})
			return err
		}},
		{"Seal", func() error {
			_, err := svc.Seal(ctx, &pb.SealRequest{Backend: "test", Data: []byte("d")})
			return err
		}},
		{"Unseal", func() error {
			_, err := svc.Unseal(ctx, &pb.UnsealRequest{Backend: "test", Ciphertext: []byte("d")})
			return err
		}},
		{"CanSeal", func() error { _, err := svc.CanSeal(ctx, &pb.CanSealRequest{}); return err }},
		{"AttestKey", func() error {
			_, err := svc.AttestKey(ctx, &pb.AttestKeyRequest{Backend: "test", KeyId: "k"})
			return err
		}},
		{"DeriveKey", func() error {
			_, err := svc.DeriveKey(ctx, &pb.DeriveKeyRequest{KeyId: "k", Backend: "test", DerivedKeyId: "dk", Algorithm: "HKDF"})
			return err
		}},
		{"DeriveKeyECDH", func() error {
			_, err := svc.DeriveKeyECDH(ctx, &pb.DeriveKeyECDHRequest{KeyId: "k", Backend: "test", PeerPublicKey: []byte("pk")})
			return err
		}},
		// service_password.go methods
		{"PasswordAdd", func() error {
			_, err := svc.PasswordAdd(ctx, &pb.PasswordAddRequest{Name: "n", Password: "p"})
			return err
		}},
		{"PasswordGet", func() error { _, err := svc.PasswordGet(ctx, &pb.PasswordGetRequest{Id: "id"}); return err }},
		{"PasswordList", func() error { _, err := svc.PasswordList(ctx, &pb.PasswordListRequest{}); return err }},
		{"PasswordUpdate", func() error {
			_, err := svc.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{Id: "id"})
			return err
		}},
		{"PasswordDelete", func() error {
			_, err := svc.PasswordDelete(ctx, &pb.PasswordDeleteRequest{Id: "id"})
			return err
		}},
		{"PasswordStoreUnlock", func() error {
			_, err := svc.PasswordStoreUnlock(ctx, &pb.PasswordStoreUnlockRequest{})
			return err
		}},
		{"PasswordStoreLock", func() error { _, err := svc.PasswordStoreLock(ctx, nil); return err }},
		{"PasswordStoreStatus", func() error {
			_, err := svc.PasswordStoreStatus(ctx, &pb.PasswordStoreStatusRequest{})
			return err
		}},
		{"PasswordGenerate", func() error { _, err := svc.PasswordGenerate(ctx, &pb.PasswordGenerateRequest{}); return err }},
		// service_piv.go methods
		{"ListPIVSlots", func() error {
			_, err := svc.ListPIVSlots(ctx, &pb.ListPIVSlotsRequest{Backend: "test"})
			return err
		}},
		{"GetPIVCertificate", func() error {
			_, err := svc.GetPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "test", Slot: "9a", Format: "PEM"})
			return err
		}},
		{"StorePIVCertificate", func() error {
			_, err := svc.StorePIVCertificate(ctx, &pb.StorePIVCertificateRequest{Backend: "test", Slot: "9a", Certificate: []byte("c"), Format: "PEM"})
			return err
		}},
		{"DeletePIVCertificate", func() error {
			_, err := svc.DeletePIVCertificate(ctx, &pb.DeletePIVCertificateRequest{Backend: "test", Slot: "9a"})
			return err
		}},
		{"GeneratePIVKey", func() error {
			_, err := svc.GeneratePIVKey(ctx, &pb.GeneratePIVKeyRequest{Backend: "test", Slot: "9a"})
			return err
		}},
		{"ImportPIVCertificate", func() error {
			_, err := svc.ImportPIVCertificate(ctx, &pb.StorePIVCertificateRequest{Backend: "test", Slot: "9a", Certificate: []byte("c"), Format: "PEM"})
			return err
		}},
		{"ExportPIVCertificate", func() error {
			_, err := svc.ExportPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "test", Slot: "9a", Format: "PEM"})
			return err
		}},
		{"GeneratePIVCSR", func() error {
			_, err := svc.GeneratePIVCSR(ctx, &pb.GeneratePIVCSRRequest{Backend: "test", Slot: "9a"})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code(), "expected PermissionDenied for %s, got %s: %s", tt.name, st.Code(), st.Message())
		})
	}
}

// TestAuthzDeny_CAMethods tests authorization denial for CA methods.
func TestAuthzDeny_CAMethods(t *testing.T) {
	svc := newDeniedService()
	ctx := deniedCtx()

	// CA methods need a CA configured
	cert := generateTestCert(t)
	svc.SetCA(&mockCAAll{
		mockCACert:      mockCACert{cert: cert},
		mockCARevoke:    mockCARevoke{},
		mockCACRL:       mockCACRL{crlDER: []byte("crl")},
		mockCAIsRevoked: mockCAIsRevoked{},
	})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GetCACertificate", func() error { _, err := svc.GetCACertificate(ctx, &pb.GetCACertificateRequest{}); return err }},
		{"SignCSR", func() error { _, err := svc.SignCSR(ctx, &pb.SignCSRRequest{CsrPem: []byte("csr")}); return err }},
		{"IssueCertificate", func() error {
			_, err := svc.IssueCertificate(ctx, &pb.IssueCertificateRequest{CommonName: "test"})
			return err
		}},
		{"RevokeCertificate", func() error {
			_, err := svc.RevokeCertificate(ctx, &pb.RevokeCertificateRequest{SerialNumber: "abc"})
			return err
		}},
		{"GenerateCRL", func() error { _, err := svc.GenerateCRL(ctx, &pb.GenerateCRLRequest{}); return err }},
		{"IsRevoked", func() error {
			_, err := svc.IsRevoked(ctx, &pb.IsRevokedRequest{SerialNumber: "abc"})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// TestAuthzDeny_CATCGMethods tests authorization denial for CA TCG methods.
func TestAuthzDeny_CATCGMethods(t *testing.T) {
	svc := newDeniedService()
	ctx := deniedCtx()

	svc.SetCA(&mockCAIssueEK{})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"IssueEKCertificate", func() error {
			_, err := svc.IssueEKCertificate(ctx, &pb.IssueEKCertificateRequest{CommonName: "test", EkPublicKey: []byte("k")})
			return err
		}},
		{"IssueAKCertificate", func() error {
			svc.SetCA(&mockCAIssueAK{})
			_, err := svc.IssueAKCertificate(ctx, &pb.IssueAKCertificateRequest{CommonName: "test", PublicKey: []byte("k")})
			return err
		}},
		{"SignTCGCSR", func() error {
			svc.SetCA(&mockCASignTCGCSR{})
			_, err := svc.SignTCGCSR(ctx, &pb.SignTCGCSRRequest{CommonName: "test", TcgCsr: []byte("csr")})
			return err
		}},
		{"EnrollDevice", func() error {
			svc.SetCA(&mockCAEnrollDevice{})
			_, err := svc.EnrollDevice(ctx, &pb.EnrollDeviceRequest{CommonName: "test", PackedCsr: []byte("csr")})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// TestAuthzDeny_CustodianShareTenantMethods tests authorization denial for
// custodian, share, and tenant methods.
func TestAuthzDeny_CustodianShareTenantMethods(t *testing.T) {
	svc := newDeniedService()
	ctx := deniedCtx()

	cs := setupCustodianClient(t)
	oldCS := GetCustodianClient()
	SetCustodianClient(cs)
	defer SetCustodianClient(oldCS)

	sc := setupShareClient(t)
	oldSS := GetShareClient()
	SetShareClient(sc)
	defer SetShareClient(oldSS)

	reg := setupBarrierRegistry(t)
	oldReg := GetBarrierRegistry()
	SetBarrierRegistry(reg)
	defer SetBarrierRegistry(oldReg)

	testTenantRegisteredTenant(t, reg, "authz-test-tenant")

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CreateCustodianGroup", func() error {
			_, err := svc.CreateCustodianGroup(ctx, &pb.CreateCustodianGroupRequest{Name: "n", Threshold: 2})
			return err
		}},
		{"GetCustodianGroup", func() error {
			_, err := svc.GetCustodianGroup(ctx, &pb.GetCustodianGroupRequest{GroupId: "g"})
			return err
		}},
		{"ListCustodianGroups", func() error {
			_, err := svc.ListCustodianGroups(ctx, &pb.ListCustodianGroupsRequest{})
			return err
		}},
		{"DeleteCustodianGroup", func() error {
			_, err := svc.DeleteCustodianGroup(ctx, &pb.DeleteCustodianGroupRequest{GroupId: "g"})
			return err
		}},
		{"AddCustodianMember", func() error {
			_, err := svc.AddCustodianMember(ctx, &pb.AddCustodianMemberRequest{GroupId: "g", UserId: "u"})
			return err
		}},
		{"RemoveCustodianMember", func() error {
			_, err := svc.RemoveCustodianMember(ctx, &pb.RemoveCustodianMemberRequest{GroupId: "g", UserId: "u"})
			return err
		}},
		{"DistributeShares", func() error {
			_, err := svc.DistributeShares(ctx, &pb.DistributeSharesRequest{GroupId: "g"})
			return err
		}},
		{"SubmitShare", func() error {
			_, err := svc.SubmitShare(ctx, &pb.SubmitShareRequest{GroupId: "g", ShareData: "d", ServerUrl: "http://x"})
			return err
		}},
		{"ListShares", func() error { _, err := svc.ListShares(ctx, &pb.ListSharesRequest{}); return err }},
		{"GetShare", func() error {
			_, err := svc.GetShare(ctx, &pb.GetShareRequest{ServerUrl: "http://x", GroupId: "g", ShareIndex: 1})
			return err
		}},
		{"DeleteShare", func() error {
			_, err := svc.DeleteShare(ctx, &pb.DeleteShareRequest{ServerUrl: "http://x", GroupId: "g", ShareIndex: 1})
			return err
		}},
		{"GetShareCollectionStatus", func() error {
			_, err := svc.GetShareCollectionStatus(ctx, &pb.GetShareCollectionStatusRequest{GroupId: "g"})
			return err
		}},
		{"CreateTenant", func() error {
			_, err := svc.CreateTenant(ctx, &pb.CreateTenantRequest{Id: "t", Name: "T"})
			return err
		}},
		{"GetTenant", func() error {
			_, err := svc.GetTenant(ctx, &pb.GetTenantRequest{TenantId: "authz-test-tenant"})
			return err
		}},
		{"ListTenants", func() error { _, err := svc.ListTenants(ctx, &pb.ListTenantsRequest{}); return err }},
		{"DeleteTenant", func() error {
			_, err := svc.DeleteTenant(ctx, &pb.DeleteTenantRequest{TenantId: "authz-test-tenant"})
			return err
		}},
		{"TenantBarrierInit", func() error {
			_, err := svc.TenantBarrierInit(ctx, &pb.TenantBarrierInitRequest{TenantId: "authz-test-tenant"})
			return err
		}},
		{"TenantBarrierUnseal", func() error {
			_, err := svc.TenantBarrierUnseal(ctx, &pb.TenantBarrierUnsealRequest{TenantId: "authz-test-tenant"})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// TestAuthzDeny_BarrierPINMethods tests authorization denial for barrier and PIN methods.
func TestAuthzDeny_BarrierPINMethods(t *testing.T) {
	svc := newDeniedService()
	ctx := deniedCtx()

	// Need barrier and PIN manager configured
	reg := setupBarrierRegistry(t)
	oldReg := GetBarrierRegistry()
	SetBarrierRegistry(reg)
	defer SetBarrierRegistry(oldReg)

	// The authorization gate runs before the service is consulted, so no
	// barrier is composed: a denial must not depend on one being there.
	tests := []struct {
		name string
		fn   func() error
	}{
		{"BarrierInitialize", func() error {
			_, err := svc.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{})
			return err
		}},
		{"BarrierUnseal", func() error {
			_, err := svc.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{})
			return err
		}},
		{"BarrierSeal", func() error { _, err := svc.BarrierSeal(ctx, &emptypb.Empty{}); return err }},
		{"BarrierStatus", func() error { _, err := svc.BarrierStatus(ctx, &emptypb.Empty{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}
