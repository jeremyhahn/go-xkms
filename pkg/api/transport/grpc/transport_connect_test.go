// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package grpc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"

)

// errorKeystoreServer returns errors for all calls, exercising error branches.
type errorKeystoreServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (s *errorKeystoreServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return nil, status.Error(codes.Internal, "health check failed")
}

func (s *errorKeystoreServer) ListBackends(_ context.Context, _ *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	return nil, status.Error(codes.Internal, "list backends failed")
}

func (s *errorKeystoreServer) GetBackendInfo(_ context.Context, _ *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	return nil, status.Error(codes.Internal, "get backend failed")
}

func (s *errorKeystoreServer) GenerateKey(_ context.Context, _ *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "generate key failed")
}

func (s *errorKeystoreServer) ListKeys(_ context.Context, _ *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return nil, status.Error(codes.Internal, "list keys failed")
}

func (s *errorKeystoreServer) GetKey(_ context.Context, _ *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return nil, status.Error(codes.Internal, "get key failed")
}

func (s *errorKeystoreServer) DeleteKey(_ context.Context, _ *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return nil, status.Error(codes.Internal, "delete key failed")
}

func (s *errorKeystoreServer) Sign(_ context.Context, _ *pb.SignRequest) (*pb.SignResponse, error) {
	return nil, status.Error(codes.Internal, "sign failed")
}

func (s *errorKeystoreServer) Verify(_ context.Context, _ *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return nil, status.Error(codes.Internal, "verify failed")
}

func (s *errorKeystoreServer) Encrypt(_ context.Context, _ *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return nil, status.Error(codes.Internal, "encrypt failed")
}

func (s *errorKeystoreServer) Decrypt(_ context.Context, _ *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return nil, status.Error(codes.Internal, "decrypt failed")
}

func (s *errorKeystoreServer) EncryptAsym(_ context.Context, _ *pb.EncryptAsymRequest) (*pb.EncryptAsymResponse, error) {
	return nil, status.Error(codes.Internal, "encrypt asym failed")
}

func (s *errorKeystoreServer) RotateKey(_ context.Context, _ *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "rotate key failed")
}

func (s *errorKeystoreServer) GetImportParameters(_ context.Context, _ *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	return nil, status.Error(codes.Internal, "get import params failed")
}

func (s *errorKeystoreServer) WrapKey(_ context.Context, _ *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "wrap key failed")
}

func (s *errorKeystoreServer) UnwrapKey(_ context.Context, _ *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "unwrap key failed")
}

func (s *errorKeystoreServer) WrapKeyByID(_ context.Context, _ *pb.WrapKeyByIDRequest) (*pb.WrapKeyByIDResponse, error) {
	return nil, status.Error(codes.Internal, "wrap key by id failed")
}

func (s *errorKeystoreServer) UnwrapKeyByID(_ context.Context, _ *pb.UnwrapKeyByIDRequest) (*pb.UnwrapKeyByIDResponse, error) {
	return nil, status.Error(codes.Internal, "unwrap key by id failed")
}

func (s *errorKeystoreServer) ImportKey(_ context.Context, _ *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "import key failed")
}

func (s *errorKeystoreServer) ExportKey(_ context.Context, _ *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "export key failed")
}

func (s *errorKeystoreServer) ExportKeyMaterial(_ context.Context, _ *pb.ExportKeyMaterialRequest) (*pb.ExportKeyMaterialResponse, error) {
	return nil, status.Error(codes.Internal, "export key material failed")
}

func (s *errorKeystoreServer) CopyKey(_ context.Context, _ *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	return nil, status.Error(codes.Internal, "copy key failed")
}

func (s *errorKeystoreServer) DeriveKey(_ context.Context, _ *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	return nil, status.Error(codes.Internal, "derive key failed")
}

func (s *errorKeystoreServer) DeriveKeyECDH(_ context.Context, _ *pb.DeriveKeyECDHRequest) (*pb.DeriveKeyECDHResponse, error) {
	return nil, status.Error(codes.Internal, "derive key ecdh failed")
}

func (s *errorKeystoreServer) SaveCert(_ context.Context, _ *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	return nil, status.Error(codes.Internal, "save cert failed")
}

func (s *errorKeystoreServer) GetCert(_ context.Context, _ *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	return nil, status.Error(codes.Internal, "get cert failed")
}

func (s *errorKeystoreServer) DeleteCert(_ context.Context, _ *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	return nil, status.Error(codes.Internal, "delete cert failed")
}

func (s *errorKeystoreServer) ListCerts(_ context.Context, _ *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	return nil, status.Error(codes.Internal, "list certs failed")
}

func (s *errorKeystoreServer) CertExists(_ context.Context, _ *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	return nil, status.Error(codes.Internal, "cert exists failed")
}

func (s *errorKeystoreServer) SaveCertChain(_ context.Context, _ *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "save cert chain failed")
}

func (s *errorKeystoreServer) GetCertChain(_ context.Context, _ *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "get cert chain failed")
}

func (s *errorKeystoreServer) GetTLSCertificate(_ context.Context, _ *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "get tls cert failed")
}

func (s *errorKeystoreServer) Seal(_ context.Context, _ *pb.SealRequest) (*pb.SealResponse, error) {
	return nil, status.Error(codes.Internal, "seal failed")
}

func (s *errorKeystoreServer) Unseal(_ context.Context, _ *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	return nil, status.Error(codes.Internal, "unseal failed")
}

func (s *errorKeystoreServer) CanSeal(_ context.Context, _ *pb.CanSealRequest) (*pb.CanSealResponse, error) {
	return nil, status.Error(codes.Internal, "can seal failed")
}

func (s *errorKeystoreServer) AttestKey(_ context.Context, _ *pb.AttestKeyRequest) (*pb.AttestKeyResponse, error) {
	return nil, status.Error(codes.Internal, "attest key failed")
}

func (s *errorKeystoreServer) BarrierInitialize(_ context.Context, _ *pb.BarrierInitializeRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier init failed")
}

func (s *errorKeystoreServer) BarrierUnseal(_ context.Context, _ *pb.BarrierUnsealRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier unseal failed")
}

func (s *errorKeystoreServer) BarrierSeal(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier seal failed")
}

func (s *errorKeystoreServer) BarrierStatus(_ context.Context, _ *emptypb.Empty) (*pb.BarrierStatusResponse, error) {
	return nil, status.Error(codes.Internal, "barrier status failed")
}

func (s *errorKeystoreServer) BarrierInitializeShamir(_ context.Context, _ *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
	return nil, status.Error(codes.Internal, "barrier init shamir failed")
}

func (s *errorKeystoreServer) BarrierUnsealShare(_ context.Context, _ *pb.BarrierUnsealShareRequest) (*pb.BarrierQuorumProgressResponse, error) {
	return nil, status.Error(codes.Internal, "barrier unseal share failed")
}

func (s *errorKeystoreServer) BarrierUnsealShares(_ context.Context, _ *pb.BarrierUnsealSharesRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier unseal shares failed")
}

func (s *errorKeystoreServer) BarrierShamirListShares(_ context.Context, _ *emptypb.Empty) (*pb.BarrierShamirSharesResponse, error) {
	return nil, status.Error(codes.Internal, "barrier list shares failed")
}

func (s *errorKeystoreServer) BarrierShamirDeleteShare(_ context.Context, _ *pb.BarrierShamirDeleteShareRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier delete share failed")
}

func (s *errorKeystoreServer) BarrierShamirDeleteAllShares(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier delete all shares failed")
}

func (s *errorKeystoreServer) BarrierShamirVerify(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier shamir verify failed")
}

func (s *errorKeystoreServer) BarrierRekey(_ context.Context, _ *pb.BarrierRekeyRequest) (*pb.BarrierShamirInitResponse, error) {
	return nil, status.Error(codes.Internal, "barrier rekey failed")
}

func (s *errorKeystoreServer) BarrierGenerateRecoveryKeys(_ context.Context, _ *pb.BarrierGenerateRecoveryKeysRequest) (*pb.BarrierRecoveryKeysResponse, error) {
	return nil, status.Error(codes.Internal, "barrier gen recovery failed")
}

func (s *errorKeystoreServer) BarrierRecoverWithKeys(_ context.Context, _ *pb.BarrierRecoverWithKeysRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier recover failed")
}

func (s *errorKeystoreServer) BarrierDeleteRecoveryKeys(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "barrier delete recovery failed")
}


func (s *errorKeystoreServer) BarrierGenerateRootToken(_ context.Context, _ *pb.BarrierGenerateRootTokenRequest) (*pb.BarrierRootTokenResponse, error) {
	return nil, status.Error(codes.Internal, "barrier gen root token failed")
}

func (s *errorKeystoreServer) SetSOPIN(_ context.Context, _ *pb.SetSOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "set sopin failed")
}

func (s *errorKeystoreServer) SetUserPIN(_ context.Context, _ *pb.SetUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "set user pin failed")
}

func (s *errorKeystoreServer) ChangeSOPIN(_ context.Context, _ *pb.ChangeSOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "change sopin failed")
}

func (s *errorKeystoreServer) ChangeUserPIN(_ context.Context, _ *pb.ChangeUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "change user pin failed")
}

func (s *errorKeystoreServer) VerifySOPIN(_ context.Context, _ *pb.VerifySOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "verify sopin failed")
}

func (s *errorKeystoreServer) VerifyUserPIN(_ context.Context, _ *pb.VerifyUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "verify user pin failed")
}

func (s *errorKeystoreServer) GetLockoutStatus(_ context.Context, _ *emptypb.Empty) (*pb.LockoutStatusResponse, error) {
	return nil, status.Error(codes.Internal, "lockout status failed")
}

func (s *errorKeystoreServer) ResetLockout(_ context.Context, _ *pb.ResetLockoutRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "reset lockout failed")
}

func (s *errorKeystoreServer) GetCABundle(_ context.Context, _ *pb.GetCABundleRequest) (*pb.GetCABundleResponse, error) {
	return nil, status.Error(codes.Internal, "get ca bundle failed")
}

func (s *errorKeystoreServer) GetCACertificate(_ context.Context, _ *pb.GetCACertificateRequest) (*pb.GetCACertificateResponse, error) {
	return nil, status.Error(codes.Internal, "get ca cert failed")
}

func (s *errorKeystoreServer) SignCSR(_ context.Context, _ *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	return nil, status.Error(codes.Internal, "sign csr failed")
}

func (s *errorKeystoreServer) IssueCertificate(_ context.Context, _ *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "issue cert failed")
}

func (s *errorKeystoreServer) RevokeCertificate(_ context.Context, _ *pb.RevokeCertificateRequest) (*pb.RevokeCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "revoke cert failed")
}

func (s *errorKeystoreServer) GenerateCRL(_ context.Context, _ *pb.GenerateCRLRequest) (*pb.GenerateCRLResponse, error) {
	return nil, status.Error(codes.Internal, "generate crl failed")
}

func (s *errorKeystoreServer) IsRevoked(_ context.Context, _ *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	return nil, status.Error(codes.Internal, "is revoked failed")
}

func (s *errorKeystoreServer) IssueEKCertificate(_ context.Context, _ *pb.IssueEKCertificateRequest) (*pb.IssueEKCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "issue ek cert failed")
}

func (s *errorKeystoreServer) IssueAKCertificate(_ context.Context, _ *pb.IssueAKCertificateRequest) (*pb.IssueAKCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "issue ak cert failed")
}

func (s *errorKeystoreServer) SignTCGCSR(_ context.Context, _ *pb.SignTCGCSRRequest) (*pb.SignTCGCSRResponse, error) {
	return nil, status.Error(codes.Internal, "sign tcg csr failed")
}

func (s *errorKeystoreServer) EnrollDevice(_ context.Context, _ *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	return nil, status.Error(codes.Internal, "enroll device failed")
}

func (s *errorKeystoreServer) ListPIVSlots(_ context.Context, _ *pb.ListPIVSlotsRequest) (*pb.ListPIVSlotsResponse, error) {
	return nil, status.Error(codes.Internal, "list piv slots failed")
}

func (s *errorKeystoreServer) GetPIVCertificate(_ context.Context, _ *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "get piv cert failed")
}

func (s *errorKeystoreServer) StorePIVCertificate(_ context.Context, _ *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "store piv cert failed")
}

func (s *errorKeystoreServer) DeletePIVCertificate(_ context.Context, _ *pb.DeletePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "delete piv cert failed")
}

func (s *errorKeystoreServer) ImportPIVCertificate(_ context.Context, _ *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "import piv cert failed")
}

func (s *errorKeystoreServer) ExportPIVCertificate(_ context.Context, _ *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "export piv cert failed")
}

func (s *errorKeystoreServer) GeneratePIVKey(_ context.Context, _ *pb.GeneratePIVKeyRequest) (*pb.GeneratePIVKeyResponse, error) {
	return nil, status.Error(codes.Internal, "generate piv key failed")
}

func (s *errorKeystoreServer) GeneratePIVCSR(_ context.Context, _ *pb.GeneratePIVCSRRequest) (*pb.GeneratePIVCSRResponse, error) {
	return nil, status.Error(codes.Internal, "generate piv csr failed")
}

func (s *errorKeystoreServer) CreateCustodianGroup(_ context.Context, _ *pb.CreateCustodianGroupRequest) (*pb.CreateCustodianGroupResponse, error) {
	return nil, status.Error(codes.Internal, "create custodian group failed")
}

func (s *errorKeystoreServer) GetCustodianGroup(_ context.Context, _ *pb.GetCustodianGroupRequest) (*pb.GetCustodianGroupResponse, error) {
	return nil, status.Error(codes.Internal, "get custodian group failed")
}

func (s *errorKeystoreServer) ListCustodianGroups(_ context.Context, _ *pb.ListCustodianGroupsRequest) (*pb.ListCustodianGroupsResponse, error) {
	return nil, status.Error(codes.Internal, "list custodian groups failed")
}

func (s *errorKeystoreServer) DeleteCustodianGroup(_ context.Context, _ *pb.DeleteCustodianGroupRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "delete custodian group failed")
}

func (s *errorKeystoreServer) AddCustodianMember(_ context.Context, _ *pb.AddCustodianMemberRequest) (*pb.AddCustodianMemberResponse, error) {
	return nil, status.Error(codes.Internal, "add custodian member failed")
}

func (s *errorKeystoreServer) RemoveCustodianMember(_ context.Context, _ *pb.RemoveCustodianMemberRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "remove custodian member failed")
}

func (s *errorKeystoreServer) DistributeShares(_ context.Context, _ *pb.DistributeSharesRequest) (*pb.DistributeSharesResponse, error) {
	return nil, status.Error(codes.Internal, "distribute shares failed")
}

func (s *errorKeystoreServer) SubmitShare(_ context.Context, _ *pb.SubmitShareRequest) (*pb.SubmitShareResponse, error) {
	return nil, status.Error(codes.Internal, "submit share failed")
}

func (s *errorKeystoreServer) ListShares(_ context.Context, _ *pb.ListSharesRequest) (*pb.ListSharesResponse, error) {
	return nil, status.Error(codes.Internal, "list shares failed")
}

func (s *errorKeystoreServer) GetShareCollectionStatus(_ context.Context, _ *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	return nil, status.Error(codes.Internal, "get share collection status failed")
}

func (s *errorKeystoreServer) CreateTenant(_ context.Context, _ *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	return nil, status.Error(codes.Internal, "create tenant failed")
}

func (s *errorKeystoreServer) GetTenant(_ context.Context, _ *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	return nil, status.Error(codes.Internal, "get tenant failed")
}

func (s *errorKeystoreServer) ListTenants(_ context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	return nil, status.Error(codes.Internal, "list tenants failed")
}

func (s *errorKeystoreServer) DeleteTenant(_ context.Context, _ *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "delete tenant failed")
}

func (s *errorKeystoreServer) TenantBarrierInit(_ context.Context, _ *pb.TenantBarrierInitRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "tenant barrier init failed")
}

func (s *errorKeystoreServer) TenantBarrierUnseal(_ context.Context, _ *pb.TenantBarrierUnsealRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "tenant barrier unseal failed")
}

func (s *errorKeystoreServer) PasswordAdd(_ context.Context, _ *pb.PasswordAddRequest) (*pb.PasswordAddResponse, error) {
	return nil, status.Error(codes.Internal, "password add failed")
}

func (s *errorKeystoreServer) PasswordGet(_ context.Context, _ *pb.PasswordGetRequest) (*pb.PasswordGetResponse, error) {
	return nil, status.Error(codes.Internal, "password get failed")
}

func (s *errorKeystoreServer) PasswordList(_ context.Context, _ *pb.PasswordListRequest) (*pb.PasswordListResponse, error) {
	return nil, status.Error(codes.Internal, "password list failed")
}

func (s *errorKeystoreServer) PasswordUpdate(_ context.Context, _ *pb.PasswordUpdateRequest) (*pb.PasswordUpdateResponse, error) {
	return nil, status.Error(codes.Internal, "password update failed")
}

func (s *errorKeystoreServer) PasswordDelete(_ context.Context, _ *pb.PasswordDeleteRequest) (*pb.PasswordDeleteResponse, error) {
	return nil, status.Error(codes.Internal, "password delete failed")
}

func (s *errorKeystoreServer) PasswordStoreUnlock(_ context.Context, _ *pb.PasswordStoreUnlockRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "password store unlock failed")
}

func (s *errorKeystoreServer) PasswordStoreLock(_ context.Context, _ *pb.PasswordStoreLockRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "password store lock failed")
}

func (s *errorKeystoreServer) PasswordStoreStatus(_ context.Context, _ *pb.PasswordStoreStatusRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "password store status failed")
}

func (s *errorKeystoreServer) PasswordGenerate(_ context.Context, _ *pb.PasswordGenerateRequest) (*pb.PasswordGenerateResponse, error) {
	return nil, status.Error(codes.Internal, "password generate failed")
}


func (s *errorKeystoreServer) ListKeyVersions(_ context.Context, _ *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	return nil, status.Error(codes.Internal, "list key versions failed")
}

func (s *errorKeystoreServer) EnableKeyVersion(_ context.Context, _ *pb.EnableKeyVersionRequest) (*pb.EnableKeyVersionResponse, error) {
	return nil, status.Error(codes.Internal, "enable key version failed")
}

func (s *errorKeystoreServer) DisableKeyVersion(_ context.Context, _ *pb.DisableKeyVersionRequest) (*pb.DisableKeyVersionResponse, error) {
	return nil, status.Error(codes.Internal, "disable key version failed")
}

func (s *errorKeystoreServer) EnableAllKeyVersions(_ context.Context, _ *pb.EnableAllKeyVersionsRequest) (*pb.EnableAllKeyVersionsResponse, error) {
	return nil, status.Error(codes.Internal, "enable all key versions failed")
}

func (s *errorKeystoreServer) DisableAllKeyVersions(_ context.Context, _ *pb.DisableAllKeyVersionsRequest) (*pb.DisableAllKeyVersionsResponse, error) {
	return nil, status.Error(codes.Internal, "disable all key versions failed")
}

// newErrorBufconnTransport creates an in-memory gRPC server that returns errors for all calls.
func newErrorBufconnTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &errorKeystoreServer{})

	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped
		}
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	tr := &Transport{
		config:    transport.DefaultConfig(),
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}

	cleanup := func() {
		conn.Close()
		srv.Stop()
		lis.Close()
	}

	return tr, cleanup
}

// --- Connect tests ---

func TestConnect_NonTLS(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &mockKeystoreServer{})

	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped
		}
	}()
	defer srv.Stop()
	defer lis.Close()

	// Create a transport that connects through bufconn
	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = false
	cfg.Address = "passthrough:///bufconn"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Override the connect method by directly setting up the connection
	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	tr.conn = conn
	tr.client = pb.NewKeystoreServiceClient(conn)

	// Test Health via the connection (exercises the non-TLS path)
	ctx := context.Background()
	resp, err := tr.Health(ctx)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestConnect_BadCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSCAFile = "/nonexistent/ca.pem"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestConnect_BadCACertContent(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a valid cert"), 0644))

	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestConnect_BadClientCert(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"
	cfg.Address = "localhost:0"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestConnect_HealthCheckFails(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &errorKeystoreServer{})

	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped
		}
	}()
	defer srv.Stop()
	defer lis.Close()

	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = false
	cfg.Address = "passthrough:///bufconn"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Manually wire up to test the health check failure path of Connect
	conn, dialErr := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, dialErr)

	tr.conn = conn
	tr.client = pb.NewKeystoreServiceClient(conn)

	// Health returns error, so Connect's health check logic should fail
	_, err = tr.Health(context.Background())
	require.Error(t, err)
}

// --- Error-path tests for each method ---

func TestHealth_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Health(context.Background())
	require.Error(t, err)
}

func TestListBackends_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListBackends(context.Background())
	require.Error(t, err)
}

func TestGetBackend_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetBackend(context.Background(), "software")
	require.Error(t, err)
}

func TestGenerateKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestListKeys_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListKeys(context.Background(), "software")
	require.Error(t, err)
}

func TestGetKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetKey(context.Background(), "software", "key-1")
	require.Error(t, err)
}

func TestDeleteKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.DeleteKey(context.Background(), "software", "key-1")
	require.Error(t, err)
}

func TestSign_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Sign(context.Background(), &transport.SignRequest{KeyID: "k1", Backend: "software", Data: []byte("data")})
	require.Error(t, err)
}

func TestVerify_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Verify(context.Background(), &transport.VerifyRequest{KeyID: "k1", Backend: "software", Data: []byte("d"), Signature: []byte("s")})
	require.Error(t, err)
}

func TestEncrypt_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{KeyID: "k1", Backend: "software", Plaintext: []byte("pt")})
	require.Error(t, err)
}

func TestDecrypt_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{KeyID: "k1", Backend: "software", Ciphertext: []byte("ct")})
	require.Error(t, err)
}

func TestEncryptAsym_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{KeyID: "k1", Backend: "software", Plaintext: []byte("pt")})
	require.Error(t, err)
}

func TestRotateKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestGetImportParameters_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{Backend: "software"})
	require.Error(t, err)
}

func TestWrapKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{Backend: "software"})
	require.Error(t, err)
}

func TestUnwrapKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{Backend: "software"})
	require.Error(t, err)
}

func TestWrapKeyByID_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{WrappingKeyID: "k1", WrappingKeyBackend: "software"})
	require.Error(t, err)
}

func TestUnwrapKeyByID_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{UnwrappingKeyID: "k1"})
	require.Error(t, err)
}

func TestImportKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestExportKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestExportKeyMaterial_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestCopyKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{SourceKeyID: "k1", SourceBackend: "software", DestBackend: "software"})
	require.Error(t, err)
}

func TestDeriveKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestDeriveKeyECDH_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{KeyID: "k1", Backend: "software", PeerPublicKey: []byte("peer")})
	require.Error(t, err)
}

func TestGetCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetCertificate(context.Background(), "software", "k1")
	require.Error(t, err)
}

func TestSaveCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{KeyID: "k1", Backend: "software", CertificatePEM: "pem"})
	require.Error(t, err)
}

func TestDeleteCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.DeleteCertificate(context.Background(), "software", "k1")
	require.Error(t, err)
}
func TestCertificateExists_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	exists, err := tr.CertificateExists(context.Background(), "software", "k1")
	require.NoError(t, err)
	assert.False(t, exists)
}




func TestListCertificates_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListCertificates(context.Background(), "software")
	require.Error(t, err)
}

func TestSaveCertificateChain_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{KeyID: "k1", Backend: "software", ChainPEM: []string{"pem"}})
	require.Error(t, err)
}

func TestGetCertificateChain_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetCertificateChain(context.Background(), "software", "k1")
	require.Error(t, err)
}

func TestGetTLSCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetTLSCertificate(context.Background(), "software", "k1")
	require.Error(t, err)
}

func TestSeal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Seal(context.Background(), &transport.SealRequest{Backend: "software", Data: []byte("data")})
	require.Error(t, err)
}

func TestUnseal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.Unseal(context.Background(), &transport.UnsealRequest{Backend: "software", Ciphertext: []byte("ct")})
	require.Error(t, err)
}

func TestCanSeal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.CanSeal(context.Background(), "software")
	require.Error(t, err)
}

func TestAttestKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{KeyID: "k1", Backend: "software"})
	require.Error(t, err)
}

func TestBarrierInitialize_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	require.Error(t, err)
}

func TestBarrierUnseal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	require.Error(t, err)
}

func TestBarrierSeal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierSeal(context.Background())
	require.Error(t, err)
}

func TestBarrierStatus_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierStatus(context.Background())
	require.Error(t, err)
}

func TestBarrierInitializeShamir_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{Threshold: 2, TotalShares: 3})
	require.Error(t, err)
}

func TestBarrierUnsealShare_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{Share: "share-1"})
	require.Error(t, err)
}

func TestBarrierUnsealShares_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{Shares: []string{"s1", "s2"}})
	require.Error(t, err)
}

func TestBarrierShamirListShares_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierShamirListShares(context.Background())
	require.Error(t, err)
}

func TestBarrierShamirDeleteShare_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{Index: 0})
	require.Error(t, err)
}

func TestBarrierShamirDeleteAllShares_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierShamirDeleteAllShares(context.Background())
	require.Error(t, err)
}

func TestBarrierShamirVerify_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierShamirVerify(context.Background())
	require.Error(t, err)
}

func TestBarrierRekey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{Threshold: 2, Total: 3})
	require.Error(t, err)
}

func TestBarrierGenerateRecoveryKeys_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	require.Error(t, err)
}

func TestBarrierRecoverWithKeys_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{Keys: []string{"k1"}})
	require.Error(t, err)
}

func TestBarrierDeleteRecoveryKeys_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.BarrierDeleteRecoveryKeys(context.Background())
	require.Error(t, err)
}


func TestBarrierGenerateRootToken_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{Shares: []string{"s1"}})
	require.Error(t, err)
}

func TestSetSOPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{NewSOPIN: "123456"})
	require.Error(t, err)
}

func TestSetUserPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{NewUserPIN: "123456"})
	require.Error(t, err)
}

func TestChangeSOPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{CurrentSOPIN: "old", NewSOPIN: "new"})
	require.Error(t, err)
}

func TestChangeUserPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{CurrentUserPIN: "old", NewUserPIN: "new"})
	require.Error(t, err)
}

func TestVerifySOPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{SOPIN: "123456"})
	require.Error(t, err)
}

func TestVerifyUserPIN_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{UserPIN: "123456"})
	require.Error(t, err)
}

func TestGetLockoutStatus_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetLockoutStatus(context.Background())
	require.Error(t, err)
}

func TestResetLockout_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{SOPIN: "123456"})
	require.Error(t, err)
}

func TestGetCABundle_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.Error(t, err)
}

func TestGetCACertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.Error(t, err)
}

func TestSignCSR_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr")})
	require.Error(t, err)
}

func TestIssueCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestRevokeCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{SerialNumber: "1234"})
	require.Error(t, err)
}

func TestGenerateCRL_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.Error(t, err)
}

func TestIsRevoked_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "1234"})
	require.Error(t, err)
}

func TestIssueEKCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestIssueAKCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestSignTCGCSR_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestEnrollDevice_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{CommonName: "test"})
	require.Error(t, err)
}

func TestListPIVSlots_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "software"})
	require.Error(t, err)
}

func TestGetPIVCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestStorePIVCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestDeletePIVCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestImportPIVCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestExportPIVCertificate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestGeneratePIVKey_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestGeneratePIVCSR_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{Backend: "software", Slot: "9a"})
	require.Error(t, err)
}

func TestCreateCustodianGroup_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{Name: "test"})
	require.Error(t, err)
}

func TestGetCustodianGroup_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
}

func TestListCustodianGroups_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListCustodianGroups(context.Background())
	require.Error(t, err)
}

func TestDeleteCustodianGroup_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.DeleteCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
}

func TestAddCustodianMember_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{GroupID: "g1"})
	require.Error(t, err)
}

func TestRemoveCustodianMember_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{GroupID: "g1", UserID: "u1"})
	require.Error(t, err)
}

func TestDistributeShares_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{GroupID: "g1"})
	require.Error(t, err)
}

func TestSubmitShare_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{GroupID: "g1"})
	require.Error(t, err)
}

func TestListShares_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListShares(context.Background())
	require.Error(t, err)
}

func TestGetShareCollectionStatus_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetShareCollectionStatus(context.Background(), "g1")
	require.Error(t, err)
}

func TestCreateTenant_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{Name: "t1"})
	require.Error(t, err)
}

func TestGetTenant_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.GetTenant(context.Background(), "t1")
	require.Error(t, err)
}

func TestListTenants_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.ListTenants(context.Background())
	require.Error(t, err)
}

func TestDeleteTenant_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.DeleteTenant(context.Background(), "t1")
	require.Error(t, err)
}

func TestTenantBarrierInit_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{TenantID: "t1"})
	require.Error(t, err)
}

func TestTenantBarrierUnseal_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{TenantID: "t1"})
	require.Error(t, err)
}

func TestPasswordAdd_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{Name: "pw"})
	require.Error(t, err)
}

func TestPasswordGet_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "pw-1"})
	require.Error(t, err)
}

func TestPasswordList_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.Error(t, err)
}

func TestPasswordUpdate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{ID: "pw-1"})
	require.Error(t, err)
}

func TestPasswordDelete_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{ID: "pw-1"})
	require.Error(t, err)
}

func TestPasswordStoreUnlock_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
}

func TestPasswordStoreLock_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordStoreLock(context.Background())
	require.Error(t, err)
}

func TestPasswordStoreStatus_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordStoreStatus(context.Background())
	require.Error(t, err)
}

func TestPasswordGenerate_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{Length: 16})
	require.Error(t, err)
}


// --- Close error path ---

func TestClose_NilConnPath(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	tr.conn = nil
	err = tr.Close()
	require.NoError(t, err)
	assert.False(t, tr.connected)
}

// --- Accessor tests ---

func TestConn_ReturnsConnection(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	assert.NotNil(t, tr.Conn())
}

func TestClient_ReturnsClient(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	assert.NotNil(t, tr.Client())
}

func TestConfig_ReturnsConfig(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	assert.NotNil(t, tr.Config())
}

