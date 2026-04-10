// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// errServer returns gRPC errors for all methods.
type errServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (s *errServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListBackends(context.Context, *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetBackendInfo(context.Context, *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GenerateKey(context.Context, *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListKeys(context.Context, *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetKey(context.Context, *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteKey(context.Context, *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Sign(context.Context, *pb.SignRequest) (*pb.SignResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Verify(context.Context, *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Encrypt(context.Context, *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Decrypt(context.Context, *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) EncryptAsym(context.Context, *pb.EncryptAsymRequest) (*pb.EncryptAsymResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) RotateKey(context.Context, *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetImportParameters(context.Context, *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) WrapKey(context.Context, *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) UnwrapKey(context.Context, *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) WrapKeyByID(context.Context, *pb.WrapKeyByIDRequest) (*pb.WrapKeyByIDResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) UnwrapKeyByID(context.Context, *pb.UnwrapKeyByIDRequest) (*pb.UnwrapKeyByIDResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ImportKey(context.Context, *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ExportKey(context.Context, *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ExportKeyMaterial(context.Context, *pb.ExportKeyMaterialRequest) (*pb.ExportKeyMaterialResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) CopyKey(context.Context, *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeriveKey(context.Context, *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeriveKeyECDH(context.Context, *pb.DeriveKeyECDHRequest) (*pb.DeriveKeyECDHResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SaveCert(context.Context, *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetCert(context.Context, *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteCert(context.Context, *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListCerts(context.Context, *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) CertExists(context.Context, *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SaveCertChain(context.Context, *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetCertChain(context.Context, *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetTLSCertificate(context.Context, *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Seal(context.Context, *pb.SealRequest) (*pb.SealResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Unseal(context.Context, *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) CanSeal(context.Context, *pb.CanSealRequest) (*pb.CanSealResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) AttestKey(context.Context, *pb.AttestKeyRequest) (*pb.AttestKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierInitialize(context.Context, *pb.BarrierInitializeRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierUnseal(context.Context, *pb.BarrierUnsealRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierSeal(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierStatus(context.Context, *emptypb.Empty) (*pb.BarrierStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierInitializeShamir(context.Context, *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierUnsealShare(context.Context, *pb.BarrierUnsealShareRequest) (*pb.BarrierQuorumProgressResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierUnsealShares(context.Context, *pb.BarrierUnsealSharesRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierShamirListShares(context.Context, *emptypb.Empty) (*pb.BarrierShamirSharesResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierShamirDeleteShare(context.Context, *pb.BarrierShamirDeleteShareRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierShamirDeleteAllShares(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierShamirVerify(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierRekey(context.Context, *pb.BarrierRekeyRequest) (*pb.BarrierShamirInitResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierGenerateRecoveryKeys(context.Context, *pb.BarrierGenerateRecoveryKeysRequest) (*pb.BarrierRecoveryKeysResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierRecoverWithKeys(context.Context, *pb.BarrierRecoverWithKeysRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierDeleteRecoveryKeys(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) BarrierGenerateRootToken(context.Context, *pb.BarrierGenerateRootTokenRequest) (*pb.BarrierRootTokenResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SetSOPIN(context.Context, *pb.SetSOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SetUserPIN(context.Context, *pb.SetUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ChangeSOPIN(context.Context, *pb.ChangeSOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ChangeUserPIN(context.Context, *pb.ChangeUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) VerifySOPIN(context.Context, *pb.VerifySOPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) VerifyUserPIN(context.Context, *pb.VerifyUserPINRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetLockoutStatus(context.Context, *emptypb.Empty) (*pb.LockoutStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ResetLockout(context.Context, *pb.ResetLockoutRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetCABundle(context.Context, *pb.GetCABundleRequest) (*pb.GetCABundleResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetCACertificate(context.Context, *pb.GetCACertificateRequest) (*pb.GetCACertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SignCSR(context.Context, *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) IssueCertificate(context.Context, *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) RevokeCertificate(context.Context, *pb.RevokeCertificateRequest) (*pb.RevokeCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GenerateCRL(context.Context, *pb.GenerateCRLRequest) (*pb.GenerateCRLResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) IsRevoked(context.Context, *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) IssueEKCertificate(context.Context, *pb.IssueEKCertificateRequest) (*pb.IssueEKCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) IssueAKCertificate(context.Context, *pb.IssueAKCertificateRequest) (*pb.IssueAKCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SignTCGCSR(context.Context, *pb.SignTCGCSRRequest) (*pb.SignTCGCSRResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) EnrollDevice(context.Context, *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListPIVSlots(context.Context, *pb.ListPIVSlotsRequest) (*pb.ListPIVSlotsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetPIVCertificate(context.Context, *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) StorePIVCertificate(context.Context, *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeletePIVCertificate(context.Context, *pb.DeletePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ImportPIVCertificate(context.Context, *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ExportPIVCertificate(context.Context, *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GeneratePIVKey(context.Context, *pb.GeneratePIVKeyRequest) (*pb.GeneratePIVKeyResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GeneratePIVCSR(context.Context, *pb.GeneratePIVCSRRequest) (*pb.GeneratePIVCSRResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) CreateCustodianGroup(context.Context, *pb.CreateCustodianGroupRequest) (*pb.CreateCustodianGroupResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetCustodianGroup(context.Context, *pb.GetCustodianGroupRequest) (*pb.GetCustodianGroupResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListCustodianGroups(context.Context, *pb.ListCustodianGroupsRequest) (*pb.ListCustodianGroupsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteCustodianGroup(context.Context, *pb.DeleteCustodianGroupRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) AddCustodianMember(context.Context, *pb.AddCustodianMemberRequest) (*pb.AddCustodianMemberResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) RemoveCustodianMember(context.Context, *pb.RemoveCustodianMemberRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DistributeShares(context.Context, *pb.DistributeSharesRequest) (*pb.DistributeSharesResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) SubmitShare(context.Context, *pb.SubmitShareRequest) (*pb.SubmitShareResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListShares(context.Context, *pb.ListSharesRequest) (*pb.ListSharesResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetShareCollectionStatus(context.Context, *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) CreateTenant(context.Context, *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) GetTenant(context.Context, *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) ListTenants(context.Context, *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteTenant(context.Context, *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) TenantBarrierInit(context.Context, *pb.TenantBarrierInitRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) TenantBarrierUnseal(context.Context, *pb.TenantBarrierUnsealRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordAdd(context.Context, *pb.PasswordAddRequest) (*pb.PasswordAddResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordGet(context.Context, *pb.PasswordGetRequest) (*pb.PasswordGetResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordList(context.Context, *pb.PasswordListRequest) (*pb.PasswordListResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordUpdate(context.Context, *pb.PasswordUpdateRequest) (*pb.PasswordUpdateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordDelete(context.Context, *pb.PasswordDeleteRequest) (*pb.PasswordDeleteResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordStoreUnlock(context.Context, *pb.PasswordStoreUnlockRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordStoreLock(context.Context, *pb.PasswordStoreLockRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordStoreStatus(context.Context, *pb.PasswordStoreStatusRequest) (*pb.PasswordStoreStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PasswordGenerate(context.Context, *pb.PasswordGenerateRequest) (*pb.PasswordGenerateResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}

// newErrTransport creates a Transport backed by an error-returning gRPC server
// and a 500-returning HTTP server.
func newErrTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &errServer{})

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

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "fail"})
	}))

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test-err.sock"

	tr := &Transport{
		config:     cfg,
		conn:       conn,
		client:     pb.NewKeystoreServiceClient(conn),
		httpClient: httpSrv.Client(),
		connected:  true,
	}

	cleanup := func() {
		conn.Close()
		srv.Stop()
		lis.Close()
		httpSrv.Close()
	}

	return tr, cleanup
}

// newHTTPOnlyTransport returns a transport with HTTP client for REST-only methods.
func newHTTPOnlyTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rec).Encode(map[string]interface{}{
				"status": "initialized", "strategy": "manual",
				"challenge_nonce": "abc123", "officer_name": "alice",
				"share": "c2hhcmU=", "claimed": true, "accepted": true,
				"certificate_pem": "Y2VydA==", "serial_number": "1234",
			})
			return rec.Result(), nil
		}),
	}

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test-http.sock"

	tr := &Transport{
		config:     cfg,
		httpClient: client,
		connected:  true,
	}

	return tr, func() {}
}

// --- Connect error tests ---

func TestConnect_BadCAFile(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = "/nonexistent/ca.pem"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

func TestConnect_BadCACertContent(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a cert"), 0644))

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestConnect_BadClientCert(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestConnect_SPKIPinNoCA(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.SPKIPin = "sha256/abc123"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Connect will fail at health check but exercises the SPKI pin no-CA branch
	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection failed")
}

func TestConnect_SPKIPinWithCA(t *testing.T) {
	tmpDir := t.TempDir()
	// Write a valid-looking but useless CA cert (ParseCertificates will fail later)
	caFile := filepath.Join(tmpDir, "ca.pem")
	// Need a real PEM block to pass AppendCertsFromPEM
	// Use a self-signed test CA
	require.NoError(t, os.WriteFile(caFile, testCAPEM(), 0644))

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.SPKIPin = "sha256/abc123"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Connect will fail at health check but exercises the SPKI+CA branch
	err = tr.Connect(context.Background())
	require.Error(t, err)
}

func TestConnect_TLSConfigProvided(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.TLSEnabled = true
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// Connect will fail at health check but exercises the TLSConfig branch
	err = tr.Connect(context.Background())
	require.Error(t, err)
}

// --- Accessor tests ---

func TestClient_ReturnsClient(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	assert.NotNil(t, tr.Client())
}

func TestSocketPath_ReturnsPath(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	assert.NotEmpty(t, tr.SocketPath())
}

// --- gRPC error-path tests ---

func TestHealth_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Health(context.Background())
	require.Error(t, err)
}

func TestListBackends_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListBackends(context.Background())
	require.Error(t, err)
}

func TestGetBackend_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetBackend(context.Background(), "s")
	require.Error(t, err)
}

func TestGenerateKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	require.Error(t, err)
}

func TestListKeys_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListKeys(context.Background(), "s")
	require.Error(t, err)
}

func TestGetKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetKey(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestDeleteKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeleteKey(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSign_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Sign(context.Background(), &transport.SignRequest{})
	require.Error(t, err)
}

func TestVerify_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Verify(context.Background(), &transport.VerifyRequest{})
	require.Error(t, err)
}

func TestEncrypt_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{})
	require.Error(t, err)
}

func TestDecrypt_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{})
	require.Error(t, err)
}

func TestEncryptAsym_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{})
	require.Error(t, err)
}

func TestRotateKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{})
	require.Error(t, err)
}

func TestGetImportParameters_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	require.Error(t, err)
}

func TestWrapKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	require.Error(t, err)
}

func TestUnwrapKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	require.Error(t, err)
}

func TestImportKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	require.Error(t, err)
}

func TestExportKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{})
	require.Error(t, err)
}

func TestExportKeyMaterial_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{})
	require.Error(t, err)
}

func TestCopyKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	require.Error(t, err)
}

func TestDeriveKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{})
	require.Error(t, err)
}

func TestDeriveKeyECDH_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	require.Error(t, err)
}

func TestGetCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSaveCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{})
	require.Error(t, err)
}

func TestDeleteCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestCertificateExists_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	exists, err := tr.CertificateExists(context.Background(), "s", "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestListCertificates_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListCertificates(context.Background(), "s")
	require.Error(t, err)
}

func TestSaveCertificateChain_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{})
	require.Error(t, err)
}

func TestGetCertificateChain_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCertificateChain(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestGetTLSCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetTLSCertificate(context.Background(), "s", "k")
	require.Error(t, err)
}

func TestSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Seal(context.Background(), &transport.SealRequest{})
	require.Error(t, err)
}

func TestUnseal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Unseal(context.Background(), &transport.UnsealRequest{})
	require.Error(t, err)
}

func TestCanSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CanSeal(context.Background(), "s")
	require.Error(t, err)
}

func TestAttestKey_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{})
	require.Error(t, err)
}

func TestBarrierInitialize_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	require.Error(t, err)
}

func TestBarrierUnseal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	require.Error(t, err)
}

func TestBarrierSeal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.BarrierSeal(context.Background())
	require.Error(t, err)
}

func TestBarrierStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.BarrierStatus(context.Background())
	require.Error(t, err)
}

func TestIssueEKCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{})
	require.Error(t, err)
}

func TestIssueAKCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueAKCertificate(context.Background(), &transport.IssueAKCertificateRequest{})
	require.Error(t, err)
}

func TestSignTCGCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SignTCGCSR(context.Background(), &transport.SignTCGCSRRequest{})
	require.Error(t, err)
}

func TestEnrollDevice_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.EnrollDevice(context.Background(), &transport.EnrollDeviceRequest{})
	require.Error(t, err)
}

func TestSetSOPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	require.Error(t, err)
}

func TestSetUserPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	require.Error(t, err)
}

func TestChangeSOPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	require.Error(t, err)
}

func TestChangeUserPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	require.Error(t, err)
}

func TestVerifySOPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	require.Error(t, err)
}

func TestVerifyUserPIN_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	require.Error(t, err)
}

func TestGetLockoutStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetLockoutStatus(context.Background())
	require.Error(t, err)
}

func TestResetLockout_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	require.Error(t, err)
}

func TestPasswordAdd_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.Error(t, err)
}

func TestPasswordGet_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{})
	require.Error(t, err)
}

func TestPasswordList_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.Error(t, err)
}

func TestPasswordUpdate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{})
	require.Error(t, err)
}

func TestPasswordDelete_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{})
	require.Error(t, err)
}

func TestPasswordStoreUnlock_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
}

func TestPasswordStoreLock_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.PasswordStoreLock(context.Background())
	require.Error(t, err)
}

func TestPasswordStoreStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordStoreStatus(context.Background())
	require.Error(t, err)
}

func TestPasswordGenerate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.Error(t, err)
}

func TestGetCABundle_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.Error(t, err)
}

func TestGetCACertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.Error(t, err)
}

func TestSignCSR_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{})
	require.Error(t, err)
}

func TestIssueCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{})
	require.Error(t, err)
}

func TestRevokeCertificate_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{})
	require.Error(t, err)
}

func TestGenerateCRL_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.Error(t, err)
}

func TestIsRevoked_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{})
	require.Error(t, err)
}

func TestCreateCustodianGroup_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{})
	require.Error(t, err)
}

func TestGetCustodianGroup_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
}

func TestListCustodianGroups_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListCustodianGroups(context.Background())
	require.Error(t, err)
}

func TestDeleteCustodianGroup_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
}

func TestAddCustodianMember_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{})
	require.Error(t, err)
}

func TestRemoveCustodianMember_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{})
	require.Error(t, err)
}

func TestDistributeShares_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{})
	require.Error(t, err)
}

func TestSubmitShare_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{})
	require.Error(t, err)
}

func TestListShares_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListShares(context.Background())
	require.Error(t, err)
}

func TestGetShareCollectionStatus_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetShareCollectionStatus(context.Background(), "g1")
	require.Error(t, err)
}

func TestCreateTenant_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{})
	require.Error(t, err)
}

func TestGetTenant_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetTenant(context.Background(), "t1")
	require.Error(t, err)
}

func TestListTenants_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.ListTenants(context.Background())
	require.Error(t, err)
}

func TestDeleteTenant_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteTenant(context.Background(), "t1")
	require.Error(t, err)
}

func TestTenantBarrierInit_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{})
	require.Error(t, err)
}

func TestTenantBarrierUnseal_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{})
	require.Error(t, err)
}

// --- REST-only method tests (HTTP) ---

func TestGetInitStatus_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertBegin_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.ClaimCertBegin(context.Background(), &transport.ClaimCertBeginRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimCertComplete_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.ClaimCertComplete(context.Background(), &transport.ClaimCertCompleteRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimShare_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.ClaimShare(context.Background(), &transport.ClaimShareRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSignCSRInit_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.SignCSRInit(context.Background(), &transport.SignCSRInitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSubmitCredential_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetCredentialStrategy_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// --- doRawRequest tests ---

func TestDoRawRequest_NilHTTPClient(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	tr.httpClient = nil

	_, err = tr.doRawRequest(context.Background(), http.MethodGet, "/test", nil)
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRawRequest_WithJWTAndHeaders(t *testing.T) {
	// Use a round-tripper that captures headers and returns a response
	var capturedReq *http.Request
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			capturedReq = r
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rec).Encode(map[string]string{"ok": "true"})
			return rec.Result(), nil
		}),
	}

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	cfg.JWTToken = "test-token"
	cfg.Headers = map[string]string{"X-Custom": "custom-value"}

	tr := &Transport{
		config:     cfg,
		httpClient: client,
		connected:  true,
	}

	data, err := tr.doRawRequest(context.Background(), http.MethodGet, "/test", nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "ok")
	require.NotNil(t, capturedReq)
	assert.Equal(t, "Bearer test-token", capturedReq.Header.Get("Authorization"))
	assert.Equal(t, "custom-value", capturedReq.Header.Get("X-Custom"))
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// testCAPEM returns a minimal self-signed CA cert for testing.
func testCAPEM() []byte {
	// Generate a self-signed cert for testing purposes
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// --- pbPasswordEntryToTransport tests ---

func TestPbPasswordEntryToTransport_Nil(t *testing.T) {
	result := pbPasswordEntryToTransport(nil)
	assert.Nil(t, result)
}

func TestPbPasswordEntryToTransport_WithTimestamps(t *testing.T) {
	now := timestamppb.Now()
	entry := &pb.PasswordEntry{
		Id:         "pw-1",
		Name:       "test",
		Username:   "user",
		Password:   "secret",
		Url:        "https://example.com",
		Notes:      "notes",
		FolderPath: "/folder",
		BackendId:  "software",
		ReadOnly:   true,
		Encrypted:  true,
		OwnerId:    "owner-1",
		Shared:     true,
		ExpiresAt:  now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	result := pbPasswordEntryToTransport(entry)
	require.NotNil(t, result)
	assert.Equal(t, "pw-1", result.ID)
	assert.Equal(t, "test", result.Name)
	assert.NotEmpty(t, result.ExpiresAt)
	assert.NotEmpty(t, result.CreatedAt)
	assert.NotEmpty(t, result.UpdatedAt)
}
