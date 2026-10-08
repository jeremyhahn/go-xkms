// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

const bufSize = 1024 * 1024

// mockKeystoreServer implements the KeystoreServiceServer interface for testing.
type mockKeystoreServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (s *mockKeystoreServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: "healthy", Version: "1.0.0"}, nil
}

func (s *mockKeystoreServer) ListBackends(_ context.Context, _ *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	return &pb.ListBackendsResponse{
		Backends: []*pb.BackendInfo{
			{
				Name:                        "software",
				Type:                        "software",
				HardwareBacked:              false,
				SupportsSigning:             true,
				SupportsDecryption:          true,
				SupportsRotation:            true,
				SupportsSymmetricEncryption: true,
			},
		},
	}, nil
}

func (s *mockKeystoreServer) GetBackendInfo(_ context.Context, req *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	return &pb.GetBackendInfoResponse{
		Backend: &pb.BackendInfo{
			Name:            req.Name,
			Type:            "software",
			HardwareBacked:  false,
			SupportsSigning: true,
		},
	}, nil
}

func (s *mockKeystoreServer) GenerateKey(_ context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return &pb.GenerateKeyResponse{
		KeyId:        req.KeyId,
		KeyType:      req.KeyType,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}, nil
}

func (s *mockKeystoreServer) ListKeys(_ context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return &pb.ListKeysResponse{
		Keys: []*pb.KeyInfo{
			{KeyId: "key-1", KeyType: "ECDSA", Algorithm: "P-256", Backend: req.Backend},
		},
	}, nil
}

func (s *mockKeystoreServer) GetKey(_ context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return &pb.GetKeyResponse{
		Key:          &pb.KeyInfo{KeyId: req.KeyId, KeyType: "ECDSA", Algorithm: "P-256", Backend: req.Backend},
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}, nil
}

func (s *mockKeystoreServer) DeleteKey(_ context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return &pb.DeleteKeyResponse{Success: true, Message: "key deleted: " + req.KeyId}, nil
}

func (s *mockKeystoreServer) Sign(_ context.Context, _ *pb.SignRequest) (*pb.SignResponse, error) {
	return &pb.SignResponse{Signature: []byte("mock-signature")}, nil
}

func (s *mockKeystoreServer) Verify(_ context.Context, _ *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return &pb.VerifyResponse{Valid: true, Message: "signature valid"}, nil
}

func (s *mockKeystoreServer) Encrypt(_ context.Context, _ *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return &pb.EncryptResponse{
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("mock-nonce"),
		Tag:        []byte("mock-tag"),
	}, nil
}

func (s *mockKeystoreServer) Decrypt(_ context.Context, _ *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return &pb.DecryptResponse{Plaintext: []byte("decrypted-data")}, nil
}

func (s *mockKeystoreServer) EncryptAsym(_ context.Context, _ *pb.EncryptAsymRequest) (*pb.EncryptAsymResponse, error) {
	return &pb.EncryptAsymResponse{Ciphertext: []byte("asym-encrypted")}, nil
}

func (s *mockKeystoreServer) RotateKey(_ context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return &pb.RotateKeyResponse{
		KeyId:        req.KeyId,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----",
	}, nil
}

func (s *mockKeystoreServer) ListKeyVersions(_ context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	return &pb.ListKeyVersionsResponse{
		Versions: []*pb.KeyVersionInfo{{Version: 1, Status: "enabled"}},
	}, nil
}

func (s *mockKeystoreServer) EnableKeyVersion(_ context.Context, req *pb.EnableKeyVersionRequest) (*pb.EnableKeyVersionResponse, error) {
	return &pb.EnableKeyVersionResponse{KeyId: req.KeyId, Version: req.Version, Status: "enabled"}, nil
}

func (s *mockKeystoreServer) DisableKeyVersion(_ context.Context, req *pb.DisableKeyVersionRequest) (*pb.DisableKeyVersionResponse, error) {
	return &pb.DisableKeyVersionResponse{KeyId: req.KeyId, Version: req.Version, Status: "disabled"}, nil
}

func (s *mockKeystoreServer) EnableAllKeyVersions(_ context.Context, req *pb.EnableAllKeyVersionsRequest) (*pb.EnableAllKeyVersionsResponse, error) {
	return &pb.EnableAllKeyVersionsResponse{KeyId: req.KeyId, Count: 2}, nil
}

func (s *mockKeystoreServer) DisableAllKeyVersions(_ context.Context, req *pb.DisableAllKeyVersionsRequest) (*pb.DisableAllKeyVersionsResponse, error) {
	return &pb.DisableAllKeyVersionsResponse{KeyId: req.KeyId, Count: 2}, nil
}

func (s *mockKeystoreServer) GetImportParameters(_ context.Context, _ *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	return &pb.GetImportParametersResponse{
		WrappingPublicKey: []byte("mock-wrapping-key"),
		ImportToken:       []byte("mock-import-token"),
		Algorithm:         "RSA-OAEP",
		ExpiresAt:         timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *mockKeystoreServer) WrapKey(_ context.Context, _ *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	return &pb.WrapKeyResponse{WrappedKey: []byte("wrapped-key-material"), Algorithm: "AES-256-WRAP"}, nil
}

func (s *mockKeystoreServer) UnwrapKey(_ context.Context, _ *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	return &pb.UnwrapKeyResponse{KeyMaterial: []byte("unwrapped-key-material")}, nil
}

func (s *mockKeystoreServer) WrapKeyByID(_ context.Context, _ *pb.WrapKeyByIDRequest) (*pb.WrapKeyByIDResponse, error) {
	return &pb.WrapKeyByIDResponse{WrappedKey: []byte("wrapped-by-id"), Algorithm: "AES-256-WRAP"}, nil
}

func (s *mockKeystoreServer) UnwrapKeyByID(_ context.Context, _ *pb.UnwrapKeyByIDRequest) (*pb.UnwrapKeyByIDResponse, error) {
	return &pb.UnwrapKeyByIDResponse{KeyId: "imported-key", Success: true, Message: "key unwrapped"}, nil
}

func (s *mockKeystoreServer) ImportKey(_ context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return &pb.ImportKeyResponse{Success: true, KeyId: req.KeyId, Message: "key imported"}, nil
}

func (s *mockKeystoreServer) ExportKey(_ context.Context, _ *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return &pb.ExportKeyResponse{WrappedKey: []byte("exported-key"), Algorithm: "AES-256-WRAP"}, nil
}

func (s *mockKeystoreServer) ExportKeyMaterial(_ context.Context, _ *pb.ExportKeyMaterialRequest) (*pb.ExportKeyMaterialResponse, error) {
	return &pb.ExportKeyMaterialResponse{KeyMaterial: []byte("raw-key-bytes"), KeyType: "aes256-gcm"}, nil
}

func (s *mockKeystoreServer) CopyKey(_ context.Context, _ *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	return &pb.CopyKeyResponse{Success: true, DestKeyId: "dest-key", Message: "key copied"}, nil
}

func (s *mockKeystoreServer) DeriveKey(_ context.Context, _ *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	return &pb.DeriveKeyResponse{DerivedKey: []byte("derived-key"), KeyId: "derived-1", Algorithm: "HKDF", KeyLength: 32}, nil
}

func (s *mockKeystoreServer) DeriveKeyECDH(_ context.Context, _ *pb.DeriveKeyECDHRequest) (*pb.DeriveKeyECDHResponse, error) {
	return &pb.DeriveKeyECDHResponse{DerivedKey: []byte("ecdh-derived")}, nil
}

func (s *mockKeystoreServer) SaveCert(_ context.Context, _ *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	return &pb.SaveCertResponse{Success: true}, nil
}

func (s *mockKeystoreServer) GetCert(_ context.Context, req *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	return &pb.GetCertResponse{CertPem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"}, nil
}

func (s *mockKeystoreServer) DeleteCert(_ context.Context, _ *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	return &pb.DeleteCertResponse{Success: true}, nil
}

func (s *mockKeystoreServer) ListCerts(_ context.Context, _ *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	return &pb.ListCertsResponse{KeyIds: []string{"key-1"}, Total: 1}, nil
}

func (s *mockKeystoreServer) CertExists(_ context.Context, _ *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	return &pb.CertExistsResponse{Exists: true}, nil
}

func (s *mockKeystoreServer) SaveCertChain(_ context.Context, _ *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	return &pb.SaveCertChainResponse{Success: true}, nil
}

func (s *mockKeystoreServer) GetCertChain(_ context.Context, _ *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	return &pb.GetCertChainResponse{CertChainPem: []string{"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"}}, nil
}

func (s *mockKeystoreServer) GetTLSCertificate(_ context.Context, _ *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	return &pb.GetTLSCertificateResponse{
		CertPem:      "-----BEGIN CERTIFICATE-----\ntls\n-----END CERTIFICATE-----",
		CertChainPem: []string{"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"},
	}, nil
}

func (s *mockKeystoreServer) Seal(_ context.Context, _ *pb.SealRequest) (*pb.SealResponse, error) {
	return &pb.SealResponse{Ciphertext: []byte("sealed-data")}, nil
}

func (s *mockKeystoreServer) Unseal(_ context.Context, _ *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	return &pb.UnsealResponse{Plaintext: []byte("unsealed-data")}, nil
}

func (s *mockKeystoreServer) CanSeal(_ context.Context, _ *pb.CanSealRequest) (*pb.CanSealResponse, error) {
	return &pb.CanSealResponse{CanSeal: true}, nil
}

func (s *mockKeystoreServer) AttestKey(_ context.Context, _ *pb.AttestKeyRequest) (*pb.AttestKeyResponse, error) {
	return &pb.AttestKeyResponse{AttestationData: []byte("attestation-data"), Format: "tpm2"}, nil
}

func (s *mockKeystoreServer) BarrierSeal(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierDeleteRecoveryKeys(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) SetSOPIN(_ context.Context, _ *pb.SetSOPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) SetUserPIN(_ context.Context, _ *pb.SetUserPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) ChangeSOPIN(_ context.Context, _ *pb.ChangeSOPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) ChangeUserPIN(_ context.Context, _ *pb.ChangeUserPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) VerifySOPIN(_ context.Context, _ *pb.VerifySOPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) VerifyUserPIN(_ context.Context, _ *pb.VerifyUserPINRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) GetLockoutStatus(_ context.Context, _ *emptypb.Empty) (*pb.LockoutStatusResponse, error) {
	return &pb.LockoutStatusResponse{IsLocked: false}, nil
}

func (s *mockKeystoreServer) ResetLockout(_ context.Context, _ *pb.ResetLockoutRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) GetCABundle(_ context.Context, _ *pb.GetCABundleRequest) (*pb.GetCABundleResponse, error) {
	return &pb.GetCABundleResponse{BundlePem: []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----")}, nil
}

func (s *mockKeystoreServer) GetCACertificate(_ context.Context, _ *pb.GetCACertificateRequest) (*pb.GetCACertificateResponse, error) {
	return &pb.GetCACertificateResponse{
		CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"),
		Subject:        "CN=Test CA",
		Issuer:         "CN=Test CA",
	}, nil
}

func (s *mockKeystoreServer) SignCSR(_ context.Context, _ *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	return &pb.SignCSRResponse{CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nsigned\n-----END CERTIFICATE-----")}, nil
}

func (s *mockKeystoreServer) IssueCertificate(_ context.Context, _ *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	return &pb.IssueCertificateResponse{
		CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nissued\n-----END CERTIFICATE-----"),
		SerialNumber:   "ABCD1234",
	}, nil
}

func (s *mockKeystoreServer) RevokeCertificate(_ context.Context, _ *pb.RevokeCertificateRequest) (*pb.RevokeCertificateResponse, error) {
	return &pb.RevokeCertificateResponse{Success: true, Message: "revoked"}, nil
}

func (s *mockKeystoreServer) GenerateCRL(_ context.Context, _ *pb.GenerateCRLRequest) (*pb.GenerateCRLResponse, error) {
	return &pb.GenerateCRLResponse{CrlPem: []byte("-----BEGIN X509 CRL-----\ncrl\n-----END X509 CRL-----")}, nil
}

func (s *mockKeystoreServer) IsRevoked(_ context.Context, _ *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	return &pb.IsRevokedResponse{Revoked: false}, nil
}

func (s *mockKeystoreServer) IssueEKCertificate(_ context.Context, _ *pb.IssueEKCertificateRequest) (*pb.IssueEKCertificateResponse, error) {
	return &pb.IssueEKCertificateResponse{CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nek\n-----END CERTIFICATE-----"), SerialNumber: "EK1234"}, nil
}

func (s *mockKeystoreServer) IssueAKCertificate(_ context.Context, _ *pb.IssueAKCertificateRequest) (*pb.IssueAKCertificateResponse, error) {
	return &pb.IssueAKCertificateResponse{CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nak\n-----END CERTIFICATE-----"), SerialNumber: "AK1234"}, nil
}

func (s *mockKeystoreServer) SignTCGCSR(_ context.Context, _ *pb.SignTCGCSRRequest) (*pb.SignTCGCSRResponse, error) {
	return &pb.SignTCGCSRResponse{IakCertDer: []byte("iak-cert-der")}, nil
}

func (s *mockKeystoreServer) EnrollDevice(_ context.Context, _ *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	return &pb.EnrollDeviceResponse{
		IakCertDer:    []byte("iak-cert-der"),
		IdevidCertDer: []byte("idevid-cert-der"),
	}, nil
}

func (s *mockKeystoreServer) ListPIVSlots(_ context.Context, _ *pb.ListPIVSlotsRequest) (*pb.ListPIVSlotsResponse, error) {
	return &pb.ListPIVSlotsResponse{
		Slots: []*pb.PIVSlotStatus{{Slot: "9a", Name: "Authentication", HasCert: true}},
	}, nil
}

func (s *mockKeystoreServer) GetPIVCertificate(_ context.Context, _ *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return &pb.GetPIVCertificateResponse{Certificate: []byte("-----BEGIN CERTIFICATE-----\npiv\n-----END CERTIFICATE-----"), Slot: "9a"}, nil
}

func (s *mockKeystoreServer) StorePIVCertificate(_ context.Context, _ *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) DeletePIVCertificate(_ context.Context, _ *pb.DeletePIVCertificateRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) ImportPIVCertificate(_ context.Context, _ *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) ExportPIVCertificate(_ context.Context, _ *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	return &pb.GetPIVCertificateResponse{Certificate: []byte("-----BEGIN CERTIFICATE-----\nexport\n-----END CERTIFICATE-----"), Slot: "9a"}, nil
}

func (s *mockKeystoreServer) GeneratePIVKey(_ context.Context, _ *pb.GeneratePIVKeyRequest) (*pb.GeneratePIVKeyResponse, error) {
	return &pb.GeneratePIVKeyResponse{
		PublicKey: []byte("-----BEGIN PUBLIC KEY-----\npiv\n-----END PUBLIC KEY-----"),
		Slot:      "9a",
	}, nil
}

func (s *mockKeystoreServer) CreateTenant(_ context.Context, _ *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	return &pb.CreateTenantResponse{
		Tenant: &pb.TenantInfo{
			Id: "tenant-1", Name: "test-tenant",
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		},
	}, nil
}

func (s *mockKeystoreServer) GetTenant(_ context.Context, _ *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	return &pb.GetTenantResponse{
		Tenant: &pb.TenantInfo{
			Id: "tenant-1", Name: "test-tenant",
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		},
	}, nil
}

func (s *mockKeystoreServer) ListTenants(_ context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	return &pb.ListTenantsResponse{
		Tenants: []*pb.TenantInfo{
			{
				Id: "tenant-1", Name: "test-tenant",
				CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
			},
		},
	}, nil
}

func (s *mockKeystoreServer) DeleteTenant(_ context.Context, _ *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) PasswordAdd(_ context.Context, _ *pb.PasswordAddRequest) (*pb.PasswordAddResponse, error) {
	return &pb.PasswordAddResponse{Id: "pw-1", Name: "test-password", CreatedAt: time.Now().Format(time.RFC3339)}, nil
}

func (s *mockKeystoreServer) PasswordGet(_ context.Context, _ *pb.PasswordGetRequest) (*pb.PasswordGetResponse, error) {
	return &pb.PasswordGetResponse{
		Entry: &pb.PasswordEntry{Id: "pw-1", Name: "test-password", Username: "user", Password: "secret"},
	}, nil
}

func (s *mockKeystoreServer) PasswordList(_ context.Context, _ *pb.PasswordListRequest) (*pb.PasswordListResponse, error) {
	return &pb.PasswordListResponse{
		Passwords: []*pb.PasswordEntry{{Id: "pw-1", Name: "test-password", Username: "user"}},
		Total:     1,
	}, nil
}

func (s *mockKeystoreServer) PasswordUpdate(_ context.Context, _ *pb.PasswordUpdateRequest) (*pb.PasswordUpdateResponse, error) {
	return &pb.PasswordUpdateResponse{}, nil
}

func (s *mockKeystoreServer) PasswordDelete(_ context.Context, _ *pb.PasswordDeleteRequest) (*pb.PasswordDeleteResponse, error) {
	return &pb.PasswordDeleteResponse{}, nil
}

func (s *mockKeystoreServer) PasswordStoreUnlock(_ context.Context, req *pb.PasswordStoreUnlockRequest) (*pb.PasswordStoreStatusResponse, error) {
	if req.GetCredential().GetPassphrase() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential is required")
	}
	return &pb.PasswordStoreStatusResponse{IsLocked: false}, nil
}

func (s *mockKeystoreServer) PasswordStoreLock(_ context.Context, _ *pb.PasswordStoreLockRequest) (*pb.PasswordStoreStatusResponse, error) {
	return &pb.PasswordStoreStatusResponse{IsLocked: true}, nil
}

func (s *mockKeystoreServer) PasswordStoreStatus(_ context.Context, _ *pb.PasswordStoreStatusRequest) (*pb.PasswordStoreStatusResponse, error) {
	return &pb.PasswordStoreStatusResponse{
		AccessMode: "private", IsLocked: false, BarrierSealed: false, PasswordCount: 5,
	}, nil
}

func (s *mockKeystoreServer) PasswordGenerate(_ context.Context, req *pb.PasswordGenerateRequest) (*pb.PasswordGenerateResponse, error) {
	if req.GetCharset() != "" {
		// Echo the charset so a test can prove it crossed the wire.
		return &pb.PasswordGenerateResponse{Password: req.GetCharset()}, nil
	}
	return &pb.PasswordGenerateResponse{Password: "Rand0m!P@ssw0rd"}, nil
}

func (s *mockKeystoreServer) SealStorePut(_ context.Context, req *pb.SealStorePutRequest) (*pb.SealStorePutResponse, error) {
	return &pb.SealStorePutResponse{Name: req.Name}, nil
}

func (s *mockKeystoreServer) SealStoreGet(_ context.Context, req *pb.SealStoreGetRequest) (*pb.SealStoreGetResponse, error) {
	return &pb.SealStoreGetResponse{Name: req.Name, Secret: []byte("s3cret")}, nil
}

func (s *mockKeystoreServer) SealStoreDelete(_ context.Context, _ *pb.SealStoreDeleteRequest) (*pb.SealStoreDeleteResponse, error) {
	return &pb.SealStoreDeleteResponse{}, nil
}

func (s *mockKeystoreServer) SealStoreList(_ context.Context, _ *pb.SealStoreListRequest) (*pb.SealStoreListResponse, error) {
	return &pb.SealStoreListResponse{Names: []string{"db-password"}}, nil
}

func (s *mockKeystoreServer) SealStoreReseal(_ context.Context, req *pb.SealStoreResealRequest) (*pb.SealStoreResealResponse, error) {
	return &pb.SealStoreResealResponse{Name: req.Name}, nil
}

func (s *mockKeystoreServer) SealStoreStatus(_ context.Context, _ *pb.SealStoreStatusRequest) (*pb.SealStoreStatusResponse, error) {
	return &pb.SealStoreStatusResponse{Available: true, SealerId: "tpm2", SecretCount: 1, SecretNames: []string{"db-password"}}, nil
}

func (s *mockKeystoreServer) PasswordStoreSetAccessMode(_ context.Context, req *pb.PasswordStoreSetAccessModeRequest) (*pb.PasswordStoreSetAccessModeResponse, error) {
	return &pb.PasswordStoreSetAccessModeResponse{Mode: req.Mode, Message: "ok"}, nil
}

// TPMPolicyGet echoes the requested policy, so a client test can see the
// request's tenant and name arrive.
func (s *mockKeystoreServer) TPMPolicyGet(_ context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	return &pb.TPMPolicy{Name: req.GetName(), TenantId: req.GetTenantId(), Branches: []*pb.TPMPolicyBranch{{Conditions: []*pb.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", Pcrs: []uint32{7}}}}}, Approved: true}, nil
}

// RetireKeyVersion echoes the retired version.
func (s *mockKeystoreServer) RetireKeyVersion(_ context.Context, req *pb.RetireKeyVersionRequest) (*pb.RetireKeyVersionResponse, error) {
	return &pb.RetireKeyVersionResponse{KeyId: req.GetKeyId(), Version: req.GetVersion(), Status: "retired", Changed: true}, nil
}

// RotateScopeKeys echoes the requested tenant with one rotated key.
func (s *mockKeystoreServer) RotateScopeKeys(_ context.Context, req *pb.RotateScopeKeysRequest) (*pb.RotateScopeKeysResponse, error) {
	return &pb.RotateScopeKeysResponse{
		TenantId: req.GetTenantId(), Rotated: 1,
		Results: []*pb.KeyRotationResult{{Backend: "software", KeyId: "signer", KeyVersion: 3}},
	}, nil
}

// newBufconnTransport creates an in-memory gRPC server + connected Unix Transport for testing.
func newBufconnTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &mockKeystoreServer{})

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"

	// Create a mock HTTP server for REST endpoints
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return minimal valid JSON for any endpoint
		resp := map[string]interface{}{
			"status": "ok", "success": true,
			"iak_cert_der": "aWFrLWNlcnQ=", "idevid_cert_der": "aWRldmlkLWNlcnQ=",
			"credential_blob": "Y3JlZA==", "encrypted_secret": "ZW5j", "plain_secret": "cGxhaW4=",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))

	tr := &Transport{
		config:     cfg,
		conn:       conn,
		client:     pb.NewKeystoreServiceClient(conn),
		httpClient: httpSrv.Client(),
		connected:  true,
	}

	cleanup := func() {
		httpSrv.Close()
		conn.Close()
		srv.Stop()
		lis.Close()
	}

	return tr, cleanup
}

// --- Connected happy-path tests ---

func TestHealth_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "1.0.0", resp.Version)
}

func TestListBackends_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListBackends(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Backends, 1)
	assert.Equal(t, "software", resp.Backends[0].ID)
	assert.True(t, resp.Backends[0].Capabilities.Signing)
}

func TestGetBackend_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.Equal(t, "software", resp.ID)
}

func TestGenerateKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: "test-key", Backend: "software", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: "P-256",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestListKeys_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListKeys(context.Background(), "software")
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "key-1", resp.Keys[0].KeyID)
}

func TestGetKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetKey(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", resp.KeyID)
}

func TestDeleteKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.DeleteKey(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestSign_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		KeyID: "key-1", Backend: "software", Data: []byte("dGVzdA=="),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestVerify_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Verify(context.Background(), &transport.VerifyRequest{
		KeyID: "key-1", Backend: "software", Data: []byte("dGVzdA=="), Signature: []byte("c2ln"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestEncrypt_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Encrypt(context.Background(), &transport.EncryptRequest{
		KeyID: "key-1", Backend: "software", Plaintext: []byte("plaintext"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestDecrypt_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Decrypt(context.Background(), &transport.DecryptRequest{
		KeyID: "key-1", Backend: "software", Ciphertext: []byte("encrypted"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Plaintext)
}

func TestEncryptAsym_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		KeyID: "key-1", Backend: "software", Plaintext: []byte("plaintext"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestRotateKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.RotateKey(context.Background(), &transport.RotateKeyRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGetImportParameters_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{Backend: "software", KeyID: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, "RSA-OAEP", resp.Algorithm)
	assert.NotEmpty(t, resp.ExpiresAt)
}

func TestWrapKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{KeyMaterial: []byte("key"), Algorithm: "AES-256-WRAP"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestUnwrapKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{WrappedKeyMaterial: []byte("wrapped"), Algorithm: "AES-256-WRAP"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
}

func TestWrapKeyByID_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{WrappingKeyBackend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
}

func TestUnwrapKeyByID_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{UnwrappingKeyBackend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestImportKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ImportKey(context.Background(), &transport.ImportKeyRequest{KeyID: "import-key", Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestExportKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{KeyID: "key-1", Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestExportKeyMaterial_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{KeyID: "sym-key", Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.KeyMaterial)
}

func TestCopyKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "software", SourceKeyID: "key-1", DestBackend: "software", DestKeyID: "key-2",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestDeriveKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "software", KeyID: "key-1", Algorithm: "HKDF", KeyLength: 32,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.DerivedKey)
	assert.Equal(t, "HKDF", resp.Algorithm)
}

func TestDeriveKeyECDH_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{Backend: "software", KeyID: "key-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.DerivedKey)
}

func TestGetCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.Contains(t, resp.CertificatePEM, "CERTIFICATE")
}

func TestSaveCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		KeyID: "key-1", CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	require.NoError(t, err)
}

func TestDeleteCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.DeleteCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
}

func TestCertificateExists_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	exists, err := tr.CertificateExists(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestListCertificates_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	require.Len(t, resp.Certificates, 1)
}

func TestSaveCertificateChain_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		KeyID: "key-1", Backend: "software",
		ChainPEM: []string{"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	})
	require.NoError(t, err)
}

func TestGetCertificateChain_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetCertificateChain(context.Background(), "software", "key-1")
	require.NoError(t, err)
	require.Len(t, resp.ChainPEM, 1)
}

func TestGetTLSCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetTLSCertificate(context.Background(), "software", "key-1")
	require.NoError(t, err)
	assert.Contains(t, resp.CertificatePEM, "CERTIFICATE")
	require.Len(t, resp.ChainPEM, 1)
	assert.Contains(t, resp.ChainPEM[0], "CERTIFICATE")
}

func TestSeal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Seal(context.Background(), &transport.SealRequest{Backend: "software", Data: []byte("secret")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestUnseal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.Unseal(context.Background(), &transport.UnsealRequest{Backend: "software", Ciphertext: []byte("sealed")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Plaintext)
}

func TestCanSeal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.CanSeal(context.Background(), "software")
	require.NoError(t, err)
	assert.True(t, resp.CanSeal)
}

func TestAttestKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.AttestKey(context.Background(), &transport.AttestKeyRequest{Backend: "software", KeyID: "key-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AttestationData)
}

func TestSetSOPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.SetSOPIN(context.Background(), &transport.SetSOPINRequest{NewSOPIN: "123456"}))
}

func TestSetUserPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.SetUserPIN(context.Background(), &transport.SetUserPINRequest{NewUserPIN: "654321"}))
}

func TestChangeSOPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{CurrentSOPIN: "123456", NewSOPIN: "654321"}))
}

func TestChangeUserPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{CurrentUserPIN: "123456", NewUserPIN: "654321"}))
}

func TestVerifySOPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{SOPIN: "123456"}))
}

func TestVerifyUserPIN_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{UserPIN: "654321"}))
}

func TestGetLockoutStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, resp.IsLocked)
}

func TestResetLockout_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.ResetLockout(context.Background(), &transport.ResetLockoutRequest{SOPIN: "123456"}))
}

func TestGetCABundle_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetCABundle(context.Background(), &transport.GetCABundleRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.BundlePEM)
}

func TestGetCACertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestSignCSR_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr")})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestIssueCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{CommonName: "test"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestRevokeCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{SerialNumber: "ABCD"})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestGenerateCRL_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CRLPEM)
}

func TestIsRevoked_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.IsRevoked(context.Background(), &transport.IsRevokedRequest{SerialNumber: "ABCD"})
	require.NoError(t, err)
	assert.False(t, resp.Revoked)
}

func TestListPIVSlots_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{Backend: "software"})
	require.NoError(t, err)
	require.Len(t, resp.Slots, 1)
}

func TestGetPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
}

func TestStorePIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("cert")}))
}

func TestDeletePIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{Backend: "software", Slot: "9a"}))
}

func TestGeneratePIVKey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{Backend: "software", Slot: "9a", Algorithm: "ECDSA-P256"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.PublicKey)
}

func TestImportPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("cert")}))
}

func TestExportPIVCertificate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
}

func TestCreateTenant_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{Name: "test-tenant"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", resp.Tenant.ID)
}

func TestGetTenant_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetTenant(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", resp.Tenant.ID)
}

func TestListTenants_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListTenants(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Tenants, 1)
}

func TestDeleteTenant_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DeleteTenant(context.Background(), "tenant-1"))
}

func TestPasswordAdd_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordAdd(context.Background(), &transport.PasswordAddRequest{Name: "pw", Username: "u", Password: "p"})
	require.NoError(t, err)
	assert.Equal(t, "pw-1", resp.ID)
}

func TestPasswordGet_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "pw-1"})
	require.NoError(t, err)
	assert.Equal(t, "pw-1", resp.ID)
	assert.Equal(t, "secret", resp.Password)
}

func TestPasswordList_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Passwords, 1)
}

func TestPasswordList_NilRequest(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordList(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, resp.Passwords, 1)
}

func TestPasswordUpdate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{ID: "pw-1", Name: func() *string { s := "updated"; return &s }()}))
}

func TestPasswordDelete_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{ID: "pw-1"}))
}

func TestPasswordStoreUnlock_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{
		PasswordVaultCredential: transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "correct horse"},
	}))
}

func TestPasswordStoreLock_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.PasswordStoreLock(context.Background()))
}

func TestPasswordStoreStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordStoreStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "private", resp.AccessMode)
	assert.Equal(t, 5, resp.PasswordCount)
}

func TestPasswordGenerate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{Length: 16})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Password)
}

func TestSealStore_RoundTrip(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	ctx := context.Background()

	require.NoError(t, tr.SealStorePut(ctx, &transport.SealStorePutRequest{Name: "db-password", Secret: []byte("s3cret")}))

	getResp, err := tr.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, "db-password", getResp.Name)
	assert.Equal(t, []byte("s3cret"), getResp.Secret)

	listResp, err := tr.SealStoreList(ctx)
	require.NoError(t, err)
	assert.Contains(t, listResp.Names, "db-password")

	require.NoError(t, tr.SealStoreReseal(ctx, &transport.SealStoreResealRequest{Name: "db-password"}))

	statusResp, err := tr.SealStoreStatus(ctx)
	require.NoError(t, err)
	assert.True(t, statusResp.Available)

	require.NoError(t, tr.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{Name: "db-password"}))
}

// --- PasswordStoreSetAccessMode and Policy ---
//
// go-xkms#691 moved both off the ErrNotSupported table this file used to
// carry (TestErrNotSupported_Methods): the Unix transport dials the same
// generated gRPC client pkg/api/transport/grpc uses, over a Unix socket
// instead of TCP, so both now round-trip against the mock KeystoreService
// exactly as every other implemented method here does.

func TestPasswordStoreSetAccessMode_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{Mode: "session_based"})
	assert.NoError(t, err)
}

// TestRegistration_RPCWired confirms the FIDO2 registration and authentication
// RPCs reach the server over the unix-socket gRPC transport. Empty/invalid
// requests are rejected with an error, proving the calls are plumbed end-to-end.
func TestRegistration_RPCWired(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	_, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	assert.Error(t, err)

	_, err = tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	assert.Error(t, err)

	_, err = tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	assert.Error(t, err)

	_, err = tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	assert.Error(t, err)
}

// --- Helper function tests ---

func TestPbTenantInfoToTransport_Nil(t *testing.T) {
	assert.Empty(t, pbTenantInfoToTransport(nil).ID)
}

func TestPbTenantInfoToTransport_WithData(t *testing.T) {
	ti := &pb.TenantInfo{
		Id: "t-1", Name: "test",
		CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
	}
	assert.Equal(t, "t-1", pbTenantInfoToTransport(ti).ID)
}

func TestParseTimestamp_Empty(t *testing.T) {
	assert.True(t, parseTimestamp("field", "").IsZero())
}

func TestParseTimestamp_Malformed(t *testing.T) {
	assert.True(t, parseTimestamp("field", "not-a-timestamp").IsZero())
}

func TestParseTimestamp_Valid(t *testing.T) {
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := parseTimestamp("field", want.Format(time.RFC3339))
	assert.True(t, want.Equal(got))
}

func TestClose_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	assert.True(t, tr.connected)
	require.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}
