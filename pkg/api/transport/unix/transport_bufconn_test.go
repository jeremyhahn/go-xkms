// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
		CertPem:       "-----BEGIN CERTIFICATE-----\ntls\n-----END CERTIFICATE-----",
		PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ntls\n-----END PRIVATE KEY-----",
		CertChainPem:  []string{"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"},
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

func (s *mockKeystoreServer) BarrierInitialize(_ context.Context, _ *pb.BarrierInitializeRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierUnseal(_ context.Context, _ *pb.BarrierUnsealRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierSeal(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierStatus(_ context.Context, _ *emptypb.Empty) (*pb.BarrierStatusResponse, error) {
	return &pb.BarrierStatusResponse{Sealed: false, InitializedAt: "2024-01-01T00:00:00Z"}, nil
}

func (s *mockKeystoreServer) BarrierInitializeShamir(_ context.Context, _ *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
	return &pb.BarrierShamirInitResponse{Shares: []string{"share-1", "share-2", "share-3"}, Threshold: 2}, nil
}

func (s *mockKeystoreServer) BarrierUnsealShare(_ context.Context, _ *pb.BarrierUnsealShareRequest) (*pb.BarrierQuorumProgressResponse, error) {
	return &pb.BarrierQuorumProgressResponse{Required: 2, Submitted: 1, Complete: false}, nil
}

func (s *mockKeystoreServer) BarrierUnsealShares(_ context.Context, _ *pb.BarrierUnsealSharesRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierShamirListShares(_ context.Context, _ *emptypb.Empty) (*pb.BarrierShamirSharesResponse, error) {
	return &pb.BarrierShamirSharesResponse{Count: 2, Threshold: 2, Total: 3}, nil
}

func (s *mockKeystoreServer) BarrierShamirDeleteShare(_ context.Context, _ *pb.BarrierShamirDeleteShareRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierShamirDeleteAllShares(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierShamirVerify(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierRekey(_ context.Context, _ *pb.BarrierRekeyRequest) (*pb.BarrierShamirInitResponse, error) {
	return &pb.BarrierShamirInitResponse{Shares: []string{"new-share-1", "new-share-2"}, Threshold: 2}, nil
}

func (s *mockKeystoreServer) BarrierGenerateRecoveryKeys(_ context.Context, _ *pb.BarrierGenerateRecoveryKeysRequest) (*pb.BarrierRecoveryKeysResponse, error) {
	return &pb.BarrierRecoveryKeysResponse{Shares: []string{"recovery-1", "recovery-2"}, Threshold: 2}, nil
}

func (s *mockKeystoreServer) BarrierRecoverWithKeys(_ context.Context, _ *pb.BarrierRecoverWithKeysRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierDeleteRecoveryKeys(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) BarrierGenerateRootToken(_ context.Context, _ *pb.BarrierGenerateRootTokenRequest) (*pb.BarrierRootTokenResponse, error) {
	return &pb.BarrierRootTokenResponse{
		Token:     "root-token-123",
		CreatedAt: time.Now().Format(time.RFC3339),
	}, nil
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

func (s *mockKeystoreServer) CreateCustodianGroup(_ context.Context, _ *pb.CreateCustodianGroupRequest) (*pb.CreateCustodianGroupResponse, error) {
	return &pb.CreateCustodianGroupResponse{
		Group: &pb.CustodianGroup{
			Id: "group-1", Name: "test-group", Description: "test", Threshold: 2,
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		},
	}, nil
}

func (s *mockKeystoreServer) GetCustodianGroup(_ context.Context, _ *pb.GetCustodianGroupRequest) (*pb.GetCustodianGroupResponse, error) {
	return &pb.GetCustodianGroupResponse{
		Group: &pb.CustodianGroup{
			Id: "group-1", Name: "test-group", Description: "test", Threshold: 2,
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		},
	}, nil
}

func (s *mockKeystoreServer) ListCustodianGroups(_ context.Context, _ *pb.ListCustodianGroupsRequest) (*pb.ListCustodianGroupsResponse, error) {
	return &pb.ListCustodianGroupsResponse{
		Groups: []*pb.CustodianGroup{
			{
				Id: "group-1", Name: "test-group", Description: "test", Threshold: 2,
				CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
			},
		},
	}, nil
}

func (s *mockKeystoreServer) DeleteCustodianGroup(_ context.Context, _ *pb.DeleteCustodianGroupRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) AddCustodianMember(_ context.Context, _ *pb.AddCustodianMemberRequest) (*pb.AddCustodianMemberResponse, error) {
	return &pb.AddCustodianMemberResponse{
		Member: &pb.CustodianMember{UserId: "user-1", Name: "alice", Role: "officer"},
	}, nil
}

func (s *mockKeystoreServer) RemoveCustodianMember(_ context.Context, _ *pb.RemoveCustodianMemberRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) DistributeShares(_ context.Context, _ *pb.DistributeSharesRequest) (*pb.DistributeSharesResponse, error) {
	return &pb.DistributeSharesResponse{Distributed: 3}, nil
}

func (s *mockKeystoreServer) SubmitShare(_ context.Context, _ *pb.SubmitShareRequest) (*pb.SubmitShareResponse, error) {
	return &pb.SubmitShareResponse{Id: "share-1", Message: "accepted"}, nil
}

func (s *mockKeystoreServer) ListShares(_ context.Context, _ *pb.ListSharesRequest) (*pb.ListSharesResponse, error) {
	return &pb.ListSharesResponse{
		Shares: []*pb.ShareInfo{
			{GroupId: "group-1", GroupName: "test-group", ShareIndex: 0, ServerUrl: "https://localhost"},
		},
	}, nil
}

func (s *mockKeystoreServer) GetShareCollectionStatus(_ context.Context, _ *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	return &pb.ShareCollectionStatusResponse{GroupId: "group-1", Collected: 1, Required: 2, Complete: false}, nil
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

func (s *mockKeystoreServer) TenantBarrierInit(_ context.Context, _ *pb.TenantBarrierInitRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) TenantBarrierUnseal(_ context.Context, _ *pb.TenantBarrierUnsealRequest) (*emptypb.Empty, error) {
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

func (s *mockKeystoreServer) PasswordStoreUnlock(_ context.Context, _ *pb.PasswordStoreUnlockRequest) (*pb.PasswordStoreStatusResponse, error) {
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

func (s *mockKeystoreServer) PasswordGenerate(_ context.Context, _ *pb.PasswordGenerateRequest) (*pb.PasswordGenerateResponse, error) {
	return &pb.PasswordGenerateResponse{Password: "Rand0m!P@ssw0rd"}, nil
}

// newBufconnTransport creates an in-memory gRPC server + connected Unix Transport for testing.
func newBufconnTransport(t *testing.T) (*Transport, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &mockKeystoreServer{})

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
		json.NewEncoder(w).Encode(resp)
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
		KeyID: "test-key", Backend: "software", KeyType: "ECDSA", Curve: "P-256",
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
	assert.Equal(t, "key-1", resp.KeyInfo.KeyID)
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
	assert.Contains(t, resp.PrivateKeyPEM, "PRIVATE KEY")
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

func TestBarrierInitialize_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{}))
}

func TestBarrierUnseal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{}))
}

func TestBarrierSeal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierSeal(context.Background()))
}

func TestBarrierStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierStatus(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.InitializedAt)
	assert.False(t, resp.Sealed)
}

func TestBarrierInitializeShamir_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierInitializeShamir(context.Background(), &transport.BarrierInitializeShamirRequest{Threshold: 2, TotalShares: 3})
	require.NoError(t, err)
	require.Len(t, resp.Shares, 3)
	assert.Equal(t, 2, resp.Threshold)
}

func TestBarrierUnsealWithShare_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierUnsealWithShare(context.Background(), &transport.BarrierUnsealShareRequest{Share: "share-1"})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Submitted)
}

func TestBarrierUnsealWithShares_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{Shares: []string{"s1", "s2"}}))
}

func TestBarrierShamirListShares_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierShamirListShares(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
}

func TestBarrierShamirDeleteShare_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierShamirDeleteShare(context.Background(), &transport.BarrierShamirDeleteShareRequest{Index: 0}))
}

func TestBarrierShamirDeleteAllShares_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierShamirDeleteAllShares(context.Background()))
}

func TestBarrierShamirVerify_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierShamirVerify(context.Background()))
}

func TestBarrierRekey_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierRekey(context.Background(), &transport.BarrierRekeyRequest{Threshold: 2, Total: 3})
	require.NoError(t, err)
	require.Len(t, resp.Shares, 2)
}

func TestBarrierGenerateRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierGenerateRecoveryKeys(context.Background(), &transport.BarrierGenerateRecoveryKeysRequest{Total: 2})
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 2)
}

func TestBarrierRecoverWithKeys_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{Keys: []string{"r1"}}))
}

func TestBarrierDeleteRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BarrierDeleteRecoveryKeys(context.Background()))
}

func TestBarrierHasRecoveryKeys_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	_, err := tr.BarrierHasRecoveryKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotImplemented)
}

func TestBarrierGenerateRootToken_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "root-token-123", resp.Token)
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

func TestCreateCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{Name: "test-group", Threshold: 2})
	require.NoError(t, err)
	assert.Equal(t, "group-1", resp.Group.ID)
}

func TestGetCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetCustodianGroup(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, "group-1", resp.Group.ID)
}

func TestListCustodianGroups_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListCustodianGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Groups, 1)
}

func TestDeleteCustodianGroup_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DeleteCustodianGroup(context.Background(), "group-1"))
}

func TestAddCustodianMember_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{GroupID: "group-1", UserID: "user-1"})
	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.Member.UserID)
}

func TestRemoveCustodianMember_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{GroupID: "g1", UserID: "u1"}))
}

func TestDistributeShares_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.DistributeShares(context.Background(), &transport.DistributeSharesRequest{GroupID: "group-1"})
	require.NoError(t, err)
	assert.Equal(t, 3, resp.Distributed)
}

func TestSubmitShare_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.SubmitShare(context.Background(), &transport.SubmitShareRequest{GroupID: "group-1", ShareData: []byte("share-data")})
	require.NoError(t, err)
	assert.True(t, resp.Accepted)
}

func TestListShares_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.ListShares(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Shares, 1)
}

func TestGetShareCollectionStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.GetShareCollectionStatus(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, "group-1", resp.GroupID)
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

func TestTenantBarrierInit_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{TenantID: "t1"}))
}

func TestTenantBarrierUnseal_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{TenantID: "t1"}))
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

	resp, err := tr.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "pw-1", Decrypt: true})
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
	require.NoError(t, tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{UserPIN: "1234"}))
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

// --- ErrNotSupported methods ---

func TestErrNotSupported_Methods(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"ListUsers", func() error { _, err := tr.ListUsers(context.Background()); return err }},
		{"GetUser", func() error { _, err := tr.GetUser(context.Background(), "u"); return err }},
		{"DeleteUser", func() error { return tr.DeleteUser(context.Background(), "u") }},
		{"EnableUser", func() error { return tr.EnableUser(context.Background(), "u") }},
		{"DisableUser", func() error { return tr.DisableUser(context.Background(), "u") }},
		{"ListUserCredentials", func() error { _, err := tr.ListUserCredentials(context.Background(), "u"); return err }},
		{"PasswordStoreSetAccessMode", func() error { return tr.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{}) }},
		{"SealStorePut", func() error { return tr.SealStorePut(context.Background(), &transport.SealStorePutRequest{}) }},
		{"SealStoreGet", func() error { _, err := tr.SealStoreGet(context.Background(), &transport.SealStoreGetRequest{}); return err }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{}) }},
		{"SealStoreList", func() error { _, err := tr.SealStoreList(context.Background()); return err }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{}) }},
		{"SealStoreStatus", func() error { _, err := tr.SealStoreStatus(context.Background()); return err }},
		{"PolicyCreate", func() error { _, err := tr.PolicyCreate(context.Background(), &transport.PolicyCreateRequest{}); return err }},
		{"PolicyGet", func() error { _, err := tr.PolicyGet(context.Background(), &transport.PolicyGetRequest{}); return err }},
		{"PolicyList", func() error { _, err := tr.PolicyList(context.Background()); return err }},
		{"PolicyDelete", func() error { return tr.PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{}) }},
		{"PolicyRefresh", func() error { _, err := tr.PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{}); return err }},
		{"PolicyVerify", func() error { _, err := tr.PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{}); return err }},
		{"PolicyExport", func() error { _, err := tr.PolicyExport(context.Background(), &transport.PolicyExportRequest{}); return err }},
		{"BeginRegistration", func() error { _, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{}); return err }},
		{"FinishRegistration", func() error { _, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{}); return err }},
		{"BeginAuthentication", func() error { _, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{}); return err }},
		{"FinishAuthentication", func() error { _, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{}); return err }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}


}

// --- Helper function tests ---





func TestPbCustodianGroupToTransport_Nil(t *testing.T) {
	assert.Empty(t, pbCustodianGroupToTransport(nil).ID)
}

func TestPbCustodianGroupToTransport_WithMembers(t *testing.T) {
	g := &pb.CustodianGroup{
		Id: "g-1", Name: "test", Description: "desc", Threshold: 2,
		Members:   []*pb.CustodianMember{{UserId: "u-1", Name: "alice", Role: "officer"}},
		CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
	}
	result := pbCustodianGroupToTransport(g)
	assert.Equal(t, "g-1", result.ID)
	require.Len(t, result.Members, 1)
}

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







func TestClose_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	assert.True(t, tr.connected)
	require.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}
