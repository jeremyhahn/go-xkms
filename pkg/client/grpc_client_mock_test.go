// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// mockKeystoreServer implements pb.KeystoreServiceServer for testing
type mockKeystoreServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (s *mockKeystoreServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Status:  "healthy",
		Version: "1.0.0",
	}, nil
}

func (s *mockKeystoreServer) ListBackends(ctx context.Context, req *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
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
		Count: 1,
	}, nil
}

func (s *mockKeystoreServer) GetBackendInfo(ctx context.Context, req *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	return &pb.GetBackendInfoResponse{
		Backend: &pb.BackendInfo{
			Name:                        req.Name,
			Type:                        "software",
			HardwareBacked:              false,
			SupportsSigning:             true,
			SupportsDecryption:          true,
			SupportsRotation:            true,
			SupportsSymmetricEncryption: true,
		},
	}, nil
}

func (s *mockKeystoreServer) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return &pb.GenerateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      req.KeyType,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}, nil
}

func (s *mockKeystoreServer) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return &pb.ListKeysResponse{
		Keys: []*pb.KeyInfo{
			{
				KeyId:     "test-key",
				KeyType:   "RSA",
				Algorithm: "RSA-2048",
				Backend:   req.Backend,
			},
		},
	}, nil
}

func (s *mockKeystoreServer) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return &pb.GetKeyResponse{
		Key: &pb.KeyInfo{
			KeyId:     req.KeyId,
			KeyType:   "RSA",
			Algorithm: "RSA-2048",
			Backend:   req.Backend,
		},
	}, nil
}

func (s *mockKeystoreServer) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return &pb.DeleteKeyResponse{
		Success: true,
		Message: "key deleted",
	}, nil
}

func (s *mockKeystoreServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	return &pb.SignResponse{
		Signature: []byte("mock-signature"),
	}, nil
}

func (s *mockKeystoreServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return &pb.VerifyResponse{
		Valid:   true,
		Message: "signature verified",
	}, nil
}

func (s *mockKeystoreServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return &pb.EncryptResponse{
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("nonce"),
		Tag:        []byte("tag"),
	}, nil
}

func (s *mockKeystoreServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return &pb.DecryptResponse{
		Plaintext: []byte("decrypted-data"),
	}, nil
}

func (s *mockKeystoreServer) GetCert(ctx context.Context, req *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	return &pb.GetCertResponse{
		CertPem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}, nil
}

func (s *mockKeystoreServer) SaveCert(ctx context.Context, req *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	return &pb.SaveCertResponse{
		Success: true,
	}, nil
}

func (s *mockKeystoreServer) DeleteCert(ctx context.Context, req *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	return &pb.DeleteCertResponse{
		Success: true,
	}, nil
}

func (s *mockKeystoreServer) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return &pb.ImportKeyResponse{
		Success: true,
		KeyId:   req.KeyId,
		Message: "key imported",
	}, nil
}

func (s *mockKeystoreServer) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return &pb.ExportKeyResponse{
		WrappedKey:  []byte("wrapped-key"),
		Algorithm:   req.WrappingAlgorithm,
		ImportToken: []byte("import-token"),
	}, nil
}

func (s *mockKeystoreServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return &pb.RotateKeyResponse{
		KeyId:        req.KeyId,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nrotated\n-----END PUBLIC KEY-----",
	}, nil
}

func (s *mockKeystoreServer) GetImportParameters(ctx context.Context, req *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	return &pb.GetImportParametersResponse{
		WrappingPublicKey: []byte("wrapping-public-key"),
		ImportToken:       []byte("import-token"),
		Algorithm:         req.WrappingAlgorithm,
	}, nil
}

func (s *mockKeystoreServer) WrapKey(ctx context.Context, req *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	return &pb.WrapKeyResponse{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  req.Algorithm,
	}, nil
}

func (s *mockKeystoreServer) UnwrapKey(ctx context.Context, req *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	return &pb.UnwrapKeyResponse{
		KeyMaterial: []byte("unwrapped-key-material"),
	}, nil
}

func (s *mockKeystoreServer) CopyKey(ctx context.Context, req *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	return &pb.CopyKeyResponse{
		Success:   true,
		DestKeyId: req.DestKeyId,
		Message:   "key copied successfully",
	}, nil
}

func (s *mockKeystoreServer) ListCerts(ctx context.Context, req *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	return &pb.ListCertsResponse{
		KeyIds: []string{"cert-1", "cert-2"},
	}, nil
}

func (s *mockKeystoreServer) CertExists(ctx context.Context, req *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	return &pb.CertExistsResponse{
		Exists: true,
	}, nil
}

func (s *mockKeystoreServer) SaveCertChain(ctx context.Context, req *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	return &pb.SaveCertChainResponse{
		Success: true,
	}, nil
}

func (s *mockKeystoreServer) GetCertChain(ctx context.Context, req *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	return &pb.GetCertChainResponse{
		CertChainPem: []string{"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"},
	}, nil
}

func (s *mockKeystoreServer) GetTLSCertificate(ctx context.Context, req *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	return &pb.GetTLSCertificateResponse{
		PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
		CertPem:       "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
		CertChainPem:  []string{"-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"},
	}, nil
}

// setupMockGRPCServer creates a mock gRPC server using bufconn
func setupMockGRPCServer(t *testing.T) (*grpc.Server, *bufconn.Listener) {
	lis := bufconn.Listen(bufSize)
	server := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(server, &mockKeystoreServer{})

	go func() {
		_ = server.Serve(lis) // Error is expected during test cleanup
	}()

	return server, lis
}

// createMockGRPCClient creates a gRPC client connected to the mock server
func createMockGRPCClient(t *testing.T, lis *bufconn.Listener) *grpcClient {
	t.Helper()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	client := &grpcClient{
		config: &Config{
			Address:  "bufnet",
			Protocol: ProtocolGRPC,
		},
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}

	return client
}

func TestGRPCClient_WithMockServer_Health(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Health() status = %v, want healthy", resp.Status)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Health() version = %v, want 1.0.0", resp.Version)
	}
}

func TestGRPCClient_WithMockServer_ListBackends(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.ListBackends(context.Background())
	if err != nil {
		t.Fatalf("ListBackends() error = %v", err)
	}

	if len(resp.Backends) != 1 {
		t.Errorf("ListBackends() count = %d, want 1", len(resp.Backends))
	}
	if resp.Backends[0].ID != "software" {
		t.Errorf("ListBackends()[0].ID = %v, want software", resp.Backends[0].ID)
	}
}

func TestGRPCClient_WithMockServer_GetBackend(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetBackend(context.Background(), "software")
	if err != nil {
		t.Fatalf("GetBackend() error = %v", err)
	}

	if resp.ID != "software" {
		t.Errorf("GetBackend().ID = %v, want software", resp.ID)
	}
	if resp.HardwareBacked {
		t.Error("GetBackend().HardwareBacked = true, want false")
	}
}

func TestGRPCClient_WithMockServer_GenerateKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GenerateKey(context.Background(), &GenerateKeyRequest{
		KeyID:   "new-key",
		Backend: "software",
		KeyType: "RSA",
		KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if resp.KeyID != "new-key" {
		t.Errorf("GenerateKey().KeyID = %v, want new-key", resp.KeyID)
	}
	if resp.KeyType != "RSA" {
		t.Errorf("GenerateKey().KeyType = %v, want RSA", resp.KeyType)
	}
}

func TestGRPCClient_WithMockServer_ListKeys(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.ListKeys(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(resp.Keys) != 1 {
		t.Errorf("ListKeys() count = %d, want 1", len(resp.Keys))
	}
	if resp.Keys[0].KeyID != "test-key" {
		t.Errorf("ListKeys()[0].KeyID = %v, want test-key", resp.Keys[0].KeyID)
	}
}

func TestGRPCClient_WithMockServer_GetKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetKey().KeyID = %v, want test-key", resp.KeyID)
	}
}

func TestGRPCClient_WithMockServer_DeleteKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.DeleteKey(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("DeleteKey().Success = false, want true")
	}
}

func TestGRPCClient_WithMockServer_Sign(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	data, _ := json.Marshal([]byte("test data"))
	resp, err := client.Sign(context.Background(), &SignRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    data,
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Sign().Signature is empty")
	}
}

func TestGRPCClient_WithMockServer_Sign_RawData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	// Test with raw data (not base64 encoded json)
	resp, err := client.Sign(context.Background(), &SignRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    json.RawMessage("not-valid-json"),
		Hash:    "SHA256",
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(resp.Signature) == 0 {
		t.Error("Sign().Signature is empty")
	}
}

func TestGRPCClient_WithMockServer_Verify(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	data, _ := json.Marshal([]byte("test data"))
	sig, _ := json.Marshal([]byte("signature"))
	resp, err := client.Verify(context.Background(), &VerifyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Data:      data,
		Signature: sig,
		Hash:      "SHA256",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !resp.Valid {
		t.Error("Verify().Valid = false, want true")
	}
}

func TestGRPCClient_WithMockServer_Verify_RawData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	// Test with raw data (not base64 encoded json)
	resp, err := client.Verify(context.Background(), &VerifyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Data:      json.RawMessage("raw-data"),
		Signature: json.RawMessage("raw-sig"),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !resp.Valid {
		t.Error("Verify().Valid = false, want true")
	}
}

func TestGRPCClient_WithMockServer_Encrypt(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	plaintext, _ := json.Marshal([]byte("test data"))
	resp, err := client.Encrypt(context.Background(), &EncryptRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(resp.Ciphertext) == 0 {
		t.Error("Encrypt().Ciphertext is empty")
	}
}

func TestGRPCClient_WithMockServer_Encrypt_WithAdditionalData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	plaintext, _ := json.Marshal([]byte("test data"))
	additionalData, _ := json.Marshal([]byte("aad"))
	resp, err := client.Encrypt(context.Background(), &EncryptRequest{
		Backend:        "software",
		KeyID:          "test-key",
		Plaintext:      plaintext,
		AdditionalData: additionalData,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(resp.Ciphertext) == 0 {
		t.Error("Encrypt().Ciphertext is empty")
	}
}

func TestGRPCClient_WithMockServer_Encrypt_RawData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.Encrypt(context.Background(), &EncryptRequest{
		Backend:        "software",
		KeyID:          "test-key",
		Plaintext:      json.RawMessage("raw-plaintext"),
		AdditionalData: json.RawMessage("raw-aad"),
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(resp.Ciphertext) == 0 {
		t.Error("Encrypt().Ciphertext is empty")
	}
}

func TestGRPCClient_WithMockServer_Decrypt(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	ciphertext, _ := json.Marshal([]byte("ciphertext"))
	resp, err := client.Decrypt(context.Background(), &DecryptRequest{
		Backend:    "software",
		KeyID:      "test-key",
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(resp.Plaintext) == 0 {
		t.Error("Decrypt().Plaintext is empty")
	}
}

func TestGRPCClient_WithMockServer_Decrypt_WithAllFields(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	ciphertext, _ := json.Marshal([]byte("ciphertext"))
	nonce, _ := json.Marshal([]byte("nonce"))
	tag, _ := json.Marshal([]byte("tag"))
	additionalData, _ := json.Marshal([]byte("aad"))

	resp, err := client.Decrypt(context.Background(), &DecryptRequest{
		Backend:        "software",
		KeyID:          "test-key",
		Ciphertext:     ciphertext,
		Nonce:          nonce,
		Tag:            tag,
		AdditionalData: additionalData,
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(resp.Plaintext) == 0 {
		t.Error("Decrypt().Plaintext is empty")
	}
}

func TestGRPCClient_WithMockServer_Decrypt_RawData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.Decrypt(context.Background(), &DecryptRequest{
		Backend:        "software",
		KeyID:          "test-key",
		Ciphertext:     json.RawMessage("raw-ciphertext"),
		Nonce:          json.RawMessage("raw-nonce"),
		Tag:            json.RawMessage("raw-tag"),
		AdditionalData: json.RawMessage("raw-aad"),
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(resp.Plaintext) == 0 {
		t.Error("Decrypt().Plaintext is empty")
	}
}

func TestGRPCClient_WithMockServer_GetCertificate(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificate().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.CertificatePEM == "" {
		t.Error("GetCertificate().CertificatePEM is empty")
	}
}

func TestGRPCClient_WithMockServer_SaveCertificate(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	err := client.SaveCertificate(context.Background(), &SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "test-key",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}
}

func TestGRPCClient_WithMockServer_DeleteCertificate(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	err := client.DeleteCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("DeleteCertificate() error = %v", err)
	}
}

func TestGRPCClient_WithMockServer_ImportKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	wrappedKey, _ := json.Marshal([]byte("wrapped-key-data"))
	resp, err := client.ImportKey(context.Background(), &ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported-key",
		KeyType:            "RSA",
		WrappedKeyMaterial: wrappedKey,
		Algorithm:          "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("ImportKey().Success = false, want true")
	}
	if resp.KeyID != "imported-key" {
		t.Errorf("ImportKey().KeyID = %v, want imported-key", resp.KeyID)
	}
}

func TestGRPCClient_WithMockServer_ImportKey_WithToken(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	wrappedKey, _ := json.Marshal([]byte("wrapped-key-data"))
	resp, err := client.ImportKey(context.Background(), &ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported-key",
		KeyType:            "RSA",
		WrappedKeyMaterial: wrappedKey,
		Algorithm:          "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("ImportKey().Success = false, want true")
	}
}

func TestGRPCClient_WithMockServer_ImportKey_RawData(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.ImportKey(context.Background(), &ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported-key",
		KeyType:            "RSA",
		WrappedKeyMaterial: []byte("raw-wrapped-key"),
		Algorithm:          "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("ImportKey().Success = false, want true")
	}
}

func TestGRPCClient_WithMockServer_ExportKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.ExportKey(context.Background(), &ExportKeyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Algorithm: "AES-KWP",
	})
	if err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("ExportKey().KeyID = %v, want test-key", resp.KeyID)
	}
	if len(resp.WrappedKeyMaterial) == 0 {
		t.Error("ExportKey().WrappedKeyMaterial is empty")
	}
}

func TestGRPCClient_Close_WithConnection(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)

	err := client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if client.connected {
		t.Error("client.connected should be false after Close()")
	}
}

func TestGRPCClient_WithMockServer_RotateKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.RotateKey(context.Background(), &RotateKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("RotateKey().Success = false, want true")
	}
	if resp.KeyID != "test-key" {
		t.Errorf("RotateKey().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.PublicKeyPEM == "" {
		t.Error("RotateKey().PublicKeyPEM is empty")
	}
}

func TestGRPCClient_WithMockServer_GetImportParameters(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetImportParameters(context.Background(), &GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Algorithm: "RSA_AES_KEY_WRAP_SHA_256",
		KeyType:   "RSA",
		KeySize:   2048,
	})
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	if len(resp.WrappingPublicKey) == 0 {
		t.Error("GetImportParameters().WrappingPublicKey is empty")
	}
	if len(resp.ImportToken) == 0 {
		t.Error("GetImportParameters().ImportToken is empty")
	}
	if resp.Algorithm != "RSA_AES_KEY_WRAP_SHA_256" {
		t.Errorf("GetImportParameters().Algorithm = %v, want RSA_AES_KEY_WRAP_SHA_256", resp.Algorithm)
	}
}

func TestGRPCClient_WithMockServer_WrapKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.WrapKey(context.Background(), &WrapKeyRequest{
		Backend:           "software",
		KeyMaterial:       []byte("key-material"),
		Algorithm:         "RSA_AES_KEY_WRAP_SHA_256",
		WrappingPublicKey: []byte("wrapping-key"),
		ImportToken:       []byte("import-token"),
	})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	if len(resp.WrappedKeyMaterial) == 0 {
		t.Error("WrapKey().WrappedKeyMaterial is empty")
	}
	if resp.Algorithm != "RSA_AES_KEY_WRAP_SHA_256" {
		t.Errorf("WrapKey().Algorithm = %v, want RSA_AES_KEY_WRAP_SHA_256", resp.Algorithm)
	}
}

func TestGRPCClient_WithMockServer_UnwrapKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.UnwrapKey(context.Background(), &UnwrapKeyRequest{
		Backend:            "software",
		WrappedKeyMaterial: []byte("wrapped-key"),
		Algorithm:          "RSA_AES_KEY_WRAP_SHA_256",
		ImportToken:        []byte("import-token"),
	})
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}

	if len(resp.KeyMaterial) == 0 {
		t.Error("UnwrapKey().KeyMaterial is empty")
	}
}

func TestGRPCClient_WithMockServer_CopyKey(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.CopyKey(context.Background(), &CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "source-key",
		DestBackend:   "pkcs11",
		DestKeyID:     "dest-key",
		Algorithm:     "RSA_AES_KEY_WRAP_SHA_256",
	})
	if err != nil {
		t.Fatalf("CopyKey() error = %v", err)
	}

	if !resp.Success {
		t.Error("CopyKey().Success = false, want true")
	}
	if resp.KeyID != "dest-key" {
		t.Errorf("CopyKey().KeyID = %v, want dest-key", resp.KeyID)
	}
}

func TestGRPCClient_WithMockServer_ListCertificates(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.ListCertificates(context.Background(), "software")
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("ListCertificates() count = %d, want 2", len(resp.Certificates))
	}
	if resp.Certificates[0].KeyID != "cert-1" {
		t.Errorf("ListCertificates()[0].KeyID = %v, want cert-1", resp.Certificates[0].KeyID)
	}
}

func TestGRPCClient_WithMockServer_SaveCertificateChain(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	err := client.SaveCertificateChain(context.Background(), &SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "test-key",
		ChainPEM: []string{"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	})
	if err != nil {
		t.Fatalf("SaveCertificateChain() error = %v", err)
	}
}

func TestGRPCClient_WithMockServer_GetCertificateChain(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetCertificateChain(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetCertificateChain() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetCertificateChain().KeyID = %v, want test-key", resp.KeyID)
	}
	if len(resp.ChainPEM) == 0 {
		t.Error("GetCertificateChain().ChainPEM is empty")
	}
}

func TestGRPCClient_WithMockServer_GetTLSCertificate(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	resp, err := client.GetTLSCertificate(context.Background(), "software", "test-key")
	if err != nil {
		t.Fatalf("GetTLSCertificate() error = %v", err)
	}

	if resp.KeyID != "test-key" {
		t.Errorf("GetTLSCertificate().KeyID = %v, want test-key", resp.KeyID)
	}
	if resp.PrivateKeyPEM == "" {
		t.Error("GetTLSCertificate().PrivateKeyPEM is empty")
	}
	if resp.CertificatePEM == "" {
		t.Error("GetTLSCertificate().CertificatePEM is empty")
	}
	if resp.ChainPEM == "" {
		t.Error("GetTLSCertificate().ChainPEM is empty")
	}
}

func TestGRPCClient_NotConnected_RotateKey(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.RotateKey(context.Background(), &RotateKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	})
	if err != ErrNotConnected {
		t.Errorf("RotateKey() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_GetImportParameters(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.GetImportParameters(context.Background(), &GetImportParametersRequest{})
	if err != ErrNotConnected {
		t.Errorf("GetImportParameters() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_WrapKey(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.WrapKey(context.Background(), &WrapKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("WrapKey() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_UnwrapKey(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.UnwrapKey(context.Background(), &UnwrapKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("UnwrapKey() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_CopyKey(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.CopyKey(context.Background(), &CopyKeyRequest{})
	if err != ErrNotConnected {
		t.Errorf("CopyKey() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_ListCertificates(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.ListCertificates(context.Background(), "software")
	if err != ErrNotConnected {
		t.Errorf("ListCertificates() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_SaveCertificateChain(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	err := client.SaveCertificateChain(context.Background(), &SaveCertificateChainRequest{})
	if err != ErrNotConnected {
		t.Errorf("SaveCertificateChain() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_GetCertificateChain(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.GetCertificateChain(context.Background(), "software", "test-key")
	if err != ErrNotConnected {
		t.Errorf("GetCertificateChain() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_NotConnected_GetTLSCertificate(t *testing.T) {
	client := &grpcClient{
		config: &Config{
			Address:  "test",
			Protocol: ProtocolGRPC,
		},
		connected: false,
	}

	_, err := client.GetTLSCertificate(context.Background(), "software", "test-key")
	if err != ErrNotConnected {
		t.Errorf("GetTLSCertificate() error = %v, want ErrNotConnected", err)
	}
}

func TestGRPCClient_EncryptAsym_NotSupported(t *testing.T) {
	server, lis := setupMockGRPCServer(t)
	defer server.Stop()

	client := createMockGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	plaintext, _ := json.Marshal([]byte("test data"))
	_, err := client.EncryptAsym(context.Background(), &EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Plaintext: plaintext,
		Hash:      "SHA256",
	})

	if err == nil {
		t.Error("EncryptAsym() should return error")
	}
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("EncryptAsym() error = %v, want ErrNotSupported", err)
	}
}

// errorKeystoreServer returns errors for all methods to test error handling
type errorKeystoreServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (s *errorKeystoreServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	// Health still returns OK so we can connect
	return &pb.HealthResponse{Status: "healthy", Version: "1.0.0"}, nil
}

func (s *errorKeystoreServer) ListBackends(ctx context.Context, req *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GetBackendInfo(ctx context.Context, req *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) CertExists(ctx context.Context, req *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GetImportParameters(ctx context.Context, req *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) WrapKey(ctx context.Context, req *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) UnwrapKey(ctx context.Context, req *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) CopyKey(ctx context.Context, req *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) ListCerts(ctx context.Context, req *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) SaveCert(ctx context.Context, req *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) DeleteCert(ctx context.Context, req *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) SaveCertChain(ctx context.Context, req *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GetCertChain(ctx context.Context, req *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func (s *errorKeystoreServer) GetTLSCertificate(ctx context.Context, req *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	return nil, status.Error(codes.Internal, "mock error")
}

func setupErrorGRPCServer(t *testing.T) (*grpc.Server, *bufconn.Listener) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	server := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(server, &errorKeystoreServer{})
	go func() {
		if err := server.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("error serving grpc server: %v", err)
		}
	}()
	return server, lis
}

func createErrorGRPCClient(t *testing.T, lis *bufconn.Listener) *grpcClient {
	t.Helper()

	client, err := newGRPCClient(&Config{
		Address:  "passthrough:///bufnet",
		Protocol: ProtocolGRPC,
	})
	if err != nil {
		t.Fatalf("newGRPCClient() error = %v", err)
	}

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}

	client.conn = conn
	client.client = pb.NewKeystoreServiceClient(conn)
	client.connected = true

	return client
}

func TestGRPCClient_ErrorPaths(t *testing.T) {
	server, lis := setupErrorGRPCServer(t)
	defer server.Stop()

	client := createErrorGRPCClient(t, lis)
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	t.Run("ListBackends error", func(t *testing.T) {
		_, err := client.ListBackends(ctx)
		if err == nil {
			t.Error("ListBackends() should return error")
		}
	})

	t.Run("GetBackend error", func(t *testing.T) {
		_, err := client.GetBackend(ctx, "software")
		if err == nil {
			t.Error("GetBackend() should return error")
		}
	})

	t.Run("GenerateKey error", func(t *testing.T) {
		_, err := client.GenerateKey(ctx, &GenerateKeyRequest{KeyID: "test", Backend: "software"})
		if err == nil {
			t.Error("GenerateKey() should return error")
		}
	})

	t.Run("ListKeys error", func(t *testing.T) {
		_, err := client.ListKeys(ctx, "software")
		if err == nil {
			t.Error("ListKeys() should return error")
		}
	})

	t.Run("GetKey error", func(t *testing.T) {
		_, err := client.GetKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("GetKey() should return error")
		}
	})

	t.Run("DeleteKey error", func(t *testing.T) {
		_, err := client.DeleteKey(ctx, "software", "test-key")
		if err == nil {
			t.Error("DeleteKey() should return error")
		}
	})

	t.Run("Sign error", func(t *testing.T) {
		data, _ := json.Marshal([]byte("test"))
		_, err := client.Sign(ctx, &SignRequest{KeyID: "test", Backend: "software", Data: data})
		if err == nil {
			t.Error("Sign() should return error")
		}
	})

	t.Run("Verify error", func(t *testing.T) {
		data, _ := json.Marshal([]byte("test"))
		sig, _ := json.Marshal([]byte("sig"))
		_, err := client.Verify(ctx, &VerifyRequest{KeyID: "test", Backend: "software", Data: data, Signature: sig})
		if err == nil {
			t.Error("Verify() should return error")
		}
	})

	t.Run("Encrypt error", func(t *testing.T) {
		pt, _ := json.Marshal([]byte("test"))
		_, err := client.Encrypt(ctx, &EncryptRequest{KeyID: "test", Backend: "software", Plaintext: pt})
		if err == nil {
			t.Error("Encrypt() should return error")
		}
	})

	t.Run("Decrypt error", func(t *testing.T) {
		ct, _ := json.Marshal([]byte("test"))
		_, err := client.Decrypt(ctx, &DecryptRequest{KeyID: "test", Backend: "software", Ciphertext: ct})
		if err == nil {
			t.Error("Decrypt() should return error")
		}
	})

	t.Run("GetCertificate error", func(t *testing.T) {
		_, err := client.GetCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("GetCertificate() should return error")
		}
	})

	t.Run("ImportKey error", func(t *testing.T) {
		_, err := client.ImportKey(ctx, &ImportKeyRequest{KeyID: "test", Backend: "software", WrappedKeyMaterial: []byte("test")})
		if err == nil {
			t.Error("ImportKey() should return error")
		}
	})

	t.Run("ExportKey error", func(t *testing.T) {
		_, err := client.ExportKey(ctx, &ExportKeyRequest{KeyID: "test", Backend: "software"})
		if err == nil {
			t.Error("ExportKey() should return error")
		}
	})

	t.Run("RotateKey error", func(t *testing.T) {
		_, err := client.RotateKey(ctx, &RotateKeyRequest{KeyID: "test", Backend: "software"})
		if err == nil {
			t.Error("RotateKey() should return error")
		}
	})

	t.Run("GetImportParameters error", func(t *testing.T) {
		_, err := client.GetImportParameters(ctx, &GetImportParametersRequest{Backend: "software", Algorithm: "RSA"})
		if err == nil {
			t.Error("GetImportParameters() should return error")
		}
	})

	t.Run("WrapKey error", func(t *testing.T) {
		_, err := client.WrapKey(ctx, &WrapKeyRequest{Backend: "software", KeyMaterial: []byte("test")})
		if err == nil {
			t.Error("WrapKey() should return error")
		}
	})

	t.Run("UnwrapKey error", func(t *testing.T) {
		_, err := client.UnwrapKey(ctx, &UnwrapKeyRequest{Backend: "software", WrappedKeyMaterial: []byte("test")})
		if err == nil {
			t.Error("UnwrapKey() should return error")
		}
	})

	t.Run("CopyKey error", func(t *testing.T) {
		_, err := client.CopyKey(ctx, &CopyKeyRequest{SourceBackend: "software", SourceKeyID: "test", DestBackend: "tpm2"})
		if err == nil {
			t.Error("CopyKey() should return error")
		}
	})

	t.Run("ListCertificates error", func(t *testing.T) {
		_, err := client.ListCertificates(ctx, "software")
		if err == nil {
			t.Error("ListCertificates() should return error")
		}
	})

	t.Run("SaveCertificate error", func(t *testing.T) {
		err := client.SaveCertificate(ctx, &SaveCertificateRequest{KeyID: "test", Backend: "software", CertificatePEM: "test"})
		if err == nil {
			t.Error("SaveCertificate() should return error")
		}
	})

	t.Run("DeleteCertificate error", func(t *testing.T) {
		err := client.DeleteCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("DeleteCertificate() should return error")
		}
	})

	t.Run("SaveCertificateChain error", func(t *testing.T) {
		err := client.SaveCertificateChain(ctx, &SaveCertificateChainRequest{KeyID: "test", Backend: "software", ChainPEM: []string{"test"}})
		if err == nil {
			t.Error("SaveCertificateChain() should return error")
		}
	})

	t.Run("GetCertificateChain error", func(t *testing.T) {
		_, err := client.GetCertificateChain(ctx, "software", "test-key")
		if err == nil {
			t.Error("GetCertificateChain() should return error")
		}
	})

	t.Run("GetTLSCertificate error", func(t *testing.T) {
		_, err := client.GetTLSCertificate(ctx, "software", "test-key")
		if err == nil {
			t.Error("GetTLSCertificate() should return error")
		}
	})
}

// Test gRPC Connect error paths
func TestGRPCClient_Connect_CAFileError(t *testing.T) {
	cfg := &Config{
		Address:    "localhost:50051",
		Protocol:   ProtocolGRPC,
		TLSEnabled: true,
		TLSCAFile:  "/nonexistent/ca.pem",
	}

	client, err := newGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newGRPCClient() error = %v", err)
	}

	err = client.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with nonexistent CA file")
	}
}

func TestGRPCClient_Connect_InvalidCA(t *testing.T) {
	// Create temp file with invalid CA
	tmpFile, err := createTempFile(t, "invalid ca content")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg := &Config{
		Address:    "localhost:50051",
		Protocol:   ProtocolGRPC,
		TLSEnabled: true,
		TLSCAFile:  tmpFile,
	}

	client, err := newGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newGRPCClient() error = %v", err)
	}

	err = client.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with invalid CA content")
	}
}

func TestGRPCClient_Connect_CertError(t *testing.T) {
	cfg := &Config{
		Address:     "localhost:50051",
		Protocol:    ProtocolGRPC,
		TLSEnabled:  true,
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	}

	client, err := newGRPCClient(cfg)
	if err != nil {
		t.Fatalf("newGRPCClient() error = %v", err)
	}

	err = client.Connect(context.Background())
	if err == nil {
		t.Error("Connect() should error with nonexistent cert/key files")
	}
}

func createTempFile(t *testing.T, content string) (string, error) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "grpc-test-*")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	tmpFile := filepath.Join(tmpDir, "test.pem")
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		return "", err
	}
	return tmpFile, nil
}
