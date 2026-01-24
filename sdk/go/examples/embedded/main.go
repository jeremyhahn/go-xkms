// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Example demonstrating embedded (in-process) SDK usage.
// This example shows how to use the SDK with direct service calls
// without network overhead.

package main

import (
	"context"
	"fmt"
	"log"

	keychain "github.com/jeremyhahn/go-keychain/sdk/go"
)

// MockKeychainService is a mock implementation of KeychainServicer for demonstration.
// In production, you would use the actual keychain.KeychainService.
type MockKeychainService struct{}

func (m *MockKeychainService) Health(ctx context.Context) (string, string, error) {
	return "healthy", "1.0.0", nil
}

func (m *MockKeychainService) ListBackends(ctx context.Context) ([]keychain.BackendInfo, error) {
	return []keychain.BackendInfo{
		{ID: "software", Type: "software", HardwareBacked: false},
		{ID: "tpm2", Type: "tpm2", HardwareBacked: true},
	}, nil
}

func (m *MockKeychainService) GetBackend(ctx context.Context, backendID string) (*keychain.BackendInfo, error) {
	return &keychain.BackendInfo{ID: backendID, Type: "software"}, nil
}

func (m *MockKeychainService) GenerateKey(ctx context.Context, req *keychain.GenerateKeyRequest) (*keychain.GenerateKeyResponse, error) {
	return &keychain.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----",
	}, nil
}

func (m *MockKeychainService) ListKeys(ctx context.Context, backend string) (*keychain.ListKeysResponse, error) {
	return &keychain.ListKeysResponse{Keys: []keychain.KeyInfo{}}, nil
}

func (m *MockKeychainService) GetKey(ctx context.Context, backend, keyID string) (*keychain.GetKeyResponse, error) {
	return &keychain.GetKeyResponse{KeyInfo: keychain.KeyInfo{KeyID: keyID}}, nil
}

func (m *MockKeychainService) DeleteKey(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *MockKeychainService) Sign(ctx context.Context, req *keychain.SignRequest) (*keychain.SignResponse, error) {
	return &keychain.SignResponse{Signature: []byte("mock-signature")}, nil
}

func (m *MockKeychainService) Verify(ctx context.Context, req *keychain.VerifyRequest) (*keychain.VerifyResponse, error) {
	return &keychain.VerifyResponse{Valid: true}, nil
}

func (m *MockKeychainService) Encrypt(ctx context.Context, req *keychain.EncryptRequest) (*keychain.EncryptResponse, error) {
	return &keychain.EncryptResponse{Ciphertext: []byte("mock-ciphertext")}, nil
}

func (m *MockKeychainService) Decrypt(ctx context.Context, req *keychain.DecryptRequest) (*keychain.DecryptResponse, error) {
	return &keychain.DecryptResponse{Plaintext: []byte("mock-plaintext")}, nil
}

func (m *MockKeychainService) EncryptAsym(ctx context.Context, req *keychain.EncryptAsymRequest) (*keychain.EncryptAsymResponse, error) {
	return &keychain.EncryptAsymResponse{Ciphertext: []byte("mock-ciphertext")}, nil
}

func (m *MockKeychainService) GetCertificate(ctx context.Context, backend, keyID string) (*keychain.GetCertificateResponse, error) {
	return &keychain.GetCertificateResponse{KeyID: keyID}, nil
}

func (m *MockKeychainService) SaveCertificate(ctx context.Context, req *keychain.SaveCertificateRequest) error {
	return nil
}

func (m *MockKeychainService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *MockKeychainService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *MockKeychainService) ImportKey(ctx context.Context, req *keychain.ImportKeyRequest) (*keychain.ImportKeyResponse, error) {
	return &keychain.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) ExportKey(ctx context.Context, req *keychain.ExportKeyRequest) (*keychain.ExportKeyResponse, error) {
	return &keychain.ExportKeyResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) RotateKey(ctx context.Context, req *keychain.RotateKeyRequest) (*keychain.RotateKeyResponse, error) {
	return &keychain.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) ListKeyVersions(ctx context.Context, req *keychain.ListKeyVersionsRequest) (*keychain.ListKeyVersionsResponse, error) {
	return &keychain.ListKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) EnableKeyVersion(ctx context.Context, req *keychain.EnableKeyVersionRequest) (*keychain.EnableKeyVersionResponse, error) {
	return &keychain.EnableKeyVersionResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) DisableKeyVersion(ctx context.Context, req *keychain.DisableKeyVersionRequest) (*keychain.DisableKeyVersionResponse, error) {
	return &keychain.DisableKeyVersionResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) EnableAllKeyVersions(ctx context.Context, req *keychain.EnableAllKeyVersionsRequest) (*keychain.EnableAllKeyVersionsResponse, error) {
	return &keychain.EnableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) DisableAllKeyVersions(ctx context.Context, req *keychain.DisableAllKeyVersionsRequest) (*keychain.DisableAllKeyVersionsResponse, error) {
	return &keychain.DisableAllKeyVersionsResponse{KeyID: req.KeyID}, nil
}

func (m *MockKeychainService) GetImportParameters(ctx context.Context, req *keychain.GetImportParametersRequest) (*keychain.GetImportParametersResponse, error) {
	return &keychain.GetImportParametersResponse{}, nil
}

func (m *MockKeychainService) WrapKey(ctx context.Context, req *keychain.WrapKeyRequest) (*keychain.WrapKeyResponse, error) {
	return &keychain.WrapKeyResponse{}, nil
}

func (m *MockKeychainService) UnwrapKey(ctx context.Context, req *keychain.UnwrapKeyRequest) (*keychain.UnwrapKeyResponse, error) {
	return &keychain.UnwrapKeyResponse{}, nil
}

func (m *MockKeychainService) CopyKey(ctx context.Context, req *keychain.CopyKeyRequest) (*keychain.CopyKeyResponse, error) {
	return &keychain.CopyKeyResponse{Success: true}, nil
}

func (m *MockKeychainService) ListCertificates(ctx context.Context, backend string) (*keychain.ListCertificatesResponse, error) {
	return &keychain.ListCertificatesResponse{}, nil
}

func (m *MockKeychainService) SaveCertificateChain(ctx context.Context, req *keychain.SaveCertificateChainRequest) error {
	return nil
}

func (m *MockKeychainService) GetCertificateChain(ctx context.Context, backend, keyID string) (*keychain.GetCertificateChainResponse, error) {
	return &keychain.GetCertificateChainResponse{KeyID: keyID}, nil
}

func (m *MockKeychainService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*keychain.GetTLSCertificateResponse, error) {
	return &keychain.GetTLSCertificateResponse{KeyID: keyID}, nil
}

func (m *MockKeychainService) Seal(ctx context.Context, req *keychain.SealRequest) (*keychain.SealResponse, error) {
	return &keychain.SealResponse{Ciphertext: []byte("sealed")}, nil
}

func (m *MockKeychainService) Unseal(ctx context.Context, req *keychain.UnsealRequest) (*keychain.UnsealResponse, error) {
	return &keychain.UnsealResponse{Plaintext: []byte("unsealed")}, nil
}

func (m *MockKeychainService) CanSeal(ctx context.Context, backend string) (*keychain.CanSealResponse, error) {
	return &keychain.CanSealResponse{CanSeal: true, Backend: backend}, nil
}

// User management methods

func (m *MockKeychainService) ListUsers(ctx context.Context) (*keychain.ListUsersResponse, error) {
	return &keychain.ListUsersResponse{Users: []keychain.UserInfo{}}, nil
}

func (m *MockKeychainService) GetUser(ctx context.Context, username string) (*keychain.GetUserResponse, error) {
	return &keychain.GetUserResponse{User: keychain.UserInfo{Username: username}}, nil
}

func (m *MockKeychainService) DeleteUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockKeychainService) EnableUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockKeychainService) DisableUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockKeychainService) ListUserCredentials(ctx context.Context, username string) (*keychain.ListUserCredentialsResponse, error) {
	return &keychain.ListUserCredentialsResponse{Credentials: []keychain.CredentialInfo{}}, nil
}

// Authentication flow methods

func (m *MockKeychainService) BeginRegistration(ctx context.Context, req *keychain.BeginRegistrationRequest) (*keychain.BeginRegistrationResponse, error) {
	return &keychain.BeginRegistrationResponse{
		Challenge: "mock-challenge",
		UserID:    "mock-user-id",
		RPID:      req.RPID,
		RPName:    req.RPName,
	}, nil
}

func (m *MockKeychainService) FinishRegistration(ctx context.Context, req *keychain.FinishRegistrationRequest) (*keychain.FinishRegistrationResponse, error) {
	return &keychain.FinishRegistrationResponse{
		Success:      true,
		CredentialID: req.CredentialID,
	}, nil
}

func (m *MockKeychainService) BeginAuthentication(ctx context.Context, req *keychain.BeginAuthenticationRequest) (*keychain.BeginAuthenticationResponse, error) {
	return &keychain.BeginAuthenticationResponse{
		Challenge: "mock-challenge",
		RPID:      req.RPID,
	}, nil
}

func (m *MockKeychainService) FinishAuthentication(ctx context.Context, req *keychain.FinishAuthenticationRequest) (*keychain.FinishAuthenticationResponse, error) {
	return &keychain.FinishAuthenticationResponse{
		Success: true,
		Token:   "mock-jwt-token",
	}, nil
}

func main() {
	ctx := context.Background()

	// Create the mock service (in production, use actual KeychainService)
	service := &MockKeychainService{}

	// Create an embedded client
	client, err := keychain.NewEmbedded(service)
	if err != nil {
		log.Fatalf("Failed to create embedded client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Failed to close client: %v", err)
		}
	}()

	// No need to call Connect() for embedded - already connected
	fmt.Println("Created embedded client (no network overhead)")

	// Check health (direct call, no serialization)
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}
	fmt.Printf("Service status: %s (version: %s)\n", health.Status, health.Version)

	// List backends
	backends, err := client.ListBackends(ctx)
	if err != nil {
		log.Fatalf("Failed to list backends: %v", err)
	}
	fmt.Printf("Available backends: %d\n", len(backends.Backends))
	for _, b := range backends.Backends {
		hw := ""
		if b.HardwareBacked {
			hw = " [hardware]"
		}
		fmt.Printf("  - %s%s\n", b.ID, hw)
	}

	// Generate a key
	keyResp, err := client.GenerateKey(ctx, &keychain.GenerateKeyRequest{
		KeyID:   "embedded-key",
		Backend: "software",
		KeyType: "EC",
		Curve:   "P-256",
	})
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("Generated key: %s\n", keyResp.KeyID)

	// Sign and verify
	signResp, err := client.Sign(ctx, &keychain.SignRequest{
		Backend: "software",
		KeyID:   "embedded-key",
		Data:    []byte("Hello, embedded!"),
	})
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	fmt.Printf("Signed data with embedded client\n")

	verifyResp, err := client.Verify(ctx, &keychain.VerifyRequest{
		Backend:   "software",
		KeyID:     "embedded-key",
		Data:      []byte("Hello, embedded!"),
		Signature: signResp.Signature,
	})
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}
	fmt.Printf("Signature valid: %t\n", verifyResp.Valid)

	fmt.Println("\nEmbedded mode provides the fastest possible access")
	fmt.Println("without network overhead or serialization costs.")
}
