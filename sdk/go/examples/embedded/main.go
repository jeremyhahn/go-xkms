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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockUnsupportedError reports that a capability is not implemented by the
// mock XKMS service used in this example.
type mockUnsupportedError struct {
	capability string
}

// Error returns a human-readable description.
func (e *mockUnsupportedError) Error() string {
	return e.capability + " not supported in mock"
}

// MockXKMSService is a mock implementation of XKMSServicer for demonstration.
// In production, you would use the actual xkms.XKMSService.
type MockXKMSService struct{}

func (m *MockXKMSService) Health(ctx context.Context) (string, string, error) {
	return "healthy", "1.0.0", nil
}

func (m *MockXKMSService) ListBackends(ctx context.Context, opts ...xkms.ListOption) ([]xkms.BackendInfo, error) {
	return []xkms.BackendInfo{
		{ID: "software", Type: "software", HardwareBacked: false},
		{ID: "tpm2", Type: "tpm2", HardwareBacked: true},
	}, nil
}

func (m *MockXKMSService) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, &mockUnsupportedError{capability: "algorithm discovery"}
}

func (m *MockXKMSService) GetBackend(ctx context.Context, backendID string) (*xkms.BackendInfo, error) {
	return &xkms.BackendInfo{ID: backendID, Type: "software"}, nil
}

func (m *MockXKMSService) GenerateKey(ctx context.Context, req *xkms.GenerateKeyRequest) (*xkms.GenerateKeyResponse, error) {
	return &xkms.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----",
	}, nil
}

func (m *MockXKMSService) ListKeys(ctx context.Context, backend string, opts ...xkms.ListOption) (*xkms.ListKeysResponse, error) {
	return &xkms.ListKeysResponse{Keys: []xkms.KeyInfo{}}, nil
}

func (m *MockXKMSService) GetKey(ctx context.Context, backend, keyID string) (*xkms.GetKeyResponse, error) {
	return &xkms.GetKeyResponse{KeyInfo: xkms.KeyInfo{KeyID: keyID}}, nil
}

func (m *MockXKMSService) DeleteKey(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *MockXKMSService) Sign(ctx context.Context, req *xkms.SignRequest) (*xkms.SignResponse, error) {
	return &xkms.SignResponse{Signature: []byte("mock-signature")}, nil
}

func (m *MockXKMSService) Verify(ctx context.Context, req *xkms.VerifyRequest) (*xkms.VerifyResponse, error) {
	return &xkms.VerifyResponse{Valid: true}, nil
}

func (m *MockXKMSService) Encrypt(ctx context.Context, req *xkms.EncryptRequest) (*xkms.EncryptResponse, error) {
	return &xkms.EncryptResponse{Ciphertext: []byte("mock-ciphertext")}, nil
}

func (m *MockXKMSService) Decrypt(ctx context.Context, req *xkms.DecryptRequest) (*xkms.DecryptResponse, error) {
	return &xkms.DecryptResponse{Plaintext: []byte("mock-plaintext")}, nil
}

func (m *MockXKMSService) EncryptAsym(ctx context.Context, req *xkms.EncryptAsymRequest) (*xkms.EncryptAsymResponse, error) {
	return &xkms.EncryptAsymResponse{Ciphertext: []byte("mock-ciphertext")}, nil
}

func (m *MockXKMSService) GetCertificate(ctx context.Context, backend, keyID string) (*xkms.GetCertificateResponse, error) {
	return &xkms.GetCertificateResponse{KeyID: keyID}, nil
}

func (m *MockXKMSService) SaveCertificate(ctx context.Context, req *xkms.SaveCertificateRequest) error {
	return nil
}

func (m *MockXKMSService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *MockXKMSService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *MockXKMSService) ImportKey(ctx context.Context, req *xkms.ImportKeyRequest) (*xkms.ImportKeyResponse, error) {
	return &xkms.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *MockXKMSService) ExportKey(ctx context.Context, req *xkms.ExportKeyRequest) (*xkms.ExportKeyResponse, error) {
	return &xkms.ExportKeyResponse{KeyID: req.KeyID}, nil
}

func (m *MockXKMSService) RotateKey(ctx context.Context, req *xkms.RotateKeyRequest) (*xkms.RotateKeyResponse, error) {
	return &xkms.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *MockXKMSService) CreateOTAImageKey(ctx context.Context, req *xkms.OTAImageKeyRequest) (*xkms.GenerateKeyResponse, error) {
	return &xkms.GenerateKeyResponse{KeyID: "ota-image-" + req.BoardID, KeyType: "SIGNING"}, nil
}

func (m *MockXKMSService) RotateOTAImageKey(ctx context.Context, req *xkms.OTAImageKeyRequest) (*xkms.RotateKeyResponse, error) {
	return &xkms.RotateKeyResponse{Success: true, KeyID: "ota-image-" + req.BoardID, KeyVersion: 2}, nil
}

func (m *MockXKMSService) SignOTAImage(ctx context.Context, req *xkms.OTAImageSignRequest) (*xkms.SignResponse, error) {
	return &xkms.SignResponse{Signature: []byte("mock-signature"), KeyVersion: 1}, nil
}

func (m *MockXKMSService) ExportOTAImageKey(ctx context.Context, req *xkms.OTAImageKeyRequest) (*xkms.ExportOTAImageKeyResponse, error) {
	return &xkms.ExportOTAImageKeyResponse{BoardID: req.BoardID, KeyID: "ota-image-" + req.BoardID, KeyVersion: 1, Algorithm: "ES256"}, nil
}

func (m *MockXKMSService) GetImportParameters(ctx context.Context, req *xkms.GetImportParametersRequest) (*xkms.GetImportParametersResponse, error) {
	return &xkms.GetImportParametersResponse{}, nil
}

func (m *MockXKMSService) WrapKey(ctx context.Context, req *xkms.WrapKeyRequest) (*xkms.WrapKeyResponse, error) {
	return &xkms.WrapKeyResponse{}, nil
}

func (m *MockXKMSService) UnwrapKey(ctx context.Context, req *xkms.UnwrapKeyRequest) (*xkms.UnwrapKeyResponse, error) {
	return &xkms.UnwrapKeyResponse{}, nil
}

func (m *MockXKMSService) CopyKey(ctx context.Context, req *xkms.CopyKeyRequest) (*xkms.CopyKeyResponse, error) {
	return &xkms.CopyKeyResponse{Success: true}, nil
}

func (m *MockXKMSService) ListCertificates(ctx context.Context, backend string, opts ...xkms.ListOption) (*xkms.ListCertificatesResponse, error) {
	return &xkms.ListCertificatesResponse{}, nil
}

func (m *MockXKMSService) SaveCertificateChain(ctx context.Context, req *xkms.SaveCertificateChainRequest) error {
	return nil
}

func (m *MockXKMSService) GetCertificateChain(ctx context.Context, backend, keyID string) (*xkms.GetCertificateChainResponse, error) {
	return &xkms.GetCertificateChainResponse{KeyID: keyID}, nil
}

func (m *MockXKMSService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*xkms.GetTLSCertificateResponse, error) {
	return &xkms.GetTLSCertificateResponse{KeyID: keyID}, nil
}

func (m *MockXKMSService) Seal(ctx context.Context, req *xkms.SealRequest) (*xkms.SealResponse, error) {
	return &xkms.SealResponse{Ciphertext: []byte("sealed")}, nil
}

func (m *MockXKMSService) Unseal(ctx context.Context, req *xkms.UnsealRequest) (*xkms.UnsealResponse, error) {
	return &xkms.UnsealResponse{Plaintext: []byte("unsealed")}, nil
}

func (m *MockXKMSService) CanSeal(ctx context.Context, backend string) (*xkms.CanSealResponse, error) {
	return &xkms.CanSealResponse{CanSeal: true, Backend: backend}, nil
}

func (m *MockXKMSService) AttestKey(ctx context.Context, req *xkms.AttestKeyRequest) (*xkms.AttestKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "attestation"}
}

// Authentication flow methods

func (m *MockXKMSService) BeginRegistration(ctx context.Context, req *xkms.BeginRegistrationRequest) (*xkms.BeginRegistrationResponse, error) {
	return &xkms.BeginRegistrationResponse{
		SessionID:   "mock-session-id",
		OptionsJSON: `{"publicKey":{"challenge":"bW9jay1jaGFsbGVuZ2U"}}`,
	}, nil
}

func (m *MockXKMSService) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
	return &xkms.FinishRegistrationResponse{
		Success:      true,
		CredentialID: "mock-credential-id",
		Token:        "mock-jwt-token",
	}, nil
}

func (m *MockXKMSService) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
	return &xkms.BeginAuthenticationResponse{
		SessionID:   "mock-session-id",
		OptionsJSON: `{"publicKey":{"challenge":"bW9jay1jaGFsbGVuZ2U"}}`,
	}, nil
}

func (m *MockXKMSService) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
	return &xkms.FinishAuthenticationResponse{
		Success:  true,
		Token:    "mock-jwt-token",
		Username: req.Email,
	}, nil
}

func (m *MockXKMSService) GetInvite(ctx context.Context, req *xkms.GetInviteRequest) (*xkms.GetInviteResponse, error) {
	return nil, xkms.ErrNotSupported
}

func (m *MockXKMSService) BeginInviteRegistration(ctx context.Context, req *xkms.BeginInviteRegistrationRequest) (*xkms.BeginInviteRegistrationResponse, error) {
	return nil, xkms.ErrNotSupported
}

func (m *MockXKMSService) FinishInviteRegistration(ctx context.Context, req *xkms.FinishInviteRegistrationRequest) (*xkms.FinishInviteRegistrationResponse, error) {
	return nil, xkms.ErrNotSupported
}

func (m *MockXKMSService) ActivateInvitePIV(ctx context.Context, req *xkms.ActivateInvitePIVRequest) (*xkms.ActivateInvitePIVResponse, error) {
	return nil, xkms.ErrNotSupported
}

func (m *MockXKMSService) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return &transport.DeriveKeyResponse{
		DerivedKey: []byte("mock-derived-key"),
		Algorithm:  req.Algorithm,
		KeyLength:  32,
	}, nil
}

func (m *MockXKMSService) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: []byte("mock-key-material"),
		KeyType:     "aes256-gcm",
		KeySize:     256,
	}, nil
}

func (m *MockXKMSService) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return &transport.WrapKeyByIDResponse{
		WrappedKey: []byte("mock-wrapped-key"),
		Algorithm:  req.Algorithm,
	}, nil
}

func (m *MockXKMSService) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return &transport.UnwrapKeyByIDResponse{
		KeyID: req.TargetKeyID,
	}, nil
}

func (m *MockXKMSService) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return &transport.DeriveKeyECDHResponse{
		DerivedKey: []byte("mock-ecdh-derived-key"),
	}, nil
}

func (m *MockXKMSService) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, &mockUnsupportedError{capability: "CA bundle"}
}

func (m *MockXKMSService) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "CA certificate"}
}

func (m *MockXKMSService) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, &mockUnsupportedError{capability: "CSR signing"}
}

func (m *MockXKMSService) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "certificate issuance"}
}

func (m *MockXKMSService) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "certificate revocation"}
}

func (m *MockXKMSService) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, &mockUnsupportedError{capability: "CRL generation"}
}

func (m *MockXKMSService) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, &mockUnsupportedError{capability: "revocation check"}
}

// TCG CA operations

func (m *MockXKMSService) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "TCG CA"}
}

func (m *MockXKMSService) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "TCG CA"}
}

func (m *MockXKMSService) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, &mockUnsupportedError{capability: "TCG CA"}
}

func (m *MockXKMSService) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, &mockUnsupportedError{capability: "TCG CA"}
}

func (m *MockXKMSService) IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "TCG CA"}
}

// PIV operations

func (m *MockXKMSService) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIV"}
}

func (m *MockXKMSService) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, &mockUnsupportedError{capability: "credentials"}
}

func (m *MockXKMSService) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, &mockUnsupportedError{capability: "credentials"}
}

func (m *MockXKMSService) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) ListUsers(ctx context.Context, opts ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	return nil, &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) DeleteUser(ctx context.Context, username string) error {
	return &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) EnableUser(ctx context.Context, username string) error {
	return &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) DisableUser(ctx context.Context, username string) error {
	return &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	return &mockUnsupportedError{capability: "users"}
}

func (m *MockXKMSService) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	return nil, &mockUnsupportedError{capability: "users"}
}

func main() {
	ctx := context.Background()

	// Create the mock service (in production, use actual XKMSService)
	service := &MockXKMSService{}

	// Create an embedded client
	client, err := xkms.NewEmbedded(service)
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
	keyResp, err := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
		KeyID:     "embedded-key",
		Backend:   "software",
		KeyType:   "signing",
		Algorithm: "EC",
		Curve:     "P-256",
	})
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("Generated key: %s\n", keyResp.KeyID)

	// Sign and verify
	signResp, err := client.Sign(ctx, &xkms.SignRequest{
		Backend: "software",
		KeyID:   "embedded-key",
		Data:    []byte("Hello, embedded!"),
	})
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	fmt.Printf("Signed data with embedded client\n")

	verifyResp, err := client.Verify(ctx, &xkms.VerifyRequest{
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

// Barrier operations

func (m *MockXKMSService) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, &mockUnsupportedError{capability: "bootstrap"}
}

// PIN operations

func (m *MockXKMSService) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "PIN"}
}

func (m *MockXKMSService) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return &mockUnsupportedError{capability: "PIN"}
}

// Password store operations

func (m *MockXKMSService) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordStoreLock(ctx context.Context) error {
	return &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return &mockUnsupportedError{capability: "password store"}
}

func (m *MockXKMSService) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, &mockUnsupportedError{capability: "password store"}
}

// Personal password vault operations. The mock has no password store, so it
// has no per-user vault either; a real XKMSService wraps each user's
// personal-entry key under the user's passphrase or passkey.

func (m *MockXKMSService) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "password vault"}
}

func (m *MockXKMSService) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, &mockUnsupportedError{capability: "password vault"}
}

func (m *MockXKMSService) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, &mockUnsupportedError{capability: "password vault"}
}

func (m *MockXKMSService) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	return &mockUnsupportedError{capability: "password vault"}
}

func (m *MockXKMSService) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, &mockUnsupportedError{capability: "password vault"}
}

// Platform store operations

func (m *MockXKMSService) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return &mockUnsupportedError{capability: "platform store"}
}

func (m *MockXKMSService) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, &mockUnsupportedError{capability: "platform store"}
}

func (m *MockXKMSService) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return &mockUnsupportedError{capability: "platform store"}
}

func (m *MockXKMSService) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, &mockUnsupportedError{capability: "platform store"}
}

func (m *MockXKMSService) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return &mockUnsupportedError{capability: "platform store"}
}

func (m *MockXKMSService) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "platform store"}
}

// Escrow operations

func (m *MockXKMSService) EscrowKey(ctx context.Context, req *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, &mockUnsupportedError{capability: "escrow"}
}

func (m *MockXKMSService) RecoverKey(ctx context.Context, req *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, &mockUnsupportedError{capability: "escrow"}
}

func (m *MockXKMSService) ListEscrowed(ctx context.Context) ([]transport.EscrowRecord, error) {
	return nil, &mockUnsupportedError{capability: "escrow"}
}

func (m *MockXKMSService) RevokeEscrow(ctx context.Context, escrowID string) error {
	return &mockUnsupportedError{capability: "escrow"}
}

// Policy operations

func (m *MockXKMSService) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, &mockUnsupportedError{capability: "key versions"}
}

func (m *MockXKMSService) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

// OIDC credential operations are not exercised by this double.
func (*MockXKMSService) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, &mockUnsupportedError{capability: "trust roots"}
}
func (*MockXKMSService) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, &mockUnsupportedError{capability: "trust roots"}
}
func (*MockXKMSService) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, &mockUnsupportedError{capability: "trust roots"}
}
func (*MockXKMSService) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, &mockUnsupportedError{capability: "trust roots"}
}
func (*MockXKMSService) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return &mockUnsupportedError{capability: "trust roots"}
}
func (*MockXKMSService) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}
func (*MockXKMSService) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, &mockUnsupportedError{capability: "oidc credentials"}
}

func (m *MockXKMSService) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "policy"}
}

func (m *MockXKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, &mockUnsupportedError{capability: "tenant"}
}

func (m *MockXKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return nil, &mockUnsupportedError{capability: "tenant"}
}

func (m *MockXKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return nil, &mockUnsupportedError{capability: "tenant"}
}

func (m *MockXKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	return &mockUnsupportedError{capability: "tenant"}
}

func (m *MockXKMSService) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *MockXKMSService) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

func (m *MockXKMSService) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, &mockUnsupportedError{capability: "crypto utility"}
}

func (m *MockXKMSService) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (m *MockXKMSService) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, &mockUnsupportedError{capability: "key management"}
}

func (*MockXKMSService) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*MockXKMSService) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*MockXKMSService) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*MockXKMSService) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*MockXKMSService) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
