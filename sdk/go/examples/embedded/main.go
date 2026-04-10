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

	"github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

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
	return nil, fmt.Errorf("attestation not supported in mock")
}

// User management methods

func (m *MockXKMSService) ListUsers(ctx context.Context, opts ...xkms.ListOption) (*xkms.ListUsersResponse, error) {
	return &xkms.ListUsersResponse{Users: []xkms.UserInfo{}}, nil
}

func (m *MockXKMSService) GetUser(ctx context.Context, username string) (*xkms.GetUserResponse, error) {
	return &xkms.GetUserResponse{User: xkms.UserInfo{Username: username}}, nil
}

func (m *MockXKMSService) DeleteUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockXKMSService) EnableUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockXKMSService) DisableUser(ctx context.Context, username string) error {
	return nil
}

func (m *MockXKMSService) ListUserCredentials(ctx context.Context, username string) (*xkms.ListUserCredentialsResponse, error) {
	return &xkms.ListUserCredentialsResponse{Credentials: []xkms.CredentialInfo{}}, nil
}

// Authentication flow methods

func (m *MockXKMSService) BeginRegistration(ctx context.Context, req *xkms.BeginRegistrationRequest) (*xkms.BeginRegistrationResponse, error) {
	return &xkms.BeginRegistrationResponse{
		Challenge: "mock-challenge",
		UserID:    "mock-user-id",
		RPID:      req.RPID,
		RPName:    req.RPName,
	}, nil
}

func (m *MockXKMSService) FinishRegistration(ctx context.Context, req *xkms.FinishRegistrationRequest) (*xkms.FinishRegistrationResponse, error) {
	return &xkms.FinishRegistrationResponse{
		Success:      true,
		CredentialID: req.CredentialID,
	}, nil
}

func (m *MockXKMSService) BeginAuthentication(ctx context.Context, req *xkms.BeginAuthenticationRequest) (*xkms.BeginAuthenticationResponse, error) {
	return &xkms.BeginAuthenticationResponse{
		Challenge: "mock-challenge",
		RPID:      req.RPID,
	}, nil
}

func (m *MockXKMSService) FinishAuthentication(ctx context.Context, req *xkms.FinishAuthenticationRequest) (*xkms.FinishAuthenticationResponse, error) {
	return &xkms.FinishAuthenticationResponse{
		Success: true,
		Token:   "mock-jwt-token",
	}, nil
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
	return nil, fmt.Errorf("CA bundle not supported in mock")
}

func (m *MockXKMSService) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, fmt.Errorf("CA certificate not supported in mock")
}

func (m *MockXKMSService) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, fmt.Errorf("CSR signing not supported in mock")
}

func (m *MockXKMSService) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, fmt.Errorf("certificate issuance not supported in mock")
}

func (m *MockXKMSService) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, fmt.Errorf("certificate revocation not supported in mock")
}

func (m *MockXKMSService) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, fmt.Errorf("CRL generation not supported in mock")
}

func (m *MockXKMSService) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, fmt.Errorf("revocation check not supported in mock")
}

// TCG CA operations

func (m *MockXKMSService) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, fmt.Errorf("TCG CA not supported in mock")
}

func (m *MockXKMSService) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, fmt.Errorf("TCG CA not supported in mock")
}

func (m *MockXKMSService) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, fmt.Errorf("TCG CA not supported in mock")
}

func (m *MockXKMSService) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, fmt.Errorf("TCG CA not supported in mock")
}

// PIV operations

func (m *MockXKMSService) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, fmt.Errorf("PIV not supported in mock")
}

func (m *MockXKMSService) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	return nil, fmt.Errorf("init ceremony not supported in mock")
}

func (m *MockXKMSService) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, fmt.Errorf("init ceremony not supported in mock")
}

func (m *MockXKMSService) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, fmt.Errorf("init ceremony not supported in mock")
}

func (m *MockXKMSService) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, fmt.Errorf("init ceremony not supported in mock")
}

func (m *MockXKMSService) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, fmt.Errorf("init ceremony not supported in mock")
}

func (m *MockXKMSService) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, fmt.Errorf("credentials not supported in mock")
}

func (m *MockXKMSService) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, fmt.Errorf("credentials not supported in mock")
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

func (m *MockXKMSService) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierSeal(ctx context.Context) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierShamirListShares(ctx context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierShamirDeleteShare(ctx context.Context, req *transport.BarrierShamirDeleteShareRequest) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierShamirDeleteAllShares(ctx context.Context) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierShamirVerify(ctx context.Context) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	return fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

func (m *MockXKMSService) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, fmt.Errorf("barrier not supported in mock")
}

// PIN operations

func (m *MockXKMSService) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, fmt.Errorf("PIN not supported in mock")
}

func (m *MockXKMSService) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return fmt.Errorf("PIN not supported in mock")
}

// Password store operations

func (m *MockXKMSService) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordStoreLock(ctx context.Context) error {
	return fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return fmt.Errorf("password store not supported in mock")
}

func (m *MockXKMSService) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, fmt.Errorf("password store not supported in mock")
}

// Platform store operations

func (m *MockXKMSService) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return fmt.Errorf("platform store not supported in mock")
}

func (m *MockXKMSService) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, fmt.Errorf("platform store not supported in mock")
}

func (m *MockXKMSService) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return fmt.Errorf("platform store not supported in mock")
}

func (m *MockXKMSService) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, fmt.Errorf("platform store not supported in mock")
}

func (m *MockXKMSService) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return fmt.Errorf("platform store not supported in mock")
}

func (m *MockXKMSService) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, fmt.Errorf("platform store not supported in mock")
}

// Policy operations

func (m *MockXKMSService) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	return fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, fmt.Errorf("policy not supported in mock")
}

func (m *MockXKMSService) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	return nil, fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	return fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, fmt.Errorf("custodian not supported in mock")
}

func (m *MockXKMSService) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, fmt.Errorf("share not supported in mock")
}

func (m *MockXKMSService) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	return nil, fmt.Errorf("share not supported in mock")
}

func (m *MockXKMSService) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	return nil, fmt.Errorf("share not supported in mock")
}

func (m *MockXKMSService) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, fmt.Errorf("tenant not supported in mock")
}

func (m *MockXKMSService) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return nil, fmt.Errorf("tenant not supported in mock")
}

func (m *MockXKMSService) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return nil, fmt.Errorf("tenant not supported in mock")
}

func (m *MockXKMSService) DeleteTenant(ctx context.Context, tenantID string) error {
	return fmt.Errorf("tenant not supported in mock")
}

func (m *MockXKMSService) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return fmt.Errorf("tenant not supported in mock")
}

func (m *MockXKMSService) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return fmt.Errorf("tenant not supported in mock")
}
