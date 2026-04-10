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

// Package embedded provides an embedded (in-process) transport implementation
// for the xkms SDK. This transport makes direct function calls without
// any network overhead.
package embedded

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

var (
	// ErrNilService is returned when a nil service is provided.
	ErrNilService = errors.New("xkms service is required")
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
)

// Transport implements the transport.Client interface using direct in-process calls.
// This provides the fastest possible access with no network overhead.
type Transport struct {
	config    *transport.Config
	service   XKMSServicer
	connected bool
}

// New creates a new embedded transport with the given service.
func New(service XKMSServicer, opts ...transport.Option) (*Transport, error) {
	if service == nil {
		return nil, ErrNilService
	}

	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return &Transport{
		config:    cfg,
		service:   service,
		connected: true,
	}, nil
}

// NewWithConfig creates a new embedded transport with the given configuration.
// Note: The service must be provided separately via SetService.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	return &Transport{
		config:    cfg,
		connected: false, // Not connected until service is set
	}, nil
}

// NewWithService creates a new embedded transport with the given service using default configuration.
// This is a convenience function that combines New with default options.
func NewWithService(service XKMSServicer) (*Transport, error) {
	return New(service)
}

// SetService sets the service for the embedded transport.
func (t *Transport) SetService(service XKMSServicer) error {
	if service == nil {
		return ErrNilService
	}
	t.service = service
	t.connected = true
	return nil
}

// Service returns the underlying service.
func (t *Transport) Service() XKMSServicer {
	return t.service
}

// Connect is a no-op for embedded transport (already connected if service is set).
func (t *Transport) Connect(ctx context.Context) error {
	if t.service == nil {
		return ErrNilService
	}
	t.connected = true
	return nil
}

// Close is a no-op for embedded transport.
func (t *Transport) Close() error {
	t.connected = false
	return nil
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Health checks the health of the service.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	status, version, err := t.service.Health(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.HealthResponse{
		Status:  status,
		Version: version,
	}, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context, opts ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	backends, err := t.service.ListBackends(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &transport.ListBackendsResponse{
		Backends: backends,
	}, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetBackend(ctx, backendID)
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GenerateKey(ctx, req)
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListKeys(ctx, backend, opts...)
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetKey(ctx, backend, keyID)
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	err := t.service.DeleteKey(ctx, backend, keyID)
	if err != nil {
		return nil, err
	}
	return &transport.DeleteKeyResponse{
		Success: true,
		Message: "Key deleted successfully",
	}, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Sign(ctx, req)
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Verify(ctx, req)
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Encrypt(ctx, req)
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Decrypt(ctx, req)
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.EncryptAsym(ctx, req)
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (t *Transport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.DeriveKey(ctx, req)
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCertificate(ctx, backend, keyID)
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SaveCertificate(ctx, req)
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteCertificate(ctx, backend, keyID)
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	if !t.connected {
		return false, ErrNotConnected
	}
	return t.service.CertificateExists(ctx, backend, keyID)
}

// ImportKey imports a key.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ImportKey(ctx, req)
}

// ExportKey exports a key.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ExportKey(ctx, req)
}

// RotateKey rotates a key.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.RotateKey(ctx, req)
}

// GetImportParameters gets the parameters needed to import a key.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetImportParameters(ctx, req)
}

// WrapKey wraps key material for secure transport.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.WrapKey(ctx, req)
}

// UnwrapKey unwraps key material.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.UnwrapKey(ctx, req)
}

// CopyKey copies a key from one backend to another.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.CopyKey(ctx, req)
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string, opts ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListCertificates(ctx, backend, opts...)
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SaveCertificateChain(ctx, req)
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCertificateChain(ctx, backend, keyID)
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTLSCertificate(ctx, backend, keyID)
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Seal(ctx, req)
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.Unseal(ctx, req)
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.CanSeal(ctx, backend)
}

// AttestKey requests key attestation from a backend, proving the key
// is stored in hardware (TPM2, Android TEE/StrongBox, etc.).
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.AttestKey(ctx, req)
}

// ListUsers returns a list of all users.
func (t *Transport) ListUsers(ctx context.Context, opts ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListUsers(ctx, opts...)
}

// GetUser returns information about a specific user.
func (t *Transport) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetUser(ctx, username)
}

// DeleteUser deletes a user.
func (t *Transport) DeleteUser(ctx context.Context, username string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteUser(ctx, username)
}

// EnableUser enables a user account.
func (t *Transport) EnableUser(ctx context.Context, username string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.EnableUser(ctx, username)
}

// DisableUser disables a user account.
func (t *Transport) DisableUser(ctx context.Context, username string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DisableUser(ctx, username)
}

// ListUserCredentials returns a list of credentials for a user.
func (t *Transport) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListUserCredentials(ctx, username)
}

// BeginRegistration begins a WebAuthn registration flow.
func (t *Transport) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BeginRegistration(ctx, req)
}

// FinishRegistration completes a WebAuthn registration flow.
func (t *Transport) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.FinishRegistration(ctx, req)
}

// BeginAuthentication begins a WebAuthn authentication flow.
func (t *Transport) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BeginAuthentication(ctx, req)
}

// FinishAuthentication completes a WebAuthn authentication flow.
func (t *Transport) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.FinishAuthentication(ctx, req)
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ExportKeyMaterial(ctx, req)
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.WrapKeyByID(ctx, req)
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.UnwrapKeyByID(ctx, req)
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.DeriveKeyECDH(ctx, req)
}

// GetCABundle retrieves the CA certificate bundle.
func (t *Transport) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCABundle(ctx, req)
}

// GetCACertificate retrieves the CA certificate.
func (t *Transport) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCACertificate(ctx, req)
}

// SignCSR signs a certificate signing request.
func (t *Transport) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SignCSR(ctx, req)
}

// IssueCertificate issues a new certificate.
func (t *Transport) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.IssueCertificate(ctx, req)
}

// RevokeCertificate revokes a certificate.
func (t *Transport) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.RevokeCertificate(ctx, req)
}

// GenerateCRL generates a certificate revocation list.
func (t *Transport) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GenerateCRL(ctx, req)
}

// IsRevoked checks if a certificate is revoked.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.IsRevoked(ctx, req)
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate.
func (t *Transport) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.IssueEKCertificate(ctx, req)
}

// IssueAKCertificate issues an Attestation Key certificate.
func (t *Transport) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.IssueAKCertificate(ctx, req)
}

// SignTCGCSR signs a TCG-CSR-IDEVID.
func (t *Transport) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SignTCGCSR(ctx, req)
}

// EnrollDevice performs complete TCG device enrollment.
func (t *Transport) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.EnrollDevice(ctx, req)
}

// ListPIVSlots returns the status of all PIV slots in the specified backend.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListPIVSlots(ctx, req)
}

// GetPIVCertificate retrieves the certificate from a PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetPIVCertificate(ctx, req)
}

// StorePIVCertificate stores a certificate in a PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.StorePIVCertificate(ctx, req)
}

// DeletePIVCertificate removes the certificate from a PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeletePIVCertificate(ctx, req)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GeneratePIVKey(ctx, req)
}

// ImportPIVCertificate imports a certificate into a PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.ImportPIVCertificate(ctx, req)
}

// ExportPIVCertificate exports the certificate from a PIV slot.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ExportPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GeneratePIVCSR(ctx, req)
}

// BarrierInitialize generates a root key, seals it, and transitions to unsealed state.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierInitialize(ctx, req)
}

// BarrierUnseal loads the sealed root key and derives the DEK.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierUnseal(ctx, req)
}

// BarrierSeal transitions the barrier to sealed state.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierSeal(ctx)
}

// BarrierStatus returns the current barrier status.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierStatus(ctx)
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierInitializeShamir(ctx, req)
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierUnsealWithShare(ctx, req)
}

// BarrierUnsealWithShares submits all Shamir shares at once for batch unsealing.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierUnsealWithShares(ctx, req)
}

// BarrierShamirListShares returns metadata about stored Shamir shares.
func (t *Transport) BarrierShamirListShares(ctx context.Context) (*transport.BarrierShamirSharesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierShamirListShares(ctx)
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (t *Transport) BarrierShamirDeleteShare(ctx context.Context, req *transport.BarrierShamirDeleteShareRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierShamirDeleteShare(ctx, req)
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (t *Transport) BarrierShamirDeleteAllShares(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierShamirDeleteAllShares(ctx)
}

// BarrierShamirVerify verifies the integrity of stored Shamir shares.
func (t *Transport) BarrierShamirVerify(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierShamirVerify(ctx)
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierRekey(ctx, req)
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierGenerateRecoveryKeys(ctx, req)
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierRecoverWithKeys(ctx, req)
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.BarrierDeleteRecoveryKeys(ctx)
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierHasRecoveryKeys(ctx)
}

// BarrierGenerateRootToken generates a one-time root token by proving
// knowledge of the master key through Shamir share reconstruction.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.BarrierGenerateRootToken(ctx, req)
}

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SetSOPIN(ctx, req)
}

// SetUserPIN sets the user PIN.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SetUserPIN(ctx, req)
}

// ChangeSOPIN changes the SO PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.ChangeSOPIN(ctx, req)
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.ChangeUserPIN(ctx, req)
}

// VerifySOPIN verifies the SO PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.VerifySOPIN(ctx, req)
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.VerifyUserPIN(ctx, req)
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetLockoutStatus(ctx)
}

// ResetLockout resets the PIN lockout counter.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.ResetLockout(ctx, req)
}

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PasswordAdd(ctx, req)
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PasswordGet(ctx, req)
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PasswordList(ctx, req)
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PasswordUpdate(ctx, req)
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PasswordDelete(ctx, req)
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PasswordStoreUnlock(ctx, req)
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PasswordStoreLock(ctx)
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PasswordStoreStatus(ctx)
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PasswordStoreSetAccessMode(ctx, req)
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PasswordGenerate(ctx, req)
}

// SealStorePut stores a secret in the platform store.
func (t *Transport) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SealStorePut(ctx, req)
}

// SealStoreGet retrieves a secret from the platform store.
func (t *Transport) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SealStoreGet(ctx, req)
}

// SealStoreDelete deletes a secret from the platform store.
func (t *Transport) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SealStoreDelete(ctx, req)
}

// SealStoreList lists all stored secret names.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SealStoreList(ctx)
}

// SealStoreReseal reseals a secret with the current sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.SealStoreReseal(ctx, req)
}

// SealStoreStatus returns the platform store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SealStoreStatus(ctx)
}

// PolicyCreate creates a new PCR policy.
func (t *Transport) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyCreate(ctx, req)
}

// PolicyGet retrieves a policy by name.
func (t *Transport) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyGet(ctx, req)
}

// PolicyList lists all policies.
func (t *Transport) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyList(ctx)
}

// PolicyDelete deletes a policy.
func (t *Transport) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.PolicyDelete(ctx, req)
}

// PolicyRefresh refreshes a policy with current PCR values.
func (t *Transport) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyRefresh(ctx, req)
}

// PolicyVerify verifies a policy against current PCR values.
func (t *Transport) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyVerify(ctx, req)
}

// PolicyExport exports a policy.
func (t *Transport) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PolicyExport(ctx, req)
}

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.CreateCustodianGroup(ctx, req)
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCustodianGroup(ctx, groupID)
}

// ListCustodianGroups lists all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListCustodianGroups(ctx)
}

// DeleteCustodianGroup deletes a custodian group.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteCustodianGroup(ctx, groupID)
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.AddCustodianMember(ctx, req)
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.RemoveCustodianMember(ctx, req)
}

// DistributeShares distributes Shamir shares to custodian group members.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.DistributeShares(ctx, req)
}

// SubmitShare submits a received Shamir share back to the server.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SubmitShare(ctx, req)
}

// ListShares lists shares available for the authenticated user.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListShares(ctx)
}

// GetShareCollectionStatus returns the collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetShareCollectionStatus(ctx, groupID)
}

// CreateTenant creates a new tenant.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.CreateTenant(ctx, req)
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTenant(ctx, tenantID)
}

// ListTenants lists all tenants.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListTenants(ctx)
}

// DeleteTenant deletes a tenant.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteTenant(ctx, tenantID)
}

// TenantBarrierInit initializes a per-tenant barrier.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.TenantBarrierInit(ctx, req)
}

// TenantBarrierUnseal unseals a per-tenant barrier.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.TenantBarrierUnseal(ctx, req)
}

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetInitStatus(ctx)
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ClaimCertBegin(ctx, req)
}

// ClaimCertComplete completes the certificate claim by verifying the officer's signature.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ClaimCertComplete(ctx, req)
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ClaimShare(ctx, req)
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SignCSRInit(ctx, req)
}

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.SubmitCredential(ctx, req)
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetCredentialStrategy(ctx)
}
