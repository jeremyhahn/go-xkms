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

// Package embedded provides an embedded (in-process) transport implementation
// for the keychain SDK. This transport makes direct function calls without
// any network overhead.
package embedded

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"
)

var (
	// ErrNilService is returned when a nil service is provided.
	ErrNilService = errors.New("keychain service is required")
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = errors.New("client not connected")
)

// KeychainServicer defines the interface for the keychain service.
// This is used by the embedded transport to make direct calls.
type KeychainServicer interface {
	Health(ctx context.Context) (string, string, error)
	ListBackends(ctx context.Context) ([]transport.BackendInfo, error)
	GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error)
	GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)
	ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error)
	GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error)
	DeleteKey(ctx context.Context, backend, keyID string) error
	Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)
	Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)
	Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)
	Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)
	EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error)
	GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error)
	SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error
	DeleteCertificate(ctx context.Context, backend, keyID string) error
	CertificateExists(ctx context.Context, backend, keyID string) (bool, error)
	ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error)
	ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error)
	RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error)
	ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error)
	EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error)
	DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error)
	EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error)
	DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error)
	GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error)
	WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error)
	CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error)
	ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error)
	SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error
	GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error)
	GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error)
	Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error)
	Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error)
	CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error)

	// User management operations
	ListUsers(ctx context.Context) (*transport.ListUsersResponse, error)
	GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error)
	DeleteUser(ctx context.Context, username string) error
	EnableUser(ctx context.Context, username string) error
	DisableUser(ctx context.Context, username string) error
	ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error)

	// Authentication flow operations (FIDO2/WebAuthn server-side)
	BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error)
	BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error)
	FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error)
}

// Transport implements the transport.Client interface using direct in-process calls.
// This provides the fastest possible access with no network overhead.
type Transport struct {
	config    *transport.Config
	service   KeychainServicer
	connected bool
}

// New creates a new embedded transport with the given service.
func New(service KeychainServicer, opts ...transport.Option) (*Transport, error) {
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
func NewWithService(service KeychainServicer) (*Transport, error) {
	return New(service)
}

// SetService sets the service for the embedded transport.
func (t *Transport) SetService(service KeychainServicer) error {
	if service == nil {
		return ErrNilService
	}
	t.service = service
	t.connected = true
	return nil
}

// Service returns the underlying service.
func (t *Transport) Service() KeychainServicer {
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
func (t *Transport) ListBackends(ctx context.Context) (*transport.ListBackendsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	backends, err := t.service.ListBackends(ctx)
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
func (t *Transport) ListKeys(ctx context.Context, backend string) (*transport.ListKeysResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListKeys(ctx, backend)
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

// ListKeyVersions lists all versions of a key.
func (t *Transport) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListKeyVersions(ctx, req)
}

// EnableKeyVersion enables a specific version of a key.
func (t *Transport) EnableKeyVersion(ctx context.Context, req *transport.EnableKeyVersionRequest) (*transport.EnableKeyVersionResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.EnableKeyVersion(ctx, req)
}

// DisableKeyVersion disables a specific version of a key.
func (t *Transport) DisableKeyVersion(ctx context.Context, req *transport.DisableKeyVersionRequest) (*transport.DisableKeyVersionResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.DisableKeyVersion(ctx, req)
}

// EnableAllKeyVersions enables all versions of a key.
func (t *Transport) EnableAllKeyVersions(ctx context.Context, req *transport.EnableAllKeyVersionsRequest) (*transport.EnableAllKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.EnableAllKeyVersions(ctx, req)
}

// DisableAllKeyVersions disables all versions of a key.
func (t *Transport) DisableAllKeyVersions(ctx context.Context, req *transport.DisableAllKeyVersionsRequest) (*transport.DisableAllKeyVersionsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.DisableAllKeyVersions(ctx, req)
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
func (t *Transport) ListCertificates(ctx context.Context, backend string) (*transport.ListCertificatesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListCertificates(ctx, backend)
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

// ListUsers returns a list of all users.
func (t *Transport) ListUsers(ctx context.Context) (*transport.ListUsersResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListUsers(ctx)
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
