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

package transport

import "context"

// Client is the main interface for communicating with the keychain daemon.
// All transport implementations (gRPC, REST, QUIC, MCP, Unix, Embedded)
// must implement this interface.
type Client interface {
	// Connect establishes a connection to the keychain server.
	Connect(ctx context.Context) error

	// Close closes the connection to the server.
	Close() error

	// Health checks the health of the server.
	Health(ctx context.Context) (*HealthResponse, error)

	// Backend Operations

	// ListBackends returns a list of available backends.
	ListBackends(ctx context.Context) (*ListBackendsResponse, error)

	// GetBackend returns information about a specific backend.
	GetBackend(ctx context.Context, backendID string) (*BackendInfo, error)

	// Key Operations

	// GenerateKey generates a new key.
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error)

	// ListKeys returns a list of keys in the specified backend.
	ListKeys(ctx context.Context, backend string) (*ListKeysResponse, error)

	// GetKey returns information about a specific key.
	GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error)

	// DeleteKey deletes a key.
	DeleteKey(ctx context.Context, backend, keyID string) (*DeleteKeyResponse, error)

	// Cryptographic Operations

	// Sign signs data with the specified key.
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)

	// Encrypt encrypts data with the specified key.
	Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)

	// Decrypt decrypts data with the specified key.
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)

	// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
	EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error)

	// Certificate Operations

	// GetCertificate returns the certificate for a key.
	GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error)

	// SaveCertificate saves a certificate for a key.
	SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error

	// DeleteCertificate deletes a certificate.
	DeleteCertificate(ctx context.Context, backend, keyID string) error

	// CertificateExists checks if a certificate exists for a key.
	CertificateExists(ctx context.Context, backend, keyID string) (bool, error)

	// Import/Export Operations

	// ImportKey imports a key.
	ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error)

	// ExportKey exports a key.
	ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error)

	// RotateKey rotates a key by generating a new version.
	RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)

	// ListKeyVersions lists all versions of a key.
	ListKeyVersions(ctx context.Context, req *ListKeyVersionsRequest) (*ListKeyVersionsResponse, error)

	// EnableKeyVersion enables a specific version of a key.
	EnableKeyVersion(ctx context.Context, req *EnableKeyVersionRequest) (*EnableKeyVersionResponse, error)

	// DisableKeyVersion disables a specific version of a key.
	DisableKeyVersion(ctx context.Context, req *DisableKeyVersionRequest) (*DisableKeyVersionResponse, error)

	// EnableAllKeyVersions enables all versions of a key.
	EnableAllKeyVersions(ctx context.Context, req *EnableAllKeyVersionsRequest) (*EnableAllKeyVersionsResponse, error)

	// DisableAllKeyVersions disables all versions of a key.
	DisableAllKeyVersions(ctx context.Context, req *DisableAllKeyVersionsRequest) (*DisableAllKeyVersionsResponse, error)

	// GetImportParameters gets the parameters needed to import a key.
	GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error)

	// WrapKey wraps key material for secure transport.
	WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error)

	// UnwrapKey unwraps key material.
	UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error)

	// CopyKey copies a key from one backend to another.
	CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error)

	// Certificate Chain Operations

	// ListCertificates lists all certificates in the specified backend.
	ListCertificates(ctx context.Context, backend string) (*ListCertificatesResponse, error)

	// SaveCertificateChain saves a certificate chain for a key.
	SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error

	// GetCertificateChain returns the certificate chain for a key.
	GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error)

	// GetTLSCertificate returns the TLS certificate bundle for a key.
	GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error)

	// Sealing Operations (TPM2/Hardware-backed encryption)

	// Seal seals data using the backend's sealing mechanism (e.g., TPM2).
	Seal(ctx context.Context, req *SealRequest) (*SealResponse, error)

	// Unseal unseals previously sealed data.
	Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error)

	// CanSeal checks if the backend supports sealing operations.
	CanSeal(ctx context.Context, backend string) (*CanSealResponse, error)

	// User Management Operations

	// ListUsers returns a list of all users.
	ListUsers(ctx context.Context) (*ListUsersResponse, error)

	// GetUser returns information about a specific user.
	GetUser(ctx context.Context, username string) (*GetUserResponse, error)

	// DeleteUser deletes a user.
	DeleteUser(ctx context.Context, username string) error

	// EnableUser enables a user account.
	EnableUser(ctx context.Context, username string) error

	// DisableUser disables a user account.
	DisableUser(ctx context.Context, username string) error

	// ListUserCredentials returns a list of credentials for a user.
	ListUserCredentials(ctx context.Context, username string) (*ListUserCredentialsResponse, error)

	// Authentication Flow Operations (FIDO2/WebAuthn server-side)

	// BeginRegistration begins a WebAuthn registration flow.
	BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error)

	// FinishRegistration completes a WebAuthn registration flow.
	FinishRegistration(ctx context.Context, req *FinishRegistrationRequest) (*FinishRegistrationResponse, error)

	// BeginAuthentication begins a WebAuthn authentication flow.
	BeginAuthentication(ctx context.Context, req *BeginAuthenticationRequest) (*BeginAuthenticationResponse, error)

	// FinishAuthentication completes a WebAuthn authentication flow.
	FinishAuthentication(ctx context.Context, req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error)
}
