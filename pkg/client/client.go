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

// Package client provides a unified client library for communicating with
// the keychain daemon (keychaind). The client supports multiple protocols
// including Unix domain socket (default), REST, gRPC, and QUIC.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Protocol represents the communication protocol to use.
type Protocol string

const (
	// ProtocolUnix uses Unix domain socket with HTTP (legacy, for compatibility)
	ProtocolUnix Protocol = "unix"
	// ProtocolUnixGRPC uses gRPC over Unix domain socket (default for unix:// URLs)
	ProtocolUnixGRPC Protocol = "unix-grpc"
	// ProtocolREST uses HTTP/HTTPS REST API
	ProtocolREST Protocol = "rest"
	// ProtocolGRPC uses gRPC
	ProtocolGRPC Protocol = "grpc"
	// ProtocolQUIC uses HTTP/3 over QUIC
	ProtocolQUIC Protocol = "quic"
)

// DefaultUnixSocketPath is the default Unix socket path
const DefaultUnixSocketPath = "/var/run/keychain/keychain.sock"

var (
	// ErrUnsupportedProtocol is returned when an unsupported protocol is specified
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	// ErrConnectionFailed is returned when the connection to the server fails
	ErrConnectionFailed = errors.New("connection failed")
	// ErrNotConnected is returned when trying to use a client that is not connected
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported by the protocol
	ErrNotSupported = errors.New("operation not supported by this protocol")
)

// Config configures the keychain client.
type Config struct {
	// Protocol specifies the communication protocol (default: unix-grpc)
	Protocol Protocol

	// Address is the server address (format depends on protocol):
	// - unix: /path/to/socket.sock
	// - unix-grpc: /path/to/socket.sock
	// - rest: http://host:port or https://host:port
	// - grpc: host:port
	// - quic: host:port
	Address string

	// TLSEnabled enables TLS for network protocols
	TLSEnabled bool

	// TLSInsecureSkipVerify skips TLS certificate verification (not recommended)
	TLSInsecureSkipVerify bool

	// TLSCertFile is the path to the client certificate file (for mTLS)
	TLSCertFile string

	// TLSKeyFile is the path to the client key file (for mTLS)
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate file
	TLSCAFile string

	// APIKey is the API key for authentication (optional)
	APIKey string

	// Headers are additional HTTP headers to include in requests
	Headers map[string]string
}

// Client is the main interface for communicating with the keychain daemon.
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

	// Import/Export Operations

	// ImportKey imports a key.
	ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error)

	// ExportKey exports a key.
	ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error)

	// RotateKey rotates a key by generating a new version.
	RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)

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
}

// New creates a new keychain client with the specified configuration.
// If no configuration is provided, it uses gRPC over Unix socket with the default path.
func New(cfg *Config) (Client, error) {
	if cfg == nil {
		cfg = &Config{
			Protocol: ProtocolUnixGRPC,
			Address:  DefaultUnixSocketPath,
		}
	}

	// Default to Unix socket gRPC if no protocol specified
	if cfg.Protocol == "" {
		cfg.Protocol = ProtocolUnixGRPC
	}

	// Default address based on protocol
	if cfg.Address == "" {
		switch cfg.Protocol {
		case ProtocolUnix, ProtocolUnixGRPC:
			cfg.Address = DefaultUnixSocketPath
		case ProtocolREST:
			cfg.Address = "http://localhost:8443"
		case ProtocolGRPC:
			cfg.Address = "localhost:9443"
		case ProtocolQUIC:
			cfg.Address = "localhost:8444"
		}
	}

	switch cfg.Protocol {
	case ProtocolUnix:
		return newUnixClient(cfg)
	case ProtocolUnixGRPC:
		return newUnixGRPCClient(cfg)
	case ProtocolREST:
		return newRESTClient(cfg)
	case ProtocolGRPC:
		return newGRPCClient(cfg)
	case ProtocolQUIC:
		return newQUICClient(cfg)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Protocol)
	}
}

// NewFromURL creates a new client from a URL string.
// Supported URL schemes:
// - unix:///path/to/socket.sock (uses gRPC by default)
// - unix+http:///path/to/socket.sock (uses HTTP explicitly)
// - http://host:port or https://host:port (REST)
// - grpc://host:port or grpcs://host:port
// - quic://host:port
func NewFromURL(serverURL string) (Client, error) {
	if serverURL == "" {
		// Default to Unix socket with gRPC
		return New(nil)
	}

	// Check for special unix: prefix
	if strings.HasPrefix(serverURL, "unix://") {
		return New(&Config{
			Protocol: ProtocolUnixGRPC,
			Address:  strings.TrimPrefix(serverURL, "unix://"),
		})
	}

	// Check for unix+http: prefix for HTTP-based Unix socket
	if strings.HasPrefix(serverURL, "unix+http://") {
		return New(&Config{
			Protocol: ProtocolUnix,
			Address:  strings.TrimPrefix(serverURL, "unix+http://"),
		})
	}

	// Parse as URL
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	cfg := &Config{}

	switch u.Scheme {
	case "http":
		cfg.Protocol = ProtocolREST
		cfg.Address = serverURL
		cfg.TLSEnabled = false
	case "https":
		cfg.Protocol = ProtocolREST
		cfg.Address = serverURL
		cfg.TLSEnabled = true
	case "grpc":
		cfg.Protocol = ProtocolGRPC
		cfg.Address = u.Host
		cfg.TLSEnabled = false
	case "grpcs":
		cfg.Protocol = ProtocolGRPC
		cfg.Address = u.Host
		cfg.TLSEnabled = true
	case "quic":
		cfg.Protocol = ProtocolQUIC
		cfg.Address = u.Host
		cfg.TLSEnabled = true // QUIC always uses TLS
	default:
		// Assume it's a host:port for REST
		cfg.Protocol = ProtocolREST
		cfg.Address = "http://" + serverURL
	}

	return New(cfg)
}

// Request and Response types

// HealthResponse contains health check information.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

// BackendInfo contains information about a backend.
type BackendInfo struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	HardwareBacked bool                   `json:"hardware_backed"`
	Capabilities   map[string]interface{} `json:"capabilities,omitempty"`
}

// ListBackendsResponse contains a list of backends.
type ListBackendsResponse struct {
	Backends []BackendInfo `json:"backends"`
}

// GenerateKeyRequest contains parameters for key generation.
type GenerateKeyRequest struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	KeyType   string `json:"key_type"`
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

// GenerateKeyResponse contains the result of key generation.
type GenerateKeyResponse struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Message      string `json:"message,omitempty"`
}

// KeyInfo contains information about a key.
type KeyInfo struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	Algorithm    string `json:"algorithm,omitempty"`
	Backend      string `json:"backend"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ListKeysResponse contains a list of keys.
type ListKeysResponse struct {
	Keys []KeyInfo `json:"keys"`
}

// GetKeyResponse contains key information.
type GetKeyResponse struct {
	KeyInfo
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// DeleteKeyResponse contains the result of key deletion.
type DeleteKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SignRequest contains parameters for signing.
type SignRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    []byte `json:"data"`
	Hash    string `json:"hash,omitempty"`
}

// SignResponse contains the signature.
type SignResponse struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
}

// VerifyRequest contains parameters for signature verification.
type VerifyRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash,omitempty"`
}

// VerifyResponse contains the verification result.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// EncryptRequest contains parameters for encryption.
type EncryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
}

// EncryptResponse contains the encrypted data.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}

// DecryptRequest contains parameters for decryption.
type DecryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Ciphertext     []byte `json:"ciphertext"`
	Nonce          []byte `json:"nonce,omitempty"`
	Tag            []byte `json:"tag,omitempty"`
	AdditionalData []byte `json:"additional_data,omitempty"`
}

// DecryptResponse contains the decrypted data.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// EncryptAsymRequest contains parameters for asymmetric encryption.
type EncryptAsymRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	Hash      string `json:"hash,omitempty"`
}

// EncryptAsymResponse contains the encrypted data from asymmetric encryption.
type EncryptAsymResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// GetCertificateResponse contains a certificate.
type GetCertificateResponse struct {
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// SaveCertificateRequest contains parameters for saving a certificate.
type SaveCertificateRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// ImportKeyRequest contains parameters for importing a key.
type ImportKeyRequest struct {
	Backend            string `json:"backend"`
	KeyID              string `json:"key_id"`
	KeyType            string `json:"key_type,omitempty"`
	KeySize            int    `json:"key_size,omitempty"`
	Curve              string `json:"curve,omitempty"`
	Hash               string `json:"hash,omitempty"`
	AESKeySize         int    `json:"aes_key_size,omitempty"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
}

// ImportKeyResponse contains the result of key import.
type ImportKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ExportKeyRequest contains parameters for exporting a key.
type ExportKeyRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
}

// ExportKeyResponse contains the exported key.
type ExportKeyResponse struct {
	KeyID              string `json:"key_id"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
}

// RotateKeyRequest contains parameters for key rotation.
type RotateKeyRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type,omitempty"`
	KeySize int    `json:"key_size,omitempty"`
	Curve   string `json:"curve,omitempty"`
}

// RotateKeyResponse contains the result of key rotation.
type RotateKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// GetImportParametersRequest contains parameters for getting import parameters.
type GetImportParametersRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	KeyType   string `json:"key_type,omitempty"`
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

// GetImportParametersResponse contains the import parameters.
type GetImportParametersResponse struct {
	WrappingPublicKey []byte `json:"wrapping_public_key"`
	ImportToken       []byte `json:"import_token,omitempty"`
	Algorithm         string `json:"algorithm"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

// WrapKeyRequest contains parameters for wrapping a key.
type WrapKeyRequest struct {
	Backend           string `json:"backend"`
	KeyMaterial       []byte `json:"key_material"`
	Algorithm         string `json:"algorithm"`
	WrappingPublicKey []byte `json:"wrapping_public_key,omitempty"`
	ImportToken       []byte `json:"import_token,omitempty"`
}

// WrapKeyResponse contains the wrapped key.
type WrapKeyResponse struct {
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
}

// UnwrapKeyRequest contains parameters for unwrapping a key.
type UnwrapKeyRequest struct {
	Backend            string `json:"backend"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	ImportToken        []byte `json:"import_token,omitempty"`
}

// UnwrapKeyResponse contains the unwrapped key.
type UnwrapKeyResponse struct {
	KeyMaterial []byte `json:"key_material"`
}

// CopyKeyRequest contains parameters for copying a key.
type CopyKeyRequest struct {
	SourceBackend string `json:"source_backend"`
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"`
	DestKeyID     string `json:"dest_key_id"`
	Algorithm     string `json:"algorithm"`
	KeyType       string `json:"key_type,omitempty"`
	KeySize       int    `json:"key_size,omitempty"`
	Curve         string `json:"curve,omitempty"`
}

// CopyKeyResponse contains the result of key copy.
type CopyKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// CertificateInfo contains information about a certificate.
type CertificateInfo struct {
	KeyID          string `json:"key_id"`
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	NotBefore      string `json:"not_before,omitempty"`
	NotAfter       string `json:"not_after,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

// ListCertificatesResponse contains a list of certificates.
type ListCertificatesResponse struct {
	Certificates []CertificateInfo `json:"certificates"`
}

// SaveCertificateChainRequest contains parameters for saving a certificate chain.
type SaveCertificateChainRequest struct {
	Backend  string   `json:"backend"`
	KeyID    string   `json:"key_id"`
	ChainPEM []string `json:"chain_pem"`
}

// GetCertificateChainResponse contains a certificate chain.
type GetCertificateChainResponse struct {
	KeyID    string   `json:"key_id"`
	ChainPEM []string `json:"chain_pem"`
}

// GetTLSCertificateResponse contains a TLS certificate bundle.
type GetTLSCertificateResponse struct {
	KeyID          string `json:"key_id"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
}
