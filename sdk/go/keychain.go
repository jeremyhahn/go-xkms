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

// Package keychain provides a unified client SDK for communicating with
// the keychain daemon (keychaind). The client supports multiple protocols
// including Unix domain socket (default), REST, gRPC, QUIC, and embedded.
package keychain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jeremyhahn/go-keychain/sdk/go/transport"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-keychain/sdk/go/transport/unix"
)

// Protocol represents the communication protocol to use.
type Protocol string

const (
	// ProtocolUnix uses gRPC over Unix domain socket (default)
	ProtocolUnix Protocol = "unix"
	// ProtocolUnixGRPC is an alias for ProtocolUnix
	ProtocolUnixGRPC Protocol = "unix-grpc"
	// ProtocolREST uses HTTP/HTTPS REST API
	ProtocolREST Protocol = "rest"
	// ProtocolGRPC uses gRPC over TCP
	ProtocolGRPC Protocol = "grpc"
	// ProtocolQUIC uses HTTP/3 over QUIC
	ProtocolQUIC Protocol = "quic"
	// ProtocolMCP uses JSON-RPC 2.0 over TCP (Model Context Protocol)
	ProtocolMCP Protocol = "mcp"
	// ProtocolEmbedded uses direct in-process calls (no network)
	ProtocolEmbedded Protocol = "embedded"
)

// DefaultUnixSocketPath is the default Unix socket path (relative to current working directory)
const DefaultUnixSocketPath = "keychain-data/keychain.sock"

var (
	// ErrUnsupportedProtocol is returned when an unsupported protocol is specified
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	// ErrConnectionFailed is returned when the connection to the server fails
	ErrConnectionFailed = errors.New("connection failed")
	// ErrNotConnected is returned when trying to use a client that is not connected
	ErrNotConnected = errors.New("client not connected")
	// ErrNotSupported is returned when an operation is not supported by the protocol
	ErrNotSupported = errors.New("operation not supported by this protocol")
	// ErrNilService is returned when a nil service is passed to NewEmbedded
	ErrNilService = errors.New("keychain service is required")
	// ErrKeyNotFound is returned when a key is not found
	ErrKeyNotFound = errors.New("key not found")
	// ErrCertificateNotFound is returned when a certificate is not found
	ErrCertificateNotFound = errors.New("certificate not found")
	// ErrBackendNotFound is returned when a backend is not found
	ErrBackendNotFound = errors.New("backend not found")
	// ErrInvalidRequest is returned when a request is invalid
	ErrInvalidRequest = errors.New("invalid request")
	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")
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
	// - embedded: not used
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

	// JWTToken is the JWT token for authentication (optional)
	// Obtained via FIDO2/WebAuthn login flow
	JWTToken string

	// Headers are additional HTTP headers to include in requests
	Headers map[string]string

	// Service is the keychain service for embedded protocol (required for embedded)
	Service KeychainServicer
}

// KeychainServicer defines the interface for the keychain service.
// This is used by the embedded client to make direct calls.
type KeychainServicer = embedded.KeychainServicer

// Client is the main interface for communicating with the keychain daemon.
// This is an alias for the transport.Client interface.
type Client = transport.Client

// toTransportConfig converts a keychain.Config to a transport.Config.
func toTransportConfig(cfg *Config) *transport.Config {
	tc := transport.DefaultConfig()
	tc.Address = cfg.Address
	tc.TLSEnabled = cfg.TLSEnabled
	tc.TLSInsecureSkipVerify = cfg.TLSInsecureSkipVerify
	tc.TLSCertFile = cfg.TLSCertFile
	tc.TLSKeyFile = cfg.TLSKeyFile
	tc.TLSCAFile = cfg.TLSCAFile
	tc.JWTToken = cfg.JWTToken
	if cfg.Headers != nil {
		tc.Headers = cfg.Headers
	}
	return tc
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
		case ProtocolMCP:
			cfg.Address = "localhost:9444"
		case ProtocolEmbedded:
			// No address needed for embedded
		}
	}

	tc := toTransportConfig(cfg)

	switch cfg.Protocol {
	case ProtocolUnix, ProtocolUnixGRPC:
		return unix.NewWithConfig(tc)
	case ProtocolREST:
		return rest.NewWithConfig(tc)
	case ProtocolGRPC:
		return grpc.NewWithConfig(tc)
	case ProtocolQUIC:
		return quic.NewWithConfig(tc)
	case ProtocolMCP:
		return mcp.NewWithConfig(tc)
	case ProtocolEmbedded:
		if cfg.Service == nil {
			return nil, ErrNilService
		}
		return embedded.NewWithService(cfg.Service)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Protocol)
	}
}

// NewFromURL creates a new client from a URL string.
// Supported URL schemes:
// - unix:///path/to/socket.sock (uses gRPC over Unix domain socket)
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
	case "mcp":
		cfg.Protocol = ProtocolMCP
		cfg.Address = u.Host
		cfg.TLSEnabled = false
	case "mcps":
		cfg.Protocol = ProtocolMCP
		cfg.Address = u.Host
		cfg.TLSEnabled = true
	default:
		// Assume it's a host:port for REST
		cfg.Protocol = ProtocolREST
		cfg.Address = "http://" + serverURL
	}

	return New(cfg)
}

// NewEmbedded creates a new embedded client that calls the keychain service directly.
// This is useful for in-process usage without network overhead.
func NewEmbedded(service KeychainServicer) (Client, error) {
	if service == nil {
		return nil, ErrNilService
	}
	return embedded.NewWithService(service)
}

// Re-export transport types for convenience.
// This allows users to use keychain.HealthResponse instead of transport.HealthResponse.
type (
	HealthResponse                = transport.HealthResponse
	BackendInfo                   = transport.BackendInfo
	ListBackendsResponse          = transport.ListBackendsResponse
	GenerateKeyRequest            = transport.GenerateKeyRequest
	GenerateKeyResponse           = transport.GenerateKeyResponse
	KeyInfo                       = transport.KeyInfo
	ListKeysResponse              = transport.ListKeysResponse
	GetKeyResponse                = transport.GetKeyResponse
	DeleteKeyResponse             = transport.DeleteKeyResponse
	SignRequest                   = transport.SignRequest
	SignResponse                  = transport.SignResponse
	VerifyRequest                 = transport.VerifyRequest
	VerifyResponse                = transport.VerifyResponse
	EncryptRequest                = transport.EncryptRequest
	EncryptResponse               = transport.EncryptResponse
	DecryptRequest                = transport.DecryptRequest
	DecryptResponse               = transport.DecryptResponse
	EncryptAsymRequest            = transport.EncryptAsymRequest
	EncryptAsymResponse           = transport.EncryptAsymResponse
	SealRequest                   = transport.SealRequest
	SealResponse                  = transport.SealResponse
	UnsealRequest                 = transport.UnsealRequest
	UnsealResponse                = transport.UnsealResponse
	CanSealResponse               = transport.CanSealResponse
	GetCertificateResponse        = transport.GetCertificateResponse
	SaveCertificateRequest        = transport.SaveCertificateRequest
	ImportKeyRequest              = transport.ImportKeyRequest
	ImportKeyResponse             = transport.ImportKeyResponse
	ExportKeyRequest              = transport.ExportKeyRequest
	ExportKeyResponse             = transport.ExportKeyResponse
	RotateKeyRequest              = transport.RotateKeyRequest
	RotateKeyResponse             = transport.RotateKeyResponse
	KeyVersion                    = transport.KeyVersion
	ListKeyVersionsRequest        = transport.ListKeyVersionsRequest
	ListKeyVersionsResponse       = transport.ListKeyVersionsResponse
	EnableKeyVersionRequest       = transport.EnableKeyVersionRequest
	EnableKeyVersionResponse      = transport.EnableKeyVersionResponse
	DisableKeyVersionRequest      = transport.DisableKeyVersionRequest
	DisableKeyVersionResponse     = transport.DisableKeyVersionResponse
	EnableAllKeyVersionsRequest   = transport.EnableAllKeyVersionsRequest
	EnableAllKeyVersionsResponse  = transport.EnableAllKeyVersionsResponse
	DisableAllKeyVersionsRequest  = transport.DisableAllKeyVersionsRequest
	DisableAllKeyVersionsResponse = transport.DisableAllKeyVersionsResponse
	GetImportParametersRequest    = transport.GetImportParametersRequest
	GetImportParametersResponse   = transport.GetImportParametersResponse
	WrapKeyRequest                = transport.WrapKeyRequest
	WrapKeyResponse               = transport.WrapKeyResponse
	UnwrapKeyRequest              = transport.UnwrapKeyRequest
	UnwrapKeyResponse             = transport.UnwrapKeyResponse
	CopyKeyRequest                = transport.CopyKeyRequest
	CopyKeyResponse               = transport.CopyKeyResponse
	CertificateInfo               = transport.CertificateInfo
	ListCertificatesResponse      = transport.ListCertificatesResponse
	SaveCertificateChainRequest   = transport.SaveCertificateChainRequest
	GetCertificateChainResponse   = transport.GetCertificateChainResponse
	GetTLSCertificateResponse     = transport.GetTLSCertificateResponse
	UserInfo                      = transport.UserInfo
	CredentialInfo                = transport.CredentialInfo
	ListUsersResponse             = transport.ListUsersResponse
	GetUserResponse               = transport.GetUserResponse
	ListUserCredentialsResponse   = transport.ListUserCredentialsResponse
	BeginRegistrationRequest      = transport.BeginRegistrationRequest
	BeginRegistrationResponse     = transport.BeginRegistrationResponse
	CredentialParam               = transport.CredentialParam
	FinishRegistrationRequest     = transport.FinishRegistrationRequest
	FinishRegistrationResponse    = transport.FinishRegistrationResponse
	BeginAuthenticationRequest    = transport.BeginAuthenticationRequest
	BeginAuthenticationResponse   = transport.BeginAuthenticationResponse
	FinishAuthenticationRequest   = transport.FinishAuthenticationRequest
	FinishAuthenticationResponse  = transport.FinishAuthenticationResponse
)
