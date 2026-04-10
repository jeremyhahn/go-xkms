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

package main

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ClientFactory is a function that creates a client.Client.
// This allows dependency injection for testing.
type ClientFactory func(cfg *Config) (client.Client, error)

// UserStoreFactory is a function that creates a user.Store.
// This allows dependency injection for testing user commands.
type UserStoreFactory func(storagePath string) (user.Store, error)

// BackendFactory is a function that creates a types.KeyProvider.
// Deprecated: Use ClientFactory with Protocol="embedded" instead.
// This allows dependency injection for testing backend operations.
type BackendFactory func(cfg *Config) (types.KeyProvider, error)

// Config holds global CLI configuration
type Config struct {
	// ConfigFile is the path to the configuration file
	ConfigFile string

	// Backend is the backend name to use (pkcs8, pkcs11, tpm2, etc.)
	Backend string

	// KeyDir is the directory for key storage (for file-based backends)
	KeyDir string

	// OutputFormat controls output formatting (json, text, table)
	OutputFormat string

	// Verbose enables verbose logging
	Verbose bool

	// Protocol specifies the communication protocol to use
	// Supported values: embedded, rest, grpc, quic, mcp, unix
	Protocol string

	// Server is the URL of the remote xkms server
	// If empty, uses Unix socket by default
	// Supported formats:
	// - unix:///path/to/socket.sock
	// - http://host:port or https://host:port (REST)
	// - grpc://host:port or grpcs://host:port (gRPC)
	// - quic://host:port (QUIC/HTTP3)
	Server string

	// TLSCert is the path to the client certificate file (for mTLS)
	TLSCert string

	// TLSKey is the path to the client key file (for mTLS)
	TLSKey string

	// TLSCACert is the path to the CA certificate file
	TLSCACert string

	// JWTToken is the JWT token for authentication (obtained via FIDO2 login)
	JWTToken string

	// SPKIPin is the hex-encoded SHA-256 SPKI pin for server certificate verification.
	// Used for trust-on-first-use (TOFU) bootstrap when no CA cert is available.
	SPKIPin string

	// SOPin is the security officer PIN for privileged operations.
	SOPin string

	// TPM2 configuration options
	// TPM2Device is the path to the TPM device (e.g., "/dev/tpmrm0")
	TPM2Device string

	// TPM2UseSimulator enables use of the TPM simulator instead of hardware
	TPM2UseSimulator bool

	// TPM2EncryptSession enables encrypted sessions for CPU<->TPM communication
	TPM2EncryptSession bool

	// TPM2SRKHandle is the persistent handle for the Storage Root Key
	TPM2SRKHandle uint32

	// TPM2EKHandle is the persistent handle for the Endorsement Key
	TPM2EKHandle uint32

	// PKCS11Module is the path to the PKCS#11 shared object for mTLS client auth
	PKCS11Module string

	// PKCS11Slot is the PKCS#11 slot ID (default: 0)
	PKCS11Slot int

	// PKCS11PIN is the PKCS#11 token PIN
	PKCS11PIN string

	// AuthMethod specifies the authentication method for admin create (fido2 or mtls)
	AuthMethod string

	// ClientFactory allows injecting a custom client factory for testing.
	// If nil, the default client creation logic is used.
	ClientFactory ClientFactory

	// UserStoreFactory allows injecting a custom user store factory for testing user commands.
	// If nil, the default user store creation logic is used.
	UserStoreFactory UserStoreFactory

	// BackendFactory allows injecting a custom backend factory for testing.
	// Deprecated: Use ClientFactory with Protocol="embedded" instead for SDK-based access.
	// If nil, the default backend creation logic is used.
	BackendFactory BackendFactory
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		Backend:      "software",
		KeyDir:       "xkms-data/keys",
		OutputFormat: "text",
		Verbose:      false,
		Protocol:     "", // Empty means use default Unix socket
		Server:       "", // Empty means use default Unix socket
	}
}

// IsLocal returns true if the protocol is set to embedded mode.
// Embedded mode means operations are performed directly in-process
// without network communication.
func (c *Config) IsLocal() bool {
	return c.Protocol == "embedded"
}

// CreateBackend creates a backend for embedded mode operations.
// Deprecated: Use CreateClient() with Protocol="embedded" instead for SDK-based access.
// If BackendFactory is set, it uses that factory instead.
func (c *Config) CreateBackend() (types.KeyProvider, error) {
	// Use injected backend factory if available (for testing)
	if c.BackendFactory != nil {
		return c.BackendFactory(c)
	}

	// Create file-based storage backend
	storageBackend, err := file.New(c.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Create software backend (unified asymmetric + symmetric with import/export support)
	backendConfig := &software.Config{
		KeyStorage: storageBackend,
	}

	softwareBackend, err := software.NewBackend(backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create software backend: %w", err)
	}

	return softwareBackend, nil
}

// CreateCertStorage creates certificate storage based on the configuration
func (c *Config) CreateCertStorage() (*storage.CertAdapter, error) {
	// Create file-based storage backend
	storageBackend, err := file.New(c.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Wrap in a CertAdapter for certificate-specific operations
	return storage.NewCertAdapter(storageBackend), nil
}

// CreateUserStore creates a user store based on the configuration.
// If UserStoreFactory is set, it uses that factory instead.
func (c *Config) CreateUserStore(storagePath string) (user.Store, error) {
	// Use injected user store factory if available (for testing)
	if c.UserStoreFactory != nil {
		return c.UserStoreFactory(storagePath)
	}

	return openUserStore(storagePath)
}

// IsRemote returns true if the configuration specifies an explicit server URL.
// An empty Server means use the default Unix socket (considered local).
func (c *Config) IsRemote() bool {
	return c.Server != ""
}

// createXKMSService creates a xkms.Backend for embedded mode.
// This initializes the global xkms service with the configured backend.
func (c *Config) createXKMSService() (client.XKMSServicer, error) {
	// Create file-based storage backend
	storageBackend, err := file.New(c.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Create certificate storage
	certPath := c.KeyDir + "/certs"
	certStorage, err := file.New(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate storage: %w", err)
	}

	// Create software backend (unified asymmetric + symmetric with import/export support)
	backendConfig := &software.Config{
		KeyStorage: storageBackend,
	}

	softwareBackend, err := software.NewBackend(backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create software backend: %w", err)
	}

	// Create keystore for the backend
	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	// Initialize global xkms service
	backends := map[string]xkms.Backend{
		c.Backend: ks,
	}

	serviceConfig := &xkms.ServiceConfig{
		Backends:       backends,
		DefaultBackend: c.Backend,
	}

	// Reset any existing service first (in case of reinitialize)
	xkms.Reset()

	if err := xkms.Initialize(serviceConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize xkms service: %w", err)
	}

	// Return the XKMSService singleton which implements XKMSServicer directly
	return xkms.Get()
}

// CreateClient creates a client for communicating with xkmsd.
// If Protocol is "embedded", it creates a direct in-process client.
// If Server is empty and Protocol is not "embedded", it defaults to the local Unix socket with gRPC.
// If ClientFactory is set, it uses that factory instead.
func (c *Config) CreateClient() (client.Client, error) {
	// Use injected client factory if available (for testing)
	if c.ClientFactory != nil {
		return c.ClientFactory(c)
	}

	// Handle embedded protocol
	if c.Protocol == "embedded" {
		svc, err := c.createXKMSService()
		if err != nil {
			return nil, err
		}
		return client.NewEmbedded(svc)
	}

	// Map protocol string to SDK Protocol type
	if c.Protocol != "" {
		return c.createClientFromProtocol()
	}

	if c.Server == "" {
		// Default to Unix socket with gRPC (server uses gRPC on Unix socket)
		return client.New(&client.BackendConfig{
			Protocol: client.ProtocolUnixGRPC,
			Address:  client.DefaultUnixSocketPath,
		})
	}

	// Parse the server URL to determine protocol
	cl, err := client.NewFromURL(c.Server)
	if err != nil {
		return nil, fmt.Errorf("failed to create client from URL: %w", err)
	}

	// If we need to set TLS options, we need to create a new client with full config
	if c.TLSCert != "" || c.TLSKey != "" || c.TLSCACert != "" || c.JWTToken != "" || c.PKCS11Module != "" {
		// We need to recreate with full config - parse the URL ourselves
		return c.createClientWithTLS()
	}

	return cl, nil
}

// createClientFromProtocol creates a client based on the Protocol field
func (c *Config) createClientFromProtocol() (client.Client, error) {
	cfg := &client.BackendConfig{
		TLSCertFile: c.TLSCert,
		TLSKeyFile:  c.TLSKey,
		TLSCAFile:   c.TLSCACert,
		JWTToken:    c.JWTToken,
	}

	// Wire PKCS#11-backed mTLS if --pkcs11-module is set
	if c.PKCS11Module != "" {
		tlsCfg, cleanup, err := auth.NewPKCS11TLSConfig(&auth.PKCS11TLSConfig{
			ModulePath: c.PKCS11Module,
			SlotID:     c.PKCS11Slot,
			PIN:        c.PKCS11PIN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create PKCS#11 TLS config: %w", err)
		}
		// Note: cleanup is not called here - resources live for the lifetime of the client.
		// The PKCS#11 session/module will be cleaned up when the process exits.
		_ = cleanup
		cfg.TLSConfig = tlsCfg
		cfg.TLSEnabled = true
	}

	switch c.Protocol {
	case "unix":
		cfg.Protocol = client.ProtocolUnix
		cfg.Address = c.Server
		if cfg.Address == "" {
			cfg.Address = client.DefaultUnixSocketPath
		}
	case "rest":
		cfg.Protocol = client.ProtocolREST
		cfg.Address = c.Server
		if cfg.Address == "" {
			cfg.Address = "http://localhost:8443"
		}
	case "grpc":
		cfg.Protocol = client.ProtocolGRPC
		cfg.Address = c.Server
		if cfg.Address == "" {
			cfg.Address = "localhost:9443"
		}
	case "quic":
		cfg.Protocol = client.ProtocolQUIC
		cfg.Address = c.Server
		if cfg.Address == "" {
			cfg.Address = "localhost:8444"
		}
		cfg.TLSEnabled = true // QUIC always uses TLS
	case "mcp":
		cfg.Protocol = client.ProtocolMCP
		cfg.Address = c.Server
		if cfg.Address == "" {
			cfg.Address = "localhost:9444"
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", c.Protocol)
	}

	return client.New(cfg)
}

// createClientWithTLS creates a client with TLS options
func (c *Config) createClientWithTLS() (client.Client, error) {
	cfg := &client.BackendConfig{
		TLSCertFile: c.TLSCert,
		TLSKeyFile:  c.TLSKey,
		TLSCAFile:   c.TLSCACert,
		JWTToken:    c.JWTToken,
	}

	// Wire PKCS#11-backed mTLS if --pkcs11-module is set
	if c.PKCS11Module != "" {
		tlsCfg, cleanup, err := auth.NewPKCS11TLSConfig(&auth.PKCS11TLSConfig{
			ModulePath: c.PKCS11Module,
			SlotID:     c.PKCS11Slot,
			PIN:        c.PKCS11PIN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create PKCS#11 TLS config: %w", err)
		}
		// Note: cleanup is not called here - resources live for the lifetime of the client.
		// The PKCS#11 session/module will be cleaned up when the process exits.
		_ = cleanup
		cfg.TLSConfig = tlsCfg
		cfg.TLSEnabled = true
	}

	// Parse the server URL
	serverURL := c.Server

	switch {
	case hasPrefix(serverURL, "unix://"):
		cfg.Protocol = client.ProtocolUnix
		cfg.Address = trimPrefix(serverURL, "unix://")

	case hasPrefix(serverURL, "http://"):
		cfg.Protocol = client.ProtocolREST
		cfg.Address = serverURL
		cfg.TLSEnabled = false

	case hasPrefix(serverURL, "https://"):
		cfg.Protocol = client.ProtocolREST
		cfg.Address = serverURL
		cfg.TLSEnabled = true

	case hasPrefix(serverURL, "grpc://"):
		cfg.Protocol = client.ProtocolGRPC
		cfg.Address = trimPrefix(serverURL, "grpc://")
		cfg.TLSEnabled = false

	case hasPrefix(serverURL, "grpcs://"):
		cfg.Protocol = client.ProtocolGRPC
		cfg.Address = trimPrefix(serverURL, "grpcs://")
		cfg.TLSEnabled = true

	case hasPrefix(serverURL, "quic://"):
		cfg.Protocol = client.ProtocolQUIC
		cfg.Address = trimPrefix(serverURL, "quic://")
		cfg.TLSEnabled = true // QUIC always uses TLS

	case hasPrefix(serverURL, "mcp://"):
		cfg.Protocol = client.ProtocolMCP
		cfg.Address = trimPrefix(serverURL, "mcp://")
		cfg.TLSEnabled = false

	case hasPrefix(serverURL, "mcps://"):
		cfg.Protocol = client.ProtocolMCP
		cfg.Address = trimPrefix(serverURL, "mcps://")
		cfg.TLSEnabled = true

	default:
		// Assume REST with http://
		cfg.Protocol = client.ProtocolREST
		cfg.Address = "http://" + serverURL
	}

	return client.New(cfg)
}

// Helper functions for string manipulation
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}
