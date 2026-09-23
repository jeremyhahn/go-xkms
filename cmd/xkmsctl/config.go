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
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ClientFactory is a function that creates a client.Client.
// This allows dependency injection for testing.
type ClientFactory func(cfg *Config) (client.Client, error)

// BackendFactory is a function that creates a types.KeyProvider. This allows
// dependency injection for testing backend operations.
//
// Deprecated: Use ClientFactory with Protocol="embedded" instead.
type BackendFactory func(cfg *Config) (client.KeyProvider, error)

// DefaultTransport is the canonical default transport for xkmsctl. The
// value is "unix" so the CLI talks to the local xkmsd via the Unix
// domain socket out of the box, mirroring qrdbctl / quicbaas /
// platformctl per docs/08-bootstrap-auth-architecture.md §6.
const DefaultTransport = "unix"

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

	// BackendFactory allows injecting a custom backend factory for testing.
	// If nil, the default backend creation logic is used.
	//
	// Deprecated: Use ClientFactory with Protocol="embedded" instead for
	// SDK-based access.
	BackendFactory BackendFactory
}

// NewConfig creates a new Config with default values. The transport
// defaults to DefaultTransport ("unix") so the CLI talks to the local
// xkmsd Unix socket out of the box.
func NewConfig() *Config {
	return &Config{
		Backend:      "software",
		KeyDir:       "xkms-data/keys",
		OutputFormat: "text",
		Verbose:      false,
		Protocol:     DefaultTransport,
		Server:       "",
	}
}

// IsLocal returns true if the protocol is set to embedded mode.
// Embedded mode means operations are performed directly in-process
// without network communication.
func (c *Config) IsLocal() bool {
	return c.Protocol == "embedded"
}

// CreateBackend creates a backend for embedded mode operations. If
// BackendFactory is set, it uses that factory instead.
//
// Deprecated: Use CreateClient() with Protocol="embedded" instead for
// SDK-based access.
func (c *Config) CreateBackend() (client.KeyProvider, error) {
	// Use injected backend factory if available (for testing)
	if c.BackendFactory != nil {
		return c.BackendFactory(c)
	}

	// Create file-based storage backend via the SDK.
	storageBackend, err := client.NewFileStorageBackend(c.KeyDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateStorageBackendFailed, Err: err}
	}

	// Create software backend (unified asymmetric + symmetric with import/export support)
	softwareBackend, err := client.NewSoftwareBackend(&client.SoftwareBackendConfig{
		KeyStorage: storageBackend,
	})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSoftwareBackendFailed, Err: err}
	}

	return softwareBackend, nil
}

// CreateCertStorage creates certificate storage based on the configuration
func (c *Config) CreateCertStorage() (*client.StorageCertAdapter, error) {
	// Create file-based storage backend via the SDK.
	storageBackend, err := client.NewFileStorageBackend(c.KeyDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateStorageBackendFailed, Err: err}
	}

	// Wrap in a CertAdapter for certificate-specific operations
	return client.NewStorageCertAdapter(storageBackend), nil
}

// IsRemote returns true if the configuration specifies an explicit server URL.
// An empty Server means use the default Unix socket (considered local).
func (c *Config) IsRemote() bool {
	return c.Server != ""
}

// createXKMSService creates a xkms.Backend for embedded mode.
// This initializes the global xkms service with the configured backend.
func (c *Config) createXKMSService() (client.XKMSServicer, error) {
	// Build the in-process service entirely through the SDK. The SDK factory
	// assembles file storage + software backend + keystore and initializes the
	// service singleton — no pkg/* imports required of the CLI.
	return client.NewEmbeddedService(client.EmbeddedServiceConfig{
		KeyDir:      c.KeyDir,
		BackendName: c.Backend,
	})
}

// CreateClient creates a client for communicating with xkmsd.
// If Protocol is "embedded", it creates a direct in-process client.
// Otherwise the configured transport is selected (defaults to
// DefaultTransport in NewConfig). If ClientFactory is set, it uses that
// factory instead.
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

	// Map protocol string to SDK Protocol type. An explicit scheme in --server
	// (e.g. grpcs://, https://, quic://, unix://) selects the protocol and takes
	// precedence over the (possibly defaulted) --transport flag; bare host:port or
	// socket-path servers use the configured protocol. Without this, the default
	// transport ("unix") would route every scheme'd URL through the Unix socket
	// transport, producing "unix://grpcs://…" dial targets.
	if c.Protocol != "" && !hasScheme(c.Server) {
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
		return nil, &WrappedError{Sentinel: ErrCreateClientFromURLFailed, Err: err}
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
		tlsCfg, cleanup, err := client.NewPKCS11TLSConfig(&client.PKCS11TLSConfig{
			ModulePath: c.PKCS11Module,
			SlotID:     c.PKCS11Slot,
			PIN:        c.PKCS11PIN,
		})
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrCreatePKCS11TLSConfigFailed, Err: err}
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
		// Strip the unix:// scheme — the unix transport prepends it when dialing,
		// so passing it through here yields "unix://unix:///path" (gRPC rejects it
		// with "invalid (non-empty) authority: unix:"). Matches the NewFromURL path.
		cfg.Address = trimPrefix(c.Server, "unix://")
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
		return nil, &WrappedDetailError{Sentinel: ErrUnsupportedProtocol, Detail: c.Protocol}
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
		tlsCfg, cleanup, err := client.NewPKCS11TLSConfig(&client.PKCS11TLSConfig{
			ModulePath: c.PKCS11Module,
			SlotID:     c.PKCS11Slot,
			PIN:        c.PKCS11PIN,
		})
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrCreatePKCS11TLSConfigFailed, Err: err}
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

// hasScheme reports whether s carries a URL scheme (contains "://").
func hasScheme(s string) bool {
	for i := 0; i+3 <= len(s); i++ {
		if s[i:i+3] == "://" {
			return true
		}
	}
	return false
}

func trimPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}
