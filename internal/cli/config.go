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

package cli

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/client"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

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

	// UseLocal enables local/direct backend mode (bypasses daemon)
	UseLocal bool

	// Server is the URL of the remote keychain server
	// If empty, uses Unix socket by default
	// Supported formats:
	// - unix:///path/to/socket.sock
	// - http://host:port or https://host:port (REST)
	// - grpc://host:port or grpcs://host:port (gRPC)
	// - quic://host:port (QUIC/HTTP3)
	Server string

	// TLSInsecure skips TLS certificate verification (not recommended)
	TLSInsecure bool

	// TLSCert is the path to the client certificate file (for mTLS)
	TLSCert string

	// TLSKey is the path to the client key file (for mTLS)
	TLSKey string

	// TLSCACert is the path to the CA certificate file
	TLSCACert string

	// APIKey is the API key for authentication
	APIKey string
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		Backend:      "software",
		KeyDir:       "/tmp/keystore",
		OutputFormat: "text",
		Verbose:      false,
		UseLocal:     false,
		Server:       "", // Empty means use default Unix socket
	}
}

// CreateBackend creates a backend instance based on the configuration
func (c *Config) CreateBackend() (types.Backend, error) {
	switch c.Backend {
	case "software":
		return c.createSoftwareBackend()
	case "pkcs11":
		return nil, fmt.Errorf("PKCS11 backend not yet supported in CLI")
	case "tpm2":
		return nil, fmt.Errorf("TPM2 backend not yet supported in CLI")
	case "awskms":
		return nil, fmt.Errorf("AWS KMS backend not yet supported in CLI")
	case "gcpkms":
		return nil, fmt.Errorf("GCP KMS backend not yet supported in CLI")
	case "azurekv":
		return nil, fmt.Errorf("azure Key Vault backend not yet supported in CLI")
	case "vault":
		return nil, fmt.Errorf("vault backend not yet supported in CLI")
	default:
		return nil, fmt.Errorf("unknown backend: %s", c.Backend)
	}
}

// createSoftwareBackend creates the unified software backend with file storage.
// The software backend provides both asymmetric (PKCS#8) and symmetric (AES) operations.
func (c *Config) createSoftwareBackend() (types.Backend, error) {
	// Create file-based storage backend
	storageBackend, err := file.New(c.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Create unified software backend (PKCS#8 + AES)
	backendConfig := &software.Config{
		KeyStorage: storageBackend,
	}

	return software.NewBackend(backendConfig)
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

// IsLocal returns true if the CLI should use direct backend access
func (c *Config) IsLocal() bool {
	return c.UseLocal
}

// IsRemote returns true if the configuration specifies an explicit server URL.
// An empty Server means use the default Unix socket (considered local).
func (c *Config) IsRemote() bool {
	return c.Server != ""
}

// CreateClient creates a client for communicating with keychaind.
// If Server is empty, it defaults to the local Unix socket with gRPC.
func (c *Config) CreateClient() (client.Client, error) {
	if c.Server == "" {
		// Default to Unix socket with gRPC (server uses gRPC on Unix socket)
		return client.New(&client.Config{
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
	if c.TLSInsecure || c.TLSCert != "" || c.TLSKey != "" || c.TLSCACert != "" || c.APIKey != "" {
		// We need to recreate with full config - parse the URL ourselves
		return c.createClientWithTLS()
	}

	return cl, nil
}

// createClientWithTLS creates a client with TLS options
func (c *Config) createClientWithTLS() (client.Client, error) {
	cfg := &client.Config{
		TLSInsecureSkipVerify: c.TLSInsecure,
		TLSCertFile:           c.TLSCert,
		TLSKeyFile:            c.TLSKey,
		TLSCAFile:             c.TLSCACert,
		APIKey:                c.APIKey,
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
