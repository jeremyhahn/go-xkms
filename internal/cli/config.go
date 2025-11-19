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

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
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
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		Backend:      "pkcs8",
		KeyDir:       "/tmp/keystore",
		OutputFormat: "text",
		Verbose:      false,
	}
}

// CreateBackend creates a backend instance based on the configuration
func (c *Config) CreateBackend() (types.Backend, error) {
	switch c.Backend {
	case "pkcs8":
		return c.createPKCS8Backend()
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

// createPKCS8Backend creates a PKCS8 backend with file storage
func (c *Config) createPKCS8Backend() (types.Backend, error) {
	// Create file-based storage backend
	storageBackend, err := file.New(c.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	// Create PKCS8 backend
	backendConfig := &pkcs8.Config{
		KeyStorage: storageBackend,
	}

	return pkcs8.NewBackend(backendConfig)
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
