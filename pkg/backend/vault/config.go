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

//go:build vault

package vault

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config holds the configuration for the HashiCorp Vault backend.
type Config struct {
	// Address is the Vault server address (e.g., "http://127.0.0.1:8200")
	Address string

	// Token is the Vault authentication token
	Token string

	// TransitPath is the path to the Transit secrets engine (default: "transit")
	TransitPath string

	// Namespace is the Vault namespace (Enterprise feature, optional)
	Namespace string

	// TLSSkipVerify disables TLS certificate verification (not recommended for production)
	TLSSkipVerify bool

	// KeyStorage is the storage backend for key metadata
	KeyStorage storage.Backend

	// CertStorage is the storage backend for certificates
	CertStorage storage.Backend

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("vault address is required")
	}
	if c.Token == "" {
		return fmt.Errorf("vault token is required")
	}
	if c.TransitPath == "" {
		c.TransitPath = "transit"
	}
	if c.KeyStorage == nil {
		return fmt.Errorf("key storage is required")
	}
	if c.CertStorage == nil {
		return fmt.Errorf("certificate storage is required")
	}
	return nil
}
