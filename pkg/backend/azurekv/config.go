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

//go:build azurekv

package azurekv

import (
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for Azure Key Vault backend operations.
// It specifies the vault URL and optional authentication credentials.
type Config struct {
	// VaultURL is the Azure Key Vault URL.
	// Format: https://{vault-name}.vault.azure.net/
	// Required.
	VaultURL string `yaml:"vault_url" json:"vault_url" mapstructure:"vault_url"`

	// TenantID is the Azure Active Directory tenant ID.
	// Optional - if not provided, will use DefaultAzureCredential.
	TenantID string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty" mapstructure:"tenant_id"`

	// ClientID is the Azure service principal client ID.
	// Optional - if not provided, will use DefaultAzureCredential.
	ClientID string `yaml:"client_id,omitempty" json:"client_id,omitempty" mapstructure:"client_id"`

	// ClientSecret is the Azure service principal client secret.
	// Optional - if not provided, will use DefaultAzureCredential.
	ClientSecret string `yaml:"client_secret,omitempty" json:"client_secret,omitempty" mapstructure:"client_secret"`

	// Debug enables debug logging for Azure SDK operations.
	Debug bool `yaml:"debug,omitempty" json:"debug,omitempty" mapstructure:"debug"`

	// KeyStorage is the underlying storage for key metadata.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	// Note: Actual key material stays in Azure Key Vault, this is for metadata only.
	KeyStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// CertStorage is the underlying storage for certificate material.
	// This can be file-based, memory-based, or any implementation
	// of the storage.Backend interface.
	CertStorage storage.Backend `yaml:"-" json:"-" mapstructure:"-"`

	// Tracker is the AEAD safety tracker for nonce/bytes tracking.
	// If nil, a default memory-based tracker will be created.
	// For production systems, provide a persistent tracker.
	Tracker types.AEADSafetyTracker `yaml:"-" json:"-" mapstructure:"-"`
}

// Validate checks if the configuration is valid and returns an error if not.
// It verifies that required fields are set and that values meet minimum requirements.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Vault URL is required
	if c.VaultURL == "" {
		return fmt.Errorf("%w: vault URL is required", ErrInvalidConfig)
	}

	// Validate vault URL format
	if !isValidVaultURL(c.VaultURL) {
		return fmt.Errorf("%w: %s", ErrInvalidVaultURL, c.VaultURL)
	}

	// If service principal credentials are provided, all three must be present
	hasClientID := c.ClientID != ""
	hasClientSecret := c.ClientSecret != ""
	hasTenantID := c.TenantID != ""

	if hasClientID || hasClientSecret || hasTenantID {
		if !hasClientID || !hasClientSecret || !hasTenantID {
			return fmt.Errorf("%w: tenant_id, client_id, and client_secret must all be provided together", ErrInvalidConfig)
		}
	}

	// Storage providers are required
	if c.KeyStorage == nil {
		return fmt.Errorf("%w: key storage is required", ErrInvalidConfig)
	}
	if c.CertStorage == nil {
		return fmt.Errorf("%w: cert storage is required", ErrInvalidConfig)
	}

	return nil
}

// String returns a string representation of the config with sensitive data masked.
// Credentials are masked with asterisks to prevent accidental exposure in logs.
func (c *Config) String() string {
	tenantMask := "<not set>"
	if c.TenantID != "" {
		if len(c.TenantID) > 4 {
			tenantMask = "****" + c.TenantID[len(c.TenantID)-4:]
		} else {
			tenantMask = "****"
		}
	}

	clientIDMask := "<not set>"
	if c.ClientID != "" {
		if len(c.ClientID) > 4 {
			clientIDMask = "****" + c.ClientID[len(c.ClientID)-4:]
		} else {
			clientIDMask = "****"
		}
	}

	clientSecretMask := "<not set>"
	if c.ClientSecret != "" {
		clientSecretMask = "****"
	}

	return fmt.Sprintf("Azure Key Vault Config{VaultURL: %s, TenantID: %s, ClientID: %s, ClientSecret: %s, Debug: %t}",
		c.VaultURL, tenantMask, clientIDMask, clientSecretMask, c.Debug)
}

// isValidVaultURL performs basic validation of Azure Key Vault URL format.
// Valid URLs follow the pattern: https://{vault-name}.vault.azure.net/
func isValidVaultURL(url string) bool {
	if url == "" {
		return false
	}

	// Must start with https://
	if !strings.HasPrefix(url, "https://") {
		return false
	}

	// Remove protocol
	url = strings.TrimPrefix(url, "https://")

	// Should contain vault.azure.net or similar Azure domain
	// Allow localhost for testing
	if strings.HasPrefix(url, "localhost") || strings.HasPrefix(url, "127.0.0.1") {
		return true
	}

	// Must contain vault domain
	if !strings.Contains(url, ".vault.azure.net") &&
		!strings.Contains(url, ".vault.azure.cn") &&
		!strings.Contains(url, ".vault.usgovcloudapi.net") &&
		!strings.Contains(url, ".vault.microsoftazure.de") {
		return false
	}

	return true
}
