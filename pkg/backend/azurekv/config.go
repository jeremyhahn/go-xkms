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

//go:build azurekv

package azurekv

import (
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

	// AllowLocalVaultURL permits VaultURL to name localhost or 127.0.0.1
	// instead of an Azure vault domain (*.vault.azure.net and the sovereign
	// cloud equivalents). This is a development switch for testing against a
	// local Azure Key Vault emulator or mock and must never be enabled in
	// production. Off by default: a local vault URL fails Validate.
	AllowLocalVaultURL bool `yaml:"allow_local_vault_url,omitempty" json:"allow_local_vault_url,omitempty" mapstructure:"allow_local_vault_url"`

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
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "vault URL is required"}
	}

	// Validate vault URL format
	if !isValidVaultURL(c.VaultURL) {
		return &errs.Detail{Err: ErrInvalidVaultURL, Detail: fmt.Sprintf("%s", c.VaultURL)}
	}

	// A localhost/127.0.0.1 vault URL is only well-formed for local
	// development against an emulator or mock; it requires an explicit
	// opt-in so a production configuration can never reach it silently.
	if isLocalVaultURL(c.VaultURL) && !c.AllowLocalVaultURL {
		return &errs.Detail{Err: ErrLocalVaultURLNotAllowed, Detail: fmt.Sprintf("%s", c.VaultURL)}
	}

	// If service principal credentials are provided, all three must be present
	hasClientID := c.ClientID != ""
	hasClientSecret := c.ClientSecret != ""
	hasTenantID := c.TenantID != ""

	if hasClientID || hasClientSecret || hasTenantID {
		if !hasClientID || !hasClientSecret || !hasTenantID {
			return &errs.Detail{Err: ErrInvalidConfig, Detail: "tenant_id, client_id, and client_secret must all be provided together"}
		}
	}

	// Storage providers are required
	if c.KeyStorage == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "key storage is required"}
	}
	if c.CertStorage == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "cert storage is required"}
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

	// A localhost/127.0.0.1 URL is well-formed; whether it is *permitted*
	// is a separate policy decision gated by Config.AllowLocalVaultURL in
	// Validate.
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

// isLocalVaultURL reports whether url names the local development endpoint
// (localhost or 127.0.0.1) rather than an Azure-hosted vault domain. Callers
// use this to gate the endpoint behind Config.AllowLocalVaultURL; it does
// not itself judge whether the URL is well-formed (see isValidVaultURL).
func isLocalVaultURL(url string) bool {
	url = strings.TrimPrefix(url, "https://")
	return strings.HasPrefix(url, "localhost") || strings.HasPrefix(url, "127.0.0.1")
}
