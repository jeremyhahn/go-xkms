// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestConfig_Validate_MissingStorage proves Validate rejects a config with
// a valid VaultURL but no KeyStorage or CertStorage, each reported
// distinctly (go-xkms#705): every other Validate test in this package
// supplies both, so this guard -- the one that would catch a construction
// path that forgot to wire storage -- had never run.
func TestConfig_Validate_MissingStorage(t *testing.T) {
	t.Run("missing KeyStorage", func(t *testing.T) {
		c := &Config{VaultURL: "https://test-vault.vault.azure.net/", CertStorage: storage.New()}
		if err := c.Validate(); err == nil {
			t.Error("Validate() expected error for a nil KeyStorage, got nil")
		}
	})

	t.Run("missing CertStorage", func(t *testing.T) {
		c := &Config{VaultURL: "https://test-vault.vault.azure.net/", KeyStorage: storage.New()}
		if err := c.Validate(); err == nil {
			t.Error("Validate() expected error for a nil CertStorage, got nil")
		}
	})
}

// TestConfig_String_ShortCredentials proves String's masking falls back to
// a fixed "****" for a TenantID/ClientID of 4 characters or fewer, instead
// of panicking on the last-4-characters slice every other test's
// realistic-length GUIDs take.
func TestConfig_String_ShortCredentials(t *testing.T) {
	c := &Config{
		VaultURL: "https://test-vault.vault.azure.net/",
		TenantID: "abcd",
		ClientID: "wxyz",
	}
	s := c.String()
	if !strings.Contains(s, "****") {
		t.Errorf("String() = %q, want it to mask a short TenantID/ClientID with \"****\"", s)
	}
	if strings.Contains(s, "abcd") || strings.Contains(s, "wxyz") {
		t.Errorf("String() = %q, must not leak a short TenantID/ClientID in the clear", s)
	}
}

// TestIsValidVaultURL_EmptyString proves isValidVaultURL's own empty-string
// guard rejects "" directly. Validate short-circuits on an empty VaultURL
// before ever calling isValidVaultURL (its "vault URL is required" check
// runs first), so this guard is unreachable through the public API and
// must be driven directly to run at all.
func TestIsValidVaultURL_EmptyString(t *testing.T) {
	if isValidVaultURL("") {
		t.Error("isValidVaultURL(\"\") = true, want false")
	}
}

// TestConfig_Validate_UnrecognizedDomain proves Validate rejects a
// well-formed https URL whose host is outside every recognized Key Vault
// domain (vault.azure.net/.cn/.usgovcloudapi.net/.microsoftazure.de),
// exercising isValidVaultURL's domain-suffix rejection through the public
// API, rather than only ever seeing a well-formed vault.azure.net URL
// elsewhere in this package.
func TestConfig_Validate_UnrecognizedDomain(t *testing.T) {
	c := &Config{VaultURL: "https://example.com/", KeyStorage: storage.New(), CertStorage: storage.New()}
	if err := c.Validate(); err == nil {
		t.Error("Validate() expected error for a VaultURL outside every recognized Key Vault domain, got nil")
	}
}
