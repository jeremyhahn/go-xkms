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

package config

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// frostSecretBackendNames lists the xkms backend names that may be named by
// backends.frost.secret_backend. FROST's secret share is stored through the
// same types.KeyProvider contract every backend implements (see
// pkg/keyprovider/frost.Config.SecretBackend), so any full-service backend
// qualifies except the phone backend, which proxies operations to a paired
// device rather than storing key material locally, and "frost" itself, which
// would be self-referential.
var frostSecretBackendNames = map[string]bool{
	"software": true,
	"pkcs8":    true,
	"tpm2":     true,
	"pkcs11":   true,
	"awskms":   true,
	"gcpkms":   true,
	"azurekv":  true,
	"vault":    true,
}

// FrostConfig contains configuration for the FROST threshold-signing backend
// (RFC 9591, pkg/keyprovider/frost). FROST separates a key's public group
// components (group public key, verification shares, metadata) from each
// participant's secret key share, so the secret can be held by a hardware- or
// otherwise access-controlled backend while the public components sit in
// ordinary storage; PublicPath and SecretBackend configure exactly that
// split, matching pkg/keyprovider/frost.Config and the fileSecretBackend
// abstraction cmd/xkmsctl/frost.go uses locally.
type FrostConfig struct {
	// Enabled turns on the FROST backend.
	Enabled bool `yaml:"enabled"`

	// PublicPath is the storage location for FROST public components: the
	// group public key, verification shares, and key metadata. This data is
	// not secret and needs neither encryption nor hardware backing.
	PublicPath string `yaml:"public_path"`

	// SecretBackend names the xkms backend that holds each participant's
	// FROST secret key share: one of "software", "pkcs8", "tpm2", "pkcs11",
	// "awskms", "gcpkms", "azurekv", or "vault". The named backend must
	// itself be configured and enabled under backends.
	SecretBackend string `yaml:"secret_backend"`

	// Algorithm is the default FROST ciphersuite (RFC 9591) for newly
	// generated keys. Defaults to "FROST-Ed25519-SHA512" when empty.
	Algorithm string `yaml:"algorithm,omitempty"`

	// DefaultThreshold is the default minimum number of signers (M) required
	// for newly generated keys. Must be at least 2. Defaults to 2.
	DefaultThreshold int `yaml:"default_threshold,omitempty"`

	// DefaultTotal is the default total number of participants (N) for newly
	// generated keys. Must be >= DefaultThreshold. Defaults to 3.
	DefaultTotal int `yaml:"default_total,omitempty"`
}

// FrostConfigError reports an invalid backends.frost configuration field.
type FrostConfigError struct {
	// Field is the yaml key of the invalid field, relative to backends.frost.
	Field string

	// Message describes what is wrong with Field's value.
	Message string
}

// Error returns the error message.
func (e *FrostConfigError) Error() string {
	return fmt.Sprintf("backends.frost.%s: %s", e.Field, e.Message)
}

// Validate checks the FROST backend configuration and fills in defaults for
// Algorithm, DefaultThreshold, and DefaultTotal when left unset. It is a
// no-op when the backend is not enabled. Validate does not check
// SecretBackend against the sibling backend sections — Config.Validate does
// that, since only it holds the full BackendsConfig to check the named
// backend against.
func (c *FrostConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.PublicPath == "" {
		return &FrostConfigError{Field: "public_path", Message: "required when enabled"}
	}

	if c.SecretBackend == "" {
		return &FrostConfigError{Field: "secret_backend", Message: "required when enabled"}
	}
	if !frostSecretBackendNames[c.SecretBackend] {
		return &FrostConfigError{
			Field:   "secret_backend",
			Message: fmt.Sprintf("unknown backend %q (must be one of software, pkcs8, tpm2, pkcs11, awskms, gcpkms, azurekv, vault)", c.SecretBackend),
		}
	}

	if c.Algorithm == "" {
		c.Algorithm = string(types.FrostAlgorithmEd25519)
	}
	if !types.FrostAlgorithm(c.Algorithm).IsValid() {
		return &FrostConfigError{Field: "algorithm", Message: fmt.Sprintf("unrecognized FROST ciphersuite %q", c.Algorithm)}
	}

	if c.DefaultThreshold == 0 {
		c.DefaultThreshold = 2
	}
	if c.DefaultTotal == 0 {
		c.DefaultTotal = 3
	}

	if c.DefaultThreshold < 2 {
		return &FrostConfigError{Field: "default_threshold", Message: "must be at least 2"}
	}
	if c.DefaultThreshold > 255 {
		return &FrostConfigError{Field: "default_threshold", Message: "cannot exceed 255"}
	}
	if c.DefaultTotal > 255 {
		return &FrostConfigError{Field: "default_total", Message: "cannot exceed 255"}
	}
	if c.DefaultTotal < c.DefaultThreshold {
		return &FrostConfigError{Field: "default_total", Message: "must be >= default_threshold"}
	}

	return nil
}

// enabledBackendNamed reports whether BackendsConfig configures and enables
// the backend called name. name must be one of frostSecretBackendNames; any
// other value reports false.
func (b *BackendsConfig) enabledBackendNamed(name string) bool {
	switch name {
	case "software":
		return b.Software != nil && b.Software.Enabled
	case "pkcs8":
		return b.PKCS8 != nil && b.PKCS8.Enabled
	case "tpm2":
		return b.TPM2 != nil && b.TPM2.Enabled
	case "pkcs11":
		return b.PKCS11 != nil && b.PKCS11.Enabled
	case "awskms":
		return b.AWSKMS != nil && b.AWSKMS.Enabled
	case "gcpkms":
		return b.GCPKMS != nil && b.GCPKMS.Enabled
	case "azurekv":
		return b.AzureKV != nil && b.AzureKV.Enabled
	case "vault":
		return b.Vault != nil && b.Vault.Enabled
	default:
		return false
	}
}
