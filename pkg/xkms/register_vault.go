//go:build vault

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

// Package xkms provides HashiCorp Vault backend registration and factory.
//
// The Vault backend integrates with HashiCorp Vault for secret management
// and key storage operations.
//
// This file is only compiled when the 'vault' build tag is specified.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/vault"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendVault)
	RegisterBackendFactory(BackendVault, newVaultKeyProvider)
}

// newVaultKeyProvider creates a HashiCorp Vault backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "address" (string): Vault server address (required)
//   - "token" (string): Vault authentication token (required)
//   - "transit_path" (string): Transit secrets engine path (default: "transit")
//   - "namespace" (string): Vault namespace (optional, Enterprise feature)
//   - "tls_ca_file" (string): Path to a PEM-encoded CA certificate (or bundle)
//     used to verify the Vault server's certificate
//   - "tls_ca_path" (string): Path to a directory of PEM-encoded CA
//     certificates used to verify the Vault server's certificate
//   - "tls_cert_file" (string): Path to a client certificate for mTLS to
//     Vault (requires "tls_key_file")
//   - "tls_key_file" (string): Path to the private key for "tls_cert_file"
//     (requires "tls_cert_file")
func newVaultKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	vaultConfig := &vault.Config{
		KeyStorage: storage.New(),
	}

	if address, ok := config["address"].(string); ok {
		vaultConfig.Address = address
	}
	if token, ok := config["token"].(string); ok {
		vaultConfig.Token = token
	}
	if transitPath, ok := config["transit_path"].(string); ok {
		vaultConfig.TransitPath = transitPath
	}
	if namespace, ok := config["namespace"].(string); ok {
		vaultConfig.Namespace = namespace
	}
	if caFile, ok := config["tls_ca_file"].(string); ok {
		vaultConfig.TLSCAFile = caFile
	}
	if caPath, ok := config["tls_ca_path"].(string); ok {
		vaultConfig.TLSCAPath = caPath
	}
	if certFile, ok := config["tls_cert_file"].(string); ok {
		vaultConfig.TLSCertFile = certFile
	}
	if keyFile, ok := config["tls_key_file"].(string); ok {
		vaultConfig.TLSKeyFile = keyFile
	}

	return vault.NewBackend(vaultConfig)
}
