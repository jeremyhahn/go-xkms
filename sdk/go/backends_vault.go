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

//go:build vault

package xkms

import vaultbackend "github.com/jeremyhahn/go-xkms/pkg/backend/vault"

// HashiCorp Vault transit crypto backend re-exported behind the vault build
// tag, matching the gating of pkg/backend/vault. It conforms to the same
// Backend contract as the local backends.

// VaultBackend is the HashiCorp Vault transit crypto backend.
type VaultBackend = vaultbackend.Backend

// VaultBackendConfig configures the Vault transit crypto backend.
type VaultBackendConfig = vaultbackend.Config

// NewVaultBackend constructs a Vault transit crypto backend.
var NewVaultBackend = vaultbackend.NewBackend
