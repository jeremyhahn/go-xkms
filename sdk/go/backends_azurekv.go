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

package xkms

import azurekvbackend "github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"

// Azure Key Vault crypto backend re-exported behind the azurekv build tag,
// matching the gating of pkg/backend/azurekv. It conforms to the same
// Backend contract as the local backends.

// AzureKVBackend is the Azure Key Vault crypto backend.
type AzureKVBackend = azurekvbackend.Backend

// AzureKVBackendConfig configures the Azure Key Vault crypto backend.
type AzureKVBackendConfig = azurekvbackend.Config

// NewAzureKVBackend constructs an Azure Key Vault crypto backend.
var NewAzureKVBackend = azurekvbackend.NewBackend
