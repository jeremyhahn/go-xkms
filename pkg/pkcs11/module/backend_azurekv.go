//go:build azurekv

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

// Package module provides Azure Key Vault backend registration for PKCS#11.
//
// The Azure Key Vault backend integrates with Microsoft Azure Key Vault
// for cloud-based key storage and cryptographic operations. Keys are managed
// by Azure and protected by Azure infrastructure with HSM-backing options.
//
// This file is only compiled when the 'azurekv' build tag is specified.
package module

func init() {
	RegisterBackend(BackendAzureKV)
}
