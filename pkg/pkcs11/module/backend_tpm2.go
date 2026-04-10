//go:build tpm2

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

// Package module provides TPM 2.0 backend registration for PKCS#11.
//
// The TPM 2.0 backend leverages hardware-based key storage and cryptographic
// operations through a Trusted Platform Module. Keys are protected by the TPM's
// hardware security boundary.
//
// This file is only compiled when the 'tpm2' build tag is specified.
package module

func init() {
	RegisterBackend(BackendTPM2)
}
