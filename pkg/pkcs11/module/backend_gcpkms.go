//go:build gcpkms

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

// Package module provides Google Cloud KMS backend registration for PKCS#11.
//
// The GCP KMS backend integrates with Google Cloud Key Management Service
// for cloud-based key storage and cryptographic operations. Keys are managed
// by Google Cloud and protected by GCP infrastructure.
//
// This file is only compiled when the 'gcpkms' build tag is specified.
package module

func init() {
	RegisterBackend(BackendGCPKMS)
}
