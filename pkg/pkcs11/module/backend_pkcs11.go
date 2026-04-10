//go:build pkcs11

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

// Package module provides external PKCS#11/HSM backend registration.
//
// The PKCS#11 backend allows integration with external Hardware Security Modules
// (HSMs) and smart cards that provide a PKCS#11 interface. This enables using
// certified cryptographic hardware for key storage and operations.
//
// This file is only compiled when the 'pkcs11' build tag is specified.
package module

func init() {
	RegisterBackend(BackendPKCS11)
}
