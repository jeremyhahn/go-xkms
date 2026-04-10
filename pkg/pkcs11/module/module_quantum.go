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

// Package module provides quantum build initialization for the PKCS#11 module.
//
// When built with the "quantum" build tag, this file provides access to the
// QuantumCryptoManager for ML-DSA, ML-KEM, and future PQC algorithm support.
package module

// getQuantumCryptoManager returns a new QuantumCryptoManager instance.
// Available only when built with the "quantum" build tag.
func getQuantumCryptoManager() *QuantumCryptoManager {
	return NewQuantumCryptoManager()
}
