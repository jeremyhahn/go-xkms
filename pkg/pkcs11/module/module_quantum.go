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

// Package module provides quantum initialization for the PKCS#11 module.
//
// This file gives access to the QuantumCryptoManager for ML-DSA, ML-KEM and
// future PQC algorithm support. It is compiled unconditionally: there is no
// "quantum" build tag on this package, and Module.Initialize assigns
// m.quantumCrypto in every build. The comments that said otherwise were the
// stated reason mechanism_v32.go shadowed the shared category and key-size
// constants, so the false claim had a real cost.
package module

// getQuantumCryptoManager returns a new QuantumCryptoManager instance.
func getQuantumCryptoManager() *QuantumCryptoManager {
	return NewQuantumCryptoManager()
}
