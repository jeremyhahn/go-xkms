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

// Package xkms provides post-quantum cryptography backend registration and factory.
//
// The quantum backend provides post-quantum cryptographic algorithms including
// Dilithium and Kyber for quantum-resistant key management operations.
//
// This file is only compiled when the 'quantum' build tag is specified.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendQuantum)
	RegisterBackendFactory(BackendQuantum, newQuantumKeyProvider)
}

// newQuantumKeyProvider creates a post-quantum backend KeyProvider from configuration.
//
// The quantum backend uses in-memory storage for key material.
// Configuration keys are reserved for future use.
func newQuantumKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	return quantum.New(storage.New())
}
