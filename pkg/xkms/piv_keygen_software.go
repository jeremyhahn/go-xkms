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

package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// softwareKeyGenFunc generates a crypto.Signer for a given algorithm.
type softwareKeyGenFunc func() (crypto.Signer, error)

// softwareKeyGenDispatch provides O(1) map-based dispatch for software PIV key generation.
var softwareKeyGenDispatch = map[string]softwareKeyGenFunc{
	"rsa2048": func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	},
	"rsa4096": func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 4096)
	},
	"ecdsap256": func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	},
	"ecdsap384": func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	},
	"ed25519": func() (crypto.Signer, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	},
}

// softwarePIVKeyGenerator generates PIV keys using Go's standard crypto library.
// It maintains an in-memory map of generated signers keyed by CN for later CSR generation.
type softwarePIVKeyGenerator struct {
	signers map[string]crypto.Signer
	mu      sync.RWMutex
}

// NewSoftwarePIVKeyGenerator creates a new software-based PIVKeyGenerator.
func NewSoftwarePIVKeyGenerator() *softwarePIVKeyGenerator {
	return &softwarePIVKeyGenerator{
		signers: make(map[string]crypto.Signer),
	}
}

// GeneratePIVKey generates a new key for the given PIV slot and algorithm using software cryptography.
// An empty algorithm defaults to "ecdsap256".
func (g *softwarePIVKeyGenerator) GeneratePIVKey(slot pivcert.PIVSlot, algorithm string, cn string) (crypto.Signer, error) {
	if algorithm == "" {
		algorithm = "ecdsap256"
	}

	genFunc, ok := softwareKeyGenDispatch[algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	signer, err := genFunc()
	if err != nil {
		return nil, err
	}

	// Store the signer for later CSR generation
	g.mu.Lock()
	g.signers[cn] = signer
	g.mu.Unlock()

	return signer, nil
}

// GetPIVSigner returns a signer for an existing key identified by CN.
func (g *softwarePIVKeyGenerator) GetPIVSigner(_ pivcert.PIVSlot, cn string) (crypto.Signer, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	signer, ok := g.signers[cn]
	if !ok {
		return nil, ErrPIVSignerNotAvailable
	}
	return signer, nil
}

// Verify interface compliance at compile time.
var _ PIVKeyGenerator = (*softwarePIVKeyGenerator)(nil)
