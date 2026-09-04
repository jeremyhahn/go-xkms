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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
	// origins records how each signer arrived, keyed by CN alongside signers.
	// This generator holds no types.KeyAttributes to carry the fact, and it is
	// the fallback the PIV manager uses when no backend resolver is installed,
	// so without this the default configuration could not tell a generated key
	// from an imported one. It is in-memory like the signers themselves: both
	// are lost on restart together, so they cannot disagree.
	origins map[string]types.KeyOrigin
	mu      sync.RWMutex
}

// NewSoftwarePIVKeyGenerator creates a new software-based PIVKeyGenerator.
func NewSoftwarePIVKeyGenerator() *softwarePIVKeyGenerator {
	return &softwarePIVKeyGenerator{
		signers: make(map[string]crypto.Signer),
		origins: make(map[string]types.KeyOrigin),
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

	// Store the signer for later CSR generation. The origin is a consequence
	// of this code path being the generate path, not an input.
	g.mu.Lock()
	g.signers[cn] = signer
	g.origins[cn] = types.KeyOriginGenerated
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

// ImportPIVKey installs an externally held private key for the given slot.
//
// The software generator holds signers in memory keyed by CN, so importing is
// the same act as generating with the key supplied rather than created. The
// algorithm has already been resolved from the key itself by the caller; it is
// checked here against the generator's own vocabulary so that a key this
// generator could never have produced is refused rather than stored.
func (g *softwarePIVKeyGenerator) ImportPIVKey(_ context.Context, _ pivcert.PIVSlot, algorithm string, cn string, key crypto.PrivateKey) (crypto.Signer, error) {
	if _, ok := softwareKeyGenDispatch[algorithm]; !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrPIVKeyMaterialInvalid
	}

	g.mu.Lock()
	g.signers[cn] = signer
	g.origins[cn] = types.KeyOriginImported
	g.mu.Unlock()

	return signer, nil
}

// PIVKeyOrigin reports how the slot's key arrived.
//
// This generator's keys live only in memory, so a CN it has never seen means
// no key was created through it in this process — reported as not found rather
// than as an unknown origin. Every key it does hold was placed by its own
// generate or import path, so a found key always carries a definite origin.
func (g *softwarePIVKeyGenerator) PIVKeyOrigin(_ pivcert.PIVSlot, cn string) (types.KeyOrigin, bool, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	origin, ok := g.origins[cn]
	if !ok {
		return types.KeyOriginUnknown, false, nil
	}
	return origin, true, nil
}

// Verify import capability compliance at compile time.
var _ PIVKeyImporter = (*softwarePIVKeyGenerator)(nil)

// Verify origin-reporting compliance at compile time.
var _ PIVKeyOriginReporter = (*softwarePIVKeyGenerator)(nil)
