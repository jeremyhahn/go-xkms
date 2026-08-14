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
	"crypto/elliptic"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// pivAlgorithmAttrs maps PIV algorithm strings to KeyAttributes builders.
// Each entry returns a partially-filled KeyAttributes with the correct
// algorithm, key type, and algorithm-specific parameters.
type pivAlgorithmBuilder func(cn string) *types.KeyAttributes

// pivAlgorithmDispatch provides O(1) map-based dispatch for algorithm mapping.
var pivAlgorithmDispatch = map[string]pivAlgorithmBuilder{
	"rsa2048": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}
	},
	"rsa4096": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096,
			},
		}
	},
	"ecdsap256": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
	},
	"ecdsap384": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P384(),
			},
		}
	},
	"ed25519": func(cn string) *types.KeyAttributes {
		return &types.KeyAttributes{
			CN:           cn,
			KeyAlgorithm: x509.Ed25519,
			KeyType:      types.KeyTypeSigning,
		}
	},
}

// backendPIVKeyGenerator generates PIV keys using an xkms Backend.
// It delegates key generation and signer retrieval to the configured backend,
// allowing TPM2, PKCS11, and other backends to handle actual cryptographic operations.
type backendPIVKeyGenerator struct {
	backend   Backend
	storeType types.StoreType
}

// newBackendPIVKeyGenerator creates a new backend-backed PIVKeyGenerator.
// The storeType identifies the backend storage type (e.g., "software", "tpm2", "pkcs11")
// and is set on generated KeyAttributes to satisfy validation requirements.
func newBackendPIVKeyGenerator(backend Backend, storeType types.StoreType) *backendPIVKeyGenerator {
	return &backendPIVKeyGenerator{backend: backend, storeType: storeType}
}

// GeneratePIVKey generates a new key for the given PIV slot using the configured backend.
// An empty algorithm defaults to "ecdsap256".
func (g *backendPIVKeyGenerator) GeneratePIVKey(slot pivcert.PIVSlot, algorithm string, cn string) (crypto.Signer, error) {
	if algorithm == "" {
		algorithm = "ecdsap256"
	}

	builder, ok := pivAlgorithmDispatch[algorithm]
	if !ok {
		return nil, ErrPIVInvalidAlgorithm
	}

	attrs := builder(cn)
	attrs.StoreType = g.storeType
	attrs.PIVSlot = string(slot)

	// If the backend implements PIVParentProvider, set the parent key attributes.
	// This is used by TPM2 to set PlatformSRK as the parent for PIV keys.
	if provider, ok := g.backend.(PIVParentProvider); ok {
		parentAttrs, err := provider.PIVParentAttributes()
		if err != nil {
			return nil, err
		}
		if parentAttrs != nil {
			attrs.Parent = parentAttrs
		}
	}

	// context.Background() is correct here: GeneratePIVKey implements the
	// PIVKeyGenerator interface, which carries no request context.
	ctx := context.Background()

	// Generate the key using the appropriate backend method
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if _, err := g.backend.GenerateRSA(ctx, attrs); err != nil {
			return nil, err
		}
	case x509.ECDSA:
		if _, err := g.backend.GenerateECDSA(ctx, attrs); err != nil {
			return nil, err
		}
	case x509.Ed25519:
		if _, err := g.backend.GenerateEd25519(ctx, attrs); err != nil {
			return nil, err
		}
	default:
		return nil, ErrPIVInvalidAlgorithm
	}

	// Retrieve the signer for the generated key
	return g.backend.Signer(ctx, attrs)
}

// GetPIVSigner returns a signer for an existing key in the given PIV slot.
// PIVSlot is populated so slot-constrained backends (e.g., YubiKey PKCS#11)
// can locate the key by CKA_ID instead of relying on a CN convention that may
// not match the certificate subject users choose when generating the key.
func (g *backendPIVKeyGenerator) GetPIVSigner(slot pivcert.PIVSlot, cn string) (crypto.Signer, error) {
	// context.Background() is correct here: GetPIVSigner implements the
	// PIVKeyGenerator interface, which carries no request context.
	ctx := context.Background()

	// Resolve the stored key's full attributes by CN so the backend's
	// Signer receives the algorithm, store type, and key type it validates
	// against — a CN+slot shell fails attribute validation on backends
	// that persist keys (e.g. software/pkcs8).
	if stored, err := g.backend.ListKeys(ctx); err == nil {
		for _, ka := range stored {
			if ka != nil && ka.CN == cn {
				return g.backend.Signer(ctx, ka)
			}
		}
	}

	// Fall back to the CN+slot shell for backends whose ListKeys does not
	// enumerate slot keys (e.g. hardware tokens resolving by CKA_ID).
	attrs := &types.KeyAttributes{
		CN:        cn,
		PIVSlot:   string(slot),
		StoreType: g.storeType,
		KeyType:   types.KeyTypeSigning,
	}
	return g.backend.Signer(ctx, attrs)
}

// Verify interface compliance at compile time.
var _ PIVKeyGenerator = (*backendPIVKeyGenerator)(nil)
