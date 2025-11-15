// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/jeremyhahn/go-keychain/pkg/opaque"
)

// CompareOpaqueKeyEquality compares an opaque key with a native private key for equality.
//
// For hardware-backed and cloud-backed keys, we can only compare the public key portions
// since the private key never leaves the secure environment. This function extracts public
// keys from both parameters and performs a deep comparison.
//
// This is a shared utility function used by all KeyStore implementations (PKCS#11, TPM2,
// AWS KMS, GCP KMS, Azure Key Vault) to provide consistent key equality semantics.
//
// Parameters:
//   - opaque: The opaque key from any supported keystore backend
//   - x: The private key to compare against
//
// Returns true if the public keys match, indicating the same key pair.
func CompareOpaqueKeyEquality(opaqueKey opaque.OpaqueKey, x crypto.PrivateKey) bool {
	if opaqueKey == nil || x == nil {
		return false
	}

	// Get public key from opaque key
	opaquePub := opaqueKey.Public()
	if opaquePub == nil {
		return false
	}

	// Extract public key from private key
	var xPub crypto.PublicKey
	switch pk := x.(type) {
	case *rsa.PrivateKey:
		xPub = &pk.PublicKey
	case *ecdsa.PrivateKey:
		xPub = &pk.PublicKey
	case ed25519.PrivateKey:
		xPub = pk.Public()
	default:
		return false
	}

	// Compare public keys based on type
	switch opaquePubKey := opaquePub.(type) {
	case *rsa.PublicKey:
		xPubKey, ok := xPub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		// Compare RSA modulus and exponent
		return opaquePubKey.N.Cmp(xPubKey.N) == 0 && opaquePubKey.E == xPubKey.E

	case *ecdsa.PublicKey:
		xPubKey, ok := xPub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		// Compare ECDSA curve and coordinates
		return opaquePubKey.Curve == xPubKey.Curve &&
			opaquePubKey.X.Cmp(xPubKey.X) == 0 &&
			opaquePubKey.Y.Cmp(xPubKey.Y) == 0

	case ed25519.PublicKey:
		xPubKey, ok := xPub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		// Compare Ed25519 public key bytes
		if len(opaquePubKey) != len(xPubKey) {
			return false
		}
		for i := range opaquePubKey {
			if opaquePubKey[i] != xPubKey[i] {
				return false
			}
		}
		return true

	default:
		return false
	}
}
