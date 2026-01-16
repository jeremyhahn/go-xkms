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

package quic

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"
)

// extractPublicKey extracts the public key from a private key
func extractPublicKey(privKey interface{}) (crypto.PublicKey, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	case crypto.Signer:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privKey)
	}
}

// parseHashAlgorithm parses a hash algorithm string
func parseHashAlgorithm(hashStr string) (crypto.Hash, error) {
	// Normalize: uppercase and remove hyphens for flexibility
	normalized := strings.ToUpper(strings.ReplaceAll(hashStr, "-", ""))
	switch normalized {
	case "SHA1":
		return crypto.SHA1, nil
	case "SHA224":
		return crypto.SHA224, nil
	case "SHA256", "":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
	}
}

// verifySignature verifies a signature using the public key
func verifySignature(pubKey crypto.PublicKey, digest, signature []byte, hash crypto.Hash) (bool, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key, hash, digest, signature)
		return err == nil, nil

	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest, signature), nil

	case ed25519.PublicKey:
		return ed25519.Verify(key, digest, signature), nil

	default:
		return false, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}
