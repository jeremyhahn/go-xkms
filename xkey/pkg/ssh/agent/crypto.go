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

package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// parseSubjectPublicKeyInfo parses a PKIX SubjectPublicKeyInfo structure.
func parseSubjectPublicKeyInfo(data []byte) (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// rsaPublicKey represents an RSA public key in ASN.1 format.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// parseRSAPublicKey parses an RSA public key from PKCS#1 format.
func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	var pub rsaPublicKey
	rest, err := asn1.Unmarshal(data, &pub)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after RSA public key")
	}

	if pub.N.Sign() <= 0 || pub.E <= 0 {
		return nil, fmt.Errorf("invalid RSA public key")
	}

	return &rsa.PublicKey{
		N: pub.N,
		E: pub.E,
	}, nil
}
