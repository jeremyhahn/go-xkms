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

package jwk

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// KeyIDError reports a public key that has no SubjectPublicKeyInfo encoding,
// so no key ID can be derived from it.
type KeyIDError struct {
	KeyType string
	Err     error
}

func (e *KeyIDError) Error() string {
	return "jwk: cannot derive key ID from " + e.KeyType + ": " + e.Err.Error()
}

func (e *KeyIDError) Unwrap() error { return e.Err }

// SPKIKeyID derives the key ID published for a public key: the unpadded
// base64url encoding (RFC 7515 §2) of SHA-256 over the key's DER
// SubjectPublicKeyInfo (RFC 5280 §4.1.2.7).
//
// RFC 7517 §4.5 leaves the kid value to the application. This is the
// identifier the JWKS consumers of the session signing key publish each key
// under (go-xkms#1724, c181516), so a token's kid header (RFC 7515 §4.1.4)
// carrying it selects the published key. The value is a function of the key
// alone: the issuer and the published JWK derive it from the same Signer's
// public key and cannot drift.
func SPKIKeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", &KeyIDError{KeyType: fmt.Sprintf("%T", pub), Err: err}
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
