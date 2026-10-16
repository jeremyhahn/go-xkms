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

package signing

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// verifyHashes are the digest algorithms Verify accepts.
var verifyHashes = map[crypto.Hash]struct{}{
	crypto.SHA256: {},
	crypto.SHA384: {},
	crypto.SHA512: {},
}

// Verify checks signature, an RSA PKCS#1 v1.5 signature over digest, against
// publicKey. digest is the hash of the signed message computed with hash,
// which must be SHA-256, SHA-384 or SHA-512. Any other key type or hash is
// refused. The check runs through types.SimpleVerifier, the one RSA verify
// in go-xkms.
func Verify(publicKey crypto.PublicKey, hash crypto.Hash, digest, signature []byte) error {
	if publicKey == nil {
		return ErrPublicKeyRequired
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return &errs.Detail{Err: ErrUnsupportedKeyType, Detail: fmt.Sprintf("%T", publicKey)}
	}
	if rsaKey == nil {
		return ErrPublicKeyRequired
	}
	if _, ok := verifyHashes[hash]; !ok {
		return &errs.Detail{Err: ErrInvalidHashFunction, Detail: hash.String()}
	}
	if len(signature) == 0 {
		return ErrSignatureRequired
	}

	verifier := types.NewVerifier(&types.VerifyOpts{Hash: hash})
	if err := verifier.Verify(rsaKey, digest, signature); err != nil {
		return &errs.Joined{Lead: ErrVerificationFailed, Cause: err}
	}
	return nil
}
