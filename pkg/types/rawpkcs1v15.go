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

package types

import (
	"crypto"
	"crypto/fips140"
	"crypto/rsa"
	"errors"
)

// ErrRawPKCS1v15Enforced reports a PKCS#1 v1.5 RSA signature requested over
// bytes the caller built -- crypto.Hash(0), the "NONE" hash on the wire --
// while GODEBUG=fips140=only is enforced. The only mode admits a PKCS#1 v1.5
// signature solely under a digest it can classify as approved, and a
// caller-built DigestInfo names none, so the operation is withheld.
var ErrRawPKCS1v15Enforced = errors.New("types: PKCS#1 v1.5 RSA signature without a named digest is not allowed in FIPS 140-only mode")

// CheckRawPKCS1v15 reports whether this process can produce or verify a
// PKCS#1 v1.5 RSA signature over caller-built bytes with key: an
// *rsa.PrivateKey for signing, an *rsa.PublicKey for verification, under the
// digest h. It returns ErrRawPKCS1v15Enforced when it cannot and nil when it
// can.
//
// It answers nil for every other combination -- a named digest, a non-RSA
// key, or a key that is not a crypto/rsa value -- because those never reach
// the refused call. A PKCS#11 or TPM signer holds an RSA key outside the
// process and builds its own DigestInfo, so it is deliberately not covered:
// the FIPS posture of that module, not of this process, governs it.
//
// Under fips140=only, crypto/rsa gates SignPKCS1v15 and VerifyPKCS1v15 on
// crypto/fips140.Enforced and, when it is set, calls hash.New() to classify
// the digest; crypto.Hash(0).New() panics ("requested hash function #0 is
// unavailable") rather than returning an error, so a caller that reaches the
// call dies. Enforced is the same variable the standard library reads at that
// site, which is why it is consulted here instead of a probe: it cannot
// disagree with the runtime. fips140.Enabled cannot serve, because it is true
// under fips140=on as well, where the identical raw signature works; gating
// on it would withdraw a working capability (go-xkms#303 measured the same
// split for digests). Hash.Available cannot serve either, since crypto.Hash(0)
// is never available in any mode.
func CheckRawPKCS1v15(key any, h crypto.Hash) error {
	if h != crypto.Hash(0) || !fips140.Enforced() {
		return nil
	}
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return ErrRawPKCS1v15Enforced
	}
	return nil
}
