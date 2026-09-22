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

package software

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// zeroizeParsedPrivateKey overwrites the secret components of a private key
// value produced by x509.ParsePKCS8PrivateKey.
//
// Parsing PKCS#8 creates a SECOND copy of the secret, independent of the DER
// that produced it: x509 decodes the scalar into freshly allocated big.Ints or
// byte slices, so wiping the DER leaves that copy untouched on the heap for the
// collector to release whenever it likes. This bounds the parsed copy's
// residency the same way ImportKey bounds the DER's.
//
// It is called on a key the caller is DISCARDING. Every field it touches is a
// secret component, and a key it has run over cannot sign — so it must never
// run on a key that is still going to be used.
//
// # What it cannot reach
//
// The wipe is best-effort by construction, and the residue is named here
// rather than left for a reader to discover:
//
//   - *rsa.PrivateKey — Go caches bigmod-form copies of the modulus and the
//     primes in unexported fields of rsa.PrecomputedValues (`go doc
//     crypto/rsa.PrecomputedValues` ends in "Has unexported fields"). Those
//     copies hold the same primes as Primes[], and no exported API reaches
//     them.
//   - *ecdh.PrivateKey — the X25519/NIST scalar lives in an unexported field
//     with no zeroization method. Bytes() returns a copy, so wiping what it
//     returns wipes the copy and not the key.
//   - *ecdsa.PrivateKey and ed25519.PrivateKey — IF THE KEY HAS BEEN USED.
//     Both packages keep a package-level crypto/internal/fips140cache entry
//     holding a second, FIPS-module copy of the scalar (ecdsa.go's
//     privateKeyCache, ed25519.go's privateKeyCache). It is populated lazily
//     by Sign/Bytes/ECDH, never by parsing, and it is a weak map: the entry is
//     evicted only once the key value itself becomes unreachable, which the
//     collector does on its own schedule. This function's one caller
//     (importAsymmetricKey) parses and validates without ever signing, so on
//     that path the cache is never populated and D/the seed really are the
//     only copies. A future caller that wipes a key it has USED would leave
//     that copy behind, which is why it is named here rather than implied by
//     the ed25519 case reading as complete.
//
// Reaching either needs unsafe pointer arithmetic over another package's
// private layout, which trades a bounded, documented residue for an unbounded
// one that breaks silently on a toolchain bump. The residue is therefore
// accepted and recorded (go-xkms#133) rather than hidden — see the repo
// policy at docs/development/lint-gates.md, section "Accepted residue:
// stdlib copies no exported API can wipe", which also covers the same class
// of residue in crypto/hmac (go-xkms#134, go-xkms#41).
func zeroizeParsedPrivateKey(key crypto.PrivateKey) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return
		}
		zeroizeBigInt(k.D)
		for _, prime := range k.Primes {
			zeroizeBigInt(prime)
		}
		zeroizeBigInt(k.Precomputed.Dp)
		zeroizeBigInt(k.Precomputed.Dq)
		zeroizeBigInt(k.Precomputed.Qinv)
		// SA1019 says these values "are still filled in by Precompute ... but
		// are not used", and the first half of that sentence is why they are
		// wiped: Precompute writes real CRT material for the 3rd and
		// subsequent primes, so on a multi-prime key the slice holds secrets
		// whether or not the rsa package reads them back. Deprecated is not
		// unpopulated. The slice header is hoisted so one directive covers the
		// loop; crt aliases k.Precomputed.CRTValues, so the wipe is in place.
		crt := k.Precomputed.CRTValues //nolint:staticcheck // SA1019: deprecated but still populated by Precompute; a wipe that skips it leaves CRT material on the heap
		for i := range crt {
			zeroizeBigInt(crt[i].Exp)
			zeroizeBigInt(crt[i].Coeff)
			zeroizeBigInt(crt[i].R)
		}
	case *ecdsa.PrivateKey:
		if k == nil {
			return
		}
		// SA1019 deprecates D because "modifying the raw value can produce
		// invalid keys". Producing an invalid key IS the operation: this runs
		// only on a key the caller is discarding.
		zeroizeBigInt(k.D) //nolint:staticcheck // SA1019: D is the ECDSA secret scalar and the only exported route to its storage; destroying the key is the intent
	case ed25519.PrivateKey:
		// An ed25519.PrivateKey IS the key bytes (seed || public), so wiping
		// the slice wipes the key itself rather than a view of it -- with the
		// one exception named in the doc comment above: a key that has been
		// used to Sign also has a fips140cache copy this cannot reach.
		secure.Wipe(k)
	case *ecdh.PrivateKey:
		// Unreachable through the public API; see the doc comment above.
	default:
		// A type this function does not know is a type whose secret fields it
		// cannot name. Doing nothing is the only correct action -- there is no
		// generic "wipe a private key" operation to fall back to.
	}
}

// zeroizeBigInt overwrites the magnitude of v in place.
//
// big.Int offers no zeroization API, and the obvious v.SetInt64(0) does NOT
// erase anything: it reslices the internal nat to length zero and leaves every
// word of the backing array holding the secret. Bits() is the one exported
// route to that array -- it is documented to alias v's storage, which is
// exactly the property wanted here -- so the words are cleared through it and
// v is then normalized to a genuine zero.
func zeroizeBigInt(v *big.Int) {
	if v == nil {
		return
	}
	words := v.Bits()
	for i := range words {
		words[i] = 0
	}
	v.SetInt64(0)
}
