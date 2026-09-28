// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

// rsaSigningMethods, ecdsaSigningMethods and ed25519SigningMethods are the
// jwt.SigningMethod names golang-jwt/v5 accepts for each public key type.
// They are the complete algorithm sets: pinning a token's accepted
// algorithms to the verification key's actual type is what closes the
// classic "alg: HS256 signed with the RSA/EC public key bytes" and
// "alg: none" confusion attacks, since jwt.WithValidMethods rejects any
// token whose header alg is not in this list before the key function is
// even consulted.
var (
	rsaSigningMethods     = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	ecdsaSigningMethods   = []string{"ES256", "ES384", "ES512"}
	ed25519SigningMethods = []string{"EdDSA"}
)

// UnsupportedVerificationKeyError is returned when a JWT verification key is
// neither RSA, ECDSA nor Ed25519 — most notably when it is a raw byte
// secret ([]byte, the Go representation go-jose gives an "oct" JWK), which
// would otherwise let a token forged with alg: HS* verify against the
// public key's own bytes treated as an HMAC secret.
type UnsupportedVerificationKeyError struct {
	// KeyType is the Go type of the offending key, for diagnostics.
	KeyType string
}

// Error implements the error interface.
func (e *UnsupportedVerificationKeyError) Error() string {
	return fmt.Sprintf(
		"auth: unsupported JWT verification key type %s; only RSA, ECDSA and Ed25519 public keys are accepted",
		e.KeyType)
}

// NoCommonSigningAlgorithmError is returned when a key's supported signing
// methods and an IdP's advertised id_token_signing_alg_values_supported
// share no algorithm: the discovery document and the key materially
// disagree, and there is no safe algorithm left to accept a token under.
type NoCommonSigningAlgorithmError struct {
	// KeyAlgorithms are the algorithms the verification key supports.
	KeyAlgorithms []string
	// AdvertisedAlgorithms are the algorithms the IdP's discovery document advertises.
	AdvertisedAlgorithms []string
}

// Error implements the error interface.
func (e *NoCommonSigningAlgorithmError) Error() string {
	return fmt.Sprintf(
		"auth: no signing algorithm is both supported by the verification key (%v) and advertised by the IdP (%v)",
		e.KeyAlgorithms, e.AdvertisedAlgorithms)
}

// validMethodsForKey returns the jwt.SigningMethod names permitted for pub,
// pinned to pub's concrete type. It never returns an HS* (HMAC) method:
// that family only appears here as a rejection path via
// UnsupportedVerificationKeyError, since a public/private asymmetric key
// verifier must never also be usable as an HMAC secret.
func validMethodsForKey(pub interface{}) ([]string, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return rsaSigningMethods, nil
	case *ecdsa.PublicKey:
		return ecdsaSigningMethods, nil
	case ed25519.PublicKey:
		return ed25519SigningMethods, nil
	default:
		return nil, &UnsupportedVerificationKeyError{KeyType: fmt.Sprintf("%T", pub)}
	}
}

// intersectSigningAlgorithms returns the elements of candidates that also
// appear in advertised, preserving the order of candidates. When advertised
// is empty (the discovery document did not publish
// id_token_signing_alg_values_supported, or none was consulted), it returns
// candidates unchanged.
func intersectSigningAlgorithms(candidates, advertised []string) []string {
	if len(advertised) == 0 {
		return candidates
	}
	allowed := make(map[string]bool, len(advertised))
	for _, alg := range advertised {
		allowed[alg] = true
	}
	out := make([]string, 0, len(candidates))
	for _, alg := range candidates {
		if allowed[alg] {
			out = append(out, alg)
		}
	}
	return out
}
