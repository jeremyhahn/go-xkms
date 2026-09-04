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
	"bytes"
	"crypto"
	"errors"
	"testing"
)

// kdfConformanceSecret is a fixed shared secret; the derivations below are
// compared against each other, not against published vectors (those live in
// pkg/crypto/kdf), so a constant is all that is required.
var kdfConformanceSecret = []byte("go-xkms kdf conformance shared secret")

// paramsForBridge returns a minimal, valid KDFParams for algorithm with the
// given hash, populating only the fields that algorithm consumes.
func paramsForBridge(algorithm KDFAlgorithm, hash string, keyLength int) *KDFParams {
	p := &KDFParams{Algorithm: algorithm, Hash: hash, KeyLength: keyLength}
	bridge := kdfBridges[algorithm]
	if bridge.usesInfo {
		p.Info = []byte("conformance-info")
	}
	if bridge.usesLabelContext {
		p.Label = []byte("conformance-label")
		p.Context = []byte("conformance-context")
	}
	return p
}

// TestKDFBridges_EveryAdvertisedHashDerives is the assertion that would have
// caught the PKCS#11 ECDH KDF defect. The xkms PKCS#11 module advertises one
// CK_EC_KDF_TYPE per hash and forwards the hash name here, but the KDF layer
// had a single allowlist that omitted SHA-1, SHA-224 and SHA3-224 — so
// CKD_SHA1_KDF, CKD_SHA224_KDF and CKD_SHA3_224_KDF were advertised and always
// failed at derivation time.
//
// The test is driven from the advertised tables themselves rather than a
// restated list, so a hash added to prfKDFHashes or concatKDFHashes cannot
// escape coverage.
func TestKDFBridges_EveryAdvertisedHashDerives(t *testing.T) {
	for algorithm, bridge := range kdfBridges {
		if len(bridge.hashes) == 0 {
			t.Errorf("%s advertises no hashes; every bridge must name its approved set", algorithm)
			continue
		}
		for name, want := range bridge.hashes {
			t.Run(algorithm.String()+"/"+name, func(t *testing.T) {
				// A hash the bridge advertises but this process cannot compute
				// is REPORTED as unavailable rather than derived with, so the
				// contract under test is "every hash the bridge REPORTS
				// derives". Before go-xkms#292 the two were the same thing and
				// this loop panicked under GODEBUG=fips140=only when it reached
				// X9.63/SHA-1.
				if _, ok := bridge.hash(name); !ok {
					if HashUsable(want) {
						t.Fatalf("bridge refuses %v, but this process can compute it", want)
					}
					t.Skipf("%v is not computable in this process; the bridge correctly refuses it", want)
				}

				params := paramsForBridge(algorithm, name, 48)

				// Validate is the request-admission path; Derive is the
				// execution path. Both must accept an advertised hash.
				if err := params.Validate(); err != nil {
					t.Fatalf("Validate rejected an advertised hash: %v", err)
				}

				derived, err := params.Derive(kdfConformanceSecret)
				if err != nil {
					t.Fatalf("Derive failed for an advertised hash: %v", err)
				}
				if len(derived) != 48 {
					t.Fatalf("derived %d bytes, want 48", len(derived))
				}
				if bytes.Equal(derived, make([]byte, 48)) {
					t.Fatal("derived all zero bytes")
				}

				// The named hash must be the one that ran: a different digest
				// length is impossible to fake, and a KDF that silently
				// substituted SHA-256 for SHA-1 would produce identical bytes
				// for both names.
				if got := want.Size(); got == 0 {
					t.Fatalf("%s reports a zero digest size", name)
				}
				sha256Params := paramsForBridge(algorithm, "SHA-256", 48)
				sha256Derived, err := sha256Params.Derive(kdfConformanceSecret)
				if err != nil {
					t.Fatalf("SHA-256 baseline derivation failed: %v", err)
				}
				if want != crypto.SHA256 && bytes.Equal(derived, sha256Derived) {
					t.Fatalf("%s derived the same bytes as SHA-256; the requested hash was not used", name)
				}

				// Derivation must be deterministic: the same inputs on a peer
				// must reproduce the key.
				again, err := paramsForBridge(algorithm, name, 48).Derive(kdfConformanceSecret)
				if err != nil {
					t.Fatalf("second derivation failed: %v", err)
				}
				if !bytes.Equal(derived, again) {
					t.Fatal("derivation is not deterministic")
				}
			})
		}
	}
}

// TestKDFBridges_UnadvertisedHashRejected is the converse: a hash outside the
// set a construction advertises must be refused with the typed error, and must
// be refused by Validate as well as Derive so an unapproved request never
// reaches a backend.
func TestKDFBridges_UnadvertisedHashRejected(t *testing.T) {
	// Every hash name any bridge accepts, plus a representative set of names
	// no bridge accepts.
	candidates := map[string]struct{}{
		"MD5": {}, "MD4": {}, "RIPEMD-160": {}, "MD5+SHA1": {},
		"BLAKE2b-256": {}, "SHA-512/224": {}, "SHA-512/256": {},
		"": {}, "sha256": {}, "SHA256": {}, "SHA-999": {},
	}
	for _, bridge := range kdfBridges {
		for name := range bridge.hashes {
			candidates[name] = struct{}{}
		}
	}

	for algorithm, bridge := range kdfBridges {
		for name := range candidates {
			if _, advertised := bridge.hashes[name]; advertised {
				continue
			}
			t.Run(algorithm.String()+"/"+name, func(t *testing.T) {
				// An empty name is not an unapproved hash: Validate documents
				// it as selecting the SHA-256 default. Derive does not default,
				// so it still has to reject it. See
				// TestKDFValidate_DefaultsEmptyHashToSHA256.
				if name != "" {
					params := paramsForBridge(algorithm, name, 32)
					if err := params.Validate(); !errors.Is(err, ErrUnsupportedKDFHash) {
						t.Errorf("Validate returned %v, want ErrUnsupportedKDFHash", err)
					}
				}

				params := paramsForBridge(algorithm, name, 32)
				key, err := params.Derive(kdfConformanceSecret)
				if !errors.Is(err, ErrUnsupportedKDFHash) {
					t.Errorf("Derive returned %v (%d bytes), want ErrUnsupportedKDFHash", err, len(key))
				}
				if key != nil {
					t.Error("Derive returned key material for an unapproved hash")
				}
			})
		}
	}
}

// TestKDFValidate_DefaultsEmptyHashToSHA256 pins the one documented case where
// an unnamed hash is not an error: Validate is the request-admission path and
// fills in the algorithm and hash defaults it documents. Derive does not
// default, so a caller that skips Validate gets a typed error rather than a
// key derived from a hash it never chose.
func TestKDFValidate_DefaultsEmptyHashToSHA256(t *testing.T) {
	for algorithm := range kdfBridges {
		params := paramsForBridge(algorithm, "", 32)
		if err := params.Validate(); err != nil {
			t.Fatalf("%s: Validate rejected an empty hash: %v", algorithm, err)
		}
		if params.Hash != "SHA-256" {
			t.Errorf("%s: Validate defaulted the hash to %q, want SHA-256", algorithm, params.Hash)
		}
		if _, err := params.Derive(kdfConformanceSecret); err != nil {
			t.Errorf("%s: the defaulted parameters must derive: %v", algorithm, err)
		}
	}
}

// TestConcatKDFHashes_SupersetOfPRFHashes pins the relationship between the
// two sets. The concatenation KDFs accept everything the HMAC-based KDFs do,
// plus exactly the three digests ANSI X9.63, SP 800-56A Rev. 3 and PKCS#11
// v3.0 define for that construction. Anything else appearing in the difference
// is a policy change that has to be made deliberately.
func TestConcatKDFHashes_SupersetOfPRFHashes(t *testing.T) {
	for name, want := range prfKDFHashes {
		got, ok := concatKDFHashes[name]
		if !ok || got != want {
			t.Errorf("concatKDFHashes[%q] = %v (present=%v), want %v", name, got, ok, want)
		}
	}

	extra := map[string]crypto.Hash{}
	for name, h := range concatKDFHashes {
		if _, shared := prfKDFHashes[name]; !shared {
			extra[name] = h
		}
	}
	want := map[string]crypto.Hash{
		"SHA-1":    crypto.SHA1,
		"SHA-224":  crypto.SHA224,
		"SHA3-224": crypto.SHA3_224,
	}
	if len(extra) != len(want) {
		t.Fatalf("concat-only hashes = %v, want %v", extra, want)
	}
	for name, h := range want {
		if extra[name] != h {
			t.Errorf("concat-only hash %q = %v, want %v", name, extra[name], h)
		}
	}
}

// TestPRFKDFHashes_ExcludeWeakDigests asserts the HMAC-based KDFs did not
// inherit the concatenation KDFs' SHA-1 exception. SHA-1 is approved for the
// X9.63 / SP 800-56A construction because PKCS#11 names it there; HKDF and
// SP 800-108 carry no such contract in this codebase and hold a 128-bit floor.
func TestPRFKDFHashes_ExcludeWeakDigests(t *testing.T) {
	for name, h := range prfKDFHashes {
		if IsWeakHash(h) {
			t.Errorf("prfKDFHashes[%q] = %v is a collision-broken digest", name, h)
		}
		if h.Size() < 32 {
			t.Errorf("prfKDFHashes[%q] = %v has a %d-byte digest, below the 256-bit floor", name, h, h.Size())
		}
	}

	// Concretely: SHA-1 derives under X9.63 and is refused under HKDF, in the
	// same binary, with no policy switch involved.
	if _, err := paramsForBridge(KDFAlgorithmX963, "SHA-1", 32).Derive(kdfConformanceSecret); err != nil {
		t.Errorf("X9.63 with SHA-1 must derive (PKCS#11 CKD_SHA1_KDF): %v", err)
	}
	if _, err := paramsForBridge(KDFAlgorithmHKDF, "SHA-1", 32).Derive(kdfConformanceSecret); !errors.Is(err, ErrUnsupportedKDFHash) {
		t.Errorf("HKDF with SHA-1 must be refused, got %v", err)
	}
}

// TestKDFHashSets_AreIndependentOfWeakHashPolicy asserts that the KDF
// allowlists are purpose-scoped constants, not a view of the signing-side
// weak-hash policy. Turning the policy on must not widen the KDF sets, and
// turning it off must not break CKD_SHA1_KDF — SP 800-131A Rev. 2 permits
// SHA-1 for key derivation in a deployment where it is disallowed for signing.
func TestKDFHashSets_AreIndependentOfWeakHashPolicy(t *testing.T) {
	// The subject is the WEAK-HASH POLICY: whether allow_weak_hashes is set
	// must not change the KDF hash sets, because SP 800-131A Rev. 2 keeps
	// SHA-1 acceptable for non-signature uses and the policy governs signing.
	//
	// Runtime usability is a separate axis and does bind: under
	// GODEBUG=fips140=only Go refuses crypto/sha1 for every use, so SHA-1 is
	// refused there with ErrUnsupportedKDFHash whatever the policy says
	// (go-xkms#292). The assertion below is therefore "the same answer for
	// both policy values", which is the property this test is named for,
	// rather than "SHA-1 always derives", which was only ever true of a
	// non-FIPS process.
	sha1Derives := HashUsable(crypto.SHA1)

	for _, allow := range []bool{false, true} {
		withWeakHashes(t, allow, func() {
			for _, algorithm := range []KDFAlgorithm{KDFAlgorithmX963, KDFAlgorithmSP80056A} {
				_, err := paramsForBridge(algorithm, "SHA-1", 32).Derive(kdfConformanceSecret)
				switch {
				case sha1Derives && err != nil:
					t.Errorf("allow_weak=%v: %v/SHA-1 must derive: %v", allow, algorithm, err)
				case !sha1Derives && !errors.Is(err, ErrUnsupportedKDFHash):
					t.Errorf("allow_weak=%v: %v/SHA-1 must be refused with ErrUnsupportedKDFHash, got %v",
						allow, algorithm, err)
				}
			}
			for _, name := range []string{"MD5", "MD4", "RIPEMD-160"} {
				_, err := paramsForBridge(KDFAlgorithmX963, name, 32).Derive(kdfConformanceSecret)
				if !errors.Is(err, ErrUnsupportedKDFHash) {
					t.Errorf("allow_weak=%v: X9.63/%s must be refused, got %v", allow, name, err)
				}
			}
		})
	}
}
