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
	"testing"
)

// blake2Or returns h when its implementation is linked into the test binary
// and 0 otherwise. The BLAKE2 family is only linked when something imports
// golang.org/x/crypto/blake2b or blake2s, so a table that hard-codes it would
// assert the linkage of the test binary's dependency graph rather than the
// behaviour under test.
func blake2Or(h crypto.Hash) crypto.Hash {
	if h.Available() {
		return h
	}
	return 0
}

// weakOr returns h when the current weak-hash policy admits it and the digest
// is actually linked into the binary, else 0 — the value ParseHash yields.
// Outside FIPS mode the collision-broken digests resolve (PKCS#11 and TLS
// define mechanisms over them); under FIPS mode they are withheld.
func weakOr(h crypto.Hash) crypto.Hash {
	if AllowWeakHashes() && h.Available() {
		return h
	}
	return 0
}

// withWeakHashes runs fn with the process-wide weak-hash policy set to allow
// and restores the previous setting afterwards. The policy is process-global,
// so tests that use it must not run in parallel with each other.
func withWeakHashes(t *testing.T, allow bool, fn func()) {
	t.Helper()
	prev := AllowWeakHashes()
	SetAllowWeakHashes(allow)
	defer SetAllowWeakHashes(prev)
	fn()
}

// TestWeakHashes_AreTheCollisionBrokenDigests pins the membership of the weak
// set. Adding a hash here has real consequences (it disappears from
// AvailableHashes and ParseHash for every deployment that has not opted in),
// and removing one silently re-admits a forgeable digest to the signing path,
// so the set is asserted rather than derived.
func TestWeakHashes_AreTheCollisionBrokenDigests(t *testing.T) {
	weak := []crypto.Hash{crypto.MD4, crypto.MD5, crypto.SHA1, crypto.MD5SHA1, crypto.RIPEMD160}
	for _, h := range weak {
		if !IsWeakHash(h) {
			t.Errorf("%s must be classified weak: it has no collision resistance and "+
				"SP 800-131A Rev. 2 disallows it for signature generation", h)
		}
	}

	strong := []crypto.Hash{
		crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	}
	for _, h := range strong {
		if IsWeakHash(h) {
			t.Errorf("%s must not be classified weak: it is an approved digest", h)
		}
	}

	if got, want := len(WeakHashNames()), len(weak); got != want {
		t.Errorf("WeakHashNames() reported %d names, want %d: %v", got, want, WeakHashNames())
	}
}

// TestAvailableHashes_RefusesWeakHashesByDefault is the reject side of the
// weak-hash policy. A deployment that has not opted in must not be able to
// resolve a broken digest by name from either general-purpose table, because
// both feed the signing, certificate, and TPM attestation paths.
func TestAvailableHashes_RefusesWeakHashesByDefault(t *testing.T) {
	withWeakHashes(t, false, func() {
		hashes := AvailableHashes()
		for name, h := range allKnownHashes {
			if !IsWeakHash(h) {
				continue
			}
			if got, present := hashes[name]; present {
				t.Errorf("AvailableHashes()[%q] = %v: weak hashes must be refused by default", name, got)
			}
			if got := ParseHash(name); got != 0 {
				t.Errorf("ParseHash(%q) = %v, want 0: weak hashes must be refused by default", name, got)
			}
		}

		// The two legacy spellings ParseHash accepts outside allKnownHashes
		// are weak too and must be refused on the same terms.
		for _, name := range []string{"MD5SHA1", "RIPEMD160", "md5", "SHA1", "sha1", "  SHA-1  "} {
			if got := ParseHash(name); got != 0 {
				t.Errorf("ParseHash(%q) = %v, want 0", name, got)
			}
		}
	})
}

// TestAvailableHashes_AdmitsWeakHashesUnderPolicy is the accept side. Outside
// FIPS mode these digests have to actually resolve, otherwise the PKCS#11
// module cannot offer the SHA-1/MD5 mechanisms the specification defines and
// a conformance run has nothing to exercise.
func TestAvailableHashes_AdmitsWeakHashesUnderPolicy(t *testing.T) {
	withWeakHashes(t, true, func() {
		hashes := AvailableHashes()

		// SHA-1 and MD5 are linked into this binary (pkg/tpm2 and pkg/certstore
		// import them), so the policy — not linkage — is what is under test.
		for name, want := range map[string]crypto.Hash{"SHA-1": crypto.SHA1, "MD5": crypto.MD5} {
			if !want.Available() {
				t.Fatalf("%s is not linked into the test binary; this test cannot prove the policy", name)
			}
			got, ok := hashes[name]
			if !ok || got != want {
				t.Errorf("AvailableHashes()[%q] = %v (present=%v), want %v", name, got, ok, want)
			}
			if got := ParseHash(name); got != want {
				t.Errorf("ParseHash(%q) = %v, want %v", name, got, want)
			}
			// The real proof: the returned hash computes.
			if n := want.New().Size(); n != want.Size() {
				t.Errorf("%s produced a %d-byte digest, want %d", name, n, want.Size())
			}
		}
	})
}

// TestAllowWeakHashes_RoundTrips verifies the policy accessor pair. The
// package refuses by default — a policy that defaulted to permissive would
// make every embedded/library user able to produce a forgeable signature
// without asking — and the opt-in only takes effect outside FIPS mode, where
// the validated module's approved-algorithm boundary is the ceiling.
func TestAllowWeakHashes_RoundTrips(t *testing.T) {
	original := AllowWeakHashes()
	t.Cleanup(func() { SetAllowWeakHashes(original) })

	// Tightening always takes effect, in either mode.
	SetAllowWeakHashes(false)
	if AllowWeakHashes() {
		t.Error("SetAllowWeakHashes(false) did not take effect")
	}

	// Loosening takes effect only outside FIPS mode.
	SetAllowWeakHashes(true)
	if got, want := AllowWeakHashes(), !FIPSMode(); got != want {
		t.Errorf("after SetAllowWeakHashes(true): got %t, want %t (FIPS mode = %t)", got, want, FIPSMode())
	}
}

// TestParseHash_RoundTripsEveryAdvertisedName drives the assertion from the
// advertised table itself: every name AvailableHashes hands out must parse
// back to the same hash and must actually compute a digest of the documented
// length. This is the shape of assertion that catches "the table says yes, the
// code says something else" — a name that is advertised but not parseable, or
// parseable but not constructible, fails here without anyone remembering to
// add a case.
func TestParseHash_RoundTripsEveryAdvertisedName(t *testing.T) {
	for _, allow := range []bool{false, true} {
		withWeakHashes(t, allow, func() {
			hashes := AvailableHashes()
			if len(hashes) == 0 {
				t.Fatal("AvailableHashes returned nothing")
			}
			for name, want := range hashes {
				got := ParseHash(name)
				if got != want {
					t.Errorf("allow_weak=%v: ParseHash(%q) = %v, want %v", allow, name, got, want)
					continue
				}
				// New panics for an unlinked hash; a passing call is the proof
				// that the advertisement is backed by a working implementation.
				h := got.New()
				h.Write([]byte("go-xkms"))
				if n := len(h.Sum(nil)); n != got.Size() {
					t.Errorf("allow_weak=%v: %q produced %d bytes, want %d", allow, name, n, got.Size())
				}
			}
		})
	}
}

// TestParseHash_RefusesUnlinkedHashes asserts the linkage filter. ParseHash
// previously returned crypto.BLAKE2s_256 for "BLAKE2s_256" whether or not the
// implementation was linked, and crypto.Hash.New panics rather than erroring
// for an unlinked hash, so a caller-supplied algorithm name could kill the
// process.
func TestParseHash_RefusesUnlinkedHashes(t *testing.T) {
	var unlinked []string
	for name, h := range allKnownHashes {
		if h.Available() {
			continue
		}
		unlinked = append(unlinked, name)
		if got := ParseHash(name); got != 0 {
			t.Errorf("ParseHash(%q) = %v but the implementation is not linked; "+
				"calling New on it would panic", name, got)
		}
	}
	if len(unlinked) == 0 {
		t.Fatal("every known hash is linked into the test binary, so the linkage filter is " +
			"untested here; if a dependency started linking MD4/RIPEMD-160/BLAKE2, pick another")
	}
	t.Logf("refused %d unlinked name(s), e.g. %v", len(unlinked), unlinked[:min(3, len(unlinked))])
}

// TestParseHash_RefusesUnknownNames covers the plain error path: a misspelled
// or invented name must resolve to 0 rather than to some nearby hash.
func TestParseHash_RefusesUnknownNames(t *testing.T) {
	for _, name := range []string{"", "  ", "SHA-999", "HMAC-SHA256", "sha", "SHA2", "not a hash", "SHA-256-EXTRA"} {
		if got := ParseHash(name); got != 0 {
			t.Errorf("ParseHash(%q) = %v, want 0", name, got)
		}
	}
}

// TestParseHash_NameNormalization asserts the documented spelling tolerance:
// case, surrounding whitespace, and "-" versus "_" must not change the result.
func TestParseHash_NameNormalization(t *testing.T) {
	for _, name := range []string{"SHA-256", "sha256", "SHA256", "SHA_256", "  sha-256  ", "Sha-256"} {
		if got := ParseHash(name); got != crypto.SHA256 {
			t.Errorf("ParseHash(%q) = %v, want SHA-256", name, got)
		}
	}
	for _, name := range []string{"SHA3-256", "sha3_256", "SHA3_256"} {
		if got := ParseHash(name); got != crypto.SHA3_256 {
			t.Errorf("ParseHash(%q) = %v, want SHA3-256", name, got)
		}
	}
}
