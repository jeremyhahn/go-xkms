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

//go:build integration && conformance
// +build integration,conformance

// Package conformance covers the operations no external tool exercises.
//
// The OpenSSL suites drive signing, verification and X.509 issuance, because
// those are what OpenSSL itself does. They never reach digesting, random
// generation, multi-part streaming, or the two-call output convention, and a
// defect in any of those is invisible until an application trips over it.
//
// Where a standard-library equivalent exists — digests especially — it is used
// as the oracle. Comparing the module's SHA-256 against crypto/sha256 is a
// stronger statement than checking the output is 32 bytes long, and it is the
// difference between "produced something" and "produced the right thing".
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// TestDigest_MatchesStandardLibrary proves the module's digest output equals
// the standard library's for the same input.
//
// Length and non-emptiness checks pass for any digest implementation, correct
// or not. Only comparing against a known-good implementation catches a wrong
// initial value, a truncated final block, or a mechanism wired to the wrong
// hash.
func TestDigest_MatchesStandardLibrary(t *testing.T) {
	payload := []byte("conformance digest payload")

	cases := []struct {
		name string
		mech module.MechanismType
		want []byte
	}{
		{"SHA-256", module.CKM_SHA256, sha256Sum(payload)},
		{"SHA-384", module.CKM_SHA384, sha384Sum(payload)},
		{"SHA-512", module.CKM_SHA512, sha512Sum(payload)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)

			if rv := env.Module.DigestInit(session, &module.Mechanism{Type: tc.mech}); rv != module.CKR_OK {
				t.Fatalf("C_DigestInit returned %s", rv.String())
			}

			got, rv := env.Module.Digest(session, payload)
			if rv != module.CKR_OK {
				t.Fatalf("C_Digest returned %s", rv.String())
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("digest mismatch\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

// TestDigest_MultiPartMatchesSinglePart proves that digesting a payload in
// several C_DigestUpdate calls yields the same value as digesting it at once.
//
// This is where accumulation bugs live: a module that drops the first chunk, or
// resets its state on each update, still returns a well-formed digest of the
// right length.
func TestDigest_MultiPartMatchesSinglePart(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	parts := [][]byte{
		[]byte("first chunk "),
		[]byte("second chunk "),
		[]byte("third chunk"),
	}
	var whole []byte
	for _, p := range parts {
		whole = append(whole, p...)
	}

	if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit returned %s", rv.String())
	}
	for i, p := range parts {
		if rv := env.Module.DigestUpdate(session, p); rv != module.CKR_OK {
			t.Fatalf("C_DigestUpdate #%d returned %s", i, rv.String())
		}
	}
	got, rv := env.Module.DigestFinal(session)
	if rv != module.CKR_OK {
		t.Fatalf("C_DigestFinal returned %s", rv.String())
	}

	if want := sha256Sum(whole); !bytes.Equal(got, want) {
		t.Errorf("the multi-part digest does not match the single-part digest of the "+
			"same bytes\n got %x\nwant %x", got, want)
	}
}

// TestDigest_EmptyInputIsTheEmptyDigest checks the boundary case.
//
// The digest of no input is a specific, well-known value; a module that
// special-cases empty input by returning zeros or an error is wrong, and this
// is the cheapest place to find that out.
func TestDigest_EmptyInputIsTheEmptyDigest(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit returned %s", rv.String())
	}
	got, rv := env.Module.Digest(session, nil)
	if rv != module.CKR_OK {
		t.Fatalf("C_Digest over empty input returned %s", rv.String())
	}
	if want := sha256Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("the digest of empty input is wrong\n got %x\nwant %x", got, want)
	}
}

// TestDigest_TwoCallConventionIsIdempotent proves that calling C_Digest twice
// returns the same bytes and does not re-run the operation, and that the
// operation only ends when the caller says so.
//
// PKCS#11 v3.2 §5.2 lets a caller invoke these functions twice — once to learn
// the required buffer length, once to collect the output — so neither call may
// terminate the operation. A module that terminates on the first call breaks
// every conformant client, because the length-query idiom is universal.
func TestDigest_TwoCallConventionIsIdempotent(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	payload := []byte("two call convention")
	if rv := env.Module.DigestInit(session, &module.Mechanism{Type: module.CKM_SHA256}); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit returned %s", rv.String())
	}

	first, rv := env.Module.Digest(session, payload)
	if rv != module.CKR_OK {
		t.Fatalf("the first C_Digest returned %s", rv.String())
	}

	second, rv := env.Module.Digest(session, payload)
	if rv != module.CKR_OK {
		t.Fatalf("the repeated C_Digest returned %s; the operation must stay active "+
			"until the caller has collected the output", rv.String())
	}
	if !bytes.Equal(first, second) {
		t.Errorf("the repeated call returned different bytes\nfirst  %x\nsecond %x", first, second)
	}

	if rv := env.Module.FinishOperation(session, module.OperationDigest); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	if _, rv := env.Module.Digest(session, payload); rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("after the operation was finished C_Digest returned %s, want "+
			"CKR_OPERATION_NOT_INITIALIZED", rv.String())
	}
}

// TestGenerateRandom_LengthAndVariation checks C_GenerateRandom returns the
// requested number of bytes and does not repeat itself.
//
// This cannot prove randomness, and does not try to. It catches the failures
// that actually occur: a short read, a zero-filled buffer, or a generator that
// returns the same block every call.
func TestGenerateRandom_LengthAndVariation(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	for _, n := range []int{1, 16, 32, 256} {
		buf, rv := env.Module.GenerateRandom(session, uint32(n))
		if rv != module.CKR_OK {
			t.Fatalf("C_GenerateRandom(%d) returned %s", n, rv.String())
		}
		if len(buf) != n {
			t.Errorf("C_GenerateRandom(%d) returned %d bytes", n, len(buf))
		}
		if allZero(buf) {
			t.Errorf("C_GenerateRandom(%d) returned an all-zero buffer, which means "+
				"the generator is not producing output", n)
		}
	}

	first, rv := env.Module.GenerateRandom(session, 32)
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateRandom returned %s", rv.String())
	}
	second, rv := env.Module.GenerateRandom(session, 32)
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateRandom returned %s", rv.String())
	}
	if bytes.Equal(first, second) {
		t.Error("two consecutive 32-byte reads were identical, so the generator is " +
			"returning a fixed block rather than fresh output")
	}
}

// TestOperationStateMachine_RejectsUninitializedCalls verifies the operation
// functions refuse to run without their matching *Init.
//
// Reference: PKCS#11 v3.2 — CKR_OPERATION_NOT_INITIALIZED is the defined return
// for an operation function called outside an active operation.
func TestOperationStateMachine_RejectsUninitializedCalls(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	t.Run("digest_without_init", func(t *testing.T) {
		if _, rv := env.Module.Digest(session, []byte("x")); rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("C_Digest without C_DigestInit returned %s, want CKR_OPERATION_NOT_INITIALIZED",
				rv.String())
		}
	})

	t.Run("digest_update_without_init", func(t *testing.T) {
		if rv := env.Module.DigestUpdate(session, []byte("x")); rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("C_DigestUpdate without C_DigestInit returned %s, want CKR_OPERATION_NOT_INITIALIZED",
				rv.String())
		}
	})

	t.Run("digest_final_without_init", func(t *testing.T) {
		if _, rv := env.Module.DigestFinal(session); rv != module.CKR_OPERATION_NOT_INITIALIZED {
			t.Errorf("C_DigestFinal without C_DigestInit returned %s, want CKR_OPERATION_NOT_INITIALIZED",
				rv.String())
		}
	})
}

// TestOperationStateMachine_RejectsDoubleInit verifies a second *Init while one
// is active is refused.
//
// Reference: CKR_OPERATION_ACTIVE — "there is already an active operation that
// prevents Cryptoki from activating the requested operation".
func TestOperationStateMachine_RejectsDoubleInit(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	mech := &module.Mechanism{Type: module.CKM_SHA256}
	if rv := env.Module.DigestInit(session, mech); rv != module.CKR_OK {
		t.Fatalf("the first C_DigestInit returned %s", rv.String())
	}
	if rv := env.Module.DigestInit(session, mech); rv != module.CKR_OPERATION_ACTIVE {
		t.Errorf("a second C_DigestInit returned %s, want CKR_OPERATION_ACTIVE", rv.String())
	}
}

// sha256Sum returns the SHA-256 of b.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// sha384Sum returns the SHA-384 of b.
func sha384Sum(b []byte) []byte {
	sum := sha512.Sum384(b)
	return sum[:]
}

// sha512Sum returns the SHA-512 of b.
func sha512Sum(b []byte) []byte {
	sum := sha512.Sum512(b)
	return sum[:]
}

// allZero reports whether every byte of b is zero. An empty slice is not
// treated as all-zero, since the callers only pass non-empty buffers.
func allZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
