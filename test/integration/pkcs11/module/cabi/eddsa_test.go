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

//go:build integration && pkcs11_cabi

package cabi

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"testing"
)

// TestEdDSAPureSignsAndVerifiesExternally establishes the baseline: with no
// CK_EDDSA_PARAMS the mechanism is pure Ed25519, and the signature verifies
// under crypto/ed25519.
//
// Every other test in this file is a comparison against this signature, so if
// this one is wrong the rest mean nothing.
func TestEdDSAPureSignsAndVerifiesExternally(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateEd25519KeyPair(t, f)
	pubKey := readEd25519PublicKey(t, f, pub)

	message := []byte("go-xkms PKCS#11 C ABI pure Ed25519")

	if err := f.Session.SignInit(CKM_EDDSA, nil, priv); err != nil {
		t.Fatalf("C_SignInit for pure Ed25519 (NULL pParameter): %v", err)
	}
	sig, err := f.Session.Sign(message)
	if err != nil {
		t.Fatalf("C_Sign: %v", err)
	}

	if !ed25519.Verify(pubKey, message, sig) {
		t.Fatal("crypto/ed25519 rejected the module's pure Ed25519 signature")
	}
}

// TestEdDSAPreHashIsNotSilentlyPureEd25519 proves that asking for Ed25519ph
// either produces an Ed25519ph signature or is refused outright.
//
// CK_EDDSA_PARAMS.phFlag selects among the RFC 8032 variants (PKCS#11 v3.2
// section 6.24, Table 73). Before the boundary parsed the struct, phFlag never
// reached the signing operation and every request silently produced a pure
// Ed25519 signature: the caller believed it had a prehashed signature, the
// verifier computed Ed25519ph, and the two never matched. Producing pure
// Ed25519 for a prehash request is the one outcome that must not happen; a
// deliberate CKR_MECHANISM_PARAM_INVALID is acceptable, because a refusal is
// visible and a downgrade is not.
func TestEdDSAPreHashIsNotSilentlyPureEd25519(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateEd25519KeyPair(t, f)
	pubKey := readEd25519PublicKey(t, f, pub)

	message := []byte("go-xkms PKCS#11 C ABI Ed25519ph")
	digest := sha512.Sum512(message)

	// Ed25519ph signs the SHA-512 digest of the message (RFC 8032 section
	// 5.1.7), so the digest is what is handed to C_Sign.
	err := f.Session.SignInit(CKM_EDDSA, EdDSAParams{PreHash: true}, priv)
	if err != nil {
		if got := RV(err); got == CKR_MECHANISM_PARAM_INVALID {
			t.Logf("the module deliberately refuses Ed25519ph with %s; that is a visible refusal rather than a silent downgrade", rvName(got))
			return
		}
		t.Fatalf("C_SignInit with phFlag set returned %s (0x%08X); a module that cannot do Ed25519ph must say so with CKR_MECHANISM_PARAM_INVALID",
			rvName(RV(err)), RV(err))
	}

	sig, err := f.Session.Sign(digest[:])
	if err != nil {
		if got := RV(err); got == CKR_MECHANISM_PARAM_INVALID {
			t.Logf("the module deliberately refuses Ed25519ph at C_Sign with %s", rvName(got))
			return
		}
		t.Fatalf("C_Sign with phFlag set: %v", err)
	}

	// The signature must be Ed25519ph over the message.
	if ed25519.VerifyWithOptions(pubKey, digest[:], sig, &ed25519.Options{Hash: crypto.SHA512}) == nil {
		return
	}

	// The failure that matters: a pure Ed25519 signature over the digest bytes
	// means phFlag was accepted and dropped.
	if ed25519.Verify(pubKey, digest[:], sig) {
		t.Fatal("a signature requested with CK_EDDSA_PARAMS.phFlag set is a PURE Ed25519 signature over the input. " +
			"phFlag was accepted and discarded, so the caller receives a signature under a different scheme than the one " +
			"it asked for, and any verifier performing Ed25519ph rejects it.")
	}
	if ed25519.Verify(pubKey, message, sig) {
		t.Fatal("a signature requested with CK_EDDSA_PARAMS.phFlag set is a pure Ed25519 signature over the un-prehashed message: phFlag did not cross the C ABI")
	}

	t.Fatal("the signature produced with phFlag set verifies as neither Ed25519ph nor pure Ed25519")
}

// TestEdDSAContextIsNotSilentlyIgnored proves that a supplied context string
// either changes the signature or is refused.
//
// pContextData selects Ed25519ctx (RFC 8032 section 5.1). A context is a
// domain separator: two signatures over the same message under different
// contexts must not be interchangeable. If the module returns the same
// signature with and without a context, the context provides no separation and
// a signature made for one protocol is replayable in another.
func TestEdDSAContextIsNotSilentlyIgnored(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateEd25519KeyPair(t, f)
	pubKey := readEd25519PublicKey(t, f, pub)

	message := []byte("go-xkms PKCS#11 C ABI Ed25519ctx")

	if err := f.Session.SignInit(CKM_EDDSA, nil, priv); err != nil {
		t.Fatalf("C_SignInit for the pure baseline: %v", err)
	}
	pureSig, err := f.Session.Sign(message)
	if err != nil {
		t.Fatalf("C_Sign for the pure baseline: %v", err)
	}

	err = f.Session.SignInit(CKM_EDDSA, EdDSAParams{Context: []byte("context-A")}, priv)
	if err != nil {
		if got := RV(err); got == CKR_MECHANISM_PARAM_INVALID {
			t.Logf("the module deliberately refuses a CK_EDDSA_PARAMS context with %s; that is a visible refusal rather than a silent downgrade", rvName(got))
			return
		}
		t.Fatalf("C_SignInit with pContextData returned %s (0x%08X); a module that cannot do Ed25519ctx must say so with CKR_MECHANISM_PARAM_INVALID",
			rvName(RV(err)), RV(err))
	}

	ctxSig, err := f.Session.Sign(message)
	if err != nil {
		if got := RV(err); got == CKR_MECHANISM_PARAM_INVALID {
			t.Logf("the module deliberately refuses a CK_EDDSA_PARAMS context at C_Sign with %s", rvName(got))
			return
		}
		t.Fatalf("C_Sign with pContextData: %v", err)
	}

	// Ed25519 signing is deterministic, so the same key and message under the
	// same scheme always yields the same bytes. A context that reached the
	// operation must therefore change them.
	if string(ctxSig) == string(pureSig) {
		t.Fatal("signing with and without a CK_EDDSA_PARAMS context produced identical signatures. " +
			"Ed25519 is deterministic, so pContextData was accepted and discarded: the context provides no domain " +
			"separation and a signature made under one context is valid under every other.")
	}

	// Whatever it is, it must not be a pure Ed25519 signature that merely
	// happens to differ, and it must not verify as pure.
	if ed25519.Verify(pubKey, message, ctxSig) {
		t.Fatal("a signature requested with a CK_EDDSA_PARAMS context verifies as pure Ed25519: the context did not enter the signature")
	}
}

// TestEdDSARejectsTruncatedParameters proves the boundary honours
// ulParameterLen for CK_EDDSA_PARAMS.
//
// The struct ends in a pointer, so reading it out of a shorter buffer would
// dereference caller memory past the end. A truncated parameter must be
// refused rather than treated as absent, because "absent" means pure Ed25519
// and would silently sign under a different scheme than the caller intended.
func TestEdDSARejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateEd25519KeyPair(t, f)

	full := EdDSAParams{PreHash: true, Context: []byte("ctx")}
	truncated := TruncatedParams{Params: full, Length: 4}

	err := f.Session.SignInit(CKM_EDDSA, truncated, priv)
	if err == nil {
		t.Fatal("C_SignInit accepted a CK_EDDSA_PARAMS declared as only 4 bytes; a truncated parameter that is treated as absent silently selects pure Ed25519")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_SignInit with a truncated CK_EDDSA_PARAMS returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}
