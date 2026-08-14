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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// pssConvention names what a module treated as the input to CKM_RSA_PKCS_PSS.
type pssConvention string

const (
	// pssInputIsDigest is the convention PKCS#11 v3.2 section 6.1.9 defines:
	// the mechanism "corresponds only to the part of PKCS #1 that involves
	// block formatting and RSA, given a hash value; it does not compute a hash
	// value", so the caller's input is signed as the digest.
	pssInputIsDigest pssConvention = "input signed as the digest (PKCS#11 v3.2 section 6.1.9)"
	// pssInputIsRehashed is the non-conforming convention in which the module
	// applies hashAlg to the caller's input before signing.
	pssInputIsRehashed pssConvention = "input hashed again before signing"
	// pssNoConvention means neither interpretation verified.
	pssNoConvention pssConvention = "neither convention verified"
)

// verifyPSS checks a PSS signature under both possible input conventions and
// reports which one produced it.
//
// The parameter-fidelity tests below care only whether a given field of
// CK_RSA_PKCS_PSS_PARAMS reached the operation, which is a question
// independent of what the module considers its input. Accepting either
// convention keeps those tests meaningful both now and after
// TestRSAPSSInputIsTheCallerSuppliedDigest stops failing; the convention
// itself is asserted in exactly one place rather than smeared across every
// test.
func verifyPSS(pubKey *rsa.PublicKey, hash crypto.Hash, input, sig []byte, saltLen int) pssConvention {
	opts := &rsa.PSSOptions{SaltLength: saltLen, Hash: hash}

	if err := rsa.VerifyPSS(pubKey, hash, input, sig, opts); err == nil {
		return pssInputIsDigest
	}

	hasher := hash.New()
	hasher.Write(input)
	if err := rsa.VerifyPSS(pubKey, hash, hasher.Sum(nil), sig, opts); err == nil {
		return pssInputIsRehashed
	}

	return pssNoConvention
}

// signPSS runs one C_SignInit/C_Sign pair under the given PSS parameters.
func signPSS(t *testing.T, f *Fixture, priv uint, params RSAPSSParams, input []byte) []byte {
	t.Helper()

	if err := f.Session.SignInit(CKM_RSA_PKCS_PSS, params, priv); err != nil {
		t.Fatalf("C_SignInit with hashAlg=0x%08X mgf=0x%08X sLen=%d: %v",
			params.HashAlg, params.MGF, params.SaltLen, err)
	}
	sig, err := f.Session.Sign(input)
	if err != nil {
		t.Fatalf("C_Sign with sLen=%d: %v", params.SaltLen, err)
	}
	return sig
}

// TestRSAPSSInputIsTheCallerSuppliedDigest asserts the input convention of
// CKM_RSA_PKCS_PSS.
//
// PKCS#11 v3.2 section 6.1.9 states the mechanism is given a hash value and
// does not compute one, so the caller's input must be signed as the digest.
// A module that hashes the input again produces signatures that verify only
// against itself: every external verifier, and every peer in a TLS or CMS
// exchange, computes the digest itself and checks the signature against that
// digest, not against a second hash of it.
//
// SoftHSM2 driven through this same harness signs the caller-supplied digest
// as the digest, which is what makes this a defect in the module under test
// rather than an ambiguity in the specification.
func TestRSAPSSInputIsTheCallerSuppliedDigest(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("go-xkms PKCS#11 C ABI PSS input convention"))
	params := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: 32}
	sig := signPSS(t, f, priv, params, digest[:])

	switch got := verifyPSS(pubKey, crypto.SHA256, digest[:], sig, 32); got {
	case pssInputIsDigest:
		return
	case pssInputIsRehashed:
		t.Fatal("CKM_RSA_PKCS_PSS hashed the caller's digest a second time before signing. " +
			"PKCS#11 v3.2 section 6.1.9 defines the mechanism as operating on a supplied hash value and " +
			"explicitly not computing one, and SoftHSM2 driven through this same harness signs the input as the digest. " +
			"Signatures this module produces therefore verify only against itself: any external verifier that digests " +
			"the message and checks the signature against that digest rejects them.")
	default:
		t.Fatalf("the PSS signature verified under no known input convention (%s); "+
			"it is not a SHA-256/MGF1-SHA-256 PSS signature at sLen=32 over either the input or its hash", got)
	}
}

// TestRSAPSSSignatureIsPSSAndNotPKCS1v15 proves that a signature requested with
// CKM_RSA_PKCS_PSS really is a PSS signature.
//
// This is the assertion that catches a silent downgrade. Before
// CK_RSA_PKCS_PSS_PARAMS was parsed at the cgo boundary the typed parameter
// stayed nil, and a module that responds to a nil PSS parameter by falling
// back to PKCS#1 v1.5 returns a signature that verifies perfectly well, just
// not under the scheme the caller asked for. Only the negative half, that the
// signature does not verify as v1.5, distinguishes the two.
func TestRSAPSSSignatureIsPSSAndNotPKCS1v15(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("go-xkms PKCS#11 C ABI PSS fidelity"))
	params := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: 32}
	sig := signPSS(t, f, priv, params, digest[:])

	if got := verifyPSS(pubKey, crypto.SHA256, digest[:], sig, 32); got == pssNoConvention {
		t.Fatalf("the signature is not a PSS signature under either input convention (%s)", got)
	}

	// A PKCS#1 v1.5 signature over the same digest would also be "valid", so a
	// module that quietly substituted v1.5 must be caught here rather than by
	// the positive assertion above. Both v1.5 shapes are checked: the
	// DigestInfo-wrapped form a hash-specific fallback would produce, and the
	// bare form a CKM_RSA_PKCS fallback over the same input would.
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err == nil {
		t.Fatal("a signature requested as CKM_RSA_PKCS_PSS verifies as DigestInfo-wrapped PKCS#1 v1.5: the PSS parameters were dropped and the scheme silently downgraded")
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(0), digest[:], sig); err == nil {
		t.Fatal("a signature requested as CKM_RSA_PKCS_PSS verifies as raw PKCS#1 v1.5 padding over the input: the PSS parameters were dropped and the scheme silently downgraded")
	}
}

// TestRSAPSSSaltLengthCrossesTheABI proves the sLen field of
// CK_RSA_PKCS_PSS_PARAMS reaches the signing operation.
//
// A parser that ignored sLen and defaulted to the digest length would still
// produce a valid PSS signature, and a test that verified with
// PSSSaltLengthAuto would pass against it. Verifying at an explicit,
// non-default salt length is what makes the field observable: crypto/rsa
// rejects a signature whose recovered salt is not exactly the length demanded.
func TestRSAPSSSaltLengthCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	digest := sha256.Sum256([]byte("salt length fidelity"))

	// 20 is neither the digest length nor the maximum, so nothing but the
	// caller's own sLen can produce it.
	const requestedSalt = 20

	params := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: requestedSalt}
	sig := signPSS(t, f, priv, params, digest[:])

	if got := verifyPSS(pubKey, crypto.SHA256, digest[:], sig, requestedSalt); got == pssNoConvention {
		t.Fatalf("the signature does not carry the requested %d-byte salt under either input convention", requestedSalt)
	}

	// The digest length is what a fabricating parser would have defaulted to.
	if got := verifyPSS(pubKey, crypto.SHA256, digest[:], sig, sha256.Size); got != pssNoConvention {
		t.Fatalf("the signature also verifies at the default %d-byte salt (%s), not only at the requested %d: sLen did not cross the C ABI",
			sha256.Size, got, requestedSalt)
	}
}

// TestRSAPSSHashAlgCrossesTheABI proves the hashAlg field of
// CK_RSA_PKCS_PSS_PARAMS selects the digest used inside EMSA-PSS.
//
// EMSA-PSS mixes the hash into both the encoded message and the mask
// generation function, so a signature produced under SHA-384 cannot verify
// under SHA-256. A parser that hardcoded one digest is caught by the
// cross-check rather than by the matching verification.
func TestRSAPSSHashAlgCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	message := []byte("hash algorithm fidelity")
	digest384 := sha512.Sum384(message)

	params := RSAPSSParams{HashAlg: CKM_SHA384, MGF: CKG_MGF1_SHA384, SaltLen: 48}
	sig := signPSS(t, f, priv, params, digest384[:])

	if got := verifyPSS(pubKey, crypto.SHA384, digest384[:], sig, 48); got == pssNoConvention {
		t.Fatal("the signature is not a SHA-384 PSS signature under either input convention: hashAlg did not select SHA-384")
	}

	// SHA-256 is the value a parser that ignored hashAlg would most plausibly
	// have defaulted to. Its digest of the same message is offered as the
	// input so that a SHA-256 signature would be found if one had been made.
	digest256 := sha256.Sum256(message)
	if got := verifyPSS(pubKey, crypto.SHA256, digest256[:], sig, 32); got != pssNoConvention {
		t.Fatalf("a signature requested under SHA-384 also verifies under SHA-256 (%s): hashAlg did not cross the C ABI", got)
	}
}

// TestRSAPSSVerifyThroughTheModule proves C_Verify honours the PSS parameters
// on the way back in.
//
// The negative case carries the weight: a PKCS#1 v1.5 signature over the same
// input must not satisfy a PSS verification. A C_VerifyInit that ignored its
// mechanism parameters and verified under whatever scheme the signature
// happened to use would accept exactly the substitution a downgrade attack
// needs.
func TestRSAPSSVerifyThroughTheModule(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)

	digest := sha256.Sum256([]byte("verification direction"))
	params := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: 32}

	moduleSig := signPSS(t, f, priv, params, digest[:])

	if err := f.Session.VerifyInit(CKM_RSA_PKCS_PSS, params, pub); err != nil {
		t.Fatalf("C_VerifyInit: %v", err)
	}
	if err := f.Session.Verify(digest[:], moduleSig); err != nil {
		t.Fatalf("C_Verify rejected the module's own PSS signature: %v", err)
	}

	v15Sig := signPKCS1v15ThroughModule(t, f, priv, digest[:])
	if err := f.Session.VerifyInit(CKM_RSA_PKCS_PSS, params, pub); err != nil {
		t.Fatalf("C_VerifyInit for the negative case: %v", err)
	}
	if err := f.Session.Verify(digest[:], v15Sig); err == nil {
		t.Fatal("C_Verify under CKM_RSA_PKCS_PSS accepted a PKCS#1 v1.5 signature: the PSS parameters were ignored on the verification path")
	}
}

// TestRSAPSSRejectsMissingParameters proves the module refuses
// CKM_RSA_PKCS_PSS when the caller supplies no CK_RSA_PKCS_PSS_PARAMS.
//
// PSS has no defensible default salt length or digest, so the only correct
// answer is a refusal, and it must be the specific
// CKR_MECHANISM_PARAM_INVALID rather than a generic failure that would hide
// the reason.
func TestRSAPSSRejectsMissingParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateRSAKeyPair(t, f, 2048)

	err := f.Session.SignInit(CKM_RSA_PKCS_PSS, nil, priv)
	if err == nil {
		t.Fatal("C_SignInit accepted CKM_RSA_PKCS_PSS with a NULL pParameter; PSS has no defensible default salt length or digest")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_SignInit with no PSS parameters returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID",
			rvName(got), got)
	}
}

// TestRSAPSSRejectsTruncatedParameters proves the boundary honours
// ulParameterLen instead of trusting the pointer.
//
// A parser that dereferenced a full CK_RSA_PKCS_PSS_PARAMS while the caller
// declared fewer bytes would read past the end of caller-owned memory. The
// call must be refused, and it must not fault across the C boundary.
func TestRSAPSSRejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateRSAKeyPair(t, f, 2048)

	full := RSAPSSParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, SaltLen: 32}
	truncated := TruncatedParams{Params: full, Length: 4}

	err := f.Session.SignInit(CKM_RSA_PKCS_PSS, truncated, priv)
	if err == nil {
		t.Fatal("C_SignInit accepted a CK_RSA_PKCS_PSS_PARAMS declared as only 4 bytes")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_SignInit with a truncated PSS parameter returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID",
			rvName(got), got)
	}
}
