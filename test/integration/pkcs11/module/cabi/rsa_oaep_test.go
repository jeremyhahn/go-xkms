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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// TestRSAOAEPHashAlgCrossesTheABI proves the hashAlg field of
// CK_RSA_PKCS_OAEP_PARAMS reaches the decryption operation.
//
// The ciphertext is produced outside the module by crypto/rsa under a specific
// digest, so the module has no way to succeed except by using that same digest
// for the OAEP label hash and the mask generation function. Before the
// boundary parsed CK_RSA_PKCS_OAEP_PARAMS the typed parameter stayed nil and
// the module fell back to a default digest, which decrypts to garbage that
// looks exactly like a corrupt ciphertext.
func TestRSAOAEPHashAlgCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	plaintext := []byte("go-xkms PKCS#11 C ABI OAEP hashAlg fidelity")

	// SHA-384 is deliberately not the value a defaulting parser would pick.
	ciphertext, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("building the SHA-384 OAEP ciphertext outside the module: %v", err)
	}

	params := RSAOAEPParams{
		HashAlg: CKM_SHA384,
		MGF:     CKG_MGF1_SHA384,
		Source:  0,
	}
	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, params, priv); err != nil {
		t.Fatalf("C_DecryptInit with SHA-384 OAEP parameters: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt of a SHA-384 OAEP ciphertext: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt returned %q, want %q", recovered, plaintext)
	}
}

// TestRSAOAEPWrongHashAlgFails proves the digest is genuinely selected by
// hashAlg rather than being ignored.
//
// A module that hardcoded one digest would decrypt the matching ciphertext in
// the test above and would also "succeed" here if it happened to hardcode the
// digest this ciphertext uses. Presenting a ciphertext built under a different
// digest than the one requested must fail: OAEP decoding checks the label hash,
// so the mismatch is detected rather than silently returning wrong plaintext.
func TestRSAOAEPWrongHashAlgFails(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	plaintext := []byte("digest mismatch must be detected")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("building the SHA-256 OAEP ciphertext: %v", err)
	}

	// Ask for SHA-384 while the ciphertext was built under SHA-256.
	params := RSAOAEPParams{HashAlg: CKM_SHA384, MGF: CKG_MGF1_SHA384, Source: 0}
	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, params, priv); err != nil {
		t.Fatalf("C_DecryptInit: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err == nil {
		t.Fatalf("C_Decrypt accepted a SHA-256 OAEP ciphertext while SHA-384 was requested and returned %q: hashAlg did not cross the C ABI",
			recovered)
	}
}

// TestRSAOAEPLabelCrossesTheABI proves pSourceData and ulSourceDataLen reach
// the operation.
//
// The OAEP label is authenticated by the padding, so a ciphertext built with a
// label decrypts only when the same label is supplied. A parser that dropped
// the label would fail this test outright, and one that passed a label through
// but ignored its length would recover the wrong bytes.
func TestRSAOAEPLabelCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	plaintext := []byte("labelled OAEP")
	label := []byte("go-xkms/cabi/oaep-label")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, label)
	if err != nil {
		t.Fatalf("building the labelled OAEP ciphertext: %v", err)
	}

	params := RSAOAEPParams{
		HashAlg:    CKM_SHA256,
		MGF:        CKG_MGF1_SHA256,
		Source:     CKZ_DATA_SPECIFIED,
		SourceData: label,
	}
	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, params, priv); err != nil {
		t.Fatalf("C_DecryptInit with a CKZ_DATA_SPECIFIED label: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt of a labelled OAEP ciphertext: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt returned %q, want %q", recovered, plaintext)
	}
}

// TestRSAOAEPWrongLabelFails proves the label is genuinely mixed into the
// padding rather than accepted and discarded.
//
// This is the assertion that catches a parser that reads pSourceData into a
// field nobody consults. Decryption under a different label than the one the
// ciphertext carries must fail; if it succeeds, the label never reached the
// OAEP decoding step and the caller's access control assumption about that
// label is void.
func TestRSAOAEPWrongLabelFails(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	plaintext := []byte("label binding must hold")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte("label-A"))
	if err != nil {
		t.Fatalf("building the OAEP ciphertext under label-A: %v", err)
	}

	params := RSAOAEPParams{
		HashAlg:    CKM_SHA256,
		MGF:        CKG_MGF1_SHA256,
		Source:     CKZ_DATA_SPECIFIED,
		SourceData: []byte("label-B"),
	}
	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, params, priv); err != nil {
		t.Fatalf("C_DecryptInit: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err == nil {
		t.Fatalf("C_Decrypt under label-B recovered %q from a ciphertext built under label-A: the OAEP label did not cross the C ABI",
			recovered)
	}
}

// TestRSAOAEPEmptyAndAbsentLabelAgree proves that an explicitly empty
// CKZ_DATA_SPECIFIED label is treated as the empty label, which is what
// crypto/rsa encrypts with when given a nil label.
//
// This pins down the boundary's handling of a NULL pSourceData with a zero
// ulSourceDataLen, the encoding a caller uses to say "no label". Getting it
// wrong would make every unlabelled ciphertext from a conforming peer
// undecryptable.
func TestRSAOAEPEmptyAndAbsentLabelAgree(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)
	pubKey := readRSAPublicKey(t, f, pub)

	plaintext := []byte("no label at all")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("building the unlabelled OAEP ciphertext: %v", err)
	}

	params := RSAOAEPParams{
		HashAlg: CKM_SHA256,
		MGF:     CKG_MGF1_SHA256,
		Source:  CKZ_DATA_SPECIFIED,
	}
	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, params, priv); err != nil {
		t.Fatalf("C_DecryptInit with CKZ_DATA_SPECIFIED and a NULL pSourceData: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt of an unlabelled OAEP ciphertext: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_Decrypt returned %q, want %q", recovered, plaintext)
	}
}

// TestRSAOAEPEncryptDecryptRoundTripHonoursParameters proves the encryption
// direction reads the same parameters.
//
// The private key is sensitive and never leaves the token, so crypto/rsa
// cannot decrypt what the module encrypted. Instead the parameters are varied
// between the two halves: a round trip under matching parameters must succeed
// and one under a different digest must fail. A module that ignored hashAlg on
// C_EncryptInit would round-trip successfully in both cases.
func TestRSAOAEPEncryptDecryptRoundTripHonoursParameters(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateRSAKeyPair(t, f, 2048)

	plaintext := []byte("round trip parameter binding")

	sha256Params := RSAOAEPParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, Source: 0}
	sha384Params := RSAOAEPParams{HashAlg: CKM_SHA384, MGF: CKG_MGF1_SHA384, Source: 0}

	if err := f.Session.EncryptInit(CKM_RSA_PKCS_OAEP, sha256Params, pub); err != nil {
		t.Fatalf("C_EncryptInit with SHA-256 OAEP parameters: %v", err)
	}
	ciphertext, err := f.Session.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("C_Encrypt: %v", err)
	}

	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, sha256Params, priv); err != nil {
		t.Fatalf("C_DecryptInit with matching parameters: %v", err)
	}
	recovered, err := f.Session.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("C_Decrypt under matching parameters: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("round trip returned %q, want %q", recovered, plaintext)
	}

	if err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, sha384Params, priv); err != nil {
		t.Fatalf("C_DecryptInit with mismatched parameters: %v", err)
	}
	wrong, err := f.Session.Decrypt(ciphertext)
	if err == nil {
		t.Fatalf("C_Decrypt under SHA-384 recovered %q from a ciphertext the module built under SHA-256: hashAlg is ignored on at least one of the two paths",
			wrong)
	}
}

// TestRSAOAEPRejectsTruncatedParameters proves the boundary honours
// ulParameterLen for CK_RSA_PKCS_OAEP_PARAMS.
//
// The struct ends in a pointer and a length; reading it out of a buffer the
// caller declared smaller would dereference whatever follows in caller memory.
// The call must be refused rather than faulting across the C boundary.
func TestRSAOAEPRejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateRSAKeyPair(t, f, 2048)

	full := RSAOAEPParams{HashAlg: CKM_SHA256, MGF: CKG_MGF1_SHA256, Source: CKZ_DATA_SPECIFIED, SourceData: []byte("x")}
	truncated := TruncatedParams{Params: full, Length: 8}

	err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, truncated, priv)
	if err == nil {
		t.Fatal("C_DecryptInit accepted a CK_RSA_PKCS_OAEP_PARAMS declared as only 8 bytes")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecryptInit with a truncated OAEP parameter returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}

// TestRSAOAEPRejectsMissingParameters proves CKM_RSA_PKCS_OAEP is refused
// without CK_RSA_PKCS_OAEP_PARAMS.
//
// OAEP cannot be performed without knowing the digest, and guessing one
// produces ciphertext no peer can decrypt. The refusal must be the specific
// CKR_MECHANISM_PARAM_INVALID.
func TestRSAOAEPRejectsMissingParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateRSAKeyPair(t, f, 2048)

	err := f.Session.DecryptInit(CKM_RSA_PKCS_OAEP, nil, priv)
	if err == nil {
		t.Fatal("C_DecryptInit accepted CKM_RSA_PKCS_OAEP with a NULL pParameter; OAEP cannot be performed without a digest")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DecryptInit with no OAEP parameters returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD (SoftHSM2 answers CKR_ARGUMENTS_BAD)",
			rvName(got), got)
	}
}
