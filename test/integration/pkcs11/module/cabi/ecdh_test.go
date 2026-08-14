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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// newECDHPeer generates a P-256 key pair inside the test to act as the far end
// of the exchange, returning the private key and its uncompressed public point.
func newECDHPeer(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the ECDH peer key: %v", err)
	}
	return peer, peer.PublicKey().Bytes()
}

// deriveECDHSecret runs C_DeriveKey for CKM_ECDH1_DERIVE and returns the
// derived key's handle.
func deriveECDHSecret(t *testing.T, f *Fixture, priv uint, params MechParams, valueLen uint) (uint, error) {
	t.Helper()

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
		AttrBool(CKA_TOKEN, false),
		AttrULong(CKA_VALUE_LEN, valueLen),
		// The derived key must be readable, or there is nothing to compare
		// against the oracle.
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-ecdh-derived")),
	}

	key, err := f.Session.DeriveKey(CKM_ECDH1_DERIVE, params, priv, template)
	if err != nil {
		return 0, err
	}
	return f.Track(key), nil
}

// x963KDF computes the ANSI X9.63 key derivation function over a shared
// secret, which is what CKD_SHA256_KDF specifies (PKCS#11 v3.2 section 6.3.7,
// Table 78): repeated SHA-256 over the secret, a big-endian counter starting
// at one, and the shared info, truncated to the requested length.
func x963KDF(secret, sharedInfo []byte, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	for counter := uint32(1); len(out) < length; counter++ {
		h := sha256.New()
		h.Write(secret)
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], counter)
		h.Write(encoded[:])
		h.Write(sharedInfo)
		out = h.Sum(out)
	}
	return out[:length]
}

// TestECDHDeriveMatchesAnIndependentOracle proves that pPublicData and
// pSharedData both reach the derivation, and that the result is the genuine
// ECDH secret run through the KDF the caller named.
//
// The peer key is generated in the test, so the shared secret and the X9.63
// derivation are both computed independently with crypto/ecdh and crypto/sha256.
// This is an oracle rather than a round trip: a module that returned any
// repeatable function of its inputs would satisfy a derive-twice-and-compare
// test, and one that dropped pSharedData would return a perfectly plausible
// key. Only reproducing the exact bytes shows every field arrived.
func TestECDHDeriveMatchesAnIndependentOracle(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateECKeyPair(t, f, true)
	tokenPub := readECDHPublicKey(t, f, pub)

	peer, peerPoint := newECDHPeer(t)
	sharedInfo := []byte("go-xkms/cabi/ecdh/shared-info")

	params := ECDH1DeriveParams{
		KDF:        CKD_SHA256_KDF,
		SharedData: sharedInfo,
		PublicData: peerPoint,
	}
	derived, err := deriveECDHSecret(t, f, priv, params, 32)
	if err != nil {
		t.Fatalf("C_DeriveKey with CKM_ECDH1_DERIVE and CKD_SHA256_KDF: %v", err)
	}
	got := readSecretValue(t, f, derived)

	// The peer computes the same secret from its own private key and the
	// token's public point, then applies the same KDF.
	secret, err := peer.ECDH(tokenPub)
	if err != nil {
		t.Fatalf("computing the shared secret with crypto/ecdh: %v", err)
	}
	want := x963KDF(secret, sharedInfo, 32)

	if !bytes.Equal(got, want) {
		t.Fatalf("the derived key is not X9.63-SHA256 over the ECDH shared secret and the supplied shared info:\n  module %x\n  oracle %x",
			got, want)
	}
}

// TestECDHSupportsCKDNull proves the raw-shared-secret KDF is available.
//
// CKD_NULL yields the unmodified shared secret and is the form TLS key
// exchange and OpenSSL's pkcs11-provider ask for; a token that refuses it
// cannot be used for either, however many hash-based KDFs it offers.
func TestECDHSupportsCKDNull(t *testing.T) {
	f := NewFixture(t)
	pub, priv := generateECKeyPair(t, f, true)
	tokenPub := readECDHPublicKey(t, f, pub)

	peer, peerPoint := newECDHPeer(t)

	params := ECDH1DeriveParams{KDF: CKD_NULL, PublicData: peerPoint}
	derived, err := deriveECDHSecret(t, f, priv, params, 32)
	if err != nil {
		t.Fatalf("C_DeriveKey with CKD_NULL returned %s (0x%08X). CKD_NULL is the raw shared secret and is what "+
			"TLS key exchange and OpenSSL's pkcs11-provider request, so refusing it makes the token unusable for both.",
			rvName(RV(err)), RV(err))
	}
	got := readSecretValue(t, f, derived)

	secret, err := peer.ECDH(tokenPub)
	if err != nil {
		t.Fatalf("computing the shared secret with crypto/ecdh: %v", err)
	}
	if !bytes.Equal(got, secret[:len(got)]) {
		t.Fatalf("CKD_NULL did not yield the raw ECDH shared secret:\n  module %x\n  oracle %x", got, secret)
	}
}

// TestECDHSharedDataCrossesTheABI proves pSharedData reaches the derivation.
//
// This is the parameter-fidelity assertion that matters most for ECDH. The
// shared info feeds the KDF, so a parser that dropped it would return a
// perfectly plausible key of the right length, derived from the right shared
// secret, and every other assertion in this file would still pass. Only
// changing the shared data alone and requiring the output to change can see it.
//
// Two derivations differ in nothing but pSharedData; identical results mean the
// field never arrived, and two parties that believe they are separated by
// different shared info would in fact hold the same key.
func TestECDHSharedDataCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	derive := func(shared []byte) []byte {
		t.Helper()
		params := ECDH1DeriveParams{
			KDF:        CKD_SHA256_KDF,
			SharedData: shared,
			PublicData: peerPoint,
		}
		key, err := deriveECDHSecret(t, f, priv, params, 32)
		if err != nil {
			t.Fatalf("C_DeriveKey with shared data %q: %v", shared, err)
		}
		return readSecretValue(t, f, key)
	}

	first := derive([]byte("shared-info-A"))
	second := derive([]byte("shared-info-B"))

	if bytes.Equal(first, second) {
		t.Fatalf("changing only pSharedData produced the same derived key (%x). "+
			"The shared info was accepted and discarded, so two parties that believe different shared info separates "+
			"them in fact derive identical keys.", first)
	}
}

// TestECDHKDFCrossesTheABI proves the kdf field selects the key derivation
// function.
//
// Two derivations differ in nothing but the CK_EC_KDF_TYPE. A parser that
// ignored kdf would return the same bytes for both, which would mean the
// caller's choice of KDF, and any negotiated agreement about it, is fiction.
func TestECDHKDFCrossesTheABI(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	derive := func(kdf uint) []byte {
		t.Helper()
		params := ECDH1DeriveParams{KDF: kdf, SharedData: []byte("kdf-fidelity"), PublicData: peerPoint}
		key, err := deriveECDHSecret(t, f, priv, params, 32)
		if err != nil {
			t.Fatalf("C_DeriveKey with kdf=0x%08X: %v", kdf, err)
		}
		return readSecretValue(t, f, key)
	}

	sha256Derived := derive(CKD_SHA256_KDF)
	sha384Derived := derive(CKD_SHA384_KDF)

	if bytes.Equal(sha256Derived, sha384Derived) {
		t.Fatalf("CKD_SHA256_KDF and CKD_SHA384_KDF produced the same derived key (%x): the kdf field did not cross the C ABI",
			sha256Derived)
	}
}

// TestECDHRejectsAnUnknownKDF proves an unimplemented CK_EC_KDF_TYPE is
// refused rather than quietly replaced with a default.
//
// Silently substituting a KDF the caller did not ask for produces a key the
// peer cannot reproduce, and the failure surfaces only later as an
// unexplainable decryption error.
func TestECDHRejectsAnUnknownKDF(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	const unknownKDF = 0x7FFFFFFF
	params := ECDH1DeriveParams{KDF: unknownKDF, PublicData: peerPoint}

	_, err := deriveECDHSecret(t, f, priv, params, 32)
	if err == nil {
		t.Fatalf("C_DeriveKey accepted an unknown CK_EC_KDF_TYPE 0x%08X and derived a key anyway", uint(unknownKDF))
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_DeriveKey with an unknown KDF returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID",
			rvName(got), got)
	}
}

// TestECDHHonoursCKAValueLen proves the derived key is the length the template
// asked for.
//
// The KDF output length is a template attribute rather than a mechanism
// parameter, but it travels the same C ABI. A module that always returned the
// full shared secret would give the caller more key material than requested
// and silently disagree with a peer deriving a shorter key.
func TestECDHHonoursCKAValueLen(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	params := ECDH1DeriveParams{KDF: CKD_SHA256_KDF, SharedData: []byte("length"), PublicData: peerPoint}

	for _, want := range []uint{16, 32} {
		key, err := deriveECDHSecret(t, f, priv, params, want)
		if err != nil {
			t.Fatalf("C_DeriveKey with CKA_VALUE_LEN=%d: %v", want, err)
		}
		got := readSecretValue(t, f, key)
		if uint(len(got)) != want {
			t.Errorf("CKA_VALUE_LEN=%d produced a %d-byte key: the requested length was not honoured", want, len(got))
		}
	}
}

// TestECDHRequiresCKADeriveOnTheBaseKey proves the base key's CKA_DERIVE is
// enforced, and with the specific return value the specification names.
//
// CKA_DERIVE defaults to CK_FALSE (PKCS#11 v3.2 section 4.9), so a key not
// explicitly marked for derivation must be refused. The precise code matters:
// CKR_KEY_FUNCTION_NOT_PERMITTED tells the caller its key lacks a capability,
// while a generic CKR_FUNCTION_FAILED sends it looking for a transport or
// backend fault instead.
func TestECDHRequiresCKADeriveOnTheBaseKey(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, false)
	_, peerPoint := newECDHPeer(t)

	params := ECDH1DeriveParams{KDF: CKD_NULL, PublicData: peerPoint}

	_, err := deriveECDHSecret(t, f, priv, params, 32)
	if err == nil {
		t.Fatal("C_DeriveKey derived from a base key without CKA_DERIVE; PKCS#11 v3.2 section 4.9 defaults the attribute to CK_FALSE and section 5.18.5 requires it to be CK_TRUE")
	}
	if got := RV(err); got != CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Fatalf("C_DeriveKey from a base key without CKA_DERIVE returned %s (0x%08X), want CKR_KEY_FUNCTION_NOT_PERMITTED",
			rvName(got), got)
	}
}

// TestECDHRejectsTruncatedParameters proves the boundary honours
// ulParameterLen for CK_ECDH1_DERIVE_PARAMS.
//
// The struct carries two pointers. Reading it out of a buffer the caller
// declared shorter would dereference caller memory past the end, so the call
// must be refused and must not fault across the C boundary. The whole
// mechanism depends on this parser: the derivation layer refuses to look at
// raw parameter bytes, so a parse that silently produced nothing would surface
// as CKR_MECHANISM_PARAM_INVALID anyway, and this test pins that the refusal
// happens rather than a crash.
func TestECDHRejectsTruncatedParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	full := ECDH1DeriveParams{KDF: CKD_SHA256_KDF, SharedData: []byte("s"), PublicData: peerPoint}
	truncated := TruncatedParams{Params: full, Length: SizeOfECDH1DeriveParams() - 8}

	_, err := deriveECDHSecret(t, f, priv, truncated, 32)
	if err == nil {
		t.Fatalf("C_DeriveKey accepted a CK_ECDH1_DERIVE_PARAMS declared %d bytes shorter than the struct", 8)
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DeriveKey with a truncated CK_ECDH1_DERIVE_PARAMS returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}

// TestECDHRejectsMissingParameters proves CKM_ECDH1_DERIVE is refused without
// CK_ECDH1_DERIVE_PARAMS.
//
// There is no peer public key to exchange with when the parameter is absent,
// so the only correct answer is a refusal.
func TestECDHRejectsMissingParameters(t *testing.T) {
	f := NewFixture(t)
	_, priv := generateECKeyPair(t, f, true)

	_, err := deriveECDHSecret(t, f, priv, nil, 32)
	if err == nil {
		t.Fatal("C_DeriveKey accepted CKM_ECDH1_DERIVE with a NULL pParameter; there is no peer public key to exchange with")
	}
	if got := RV(err); got != CKR_MECHANISM_PARAM_INVALID && got != CKR_ARGUMENTS_BAD {
		t.Fatalf("C_DeriveKey with no ECDH parameters returned %s (0x%08X), want CKR_MECHANISM_PARAM_INVALID or CKR_ARGUMENTS_BAD",
			rvName(got), got)
	}
}

// TestECDHCofactorDeriveIsEitherAdvertisedAndWorkingOrRefused holds
// CKM_ECDH1_COFACTOR_DERIVE to the discoverability invariant.
//
// Cofactor ECDH takes the same CK_ECDH1_DERIVE_PARAMS through the same parser
// branch as CKM_ECDH1_DERIVE, and on P-256 the cofactor is one, so the two
// mechanisms produce identical secrets and no oracle can tell them apart. What
// can be asserted is the contract every mechanism owes an application: either
// C_GetMechanismList advertises it and C_DeriveKey performs it, or it is
// absent from the list and C_DeriveKey refuses it with CKR_MECHANISM_INVALID.
// Anything else leaves a caller unable to find out what the token will do.
func TestECDHCofactorDeriveIsEitherAdvertisedAndWorkingOrRefused(t *testing.T) {
	f := NewFixture(t)
	advertised := f.SupportsMechanism(CKM_ECDH1_COFACTOR_DERIVE)

	_, priv := generateECKeyPair(t, f, true)
	_, peerPoint := newECDHPeer(t)

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
		AttrBool(CKA_TOKEN, false),
		AttrULong(CKA_VALUE_LEN, 32),
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-ecdh-cofactor")),
	}
	params := ECDH1DeriveParams{KDF: CKD_SHA256_KDF, SharedData: []byte("cofactor"), PublicData: peerPoint}

	key, err := f.Session.DeriveKey(CKM_ECDH1_COFACTOR_DERIVE, params, priv, template)
	if err == nil {
		f.Track(key)
	}

	switch {
	case advertised && err == nil:
		return
	case advertised && err != nil:
		t.Fatalf("CKM_ECDH1_COFACTOR_DERIVE is advertised by C_GetMechanismList but C_DeriveKey returned %s (0x%08X)",
			rvName(RV(err)), RV(err))
	case !advertised && err == nil:
		t.Fatal("CKM_ECDH1_COFACTOR_DERIVE is not listed by C_GetMechanismList, yet C_DeriveKey performed the derivation; " +
			"an application that enumerates mechanisms before using them cannot discover it")
	default:
		if got := RV(err); got != CKR_MECHANISM_INVALID {
			t.Fatalf("CKM_ECDH1_COFACTOR_DERIVE is not advertised, so C_DeriveKey must refuse it with CKR_MECHANISM_INVALID, but it returned %s (0x%08X)",
				rvName(got), got)
		}
	}
}
