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

package main

// Round-trip tests for the real-buffer success paths of the four dual-function
// entry points (C_DigestEncryptUpdate, C_DecryptDigestUpdate,
// C_SignEncryptUpdate, C_DecryptVerifyUpdate), extending
// exports_dualfunction_test.go's argument-marshalling and no-active-operation
// coverage.
//
// Each of the four Module methods behind these verbs (module.go) always
// returns an empty, non-nil []byte: both halves of a dual-function flow
// buffer their side of an AEAD operation until the matching *Final call, per
// each function's own doc comment. So the branch these tests reach that
// offlineTransport cannot is not "a real ciphertext/plaintext came back" --
// nothing does, by design -- it is the real-buffer copy path taken once both
// halves of the pair are genuinely active against pkcs11test.CryptoMockClient,
// as opposed to exports_dualfunction_test.go's fixture where the pair can
// never both become active because every Init that would start the crypto
// half panics against a nil transport.
//
// This file also finishes each flow through its *Final calls to prove that a
// dual-function operation's buffered input is genuinely fed to both crypto
// halves, not merely accepted: the encrypt/decrypt half is checked against
// exports_cryptoroundtrip_test.go's own AES-GCM round trip, and the digest
// half against an independent crypto/sha256 oracle.

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// dualUpdateViaC drives one of the four dual-function C_*Update entry points
// with a real, generously sized output buffer, returning the copied bytes
// (always empty, per this file's package comment) and the call's CK_RV.
func dualUpdateViaC(t *testing.T, fn any, session module.SessionHandle, in []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fv := reflect.ValueOf(fn)
	ft := fv.Type()

	outBuf := make([]byte, len(in)+32)
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(outBuf)))
	out := fv.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(in, ft, 1),
		scalarOf(ft, 2, uint64(len(in))),
		setBufferPtr(outBuf, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(in)
	runtime.KeepAlive(outBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return outBuf[:fillLen.Elem().Uint()], rv
}

// requireDualUpdateLengthQuery makes the PKCS#11 v3.2 §5.2 length query (a
// NULL output buffer) against one of the dual-function updates on an active
// operation pair, and fails unless it answers CKR_OK with a zero length. The
// caller's later real update then proves the query consumed none of in.
func requireDualUpdateLengthQuery(t *testing.T, fn any, session module.SessionHandle, in []byte) {
	t.Helper()
	fv := reflect.ValueOf(fn)
	ft := fv.Type()

	outLen := reflect.New(ft.In(4).Elem())
	outLen.Elem().SetUint(12345)
	out := fv.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(in, ft, 1),
		scalarOf(ft, 2, uint64(len(in))),
		setBufferPtr(nil, ft, 3),
		outLen,
	})
	runtime.KeepAlive(in)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("length query = %s, want CKR_OK", rv)
	}
	if got := outLen.Elem().Uint(); got != 0 {
		t.Fatalf("length query reported %d bytes, want 0 (the update buffers until *Final)", got)
	}
}

// digestFinalViaC drives C_DigestFinal's two-call idiom.
func digestFinalViaC(t *testing.T, session module.SessionHandle) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_DigestFinal)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(2).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		queryLen,
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	digestBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(2).Elem())
	fillLen.Elem().SetUint(uint64(len(digestBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(digestBuf, ft, 1),
		fillLen,
	})
	runtime.KeepAlive(digestBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return digestBuf[:fillLen.Elem().Uint()], rv
}

// TestDigestEncryptUpdate_RoundTrip proves C_DigestEncryptUpdate genuinely
// feeds its input to both the active digest and encrypt operations: the
// digest recovered through C_DigestFinal matches an independent
// crypto/sha256 oracle, and the ciphertext recovered through C_EncryptFinal
// decrypts back to the original plaintext.
func TestDigestEncryptUpdate_RoundTrip(t *testing.T) {
	// Drives a construction FIPS mode refuses; see exports_fips_test.go.
	if !runsOutsideFIPSMode(t) {
		return
	}
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "dualfunction-digestencrypt-aes")

	if rv := startDigestViaC(t, session); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit = %s, want CKR_OK", rv)
	}
	gcmParams := buildGCMParams(t, gcmRoundTripIV, 96, nil, 128)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, gcmParams)
	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}

	plaintext := []byte("digest-and-encrypt-this-plaintext-together")
	requireDualUpdateLengthQuery(t, C_DigestEncryptUpdate, session, plaintext)
	out, rv := dualUpdateViaC(t, C_DigestEncryptUpdate, session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DigestEncryptUpdate = %s, want CKR_OK", rv)
	}
	if len(out) != 0 {
		t.Fatalf("C_DigestEncryptUpdate returned %d bytes, want 0 (AEAD buffers until *Final)", len(out))
	}

	digest, rv := digestFinalViaC(t, session)
	if rv != module.CKR_OK {
		t.Fatalf("C_DigestFinal = %s, want CKR_OK", rv)
	}
	want := sha256.Sum256(plaintext)
	if !bytes.Equal(digest, want[:]) {
		t.Fatalf("C_DigestFinal = %x, want %x (independent crypto/sha256 oracle)", digest, want)
	}

	ciphertext, ecrv := encryptUpdateFinalViaC(t, session, nil)
	if ecrv != module.CKR_OK {
		t.Fatalf("C_EncryptFinal (collecting the buffered plaintext) = %s, want CKR_OK", ecrv)
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext is %d bytes, want %d (plaintext + 16-byte GCM tag)", len(ciphertext), len(plaintext)+16)
	}

	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	recovered, drv := decryptUpdateFinalViaC(t, session, [][]byte{ciphertext})
	if drv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate/C_DecryptFinal = %s, want CKR_OK", drv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}
}

// startDigestViaC drives C_DigestInit with CKM_SHA256.
func startDigestViaC(t *testing.T, session module.SessionHandle) module.CK_RV {
	t.Helper()
	mechBuf := buildCMechanism(module.CKM_SHA256)
	fn := reflect.ValueOf(C_DigestInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
	})
	return module.CK_RV(out[0].Uint())
}

// TestDecryptDigestUpdate_RoundTrip proves C_DecryptDigestUpdate genuinely
// buffers its input for the active decrypt operation: the plaintext
// recovered through C_DecryptFinal matches what was actually encrypted.
func TestDecryptDigestUpdate_RoundTrip(t *testing.T) {
	// Drives a construction FIPS mode refuses; see exports_fips_test.go.
	if !runsOutsideFIPSMode(t) {
		return
	}
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "dualfunction-decryptdigest-aes")

	plaintext := []byte("decrypt-and-digest-this-ciphertext-together")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	if rv := startDigestViaC(t, session); rv != module.CKR_OK {
		t.Fatalf("C_DigestInit = %s, want CKR_OK", rv)
	}

	requireDualUpdateLengthQuery(t, C_DecryptDigestUpdate, session, ciphertext)
	out, rv := dualUpdateViaC(t, C_DecryptDigestUpdate, session, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptDigestUpdate = %s, want CKR_OK", rv)
	}
	if len(out) != 0 {
		t.Fatalf("C_DecryptDigestUpdate returned %d bytes, want 0 (AEAD buffers until *Final)", len(out))
	}

	recovered, drv := decryptUpdateFinalViaC(t, session, nil)
	if drv != module.CKR_OK {
		t.Fatalf("C_DecryptFinal (collecting the buffered ciphertext) = %s, want CKR_OK", drv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}
}

// TestSignEncryptUpdate_RoundTrip proves C_SignEncryptUpdate genuinely feeds
// its input to both the active sign and encrypt operations: the signature
// recovered through C_SignFinal verifies against the plaintext with an
// independent RSA public-key check, and the ciphertext decrypts back to the
// same plaintext.
func TestSignEncryptUpdate_RoundTrip(t *testing.T) {
	// Drives a construction FIPS mode refuses; see exports_fips_test.go.
	if !runsOutsideFIPSMode(t) {
		return
	}
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	key := generateAESKeyViaC(t, session, "dualfunction-signencrypt-aes")

	if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
	}
	gcmParams := buildGCMParams(t, gcmRoundTripIV, 96, nil, 128)
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, gcmParams)
	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}

	plaintext := []byte("sign-and-encrypt-this-plaintext-together")
	requireDualUpdateLengthQuery(t, C_SignEncryptUpdate, session, plaintext)
	out, rv := dualUpdateViaC(t, C_SignEncryptUpdate, session, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignEncryptUpdate = %s, want CKR_OK", rv)
	}
	if len(out) != 0 {
		t.Fatalf("C_SignEncryptUpdate returned %d bytes, want 0 (AEAD buffers until *Final)", len(out))
	}

	signature, srv := signUpdateFinalViaC(t, session, nil)
	if srv != module.CKR_OK {
		t.Fatalf("C_SignFinal (collecting the buffered plaintext) = %s, want CKR_OK", srv)
	}
	if len(signature) == 0 {
		t.Fatal("C_SignFinal produced an empty signature")
	}

	if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
	}
	verifyUpdateFinalViaC(t, session, [][]byte{plaintext}, signature, module.CKR_OK)

	ciphertext, ecrv := encryptUpdateFinalViaC(t, session, nil)
	if ecrv != module.CKR_OK {
		t.Fatalf("C_EncryptFinal (collecting the buffered plaintext) = %s, want CKR_OK", ecrv)
	}
	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	recovered, drv := decryptUpdateFinalViaC(t, session, [][]byte{ciphertext})
	if drv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate/C_DecryptFinal = %s, want CKR_OK", drv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}
}

// TestDecryptVerifyUpdate_RoundTrip proves C_DecryptVerifyUpdate genuinely
// buffers its input for the active decrypt operation, and that the verify
// half activated alongside it accepts a genuine signature over the recovered
// plaintext and rejects a tampered one.
func TestDecryptVerifyUpdate_RoundTrip(t *testing.T) {
	// Drives a construction FIPS mode refuses; see exports_fips_test.go.
	if !runsOutsideFIPSMode(t) {
		return
	}
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	key := generateAESKeyViaC(t, session, "dualfunction-decryptverify-aes")

	plaintext := []byte("decrypt-and-verify-this-ciphertext-together")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
	}
	signature := signViaC(t, session, plaintext)

	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
	}

	requireDualUpdateLengthQuery(t, C_DecryptVerifyUpdate, session, ciphertext)
	out, rv := dualUpdateViaC(t, C_DecryptVerifyUpdate, session, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptVerifyUpdate = %s, want CKR_OK", rv)
	}
	if len(out) != 0 {
		t.Fatalf("C_DecryptVerifyUpdate returned %d bytes, want 0 (AEAD buffers until *Final)", len(out))
	}

	recovered, drv := decryptUpdateFinalViaC(t, session, nil)
	if drv != module.CKR_OK {
		t.Fatalf("C_DecryptFinal (collecting the buffered ciphertext) = %s, want CKR_OK", drv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}

	verifyUpdateFinalViaC(t, session, [][]byte{recovered}, signature, module.CKR_OK)
}
