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

// Round-trip tests for the multi-part streaming success paths
// exports_streaming_test.go's file comment says are out of its offlineTransport
// fixture's reach: C_EncryptUpdate*/C_EncryptFinal, C_DecryptUpdate*/
// C_DecryptFinal, and C_SignUpdate/C_SignFinal + C_VerifyUpdate/C_VerifyFinal
// carrying real ciphertext and a real signature across two or more parts, not
// merely reaching a panicking backend.
//
// These entry points buffer every *Update call and perform the real
// cryptographic operation only at *Final (module.go's EncryptUpdate/
// DecryptUpdate doc comments), so the property this file proves is that the
// *Final result matches what encrypting/signing the concatenation of the
// parts in one call would produce -- checked against
// exports_cryptoroundtrip_test.go's own single-call helpers as the oracle.

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// encryptUpdateFinalViaC drives C_EncryptUpdate once per element of parts,
// each with a real (non-NULL, generously sized) output buffer, followed by
// C_EncryptFinal's two-call idiom, returning the accumulated ciphertext.
func encryptUpdateFinalViaC(t *testing.T, session module.SessionHandle, parts [][]byte) ([]byte, module.CK_RV) {
	t.Helper()

	updateFn := reflect.ValueOf(C_EncryptUpdate)
	uft := updateFn.Type()
	for _, part := range parts {
		outBuf := make([]byte, len(part)+32)
		fillLen := reflect.New(uft.In(4).Elem())
		fillLen.Elem().SetUint(uint64(len(outBuf)))
		out := updateFn.Call([]reflect.Value{
			scalarOf(uft, 0, uint64(session)),
			setBufferPtr(part, uft, 1),
			scalarOf(uft, 2, uint64(len(part))),
			setBufferPtr(outBuf, uft, 3),
			fillLen,
		})
		runtime.KeepAlive(part)
		runtime.KeepAlive(outBuf)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			return nil, rv
		}
	}

	finalFn := reflect.ValueOf(C_EncryptFinal)
	fft := finalFn.Type()
	queryLen := reflect.New(fft.In(2).Elem())
	qout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		reflect.Zero(fft.In(1)),
		queryLen,
	})
	if rv := module.CK_RV(qout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	lastBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(fft.In(2).Elem())
	fillLen.Elem().SetUint(uint64(len(lastBuf)))
	fout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		setBufferPtr(lastBuf, fft, 1),
		fillLen,
	})
	runtime.KeepAlive(lastBuf)
	rv := module.CK_RV(fout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return lastBuf[:fillLen.Elem().Uint()], rv
}

// decryptUpdateFinalViaC mirrors encryptUpdateFinalViaC for the decrypt
// family.
func decryptUpdateFinalViaC(t *testing.T, session module.SessionHandle, parts [][]byte) ([]byte, module.CK_RV) {
	t.Helper()

	updateFn := reflect.ValueOf(C_DecryptUpdate)
	uft := updateFn.Type()
	for _, part := range parts {
		outBuf := make([]byte, len(part)+32)
		fillLen := reflect.New(uft.In(4).Elem())
		fillLen.Elem().SetUint(uint64(len(outBuf)))
		out := updateFn.Call([]reflect.Value{
			scalarOf(uft, 0, uint64(session)),
			setBufferPtr(part, uft, 1),
			scalarOf(uft, 2, uint64(len(part))),
			setBufferPtr(outBuf, uft, 3),
			fillLen,
		})
		runtime.KeepAlive(part)
		runtime.KeepAlive(outBuf)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			return nil, rv
		}
	}

	finalFn := reflect.ValueOf(C_DecryptFinal)
	fft := finalFn.Type()
	queryLen := reflect.New(fft.In(2).Elem())
	qout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		reflect.Zero(fft.In(1)),
		queryLen,
	})
	if rv := module.CK_RV(qout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	lastBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(fft.In(2).Elem())
	fillLen.Elem().SetUint(uint64(len(lastBuf)))
	fout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		setBufferPtr(lastBuf, fft, 1),
		fillLen,
	})
	runtime.KeepAlive(lastBuf)
	rv := module.CK_RV(fout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return lastBuf[:fillLen.Elem().Uint()], rv
}

// TestStreamingEncryptDecrypt_RoundTrip proves C_EncryptUpdate*/C_EncryptFinal
// and C_DecryptUpdate*/C_DecryptFinal carry a real multi-part AES-256-GCM
// ciphertext: several plaintext parts fed through C_EncryptUpdate are sealed
// as one message at C_EncryptFinal, and C_DecryptUpdate*/C_DecryptFinal
// recover the exact concatenation, whatever parts it is split into on the way
// back in.
func TestStreamingEncryptDecrypt_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "streaming-roundtrip-aes")

	plaintext := []byte("the first part!the second, longer part.the third and final part")
	parts := [][]byte{plaintext[:15], plaintext[15:40], plaintext[40:]}

	gcmParams := buildGCMParams(gcmRoundTripIV, 96, nil, 128)
	mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, gcmParams)
	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}
	ciphertext, rv := encryptUpdateFinalViaC(t, session, parts)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptUpdate*/C_EncryptFinal = %s, want CKR_OK", rv)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("streaming encrypt returned the plaintext unchanged")
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext is %d bytes, want %d (plaintext + 16-byte GCM tag)", len(ciphertext), len(plaintext)+16)
	}
	runtime.KeepAlive(gcmParams)
	runtime.KeepAlive(mechBuf)

	// Decrypt back in a different split to prove the framing does not depend
	// on the boundaries the caller happened to use on the way in.
	decryptParts := [][]byte{ciphertext[:20], ciphertext[20:]}
	decryptMechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	recovered, rv := decryptUpdateFinalViaC(t, session, decryptParts)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate*/C_DecryptFinal = %s, want CKR_OK", rv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}
	runtime.KeepAlive(decryptMechBuf)
}

// TestCEncryptFinal_BufferTooSmall proves C_EncryptFinal's two-call idiom
// reports the real buffered ciphertext size and leaves the operation usable
// for the retry PKCS#11 v3.2 §5.2 promises.
func TestCEncryptFinal_BufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "streaming-buffertoosmall-aes")

	plaintext := []byte("plaintext for the buffer-too-small probe")
	gcmParams := buildGCMParams(gcmRoundTripIV, 96, nil, 128)
	mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, gcmParams)
	if rv := encryptInitViaC(t, session, key, mechBuf); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}

	updateFn := reflect.ValueOf(C_EncryptUpdate)
	uft := updateFn.Type()
	outBuf := make([]byte, len(plaintext)+32)
	fillLen := reflect.New(uft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(outBuf)))
	uout := updateFn.Call([]reflect.Value{
		scalarOf(uft, 0, uint64(session)),
		setBufferPtr(plaintext, uft, 1),
		scalarOf(uft, 2, uint64(len(plaintext))),
		setBufferPtr(outBuf, uft, 3),
		fillLen,
	})
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(outBuf)
	if rv := module.CK_RV(uout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptUpdate = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(gcmParams)
	runtime.KeepAlive(mechBuf)

	finalFn := reflect.ValueOf(C_EncryptFinal)
	fft := finalFn.Type()
	undersized := make([]byte, 1)
	smallLen := reflect.New(fft.In(2).Elem())
	smallLen.Elem().SetUint(1)
	fout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		setBufferPtr(undersized, fft, 1),
		smallLen,
	})
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(fout[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_EncryptFinal(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	wantLen := uint64(len(plaintext) + 16)
	if got := smallLen.Elem().Uint(); got != wantLen {
		t.Fatalf("C_EncryptFinal(undersized) reported required length %d, want %d", got, wantLen)
	}

	// The operation must still be usable: a retry with a correctly sized
	// buffer succeeds and produces the real ciphertext.
	realBuf := make([]byte, wantLen)
	realLen := reflect.New(fft.In(2).Elem())
	realLen.Elem().SetUint(wantLen)
	rout := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		setBufferPtr(realBuf, fft, 1),
		realLen,
	})
	runtime.KeepAlive(realBuf)
	if rv := module.CK_RV(rout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptFinal(retry with real buffer) = %s, want CKR_OK", rv)
	}
	if realLen.Elem().Uint() != wantLen {
		t.Fatalf("C_EncryptFinal(retry) reported length %d, want %d", realLen.Elem().Uint(), wantLen)
	}
}

// signUpdateFinalViaC drives C_SignUpdate once per element of parts followed
// by C_SignFinal's two-call idiom, returning the accumulated signature.
func signUpdateFinalViaC(t *testing.T, session module.SessionHandle, parts [][]byte) ([]byte, module.CK_RV) {
	t.Helper()

	updateFn := reflect.ValueOf(C_SignUpdate)
	uft := updateFn.Type()
	for _, part := range parts {
		out := updateFn.Call([]reflect.Value{
			scalarOf(uft, 0, uint64(session)),
			setBufferPtr(part, uft, 1),
			scalarOf(uft, 2, uint64(len(part))),
		})
		runtime.KeepAlive(part)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			return nil, rv
		}
	}

	fn := reflect.ValueOf(C_SignFinal)
	ft := fn.Type()
	queryLen := reflect.New(ft.In(2).Elem())
	qout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		queryLen,
	})
	if rv := module.CK_RV(qout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	sigBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(2).Elem())
	fillLen.Elem().SetUint(uint64(len(sigBuf)))
	fout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(sigBuf, ft, 1),
		fillLen,
	})
	runtime.KeepAlive(sigBuf)
	rv := module.CK_RV(fout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return sigBuf[:fillLen.Elem().Uint()], rv
}

// TestStreamingSignVerify_RoundTrip proves C_SignUpdate/C_SignFinal and
// C_VerifyUpdate/C_VerifyFinal carry a real multi-part RSA-SHA256 signature:
// several data parts fed through C_SignUpdate are signed as one message at
// C_SignFinal, and feeding the same parts through C_VerifyUpdate/
// C_VerifyFinal accepts the genuine signature and rejects a tampered one.
func TestStreamingSignVerify_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)

	data := []byte("the first part of a multi-part signed message.and the second part.")
	parts := [][]byte{data[:30], data[30:]}

	if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
	}
	signature, rv := signUpdateFinalViaC(t, session, parts)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignUpdate/C_SignFinal = %s, want CKR_OK", rv)
	}
	if len(signature) == 0 {
		t.Fatal("C_SignFinal produced an empty signature")
	}

	if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
	}
	verifyUpdateFinalViaC(t, session, parts, signature, module.CKR_OK)

	t.Run("tampered signature is rejected across parts", func(t *testing.T) {
		if rv := verifyInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_VerifyInit = %s, want CKR_OK", rv)
		}
		tampered := append([]byte(nil), signature...)
		tampered[0] ^= 0xFF
		verifyUpdateFinalViaC(t, session, parts, tampered, module.CKR_SIGNATURE_INVALID)
	})
}

// verifyUpdateFinalViaC drives C_VerifyUpdate once per element of parts,
// followed by C_VerifyFinal with signature, asserting the call's CK_RV
// matches want.
func verifyUpdateFinalViaC(t *testing.T, session module.SessionHandle, parts [][]byte, signature []byte, want module.CK_RV) {
	t.Helper()

	updateFn := reflect.ValueOf(C_VerifyUpdate)
	uft := updateFn.Type()
	for _, part := range parts {
		out := updateFn.Call([]reflect.Value{
			scalarOf(uft, 0, uint64(session)),
			setBufferPtr(part, uft, 1),
			scalarOf(uft, 2, uint64(len(part))),
		})
		runtime.KeepAlive(part)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_VerifyUpdate = %s, want CKR_OK", rv)
		}
	}

	finalFn := reflect.ValueOf(C_VerifyFinal)
	fft := finalFn.Type()
	out := finalFn.Call([]reflect.Value{
		scalarOf(fft, 0, uint64(session)),
		setBufferPtr(signature, fft, 1),
		scalarOf(fft, 2, uint64(len(signature))),
	})
	runtime.KeepAlive(signature)
	if rv := module.CK_RV(out[0].Uint()); rv != want {
		t.Fatalf("C_VerifyFinal = %s, want %s", rv, want)
	}
}
