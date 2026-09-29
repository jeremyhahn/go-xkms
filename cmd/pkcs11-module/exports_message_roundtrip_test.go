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

// Round-trip tests for the PKCS#11 v3.0 message-based cryptographic success
// paths: C_MessageEncryptInit/C_EncryptMessage(/Begin/Next)/C_MessageEncryptFinal,
// the matching decrypt family, and C_MessageSignInit/C_SignMessage(Begin/Next)/
// C_MessageVerifyInit/C_VerifyMessage(Begin/Next).
//
// exports_streaming_test.go and exports_paramdecode_test.go's file comments
// explain why the rest of this package confines message-function coverage to
// the argument-marshalling and no-active-operation branches: their fixture is
// offlineTransport, whose embedded PKCS11Transport is nil, so any call that
// reaches the backend panics. This file swaps in
// pkcs11test.CryptoMockClient -- the same real-crypto transport
// exports_cryptoroundtrip_test.go uses -- to drive the cryptographic success
// branches those files could not reach.
//
// Every test here passes pParameter=NULL to the AEAD entry points. Module's
// EncryptMessage/DecryptMessage (module.go) treat a nil *AESGCMMessageParams
// as "use the mechanism's own CK_GCM_PARAMS IV and return ciphertext||tag
// framed exactly like C_Encrypt" -- skipping the CK_GCM_MESSAGE_PARAMS
// marshalling branches entirely. Those branches (populated pIv/pTag,
// CKG_GENERATE write-back, per-message tag length) are exercised directly
// against gcmMessageParams/writeGCMMessageParams by exports_aeadmsg_test.go,
// so re-deriving them here through a second CryptoMockClient round trip would
// duplicate coverage rather than add it; this file's job is the Module-level
// dispatch and the ciphertext/signature bytes actually crossing the cgo
// boundary.
//
// See exports_v32_kem_roundtrip_test.go's package comment for why every
// template or mechanism this file builds with buildCAttributeArray/
// buildCMechanismWithParam keeps its source []module.Attribute or parameter
// []byte alive with runtime.KeepAlive independently of the returned buffer.

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// messageGCMIV is the fixed 12-byte AES-GCM IV this file's message-based
// AEAD round trips use.
var messageGCMIV = []byte("message-ivv!")

// messageAESGCMMechanism builds the CKM_AES_GCM mechanism buffer this file's
// message-based encrypt/decrypt Init calls carry, keeping the CK_GCM_PARAMS
// buffer it points into alive for as long as the returned mechanism buffer is
// in use (see exports_v32_kem_roundtrip_test.go's package comment on why the
// source buffer, not just the CK_MECHANISM record, must stay reachable).
func messageAESGCMMechanism() (mechBuf, gcmParams []byte) {
	gcmParams = buildGCMParams(messageGCMIV, 96, nil, 128)
	return buildCMechanismWithParam(module.CKM_AES_GCM, gcmParams), gcmParams
}

// messageInitViaC drives one of the four message-based Init functions
// (C_MessageEncryptInit, C_MessageDecryptInit, C_MessageSignInit,
// C_MessageVerifyInit), all of which share the (hSession, pMechanism, hKey)
// signature.
func messageInitViaC(t *testing.T, fn any, session module.SessionHandle, mechBuf []byte, key module.ObjectHandle) module.CK_RV {
	t.Helper()
	fv := reflect.ValueOf(fn)
	ft := fv.Type()
	out := fv.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	runtime.KeepAlive(mechBuf)
	return module.CK_RV(out[0].Uint())
}

// messageFinalViaC drives one of the four message-based Final functions,
// which all take only the session handle.
func messageFinalViaC(t *testing.T, fn any, session module.SessionHandle) module.CK_RV {
	t.Helper()
	fv := reflect.ValueOf(fn)
	ft := fv.Type()
	out := fv.Call([]reflect.Value{scalarOf(ft, 0, uint64(session))})
	return module.CK_RV(out[0].Uint())
}

// encryptMessageViaC drives C_EncryptMessage with pParameter=NULL (the
// mechanism's own IV governs), in a single call sized generously for
// ciphertext||tag, returning the ciphertext and the call's CK_RV.
func encryptMessageViaC(t *testing.T, session module.SessionHandle, aad, plaintext []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_EncryptMessage)
	ft := fn.Type()

	ctBuf := make([]byte, len(plaintext)+16)
	fillLen := reflect.New(ft.In(8).Elem())
	fillLen.Elem().SetUint(uint64(len(ctBuf)))
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(aad, ft, 3),
		scalarOf(ft, 4, uint64(len(aad))),
		setBufferPtr(plaintext, ft, 5),
		scalarOf(ft, 6, uint64(len(plaintext))),
		setBufferPtr(ctBuf, ft, 7),
		fillLen,
	})
	runtime.KeepAlive(aad)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ctBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return ctBuf[:fillLen.Elem().Uint()], rv
}

// decryptMessageViaC drives C_DecryptMessage with pParameter=NULL, mirroring
// encryptMessageViaC.
func decryptMessageViaC(t *testing.T, session module.SessionHandle, aad, ciphertext []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_DecryptMessage)
	ft := fn.Type()

	ptBuf := make([]byte, len(ciphertext))
	fillLen := reflect.New(ft.In(8).Elem())
	fillLen.Elem().SetUint(uint64(len(ptBuf)))
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(aad, ft, 3),
		scalarOf(ft, 4, uint64(len(aad))),
		setBufferPtr(ciphertext, ft, 5),
		scalarOf(ft, 6, uint64(len(ciphertext))),
		setBufferPtr(ptBuf, ft, 7),
		fillLen,
	})
	runtime.KeepAlive(aad)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(ptBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return ptBuf[:fillLen.Elem().Uint()], rv
}

// TestMessageEncryptDecrypt_RoundTrip proves C_MessageEncryptInit +
// C_EncryptMessage + C_MessageEncryptFinal, and the matching decrypt family,
// carry a real AES-256-GCM ciphertext: a key generated through
// pkcs11test.CryptoMockClient encrypts a message, and the exact plaintext
// comes back through the independent decrypt lifecycle.
func TestMessageEncryptDecrypt_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-roundtrip-aes")

	encMechBuf, encGCMParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageEncryptInit, session, encMechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(encGCMParams)

	aad := []byte("message-associated-data")
	plaintext := []byte("a single message encrypted end to end through the cgo boundary")
	ciphertext, rv := encryptMessageViaC(t, session, aad, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptMessage = %s, want CKR_OK", rv)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("C_EncryptMessage returned the plaintext unchanged")
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext is %d bytes, want %d (plaintext + 16-byte GCM tag)", len(ciphertext), len(plaintext)+16)
	}

	rv = messageFinalViaC(t, C_MessageEncryptFinal, session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_MessageEncryptFinal = %s, want CKR_OK or CKR_OPERATION_NOT_INITIALIZED", rv)
	}

	decMechBuf, decGCMParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageDecryptInit, session, decMechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(decGCMParams)
	recovered, rv := decryptMessageViaC(t, session, aad, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptMessage = %s, want CKR_OK", rv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("C_DecryptMessage = %q, want %q", recovered, plaintext)
	}
	rv = messageFinalViaC(t, C_MessageDecryptFinal, session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_MessageDecryptFinal = %s, want CKR_OK or CKR_OPERATION_NOT_INITIALIZED", rv)
	}

	t.Run("tampered ciphertext is rejected", func(t *testing.T) {
		tamperMechBuf, tamperGCMParams := messageAESGCMMechanism()
		if rv := messageInitViaC(t, C_MessageDecryptInit, session, tamperMechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
		}
		runtime.KeepAlive(tamperGCMParams)
		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0xFF
		if _, rv := decryptMessageViaC(t, session, aad, tampered); rv != module.CKR_ENCRYPTED_DATA_INVALID {
			t.Fatalf("C_DecryptMessage(tampered) = %s, want CKR_ENCRYPTED_DATA_INVALID", rv)
		}
	})
}

// encryptMessageBeginNextViaC drives C_EncryptMessageBegin followed by a
// single final C_EncryptMessageNext, both with pParameter=NULL, returning the
// resulting ciphertext.
func encryptMessageBeginNextViaC(t *testing.T, session module.SessionHandle, aad, plaintext []byte) ([]byte, module.CK_RV) {
	t.Helper()

	beginFn := reflect.ValueOf(C_EncryptMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
		setBufferPtr(aad, bft, 3),
		scalarOf(bft, 4, uint64(len(aad))),
	})
	runtime.KeepAlive(aad)
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	nextFn := reflect.ValueOf(C_EncryptMessageNext)
	nft := nextFn.Type()
	ctBuf := make([]byte, len(plaintext)+16)
	fillLen := reflect.New(nft.In(6).Elem())
	fillLen.Elem().SetUint(uint64(len(ctBuf)))
	nout := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(plaintext, nft, 3),
		scalarOf(nft, 4, uint64(len(plaintext))),
		setBufferPtr(ctBuf, nft, 5),
		fillLen,
		scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
	})
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ctBuf)
	rv := module.CK_RV(nout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return ctBuf[:fillLen.Elem().Uint()], rv
}

// decryptMessageBeginNextViaC mirrors encryptMessageBeginNextViaC for the
// decrypt family.
func decryptMessageBeginNextViaC(t *testing.T, session module.SessionHandle, aad, ciphertext []byte) ([]byte, module.CK_RV) {
	t.Helper()

	beginFn := reflect.ValueOf(C_DecryptMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
		setBufferPtr(aad, bft, 3),
		scalarOf(bft, 4, uint64(len(aad))),
	})
	runtime.KeepAlive(aad)
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	nextFn := reflect.ValueOf(C_DecryptMessageNext)
	nft := nextFn.Type()
	ptBuf := make([]byte, len(ciphertext))
	fillLen := reflect.New(nft.In(6).Elem())
	fillLen.Elem().SetUint(uint64(len(ptBuf)))
	nout := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(ciphertext, nft, 3),
		scalarOf(nft, 4, uint64(len(ciphertext))),
		setBufferPtr(ptBuf, nft, 5),
		fillLen,
		scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
	})
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(ptBuf)
	rv := module.CK_RV(nout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return ptBuf[:fillLen.Elem().Uint()], rv
}

// TestMultiPartMessageEncryptDecrypt_RoundTrip proves the
// C_EncryptMessageBegin/C_EncryptMessageNext(final) pair and its decrypt
// counterpart carry a real AES-256-GCM ciphertext, mirroring
// TestMessageEncryptDecrypt_RoundTrip for the multi-part entry points
// exports_streaming_test.go's fixture cannot reach.
func TestMultiPartMessageEncryptDecrypt_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-multipart-aes")

	encMechBuf, encGCMParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageEncryptInit, session, encMechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(encGCMParams)

	aad := []byte("multipart-associated-data")
	plaintext := []byte("multi-part-message-plaintext-data")
	ciphertext, rv := encryptMessageBeginNextViaC(t, session, aad, plaintext)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncryptMessageBegin/Next(final) = %s, want CKR_OK", rv)
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Fatalf("ciphertext is %d bytes, want %d", len(ciphertext), len(plaintext)+16)
	}
	_ = messageFinalViaC(t, C_MessageEncryptFinal, session)

	decMechBuf, decGCMParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageDecryptInit, session, decMechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(decGCMParams)
	recovered, rv := decryptMessageBeginNextViaC(t, session, aad, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptMessageBegin/Next(final) = %s, want CKR_OK", rv)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q, want %q", recovered, plaintext)
	}
	_ = messageFinalViaC(t, C_MessageDecryptFinal, session)
}

// signMessageViaC drives C_SignMessage's two-call idiom with
// pParameter=NULL.
func signMessageViaC(t *testing.T, session module.SessionHandle, data []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_SignMessage)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(6).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		reflect.Zero(ft.In(5)),
		queryLen,
	})
	runtime.KeepAlive(data)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	sigBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(6).Elem())
	fillLen.Elem().SetUint(uint64(len(sigBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		setBufferPtr(sigBuf, ft, 5),
		fillLen,
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(sigBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return sigBuf[:fillLen.Elem().Uint()], rv
}

// verifyMessageViaC drives C_VerifyMessage with pParameter=NULL.
func verifyMessageViaC(t *testing.T, session module.SessionHandle, data, signature []byte) module.CK_RV {
	t.Helper()
	fn := reflect.ValueOf(C_VerifyMessage)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		setBufferPtr(signature, ft, 5),
		scalarOf(ft, 6, uint64(len(signature))),
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(signature)
	return module.CK_RV(out[0].Uint())
}

// TestMessageSignVerify_RoundTrip proves C_MessageSignInit + C_SignMessage +
// C_MessageSignFinal, and the matching verify family, carry a real RSA
// signature: a key generated through pkcs11test.CryptoMockClient signs a
// message, and C_VerifyMessage accepts the genuine signature while rejecting
// a tampered message or signature (v3.2 §5.16.2, CKR_SIGNATURE_INVALID).
func TestMessageSignVerify_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)

	mechBuf := buildCMechanism(module.CKM_SHA256_RSA_PKCS)
	if rv := messageInitViaC(t, C_MessageSignInit, session, mechBuf, priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}

	data := []byte("message-sign-verify-round-trip-data")
	signature, rv := signMessageViaC(t, session, data)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignMessage = %s, want CKR_OK", rv)
	}
	if len(signature) == 0 {
		t.Fatal("C_SignMessage produced an empty signature")
	}
	rv = messageFinalViaC(t, C_MessageSignFinal, session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_MessageSignFinal = %s, want CKR_OK or CKR_OPERATION_NOT_INITIALIZED", rv)
	}

	if rv := messageInitViaC(t, C_MessageVerifyInit, session, mechBuf, pub); rv != module.CKR_OK {
		t.Fatalf("C_MessageVerifyInit = %s, want CKR_OK", rv)
	}
	if rv := verifyMessageViaC(t, session, data, signature); rv != module.CKR_OK {
		t.Fatalf("C_VerifyMessage(genuine) = %s, want CKR_OK", rv)
	}

	t.Run("tampered data is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), data...)
		tampered[0] ^= 0xFF
		if rv := verifyMessageViaC(t, session, tampered, signature); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_VerifyMessage(tampered data) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})
	t.Run("tampered signature is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), signature...)
		tampered[0] ^= 0xFF
		if rv := verifyMessageViaC(t, session, data, tampered); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_VerifyMessage(tampered signature) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})
	// The message-based process outlives any single message: a rejected
	// verification must not tear down the operation, so the genuine signature
	// still verifies afterward.
	if rv := verifyMessageViaC(t, session, data, signature); rv != module.CKR_OK {
		t.Fatalf("C_VerifyMessage(genuine, after rejections) = %s, want CKR_OK", rv)
	}
	rv = messageFinalViaC(t, C_MessageVerifyFinal, session)
	if rv != module.CKR_OK && rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Fatalf("C_MessageVerifyFinal = %s, want CKR_OK or CKR_OPERATION_NOT_INITIALIZED", rv)
	}
}

// signMessageBeginNextViaC drives C_SignMessageBegin followed by a single
// final C_SignMessageNext (finality decided by a non-nil pulSignatureLen, per
// exports.go's C_SignMessageNext), returning the signature.
func signMessageBeginNextViaC(t *testing.T, session module.SessionHandle, data []byte) ([]byte, module.CK_RV) {
	t.Helper()

	beginFn := reflect.ValueOf(C_SignMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
	})
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	// A single call with a generously sized buffer, not the length-query-then-
	// fill idiom: unlike C_Sign/C_SignMessage (which cache their result so a
	// repeated call after a length query replays it), C_SignMessageNext calls
	// Module.SignMessageNext -- and so SignUpdate -- fresh on every invocation
	// once pulSignatureLen is non-NULL (exports.go's C_SignMessageNext decides
	// finality solely from that pointer, not from whether this is a repeat
	// call). A query call would feed the same data through SignUpdate twice.
	nextFn := reflect.ValueOf(C_SignMessageNext)
	nft := nextFn.Type()
	sigBuf := make([]byte, 512) // room for an RSA-2048 signature (256 bytes) with margin.
	fillLen := reflect.New(nft.In(6).Elem())
	fillLen.Elem().SetUint(uint64(len(sigBuf)))
	fout := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(data, nft, 3),
		scalarOf(nft, 4, uint64(len(data))),
		setBufferPtr(sigBuf, nft, 5),
		fillLen,
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(sigBuf)
	rv := module.CK_RV(fout[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return sigBuf[:fillLen.Elem().Uint()], rv
}

// verifyMessageBeginNextViaC drives C_VerifyMessageBegin followed by a single
// final C_VerifyMessageNext (finality decided by a non-nil pSignature).
func verifyMessageBeginNextViaC(t *testing.T, session module.SessionHandle, data, signature []byte) module.CK_RV {
	t.Helper()

	beginFn := reflect.ValueOf(C_VerifyMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
	})
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		return rv
	}

	nextFn := reflect.ValueOf(C_VerifyMessageNext)
	nft := nextFn.Type()
	out := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(data, nft, 3),
		scalarOf(nft, 4, uint64(len(data))),
		setBufferPtr(signature, nft, 5),
		scalarOf(nft, 6, uint64(len(signature))),
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(signature)
	return module.CK_RV(out[0].Uint())
}

// TestMultiPartMessageSignVerify_RoundTrip mirrors
// TestMessageSignVerify_RoundTrip for the C_SignMessageBegin/Next and
// C_VerifyMessageBegin/Next entry points.
func TestMultiPartMessageSignVerify_RoundTrip(t *testing.T) {
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)

	mechBuf := buildCMechanism(module.CKM_SHA256_RSA_PKCS)
	if rv := messageInitViaC(t, C_MessageSignInit, session, mechBuf, priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}

	data := []byte("multi-part-message-sign-verify-data")
	signature, rv := signMessageBeginNextViaC(t, session, data)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignMessageBegin/Next(final) = %s, want CKR_OK", rv)
	}
	_ = messageFinalViaC(t, C_MessageSignFinal, session)

	if rv := messageInitViaC(t, C_MessageVerifyInit, session, mechBuf, pub); rv != module.CKR_OK {
		t.Fatalf("C_MessageVerifyInit = %s, want CKR_OK", rv)
	}
	if rv := verifyMessageBeginNextViaC(t, session, data, signature); rv != module.CKR_OK {
		t.Fatalf("C_VerifyMessageBegin/Next(genuine) = %s, want CKR_OK", rv)
	}

	t.Run("tampered signature is rejected", func(t *testing.T) {
		tampered := append([]byte(nil), signature...)
		tampered[0] ^= 0xFF
		if rv := verifyMessageBeginNextViaC(t, session, data, tampered); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_VerifyMessageBegin/Next(tampered) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})
	_ = messageFinalViaC(t, C_MessageVerifyFinal, session)
}

// TestMessageEncryptInit_WrongMechanismIsRefused proves
// C_MessageEncryptInit is refused for a mechanism that is not an encryption
// mechanism at all (CKM_SHA256_RSA_PKCS, a signature mechanism), reaching
// Module.EncryptInit's own mechanism/key-type validation.
func TestMessageEncryptInit_WrongMechanismIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-wrong-mechanism-aes")

	rv := messageInitViaC(t, C_MessageEncryptInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), key)
	if rv == module.CKR_OK {
		t.Fatal("C_MessageEncryptInit(CKM_SHA256_RSA_PKCS, AES key) = CKR_OK, want an error")
	}
}

// TestMessageSignInit_NotLoggedInIsRefused proves C_MessageSignInit enforces
// the token's CKF_LOGIN_REQUIRED before starting a message-based signing
// process.
func TestMessageSignInit_NotLoggedInIsRefused(t *testing.T) {
	m, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)

	if rv := m.Logout(session); rv != module.CKR_OK {
		t.Fatalf("Logout: %s", rv)
	}

	rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv)
	if rv != module.CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("C_MessageSignInit(logged out) = %s, want CKR_USER_NOT_LOGGED_IN", rv)
	}
}

// TestCEncryptMessage_BufferTooSmall proves C_EncryptMessage's real-buffer
// leg reports CKR_BUFFER_TOO_SMALL and the real required length when the
// caller's buffer is undersized, and that the operation survives the failed
// call: PKCS#11 v3.2 §5.2 lets the caller retry with a larger buffer, and a
// message-based process's single encryption slot must still be usable for
// that retry.
func TestCEncryptMessage_BufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-buffertoosmall-aes")

	mechBuf, gcmParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(gcmParams)

	plaintext := []byte("plaintext for the message buffer-too-small probe")
	fn := reflect.ValueOf(C_EncryptMessage)
	ft := fn.Type()
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(8).Elem())
	smallLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		reflect.Zero(ft.In(3)),
		scalarOf(ft, 4, 0),
		setBufferPtr(plaintext, ft, 5),
		scalarOf(ft, 6, uint64(len(plaintext))),
		setBufferPtr(undersized, ft, 7),
		smallLen,
	})
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_EncryptMessage(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	wantLen := uint64(len(plaintext) + 16)
	if got := smallLen.Elem().Uint(); got != wantLen {
		t.Fatalf("C_EncryptMessage(undersized) reported required length %d, want %d", got, wantLen)
	}

	realBuf := make([]byte, wantLen)
	realLen := reflect.New(ft.In(8).Elem())
	realLen.Elem().SetUint(wantLen)
	rout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		reflect.Zero(ft.In(3)),
		scalarOf(ft, 4, 0),
		setBufferPtr(plaintext, ft, 5),
		scalarOf(ft, 6, uint64(len(plaintext))),
		setBufferPtr(realBuf, ft, 7),
		realLen,
	})
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(realBuf)
	if rv := module.CK_RV(rout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptMessage(retry with real buffer) = %s, want CKR_OK", rv)
	}
}

// TestCEncryptMessageNext_NonFinalQueryModeReportsZero proves a non-final
// C_EncryptMessageNext call with a NULL output buffer -- the §5.2 length
// query -- reports zero without buffering the part a second time: a
// multi-part AEAD message produces no ciphertext until the final part.
func TestCEncryptMessageNext_NonFinalQueryModeReportsZero(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-nonfinal-query-aes")

	mechBuf, gcmParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(gcmParams)

	beginFn := reflect.ValueOf(C_EncryptMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
		reflect.Zero(bft.In(3)),
		scalarOf(bft, 4, 0),
	})
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptMessageBegin = %s, want CKR_OK", rv)
	}

	part := []byte("a non-final part")
	nextFn := reflect.ValueOf(C_EncryptMessageNext)
	nft := nextFn.Type()
	queryLen := reflect.New(nft.In(6).Elem())
	nout := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(part, nft, 3),
		scalarOf(nft, 4, uint64(len(part))),
		reflect.Zero(nft.In(5)),
		queryLen,
		scalarOf(nft, 7, 0), // flags: not CKF_END_OF_MESSAGE.
	})
	runtime.KeepAlive(part)
	if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptMessageNext(non-final, query) = %s, want CKR_OK", rv)
	}
	if got := queryLen.Elem().Uint(); got != 0 {
		t.Fatalf("C_EncryptMessageNext(non-final, query) reported length %d, want 0", got)
	}
}

// TestCDecryptMessageNext_NonFinalQueryModeReportsZero mirrors
// TestCEncryptMessageNext_NonFinalQueryModeReportsZero for
// C_DecryptMessageNext.
func TestCDecryptMessageNext_NonFinalQueryModeReportsZero(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-decrypt-nonfinal-query-aes")

	mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
	if rv := messageInitViaC(t, C_MessageDecryptInit, session, mechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
	}

	beginFn := reflect.ValueOf(C_DecryptMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
		reflect.Zero(bft.In(3)),
		scalarOf(bft, 4, 0),
	})
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_DecryptMessageBegin = %s, want CKR_OK", rv)
	}

	part := []byte("a non-final ciphertext part")
	nextFn := reflect.ValueOf(C_DecryptMessageNext)
	nft := nextFn.Type()
	queryLen := reflect.New(nft.In(6).Elem())
	nout := nextFn.Call([]reflect.Value{
		scalarOf(nft, 0, uint64(session)),
		reflect.Zero(nft.In(1)),
		scalarOf(nft, 2, 0),
		setBufferPtr(part, nft, 3),
		scalarOf(nft, 4, uint64(len(part))),
		reflect.Zero(nft.In(5)),
		queryLen,
		scalarOf(nft, 7, 0), // flags: not CKF_END_OF_MESSAGE.
	})
	runtime.KeepAlive(part)
	if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_DecryptMessageNext(non-final, query) = %s, want CKR_OK", rv)
	}
	if got := queryLen.Elem().Uint(); got != 0 {
		t.Fatalf("C_DecryptMessageNext(non-final, query) reported length %d, want 0", got)
	}
}

// TestCEncryptMessageNext_FinalQueryModeAndBufferTooSmall covers
// C_EncryptMessageNext's final-part branches
// TestCMultiPartMessageEncryptDecrypt_RoundTrip's single sized-buffer call
// does not reach: a NULL pCiphertextPart length query on the final part, and
// an undersized real buffer.
func TestCEncryptMessageNext_FinalQueryModeAndBufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	plaintext := []byte("the final and only part of this message")

	beginFn := reflect.ValueOf(C_EncryptMessageBegin)
	bft := beginFn.Type()
	nextFn := reflect.ValueOf(C_EncryptMessageNext)
	nft := nextFn.Type()

	t.Run("query mode", func(t *testing.T) {
		// A fresh key: messageAESGCMMechanism's IV is fixed, and the module's
		// AES-GCM nonce-reuse guard (crypto.go's checkGCMNonce) refuses a
		// second real encryption under the same (key, IV) pair -- which the
		// "buffer too small" subtest below would otherwise be.
		key := generateAESKeyViaC(t, session, "message-encryptnext-final-query-aes")
		mechBuf, gcmParams := messageAESGCMMechanism()
		if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
		}
		runtime.KeepAlive(gcmParams)
		bout := beginFn.Call([]reflect.Value{
			scalarOf(bft, 0, uint64(session)), reflect.Zero(bft.In(1)), scalarOf(bft, 2, 0), reflect.Zero(bft.In(3)), scalarOf(bft, 4, 0),
		})
		if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_EncryptMessageBegin = %s, want CKR_OK", rv)
		}

		queryLen := reflect.New(nft.In(6).Elem())
		nout := nextFn.Call([]reflect.Value{
			scalarOf(nft, 0, uint64(session)), reflect.Zero(nft.In(1)), scalarOf(nft, 2, 0),
			setBufferPtr(plaintext, nft, 3), scalarOf(nft, 4, uint64(len(plaintext))),
			reflect.Zero(nft.In(5)), queryLen, scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
		})
		runtime.KeepAlive(plaintext)
		if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_EncryptMessageNext(final, query) = %s, want CKR_OK", rv)
		}
		if got := queryLen.Elem().Uint(); got != uint64(len(plaintext)+16) {
			t.Fatalf("C_EncryptMessageNext(final, query) reported length %d, want %d", got, len(plaintext)+16)
		}
		_ = messageFinalViaC(t, C_MessageEncryptFinal, session)
	})

	t.Run("buffer too small", func(t *testing.T) {
		key := generateAESKeyViaC(t, session, "message-encryptnext-final-small-aes")
		mechBuf, gcmParams := messageAESGCMMechanism()
		if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
		}
		runtime.KeepAlive(gcmParams)
		bout := beginFn.Call([]reflect.Value{
			scalarOf(bft, 0, uint64(session)), reflect.Zero(bft.In(1)), scalarOf(bft, 2, 0), reflect.Zero(bft.In(3)), scalarOf(bft, 4, 0),
		})
		if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_EncryptMessageBegin = %s, want CKR_OK", rv)
		}

		undersized := make([]byte, 1)
		smallLen := reflect.New(nft.In(6).Elem())
		smallLen.Elem().SetUint(1)
		nout := nextFn.Call([]reflect.Value{
			scalarOf(nft, 0, uint64(session)), reflect.Zero(nft.In(1)), scalarOf(nft, 2, 0),
			setBufferPtr(plaintext, nft, 3), scalarOf(nft, 4, uint64(len(plaintext))),
			setBufferPtr(undersized, nft, 5), smallLen, scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
		})
		runtime.KeepAlive(plaintext)
		runtime.KeepAlive(undersized)
		if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
			t.Fatalf("C_EncryptMessageNext(final, 1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
		}
		if got := smallLen.Elem().Uint(); got != uint64(len(plaintext)+16) {
			t.Fatalf("C_EncryptMessageNext(final, undersized) reported length %d, want %d", got, len(plaintext)+16)
		}
	})
}

// TestCDecryptMessageNext_FinalQueryModeAndBufferTooSmall mirrors
// TestCEncryptMessageNext_FinalQueryModeAndBufferTooSmall for
// C_DecryptMessageNext. Unlike the encrypt side, decrypting the same
// ciphertext twice needs no fresh key or IV per subtest: decryption is not
// an entropy-consuming operation the module's nonce-reuse guard tracks.
func TestCDecryptMessageNext_FinalQueryModeAndBufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-decryptnext-final-aes")
	plaintext := []byte("the final and only ciphertext part")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	beginFn := reflect.ValueOf(C_DecryptMessageBegin)
	bft := beginFn.Type()
	nextFn := reflect.ValueOf(C_DecryptMessageNext)
	nft := nextFn.Type()
	decMechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))

	t.Run("query mode", func(t *testing.T) {
		if rv := messageInitViaC(t, C_MessageDecryptInit, session, decMechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
		}
		bout := beginFn.Call([]reflect.Value{
			scalarOf(bft, 0, uint64(session)), reflect.Zero(bft.In(1)), scalarOf(bft, 2, 0), reflect.Zero(bft.In(3)), scalarOf(bft, 4, 0),
		})
		if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_DecryptMessageBegin = %s, want CKR_OK", rv)
		}

		queryLen := reflect.New(nft.In(6).Elem())
		nout := nextFn.Call([]reflect.Value{
			scalarOf(nft, 0, uint64(session)), reflect.Zero(nft.In(1)), scalarOf(nft, 2, 0),
			setBufferPtr(ciphertext, nft, 3), scalarOf(nft, 4, uint64(len(ciphertext))),
			reflect.Zero(nft.In(5)), queryLen, scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
		})
		runtime.KeepAlive(ciphertext)
		if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_DecryptMessageNext(final, query) = %s, want CKR_OK", rv)
		}
		if got := queryLen.Elem().Uint(); got != uint64(len(plaintext)) {
			t.Fatalf("C_DecryptMessageNext(final, query) reported length %d, want %d", got, len(plaintext))
		}
		_ = messageFinalViaC(t, C_MessageDecryptFinal, session)
	})

	t.Run("buffer too small", func(t *testing.T) {
		if rv := messageInitViaC(t, C_MessageDecryptInit, session, decMechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
		}
		bout := beginFn.Call([]reflect.Value{
			scalarOf(bft, 0, uint64(session)), reflect.Zero(bft.In(1)), scalarOf(bft, 2, 0), reflect.Zero(bft.In(3)), scalarOf(bft, 4, 0),
		})
		if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_DecryptMessageBegin = %s, want CKR_OK", rv)
		}

		undersized := make([]byte, 1)
		smallLen := reflect.New(nft.In(6).Elem())
		smallLen.Elem().SetUint(1)
		nout := nextFn.Call([]reflect.Value{
			scalarOf(nft, 0, uint64(session)), reflect.Zero(nft.In(1)), scalarOf(nft, 2, 0),
			setBufferPtr(ciphertext, nft, 3), scalarOf(nft, 4, uint64(len(ciphertext))),
			setBufferPtr(undersized, nft, 5), smallLen, scalarOf(nft, 7, uint64(module.CKF_END_OF_MESSAGE)),
		})
		runtime.KeepAlive(ciphertext)
		runtime.KeepAlive(undersized)
		if rv := module.CK_RV(nout[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
			t.Fatalf("C_DecryptMessageNext(final, 1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
		}
		if got := smallLen.Elem().Uint(); got != uint64(len(plaintext)) {
			t.Fatalf("C_DecryptMessageNext(final, undersized) reported length %d, want %d", got, len(plaintext))
		}
	})

	runtime.KeepAlive(decMechBuf)
}

// TestCEncryptMessage_BufferTooSmall for C_DecryptMessage.
func TestCDecryptMessage_BufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-decrypt-buffertoosmall-aes")

	plaintext := []byte("plaintext for the decrypt buffer-too-small probe")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	// The decrypt mechanism's IV must match the one encryptOnceViaC used
	// (gcmRoundTripIV), not messageAESGCMMechanism's own messageGCMIV.
	ivMechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
	if rv := messageInitViaC(t, C_MessageDecryptInit, session, ivMechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
	}

	fn := reflect.ValueOf(C_DecryptMessage)
	ft := fn.Type()
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(8).Elem())
	smallLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		reflect.Zero(ft.In(3)),
		scalarOf(ft, 4, 0),
		setBufferPtr(ciphertext, ft, 5),
		scalarOf(ft, 6, uint64(len(ciphertext))),
		setBufferPtr(undersized, ft, 7),
		smallLen,
	})
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_DecryptMessage(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	wantLen := uint64(len(plaintext))
	if got := smallLen.Elem().Uint(); got != wantLen {
		t.Fatalf("C_DecryptMessage(undersized) reported required length %d, want %d", got, wantLen)
	}
}

// TestCSignMessageBegin_NonNilParamIsRefused proves C_SignMessageBegin (and,
// sharing rejectSignMessageParam, C_SignMessageNext) refuses a per-message
// parameter: no signature mechanism this module implements takes one (see
// rejectSignMessageParam's doc comment in exports.go).
func TestCSignMessageBegin_NonNilParamIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}

	fn := reflect.ValueOf(C_SignMessageBegin)
	ft := fn.Type()
	param := []byte{0x01}
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cPtr(unsafe.Pointer(&param[0]), ft, 1),
		scalarOf(ft, 2, uint64(len(param))),
	})
	runtime.KeepAlive(param)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_SignMessageBegin(non-NULL pParameter) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}

// TestCSignMessageNext_NonFinalUpdatesWithoutSignature proves a non-final
// C_SignMessageNext call (pulSignatureLen=NULL) feeds its data through
// without producing a signature, the branch the two-call idiom's query and
// real-buffer legs below never reach.
func TestCSignMessageNext_NonFinalUpdatesWithoutSignature(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
		t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
	}
	beginFn := reflect.ValueOf(C_SignMessageBegin)
	bft := beginFn.Type()
	bout := beginFn.Call([]reflect.Value{
		scalarOf(bft, 0, uint64(session)),
		reflect.Zero(bft.In(1)),
		scalarOf(bft, 2, 0),
	})
	if rv := module.CK_RV(bout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_SignMessageBegin = %s, want CKR_OK", rv)
	}

	data := []byte("a non-final part of a signed message")
	fn := reflect.ValueOf(C_SignMessageNext)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		reflect.Zero(ft.In(1)),
		scalarOf(ft, 2, 0),
		setBufferPtr(data, ft, 3),
		scalarOf(ft, 4, uint64(len(data))),
		reflect.Zero(ft.In(5)),
		reflect.Zero(ft.In(6)), // pulSignatureLen=NULL: non-final.
	})
	runtime.KeepAlive(data)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_SignMessageNext(non-final) = %s, want CKR_OK", rv)
	}
}

// TestCSignMessageNext_FinalQueryModeAndBufferTooSmall proves the final
// leg's two remaining branches: a NULL pSignature length query, and a real
// but undersized buffer. Each is driven as its own independent
// C_MessageSignInit/C_SignMessageBegin sequence, since (as
// signMessageBeginNextViaC's comment explains) C_SignMessageNext re-runs
// C_SignUpdate on every call once pulSignatureLen is non-NULL, so a second
// final call under the same process is not the two-call retry PKCS#11 v3.2
// §5.2 describes for the other streaming verbs.
func TestCSignMessageNext_FinalQueryModeAndBufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	data := []byte("final message data")

	t.Run("query mode", func(t *testing.T) {
		if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
			t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
		}
		fn := reflect.ValueOf(C_SignMessageNext)
		ft := fn.Type()
		queryLen := reflect.New(ft.In(6).Elem())
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			reflect.Zero(ft.In(1)),
			scalarOf(ft, 2, 0),
			setBufferPtr(data, ft, 3),
			scalarOf(ft, 4, uint64(len(data))),
			reflect.Zero(ft.In(5)),
			queryLen,
		})
		runtime.KeepAlive(data)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_SignMessageNext(final, query) = %s, want CKR_OK", rv)
		}
		if got := queryLen.Elem().Uint(); got == 0 {
			t.Fatal("C_SignMessageNext(final, query) reported a zero-length signature")
		}

		// SignFinal caches its result but is not finalized until a caller
		// copies the bytes out (see signMessageBeginNextViaC's comment); the
		// query call above never does, so the sign operation is still active
		// and must be torn down before the next subtest's C_MessageSignInit.
		_ = messageFinalViaC(t, C_MessageSignFinal, session)
	})

	t.Run("buffer too small", func(t *testing.T) {
		if rv := messageInitViaC(t, C_MessageSignInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), priv); rv != module.CKR_OK {
			t.Fatalf("C_MessageSignInit = %s, want CKR_OK", rv)
		}
		fn := reflect.ValueOf(C_SignMessageNext)
		ft := fn.Type()
		undersized := make([]byte, 1)
		smallLen := reflect.New(ft.In(6).Elem())
		smallLen.Elem().SetUint(1)
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			reflect.Zero(ft.In(1)),
			scalarOf(ft, 2, 0),
			setBufferPtr(data, ft, 3),
			scalarOf(ft, 4, uint64(len(data))),
			setBufferPtr(undersized, ft, 5),
			smallLen,
		})
		runtime.KeepAlive(data)
		runtime.KeepAlive(undersized)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
			t.Fatalf("C_SignMessageNext(final, 1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
		}
		if got := smallLen.Elem().Uint(); got != 256 {
			t.Fatalf("C_SignMessageNext(undersized) reported required length %d, want 256", got)
		}
	})
}

// TestCVerifyMessageFamily_NonNilParamIsRefused proves C_VerifyMessage,
// C_VerifyMessageBegin and C_VerifyMessageNext each refuse a per-message
// parameter through their shared rejectSignMessageParam check, for the
// reason TestCSignMessageBegin_NonNilParamIsRefused gives on the sign side.
func TestCVerifyMessageFamily_NonNilParamIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	if rv := messageInitViaC(t, C_MessageVerifyInit, session, buildCMechanism(module.CKM_SHA256_RSA_PKCS), pub); rv != module.CKR_OK {
		t.Fatalf("C_MessageVerifyInit = %s, want CKR_OK", rv)
	}
	data := []byte("some data")
	signature := func() []byte {
		if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
		}
		return signViaC(t, session, data)
	}()
	param := []byte{0x01}

	t.Run("C_VerifyMessage", func(t *testing.T) {
		fn := reflect.ValueOf(C_VerifyMessage)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cPtr(unsafe.Pointer(&param[0]), ft, 1),
			scalarOf(ft, 2, uint64(len(param))),
			setBufferPtr(data, ft, 3),
			scalarOf(ft, 4, uint64(len(data))),
			setBufferPtr(signature, ft, 5),
			scalarOf(ft, 6, uint64(len(signature))),
		})
		runtime.KeepAlive(param)
		runtime.KeepAlive(data)
		runtime.KeepAlive(signature)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_VerifyMessage(non-NULL pParameter) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("C_VerifyMessageBegin", func(t *testing.T) {
		fn := reflect.ValueOf(C_VerifyMessageBegin)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cPtr(unsafe.Pointer(&param[0]), ft, 1),
			scalarOf(ft, 2, uint64(len(param))),
		})
		runtime.KeepAlive(param)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_VerifyMessageBegin(non-NULL pParameter) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})

	t.Run("C_VerifyMessageNext", func(t *testing.T) {
		fn := reflect.ValueOf(C_VerifyMessageNext)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cPtr(unsafe.Pointer(&param[0]), ft, 1),
			scalarOf(ft, 2, uint64(len(param))),
			setBufferPtr(data, ft, 3),
			scalarOf(ft, 4, uint64(len(data))),
			setBufferPtr(signature, ft, 5),
			scalarOf(ft, 6, uint64(len(signature))),
		})
		runtime.KeepAlive(param)
		runtime.KeepAlive(data)
		runtime.KeepAlive(signature)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_VerifyMessageNext(non-NULL pParameter) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})
}

// TestCEncryptMessage_QueryModeAndMalformedParam covers C_EncryptMessage's
// pCiphertext=NULL length-query leg and a malformed CK_GCM_MESSAGE_PARAMS,
// neither of which TestCEncryptMessage_BufferTooSmall's real-buffer call
// reaches.
func TestCEncryptMessage_QueryModeAndMalformedParam(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-encrypt-querymode-aes")

	t.Run("query mode", func(t *testing.T) {
		mechBuf, gcmParams := messageAESGCMMechanism()
		if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
		}
		runtime.KeepAlive(gcmParams)

		plaintext := []byte("plaintext for the query-mode probe")
		fn := reflect.ValueOf(C_EncryptMessage)
		ft := fn.Type()
		queryLen := reflect.New(ft.In(8).Elem())
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			reflect.Zero(ft.In(1)),
			scalarOf(ft, 2, 0),
			reflect.Zero(ft.In(3)),
			scalarOf(ft, 4, 0),
			setBufferPtr(plaintext, ft, 5),
			scalarOf(ft, 6, uint64(len(plaintext))),
			reflect.Zero(ft.In(7)),
			queryLen,
		})
		runtime.KeepAlive(plaintext)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_EncryptMessage(pCiphertext=NULL) = %s, want CKR_OK", rv)
		}
		if got := queryLen.Elem().Uint(); got != uint64(len(plaintext)+16) {
			t.Fatalf("C_EncryptMessage(query) reported length %d, want %d", got, len(plaintext)+16)
		}
		// The query leg above releases the cached result but does not
		// finalize the message-based process, so it must be torn down
		// before the next subtest's C_MessageEncryptInit.
		_ = messageFinalViaC(t, C_MessageEncryptFinal, session)
	})

	t.Run("malformed mechanism-parameter", func(t *testing.T) {
		mechBuf, gcmParams := messageAESGCMMechanism()
		if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
		}
		runtime.KeepAlive(gcmParams)

		plaintext := []byte("plaintext")
		shortParam := make([]byte, 4) // CK_GCM_MESSAGE_PARAMS is 48 bytes.
		fn := reflect.ValueOf(C_EncryptMessage)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cPtr(unsafe.Pointer(&shortParam[0]), ft, 1),
			scalarOf(ft, 2, uint64(len(shortParam))),
			reflect.Zero(ft.In(3)),
			scalarOf(ft, 4, 0),
			setBufferPtr(plaintext, ft, 5),
			scalarOf(ft, 6, uint64(len(plaintext))),
			reflect.Zero(ft.In(7)),
			allocOf(ft, 8),
		})
		runtime.KeepAlive(plaintext)
		runtime.KeepAlive(shortParam)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_EncryptMessage(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})
}

// TestCDecryptMessage_QueryModeAndMalformedParam mirrors
// TestCEncryptMessage_QueryModeAndMalformedParam for C_DecryptMessage.
func TestCDecryptMessage_QueryModeAndMalformedParam(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-decrypt-querymode-aes")
	plaintext := []byte("plaintext for the decrypt query-mode probe")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	t.Run("query mode", func(t *testing.T) {
		mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
		if rv := messageInitViaC(t, C_MessageDecryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
		}

		fn := reflect.ValueOf(C_DecryptMessage)
		ft := fn.Type()
		queryLen := reflect.New(ft.In(8).Elem())
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			reflect.Zero(ft.In(1)),
			scalarOf(ft, 2, 0),
			reflect.Zero(ft.In(3)),
			scalarOf(ft, 4, 0),
			setBufferPtr(ciphertext, ft, 5),
			scalarOf(ft, 6, uint64(len(ciphertext))),
			reflect.Zero(ft.In(7)),
			queryLen,
		})
		runtime.KeepAlive(ciphertext)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
			t.Fatalf("C_DecryptMessage(pPlaintext=NULL) = %s, want CKR_OK", rv)
		}
		if got := queryLen.Elem().Uint(); got != uint64(len(plaintext)) {
			t.Fatalf("C_DecryptMessage(query) reported length %d, want %d", got, len(plaintext))
		}
		// See the parallel comment in
		// TestCEncryptMessage_QueryModeAndMalformedParam.
		_ = messageFinalViaC(t, C_MessageDecryptFinal, session)
	})

	t.Run("malformed mechanism-parameter", func(t *testing.T) {
		mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
		if rv := messageInitViaC(t, C_MessageDecryptInit, session, mechBuf, key); rv != module.CKR_OK {
			t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
		}

		shortParam := make([]byte, 4)
		fn := reflect.ValueOf(C_DecryptMessage)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(session)),
			cPtr(unsafe.Pointer(&shortParam[0]), ft, 1),
			scalarOf(ft, 2, uint64(len(shortParam))),
			reflect.Zero(ft.In(3)),
			scalarOf(ft, 4, 0),
			setBufferPtr(ciphertext, ft, 5),
			scalarOf(ft, 6, uint64(len(ciphertext))),
			reflect.Zero(ft.In(7)),
			allocOf(ft, 8),
		})
		runtime.KeepAlive(ciphertext)
		runtime.KeepAlive(shortParam)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_DecryptMessage(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})
}

// TestCEncryptMessageBegin_MalformedParamIsRefused proves a
// CK_GCM_MESSAGE_PARAMS shorter than the structure requires is refused with
// CKR_MECHANISM_PARAM_INVALID.
func TestCEncryptMessageBegin_MalformedParamIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-encryptbegin-malformed-aes")
	mechBuf, gcmParams := messageAESGCMMechanism()
	if rv := messageInitViaC(t, C_MessageEncryptInit, session, mechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageEncryptInit = %s, want CKR_OK", rv)
	}
	runtime.KeepAlive(gcmParams)

	shortParam := make([]byte, 4)
	fn := reflect.ValueOf(C_EncryptMessageBegin)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cPtr(unsafe.Pointer(&shortParam[0]), ft, 1),
		scalarOf(ft, 2, uint64(len(shortParam))),
		reflect.Zero(ft.In(3)),
		scalarOf(ft, 4, 0),
	})
	runtime.KeepAlive(shortParam)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_EncryptMessageBegin(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}

// TestCDecryptMessageBegin_MalformedParamIsRefused mirrors
// TestCEncryptMessageBegin_MalformedParamIsRefused for
// C_DecryptMessageBegin.
func TestCDecryptMessageBegin_MalformedParamIsRefused(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "message-decryptbegin-malformed-aes")
	mechBuf := buildCMechanismWithParam(module.CKM_AES_GCM, buildGCMParams(gcmRoundTripIV, 96, nil, 128))
	if rv := messageInitViaC(t, C_MessageDecryptInit, session, mechBuf, key); rv != module.CKR_OK {
		t.Fatalf("C_MessageDecryptInit = %s, want CKR_OK", rv)
	}

	shortParam := make([]byte, 4)
	fn := reflect.ValueOf(C_DecryptMessageBegin)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cPtr(unsafe.Pointer(&shortParam[0]), ft, 1),
		scalarOf(ft, 2, uint64(len(shortParam))),
		reflect.Zero(ft.In(3)),
		scalarOf(ft, 4, 0),
	})
	runtime.KeepAlive(shortParam)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_DecryptMessageBegin(short CK_GCM_MESSAGE_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}
