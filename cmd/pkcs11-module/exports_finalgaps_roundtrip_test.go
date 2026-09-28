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

// Tests for the C_Decrypt and C_WrapKey two-call-idiom branches
// (pOutput=NULL query mode, CKR_BUFFER_TOO_SMALL) and malformed-mechanism
// rejection that exports_cryptoroundtrip_test.go's single-call helpers do
// not exercise, since decryptViaC/the wrap round trip there always supply a
// generously sized real buffer on the first call.

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// TestCDecrypt_QueryModeAndBufferTooSmall proves C_Decrypt's two-call idiom:
// a NULL pData query reports the real plaintext length, and an undersized
// real buffer is refused with CKR_BUFFER_TOO_SMALL rather than a partial
// copy.
func TestCDecrypt_QueryModeAndBufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "decrypt-querymode-aes")

	plaintext := []byte("plaintext for the C_Decrypt two-call idiom probe")
	ciphertext := encryptOnceViaC(t, session, key, gcmRoundTripIV, plaintext)

	decryptMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	if rv := decryptInitViaC(t, session, key, decryptMechBuf); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}

	fn := reflect.ValueOf(C_Decrypt)
	ft := fn.Type()
	queryLen := reflect.New(ft.In(4).Elem())
	qout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(ciphertext, ft, 1),
		scalarOf(ft, 2, uint64(len(ciphertext))),
		reflect.Zero(ft.In(3)),
		queryLen,
	})
	runtime.KeepAlive(ciphertext)
	if rv := module.CK_RV(qout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_Decrypt(pData=NULL) = %s, want CKR_OK", rv)
	}
	if got := queryLen.Elem().Uint(); got != uint64(len(plaintext)) {
		t.Fatalf("C_Decrypt(query) reported length %d, want %d", got, len(plaintext))
	}

	// The query leg above does not call FinishOperation (only a real-buffer
	// copy does, mirroring every other two-call entry point in this
	// package), so the decrypt operation is still active with its result
	// cached: no second C_DecryptInit is needed before the undersized-buffer
	// leg below.
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(4).Elem())
	smallLen.Elem().SetUint(1)
	sout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(ciphertext, ft, 1),
		scalarOf(ft, 2, uint64(len(ciphertext))),
		setBufferPtr(undersized, ft, 3),
		smallLen,
	})
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(sout[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_Decrypt(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := smallLen.Elem().Uint(); got != uint64(len(plaintext)) {
		t.Fatalf("C_Decrypt(undersized) reported required length %d, want %d", got, len(plaintext))
	}
}

// TestCWrapKey_QueryModeAndBufferTooSmall proves C_WrapKey's two-call
// idiom, mirroring TestCDecrypt_QueryModeAndBufferTooSmall.
func TestCWrapKey_QueryModeAndBufferTooSmall(t *testing.T) {
	_, session := newCryptoFixture(t)
	wrappingKey := generateAESKeyViaC(t, session, "wrapkey-querymode-wrapping")
	targetKey := generateAESKeyViaC(t, session, "wrapkey-querymode-target")

	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	fn := reflect.ValueOf(C_WrapKey)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(5).Elem())
	qout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(wrappingKey)),
		scalarOf(ft, 3, uint64(targetKey)),
		reflect.Zero(ft.In(4)),
		queryLen,
	})
	if rv := module.CK_RV(qout[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_WrapKey(pWrappedKey=NULL) = %s, want CKR_OK", rv)
	}
	required := queryLen.Elem().Uint()
	if required == 0 {
		t.Fatal("C_WrapKey(query) reported a zero-length wrapped key")
	}

	// A fresh mechanism buffer (and its own IV) for the undersized retry:
	// module_authwrap.go's guardGCMNonce doc comment (quoted in
	// exports_cryptoroundtrip_test.go) explains why the same (key, IV) pair
	// cannot be reused for a second real wrap.
	undersizedMechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, []byte("wrapkey-iv-2"), 96, nil, 128))
	undersized := make([]byte, 1)
	smallLen := reflect.New(ft.In(5).Elem())
	smallLen.Elem().SetUint(1)
	sout := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(undersizedMechBuf, ft, 1),
		scalarOf(ft, 2, uint64(wrappingKey)),
		scalarOf(ft, 3, uint64(targetKey)),
		setBufferPtr(undersized, ft, 4),
		smallLen,
	})
	runtime.KeepAlive(undersized)
	if rv := module.CK_RV(sout[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_WrapKey(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := smallLen.Elem().Uint(); got != required {
		t.Fatalf("C_WrapKey(undersized) reported required length %d, want %d", got, required)
	}
}

// TestCWrapKey_MalformedMechanismParamIsRefused proves a CK_GCM_PARAMS
// shorter than the structure requires is refused with
// CKR_MECHANISM_PARAM_INVALID by convertCMechanismToGo, before any key
// lookup.
func TestCWrapKey_MalformedMechanismParamIsRefused(t *testing.T) {
	f := newTestFixture(t)

	shortParam := make([]byte, 4) // CK_GCM_PARAMS is larger than 4 bytes.
	mechBuf := buildCMechanismWithParam(t, module.CKM_AES_GCM, shortParam)

	fn := reflect.ValueOf(C_WrapKey)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(f.privKey)),
		scalarOf(ft, 3, uint64(f.privKey)),
		reflect.Zero(ft.In(4)),
		allocOf(ft, 5),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_WrapKey(short CK_GCM_PARAMS) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}
