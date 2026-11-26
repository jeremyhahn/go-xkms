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

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// callWithOutput calls fn with the leading arguments in, then buf and a
// length set to len(buf), and returns the call's CK_RV and the length it
// wrote back.
func callWithOutput(fn any, in []reflect.Value, buf []byte) (module.CK_RV, uint64) {
	fv := reflect.ValueOf(fn)
	ft := fv.Type()
	n := ft.NumIn()
	outLen := reflect.New(ft.In(n - 1).Elem())
	outLen.Elem().SetUint(uint64(len(buf)))
	out := fv.Call(append(in, setBufferPtr(buf, ft, n-2), outLen))
	runtime.KeepAlive(buf)
	return module.CK_RV(out[0].Uint()), outLen.Elem().Uint()
}

// TestSign_BufferTooSmallKeepsTheOperation pins PKCS#11 v3.2 §5.2 for the
// single-part and multi-part signature: a buffer too small for the signature
// answers CKR_BUFFER_TOO_SMALL with the required length, and leaves the
// operation active so the retry with a large enough buffer returns the same
// signature an uninterrupted call does.
func TestSign_BufferTooSmallKeepsTheOperation(t *testing.T) {
	_, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)
	data := []byte("the buffer too small answer must not end the operation")

	// RSA PKCS#1 v1.5 is deterministic, so an uninterrupted signature is the
	// oracle for the retried ones.
	if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
	}
	want := signViaC(t, session, data)

	signType := reflect.TypeOf(C_Sign)
	signUpdateType := reflect.TypeOf(C_SignUpdate)
	signFinalType := reflect.TypeOf(C_SignFinal)
	tests := []struct {
		name  string
		start func(t *testing.T)
		fn    any
		in    func() []reflect.Value
	}{
		{"C_Sign", func(t *testing.T) {}, C_Sign, func() []reflect.Value {
			return []reflect.Value{
				scalarOf(signType, 0, uint64(session)),
				setBufferPtr(data, signType, 1),
				scalarOf(signType, 2, uint64(len(data))),
			}
		}},
		{"C_SignFinal", func(t *testing.T) {
			out := reflect.ValueOf(C_SignUpdate).Call([]reflect.Value{
				scalarOf(signUpdateType, 0, uint64(session)),
				setBufferPtr(data, signUpdateType, 1),
				scalarOf(signUpdateType, 2, uint64(len(data))),
			})
			if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
				t.Fatalf("C_SignUpdate = %s, want CKR_OK", rv)
			}
		}, C_SignFinal, func() []reflect.Value {
			return []reflect.Value{scalarOf(signFinalType, 0, uint64(session))}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rv := signInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS); rv != module.CKR_OK {
				t.Fatalf("C_SignInit = %s, want CKR_OK", rv)
			}
			tt.start(t)
			sig := requireBufferTooSmallThenRetry(t, tt.name, tt.fn, tt.in, len(want))
			runtime.KeepAlive(data)
			if !bytes.Equal(sig, want) {
				t.Fatalf("%s(retry) signature differs from an uninterrupted signature", tt.name)
			}
		})
	}
}

// TestEncryptDecryptFinal_BufferTooSmallKeepsTheOperation pins PKCS#11 v3.2
// §5.2 for C_Encrypt and C_DecryptFinal: a buffer too small for the output
// answers CKR_BUFFER_TOO_SMALL with the required length, and the retries with
// large enough buffers round trip the plaintext.
func TestEncryptDecryptFinal_BufferTooSmallKeepsTheOperation(t *testing.T) {
	_, session := newCryptoFixture(t)
	key := generateAESKeyViaC(t, session, "buffer-too-small-aes")
	plaintext := []byte("a short buffer must not end the cipher operation")
	gcmMechanism := func() []byte {
		return buildCMechanismWithParam(t, module.CKM_AES_GCM, buildGCMParams(t, gcmRoundTripIV, 96, nil, 128))
	}

	// The module refuses to reuse a GCM IV under one key, so the retried
	// ciphertext is proved by decrypting it rather than by an oracle.
	encryptType := reflect.TypeOf(C_Encrypt)
	encryptIn := func() []reflect.Value {
		return []reflect.Value{
			scalarOf(encryptType, 0, uint64(session)),
			setBufferPtr(plaintext, encryptType, 1),
			scalarOf(encryptType, 2, uint64(len(plaintext))),
		}
	}
	if rv := encryptInitViaC(t, session, key, gcmMechanism()); rv != module.CKR_OK {
		t.Fatalf("C_EncryptInit = %s, want CKR_OK", rv)
	}
	ciphertext := requireBufferTooSmallThenRetry(t, "C_Encrypt", C_Encrypt, encryptIn, len(plaintext)+16)
	runtime.KeepAlive(plaintext)

	if rv := decryptInitViaC(t, session, key, gcmMechanism()); rv != module.CKR_OK {
		t.Fatalf("C_DecryptInit = %s, want CKR_OK", rv)
	}
	updateType := reflect.TypeOf(C_DecryptUpdate)
	rv, _ := callWithOutput(C_DecryptUpdate, []reflect.Value{
		scalarOf(updateType, 0, uint64(session)),
		setBufferPtr(ciphertext, updateType, 1),
		scalarOf(updateType, 2, uint64(len(ciphertext))),
	}, make([]byte, len(ciphertext)))
	runtime.KeepAlive(ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecryptUpdate = %s, want CKR_OK", rv)
	}
	finalType := reflect.TypeOf(C_DecryptFinal)
	finalIn := func() []reflect.Value {
		return []reflect.Value{scalarOf(finalType, 0, uint64(session))}
	}
	got := requireBufferTooSmallThenRetry(t, "C_DecryptFinal", C_DecryptFinal, finalIn, len(plaintext))
	if !bytes.Equal(got, plaintext) {
		t.Fatal("the retried C_Encrypt and C_DecryptFinal outputs do not round trip the plaintext")
	}
}

// requireBufferTooSmallThenRetry calls fn with a 1-byte output buffer, which
// must answer CKR_BUFFER_TOO_SMALL with wantLen, then retries with a buffer of
// that length, which must answer CKR_OK. It returns the retry's output.
func requireBufferTooSmallThenRetry(t *testing.T, name string, fn any, in func() []reflect.Value, wantLen int) []byte {
	t.Helper()
	rv, need := callWithOutput(fn, in(), make([]byte, 1))
	if rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("%s(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", name, rv)
	}
	if need != uint64(wantLen) {
		t.Fatalf("%s(1-byte buffer) reported %d bytes, want %d", name, need, wantLen)
	}
	out := make([]byte, need)
	rv, got := callWithOutput(fn, in(), out)
	if rv != module.CKR_OK {
		t.Fatalf("%s(retry) = %s, want CKR_OK (the operation must survive CKR_BUFFER_TOO_SMALL)", name, rv)
	}
	return out[:got]
}
