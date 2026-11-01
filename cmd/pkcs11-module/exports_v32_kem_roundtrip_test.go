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

// Round-trip tests for the ML-KEM success paths of C_EncapsulateKey and
// C_DecapsulateKey (PKCS#11 v3.2 §5.18.8/§5.18.9), plus the
// CKR_BUFFER_TOO_SMALL, wrong-mechanism, wrong-key-type and not-logged-in
// error paths exports_v32_kem_wrap_test.go's NULL-argument checks do not
// reach.
//
// Unlike the RSA/AES/HKDF paths in exports_cryptoroundtrip_test.go, ML-KEM key
// generation and the KEM operations themselves never call the backend
// transport at all: module_keygen_quantum.go and module_kem.go both run
// entirely in-process against the QuantumCryptoManager (see their package
// comments). So this file drives the C ABI over the same offlineTransport
// fixture (newTestFixture) the argument-marshalling tests use rather than
// pkcs11test.CryptoMockClient -- a real ML-KEM operation here would panic
// against CryptoMockClient no more than against offlineTransport, since
// neither is ever consulted.
//
// buildCAttributeArray's CK_ATTRIBUTE.pValue is written with putPtr, which
// stores the address as a bare uint64 (exports_template_test.go /
// exports_mechdecode_test.go). putPtr pins the memory that address points
// into for the rest of the test (runtime.Pinner, unpinned via t.Cleanup), so
// the attribute *value* backing arrays stay reachable regardless of how long
// the built template remains in use -- this once had to be enforced by hand
// with runtime.KeepAlive on every source []module.Attribute slice, which is
// exactly the fragile, easy-to-miss pattern that let a real bug through here
// (C_EncapsulateKey returning CKR_ATTRIBUTE_VALUE_INVALID because a decoded
// attribute value had been silently overwritten between construction and
// use, most likely because ML-KEM-768's key generation is by far the largest
// allocation any fixture in this package makes, giving the collector a
// window the smaller fixtures don't); see #1197.

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// mlkemSharedSecretEntries is the attribute set for the shared secret object
// C_EncapsulateKey/C_DecapsulateKey create, mirroring pkg/pkcs11/module's own
// mlkemKeyGenTemplate fixtures. Returned as the source []module.Attribute
// slice (not just the built buffer) so callers can keep it alive; see this
// file's package comment.
func mlkemSharedSecretEntries() []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_GENERIC_SECRET)),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	}
}

// mlkemKeyGenEntries builds one half of a C_GenerateKeyPair template's
// attribute set for the given ML-KEM parameter set.
func mlkemKeyGenEntries(parameterSet module.ParameterSetType, class module.ObjectClass, label string) []module.Attribute {
	entries := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(class)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewUint32Attribute(module.CKA_PARAMETER_SET, uint32(parameterSet)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
	}
	if class == module.CKO_PUBLIC_KEY {
		return append(entries, module.NewBoolAttribute(module.CKA_ENCAPSULATE, true))
	}
	return append(entries,
		module.NewBoolAttribute(module.CKA_DECAPSULATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	)
}

// generateMLKEMKeyPairViaC drives C_GenerateKeyPair with CKM_ML_KEM_KEY_PAIR_GEN
// for the given parameter set and returns the public and private handles.
func generateMLKEMKeyPairViaC(t *testing.T, session module.SessionHandle, parameterSet module.ParameterSetType) (pub, priv module.ObjectHandle) {
	t.Helper()

	mechBuf := buildCMechanism(module.CKM_ML_KEM_KEY_PAIR_GEN)
	pubEntries := mlkemKeyGenEntries(parameterSet, module.CKO_PUBLIC_KEY, "mlkem-roundtrip-pub")
	privEntries := mlkemKeyGenEntries(parameterSet, module.CKO_PRIVATE_KEY, "mlkem-roundtrip-priv")
	pubTemplate := buildCAttributeArray(t, pubEntries)
	privTemplate := buildCAttributeArray(t, privEntries)

	fn := reflect.ValueOf(C_GenerateKeyPair)
	ft := fn.Type()
	args := []reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		cAttributePtr(pubTemplate, ft, 2),
		scalarOf(ft, 3, attrCount(pubTemplate)),
		cAttributePtr(privTemplate, ft, 4),
		scalarOf(ft, 5, attrCount(privTemplate)),
		allocOf(ft, 6),
		allocOf(ft, 7),
	}
	out := fn.Call(args)

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair(ML-KEM) = %s, want CKR_OK", rv)
	}
	return handleOf(args[6]), handleOf(args[7])
}

// encapsulateKeyViaC drives C_EncapsulateKey's two-call idiom (a NULL
// pCiphertext length query, then the real call), returning the created shared
// secret handle and the ciphertext.
func encapsulateKeyViaC(t *testing.T, session module.SessionHandle, pub module.ObjectHandle, mechBuf []byte) (module.ObjectHandle, []byte, module.CK_RV) {
	t.Helper()

	fn := reflect.ValueOf(C_EncapsulateKey)
	ft := fn.Type()
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	queryLen := reflect.New(ft.In(6).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		reflect.Zero(ft.In(5)),
		queryLen,
		allocOf(ft, 7),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		return module.ObjectHandle(module.InvalidHandle), nil, rv
	}

	ctBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(6).Elem())
	fillLen.Elem().SetUint(uint64(len(ctBuf)))
	keyOut := allocOf(ft, 7)
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		setBufferPtr(ctBuf, ft, 5),
		fillLen,
		keyOut,
	})
	runtime.KeepAlive(ctBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return module.ObjectHandle(module.InvalidHandle), nil, rv
	}
	return handleOf(keyOut), ctBuf[:fillLen.Elem().Uint()], module.CKR_OK
}

// decapsulateKeyViaC drives C_DecapsulateKey with a genuine ciphertext.
func decapsulateKeyViaC(t *testing.T, session module.SessionHandle, priv module.ObjectHandle, mechBuf, ciphertext []byte) (module.ObjectHandle, module.CK_RV) {
	t.Helper()

	fn := reflect.ValueOf(C_DecapsulateKey)
	ft := fn.Type()
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	keyOut := allocOf(ft, 7)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(priv)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		setBufferPtr(ciphertext, ft, 5),
		scalarOf(ft, 6, uint64(len(ciphertext))),
		keyOut,
	})
	runtime.KeepAlive(ciphertext)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return module.ObjectHandle(module.InvalidHandle), rv
	}
	return handleOf(keyOut), module.CKR_OK
}

// secretValueViaC reads CKA_VALUE off a shared secret object through the
// module's own Go API, the same oracle module_mlkem512_test.go's
// secretValueOf uses.
func secretValueViaC(t *testing.T, m *module.Module, session module.SessionHandle, handle module.ObjectHandle) []byte {
	t.Helper()
	attrs, rv := m.GetAttributeValue(session, handle, []module.Attribute{{Type: module.CKA_VALUE}})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(CKA_VALUE) = %s, want CKR_OK", rv)
	}
	return attrs[0].Value
}

// TestMLKEMEncapsulateDecapsulate_RoundTrip proves the cgo boundary carries a
// real ML-KEM-768 ciphertext and that C_EncapsulateKey/C_DecapsulateKey agree
// on the shared secret they produce -- the property KEM exists to provide.
func TestMLKEMEncapsulateDecapsulate_RoundTrip(t *testing.T) {
	f := newTestFixture(t)
	pub, priv := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)

	mechBuf := buildCMechanism(module.CKM_ML_KEM)
	encapsulatedHandle, ciphertext, rv := encapsulateKeyViaC(t, f.session, pub, mechBuf)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncapsulateKey = %s, want CKR_OK", rv)
	}
	if len(ciphertext) != module.MLKEM768CiphertextSize {
		t.Fatalf("C_EncapsulateKey ciphertext is %d bytes, want %d", len(ciphertext), module.MLKEM768CiphertextSize)
	}

	decapsulatedHandle, rv := decapsulateKeyViaC(t, f.session, priv, mechBuf, ciphertext)
	if rv != module.CKR_OK {
		t.Fatalf("C_DecapsulateKey = %s, want CKR_OK", rv)
	}

	encapsulatedSecret := secretValueViaC(t, f.m, f.session, encapsulatedHandle)
	decapsulatedSecret := secretValueViaC(t, f.m, f.session, decapsulatedHandle)
	if len(encapsulatedSecret) != module.MLKEM768SharedSecretSize {
		t.Fatalf("encapsulated shared secret is %d bytes, want %d", len(encapsulatedSecret), module.MLKEM768SharedSecretSize)
	}
	if !bytes.Equal(encapsulatedSecret, decapsulatedSecret) {
		t.Fatalf("C_EncapsulateKey and C_DecapsulateKey disagree on the shared secret\n got %x\nwant %x",
			decapsulatedSecret, encapsulatedSecret)
	}

	t.Run("tampered ciphertext decapsulates to a different secret", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0xFF

		tamperedHandle, rv := decapsulateKeyViaC(t, f.session, priv, mechBuf, tampered)
		if rv != module.CKR_OK {
			t.Fatalf("C_DecapsulateKey(tampered ciphertext) = %s, want CKR_OK: ML-KEM decapsulation has no "+
				"authentication tag to reject a corrupted ciphertext with, it silently returns the wrong secret", rv)
		}
		tamperedSecret := secretValueViaC(t, f.m, f.session, tamperedHandle)
		if bytes.Equal(tamperedSecret, encapsulatedSecret) {
			t.Fatal("a tampered ciphertext decapsulated to the same shared secret as the genuine one")
		}
	})
}

// TestCEncapsulateKey_BufferTooSmall proves the two-call idiom's
// CKR_BUFFER_TOO_SMALL leg reports the real ciphertext size for a genuine
// ML-KEM key, not merely a fixed placeholder.
func TestCEncapsulateKey_BufferTooSmall(t *testing.T) {
	f := newTestFixture(t)
	pub, _ := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)
	mechBuf := buildCMechanism(module.CKM_ML_KEM)
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	fn := reflect.ValueOf(C_EncapsulateKey)
	ft := fn.Type()

	undersized := make([]byte, 1)
	fillLen := reflect.New(ft.In(6).Elem())
	fillLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		setBufferPtr(undersized, ft, 5),
		fillLen,
		allocOf(ft, 7),
	})
	runtime.KeepAlive(undersized)

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_EncapsulateKey(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := fillLen.Elem().Uint(); got != uint64(module.MLKEM768CiphertextSize) {
		t.Fatalf("C_EncapsulateKey(undersized) reported required length %d, want %d", got, module.MLKEM768CiphertextSize)
	}
}

// TestCEncapsulateKey_WrongMechanismIsRefused proves a mechanism that does
// not support encapsulation (an ordinary symmetric-key mechanism) is refused
// with CKR_MECHANISM_INVALID rather than reaching the KEM dispatch.
func TestCEncapsulateKey_WrongMechanismIsRefused(t *testing.T) {
	f := newTestFixture(t)
	pub, _ := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)
	mechBuf := buildCMechanism(module.CKM_AES_KEY_GEN)
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	fn := reflect.ValueOf(C_EncapsulateKey)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		reflect.Zero(ft.In(5)),
		allocOf(ft, 6),
		allocOf(ft, 7),
	})

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_INVALID {
		t.Fatalf("C_EncapsulateKey(CKM_AES_KEY_GEN) = %s, want CKR_MECHANISM_INVALID", rv)
	}
}

// TestCEncapsulateKey_WrongKeyTypeIsRefused proves a public key created
// without CKA_ENCAPSULATE is refused with CKR_KEY_FUNCTION_NOT_PERMITTED, which
// v3.2 §5.1.6 defines as a key used for a purpose its attributes do not allow
// (§5.1.7 permits it although the §5.18.8 return table omits it).
func TestCEncapsulateKey_WrongKeyTypeIsRefused(t *testing.T) {
	f := newTestFixture(t)

	mechBuf := buildCMechanism(module.CKM_ML_KEM_KEY_PAIR_GEN)
	pubEntries := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewUint32Attribute(module.CKA_PARAMETER_SET, uint32(module.CKP_ML_KEM_768)),
		module.NewStringAttribute(module.CKA_LABEL, "mlkem-no-encapsulate-pub"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		// CKA_ENCAPSULATE is deliberately omitted (defaults to false).
	}
	privEntries := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_ML_KEM)),
		module.NewUint32Attribute(module.CKA_PARAMETER_SET, uint32(module.CKP_ML_KEM_768)),
		module.NewStringAttribute(module.CKA_LABEL, "mlkem-no-encapsulate-priv"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_DECAPSULATE, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	}
	pubTemplate := buildCAttributeArray(t, pubEntries)
	privTemplate := buildCAttributeArray(t, privEntries)

	genFn := reflect.ValueOf(C_GenerateKeyPair)
	gft := genFn.Type()
	genArgs := []reflect.Value{
		scalarOf(gft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, gft, 1),
		cAttributePtr(pubTemplate, gft, 2),
		scalarOf(gft, 3, attrCount(pubTemplate)),
		cAttributePtr(privTemplate, gft, 4),
		scalarOf(gft, 5, attrCount(privTemplate)),
		allocOf(gft, 6),
		allocOf(gft, 7),
	}
	genOut := genFn.Call(genArgs)
	if rv := module.CK_RV(genOut[0].Uint()); rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair(no CKA_ENCAPSULATE) = %s, want CKR_OK", rv)
	}
	pub := handleOf(genArgs[6])

	kemMechBuf := buildCMechanism(module.CKM_ML_KEM)
	sharedEntries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, sharedEntries)
	encFn := reflect.ValueOf(C_EncapsulateKey)
	eft := encFn.Type()
	out := encFn.Call([]reflect.Value{
		scalarOf(eft, 0, uint64(f.session)),
		cMechanismPtr(kemMechBuf, eft, 1),
		scalarOf(eft, 2, uint64(pub)),
		cAttributePtr(template, eft, 3),
		scalarOf(eft, 4, attrCount(template)),
		reflect.Zero(eft.In(5)),
		allocOf(eft, 6),
		allocOf(eft, 7),
	})

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Fatalf("C_EncapsulateKey(no CKA_ENCAPSULATE) = %s, want CKR_KEY_FUNCTION_NOT_PERMITTED", rv)
	}
}

// TestCEncapsulateKey_NotLoggedInIsRefused proves C_EncapsulateKey enforces
// the token's CKF_LOGIN_REQUIRED the same way C_WrapKey does: a session that
// has logged out is refused before the KEM dispatch runs.
func TestCEncapsulateKey_NotLoggedInIsRefused(t *testing.T) {
	f := newTestFixture(t)
	pub, _ := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)

	if rv := f.m.Logout(f.session); rv != module.CKR_OK {
		t.Fatalf("Logout: %s", rv)
	}

	mechBuf := buildCMechanism(module.CKM_ML_KEM)
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)
	fn := reflect.ValueOf(C_EncapsulateKey)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		reflect.Zero(ft.In(5)),
		allocOf(ft, 6),
		allocOf(ft, 7),
	})

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("C_EncapsulateKey(logged out) = %s, want CKR_USER_NOT_LOGGED_IN", rv)
	}
}

// TestCDecapsulateKey_WrongKeyTypeIsRefused mirrors
// TestCEncapsulateKey_WrongKeyTypeIsRefused for the private-key half: a
// private key created without CKA_DECAPSULATE is refused with
// CKR_KEY_FUNCTION_NOT_PERMITTED (v3.2 §5.1.6, §5.1.7, §5.18.9).
func TestCDecapsulateKey_WrongKeyTypeIsRefused(t *testing.T) {
	f := newTestFixture(t)
	pub, priv := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)
	mechBuf := buildCMechanism(module.CKM_ML_KEM)

	// SetAttributeValue turns off CKA_DECAPSULATE on the generated private
	// key: building a bespoke C_CreateObject/C_GenerateKeyPair template would
	// need private key material CreateObject cannot forge for ML-KEM, whereas
	// SetAttributeValue reaches the field CreateObject's computedAttributes
	// guard does not protect.
	rv := f.m.SetAttributeValue(f.session, priv, []module.Attribute{
		module.NewBoolAttribute(module.CKA_DECAPSULATE, false),
	})
	if rv != module.CKR_OK {
		t.Fatalf("SetAttributeValue(CKA_DECAPSULATE=false): %s", rv)
	}

	_, ciphertext, rv := encapsulateKeyViaC(t, f.session, pub, mechBuf)
	if rv != module.CKR_OK {
		t.Fatalf("C_EncapsulateKey (fixture ciphertext): %s", rv)
	}

	_, rv = decapsulateKeyViaC(t, f.session, priv, mechBuf, ciphertext)
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Fatalf("C_DecapsulateKey(CKA_DECAPSULATE=false) = %s, want CKR_KEY_FUNCTION_NOT_PERMITTED", rv)
	}
}

// TestCEncapsulateKey_MalformedMechanismParamIsRefused proves a malformed
// mechanism parameter is refused by convertCMechanismToGo before
// KEMCiphertextSize is ever consulted.
func TestCEncapsulateKey_MalformedMechanismParamIsRefused(t *testing.T) {
	f := newTestFixture(t)
	pub, _ := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)

	// CKM_RSA_PKCS_OAEP requires a CK_RSA_PKCS_OAEP_PARAMS; a 1-byte
	// parameter is short for any registered mechanism parameter.
	shortParam := []byte{0x01}
	mechBuf := buildCMechanismWithParam(t, module.CKM_RSA_PKCS_OAEP, shortParam)
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	fn := reflect.ValueOf(C_EncapsulateKey)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(f.session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(pub)),
		cAttributePtr(template, ft, 3),
		scalarOf(ft, 4, attrCount(template)),
		reflect.Zero(ft.In(5)),
		allocOf(ft, 6),
		allocOf(ft, 7),
	})
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("C_EncapsulateKey(short OAEP params) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
	}
}

// TestCDecapsulateKey_ArgumentValidation covers C_DecapsulateKey's
// argument-marshalling branches past NULL pMechanism/phKey
// (exports_v32_kem_wrap_test.go): a NULL pCiphertext with a nonzero
// declared length, and a malformed mechanism parameter.
func TestCDecapsulateKey_ArgumentValidation(t *testing.T) {
	f := newTestFixture(t)
	_, priv := generateMLKEMKeyPairViaC(t, f.session, module.CKP_ML_KEM_768)
	entries := mlkemSharedSecretEntries()
	template := buildCAttributeArray(t, entries)

	t.Run("NULL ciphertext with nonzero length", func(t *testing.T) {
		mechBuf := buildCMechanism(module.CKM_ML_KEM)
		fn := reflect.ValueOf(C_DecapsulateKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(priv)),
			cAttributePtr(template, ft, 3),
			scalarOf(ft, 4, attrCount(template)),
			reflect.Zero(ft.In(5)),
			scalarOf(ft, 6, 16),
			allocOf(ft, 7),
		})
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_ARGUMENTS_BAD {
			t.Fatalf("C_DecapsulateKey(pCiphertext=NULL, len=16) = %s, want CKR_ARGUMENTS_BAD", rv)
		}
	})

	t.Run("malformed mechanism param", func(t *testing.T) {
		shortParam := []byte{0x01}
		mechBuf := buildCMechanismWithParam(t, module.CKM_RSA_PKCS_OAEP, shortParam)
		ciphertext := make([]byte, module.MLKEM768CiphertextSize)
		fn := reflect.ValueOf(C_DecapsulateKey)
		ft := fn.Type()
		out := fn.Call([]reflect.Value{
			scalarOf(ft, 0, uint64(f.session)),
			cMechanismPtr(mechBuf, ft, 1),
			scalarOf(ft, 2, uint64(priv)),
			cAttributePtr(template, ft, 3),
			scalarOf(ft, 4, attrCount(template)),
			setBufferPtr(ciphertext, ft, 5),
			scalarOf(ft, 6, uint64(len(ciphertext))),
			allocOf(ft, 7),
		})
		runtime.KeepAlive(ciphertext)
		if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_MECHANISM_PARAM_INVALID {
			t.Fatalf("C_DecapsulateKey(short OAEP params) = %s, want CKR_MECHANISM_PARAM_INVALID", rv)
		}
	})
}
