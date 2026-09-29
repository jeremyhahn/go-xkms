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

// Round-trip tests for the C_SignRecoverInit/C_SignRecover and
// C_VerifyRecoverInit/C_VerifyRecover success paths (PKCS#11 v3.2
// §5.13.5/§5.13.6, §5.15.5/§5.15.6), plus CKR_BUFFER_TOO_SMALL,
// wrong-mechanism and not-logged-in.
//
// Only CKM_RSA_PKCS and CKM_RSA_X_509 support sign/verify-recover
// (module.go's mechanismSupportsSignRecover/mechanismSupportsVerifyRecover),
// and CKM_RSA_PKCS carries the data itself inside the PKCS#1 v1.5 block with
// no digest of its own (v3.2 §6.1.3) -- pkg/testing/pkcs11test/signing.go and
// verification.go's own module-level suite use exactly this mechanism and
// exactly this property (crypto.Hash(0) as the verification oracle) to prove
// recovery, and this file drives the same mechanism and the same oracle
// through the cgo boundary rather than the Go API.

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// enableRecoverAttributes turns on CKA_SIGN_RECOVER on priv and
// CKA_VERIFY_RECOVER on pub. generateRSAKeyPairViaC's template (shared with
// exports_cryptoroundtrip_test.go's ordinary sign/verify round trips) sets
// neither, so C_SignRecoverInit/C_VerifyRecoverInit refuse the resulting keys
// with CKR_KEY_FUNCTION_NOT_PERMITTED; SetAttributeValue reaches the two
// flags this file's tests need without a bespoke template of their own.
func enableRecoverAttributes(t *testing.T, m *module.Module, session module.SessionHandle, pub, priv module.ObjectHandle) {
	t.Helper()
	if rv := m.SetAttributeValue(session, priv, []module.Attribute{
		module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true),
	}); rv != module.CKR_OK {
		t.Fatalf("SetAttributeValue(CKA_SIGN_RECOVER=true): %s", rv)
	}
	if rv := m.SetAttributeValue(session, pub, []module.Attribute{
		module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
	}); rv != module.CKR_OK {
		t.Fatalf("SetAttributeValue(CKA_VERIFY_RECOVER=true): %s", rv)
	}
}

// signRecoverInitViaC drives C_SignRecoverInit.
func signRecoverInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechType module.MechanismType) module.CK_RV {
	t.Helper()
	mechBuf := buildCMechanism(mechType)
	fn := reflect.ValueOf(C_SignRecoverInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	runtime.KeepAlive(mechBuf)
	return module.CK_RV(out[0].Uint())
}

// verifyRecoverInitViaC drives C_VerifyRecoverInit.
func verifyRecoverInitViaC(t *testing.T, session module.SessionHandle, key module.ObjectHandle, mechType module.MechanismType) module.CK_RV {
	t.Helper()
	mechBuf := buildCMechanism(mechType)
	fn := reflect.ValueOf(C_VerifyRecoverInit)
	ft := fn.Type()
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		cMechanismPtr(mechBuf, ft, 1),
		scalarOf(ft, 2, uint64(key)),
	})
	runtime.KeepAlive(mechBuf)
	return module.CK_RV(out[0].Uint())
}

// signRecoverViaC drives C_SignRecover's two-call idiom.
func signRecoverViaC(t *testing.T, session module.SessionHandle, data []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_SignRecover)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(4).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		reflect.Zero(ft.In(3)),
		queryLen,
	})
	runtime.KeepAlive(data)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	sigBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(sigBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		setBufferPtr(sigBuf, ft, 3),
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

// verifyRecoverViaC drives C_VerifyRecover's two-call idiom.
func verifyRecoverViaC(t *testing.T, session module.SessionHandle, signature []byte) ([]byte, module.CK_RV) {
	t.Helper()
	fn := reflect.ValueOf(C_VerifyRecover)
	ft := fn.Type()

	queryLen := reflect.New(ft.In(4).Elem())
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(signature, ft, 1),
		scalarOf(ft, 2, uint64(len(signature))),
		reflect.Zero(ft.In(3)),
		queryLen,
	})
	runtime.KeepAlive(signature)
	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_OK {
		return nil, rv
	}

	dataBuf := make([]byte, queryLen.Elem().Uint())
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(uint64(len(dataBuf)))
	out = fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(signature, ft, 1),
		scalarOf(ft, 2, uint64(len(signature))),
		setBufferPtr(dataBuf, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(signature)
	runtime.KeepAlive(dataBuf)
	rv := module.CK_RV(out[0].Uint())
	if rv != module.CKR_OK {
		return nil, rv
	}
	return dataBuf[:fillLen.Elem().Uint()], rv
}

// rsaPublicKeyViaC parses the DER-decoded RSA public key off pub's
// CKA_MODULUS/CKA_PUBLIC_EXPONENT, the same oracle
// exports_cryptoroundtrip_test.go's tests check signatures against.
func rsaPublicKeyViaC(t *testing.T, m *module.Module, session module.SessionHandle, pub module.ObjectHandle) *rsa.PublicKey {
	t.Helper()
	attrs, rv := m.GetAttributeValue(session, pub, []module.Attribute{
		{Type: module.CKA_MODULUS},
		{Type: module.CKA_PUBLIC_EXPONENT},
	})
	if rv != module.CKR_OK {
		t.Fatalf("GetAttributeValue(CKA_MODULUS/CKA_PUBLIC_EXPONENT) = %s, want CKR_OK", rv)
	}
	modulus := attrs[0].Value
	exponent := attrs[1].Value

	e := 0
	for _, b := range exponent {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
}

// TestRSASignRecoverVerifyRecover_RoundTrip proves the cgo boundary carries a
// real PKCS#1 v1.5 raw RSA signature through C_SignRecover, and that
// C_VerifyRecover both accepts it and recovers the exact data C_SignRecover
// was given -- checked against an independent crypto/rsa.VerifyPKCS1v15(...,
// crypto.Hash(0), ...) oracle, not merely a non-empty result.
func TestRSASignRecoverVerifyRecover_RoundTrip(t *testing.T) {
	m, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	enableRecoverAttributes(t, m, session, pub, priv)

	if rv := signRecoverInitViaC(t, session, priv, module.CKM_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignRecoverInit = %s, want CKR_OK", rv)
	}
	data := []byte("recoverable data")
	signature, rv := signRecoverViaC(t, session, data)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignRecover = %s, want CKR_OK", rv)
	}
	if len(signature) == 0 {
		t.Fatal("C_SignRecover produced an empty signature")
	}

	pubKey := rsaPublicKeyViaC(t, m, session, pub)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(0), data, signature); err != nil {
		t.Fatalf("independent rsa.VerifyPKCS1v15(crypto.Hash(0)) oracle rejected C_SignRecover's signature: %v", err)
	}

	if rv := verifyRecoverInitViaC(t, session, pub, module.CKM_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_VerifyRecoverInit = %s, want CKR_OK", rv)
	}
	recovered, rv := verifyRecoverViaC(t, session, signature)
	if rv != module.CKR_OK {
		t.Fatalf("C_VerifyRecover = %s, want CKR_OK", rv)
	}
	if string(recovered) != string(data) {
		t.Fatalf("C_VerifyRecover recovered %q, want %q", recovered, data)
	}

	t.Run("tampered signature is rejected", func(t *testing.T) {
		if rv := verifyRecoverInitViaC(t, session, pub, module.CKM_RSA_PKCS); rv != module.CKR_OK {
			t.Fatalf("C_VerifyRecoverInit = %s, want CKR_OK", rv)
		}
		tampered := append([]byte(nil), signature...)
		tampered[0] ^= 0xFF
		if _, rv := verifyRecoverViaC(t, session, tampered); rv != module.CKR_SIGNATURE_INVALID {
			t.Fatalf("C_VerifyRecover(tampered) = %s, want CKR_SIGNATURE_INVALID", rv)
		}
	})
}

// TestCSignRecover_BufferTooSmall proves C_SignRecover's two-call idiom
// reports the real RSA-2048 signature size (256 bytes) rather than a fixed
// placeholder.
func TestCSignRecover_BufferTooSmall(t *testing.T) {
	m, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	enableRecoverAttributes(t, m, session, pub, priv)
	if rv := signRecoverInitViaC(t, session, priv, module.CKM_RSA_PKCS); rv != module.CKR_OK {
		t.Fatalf("C_SignRecoverInit = %s, want CKR_OK", rv)
	}

	fn := reflect.ValueOf(C_SignRecover)
	ft := fn.Type()
	data := []byte("recoverable data")
	undersized := make([]byte, 1)
	fillLen := reflect.New(ft.In(4).Elem())
	fillLen.Elem().SetUint(1)
	out := fn.Call([]reflect.Value{
		scalarOf(ft, 0, uint64(session)),
		setBufferPtr(data, ft, 1),
		scalarOf(ft, 2, uint64(len(data))),
		setBufferPtr(undersized, ft, 3),
		fillLen,
	})
	runtime.KeepAlive(data)
	runtime.KeepAlive(undersized)

	if rv := module.CK_RV(out[0].Uint()); rv != module.CKR_BUFFER_TOO_SMALL {
		t.Fatalf("C_SignRecover(1-byte buffer) = %s, want CKR_BUFFER_TOO_SMALL", rv)
	}
	if got := fillLen.Elem().Uint(); got != 256 {
		t.Fatalf("C_SignRecover(undersized) reported required length %d, want 256", got)
	}
}

// TestCSignRecoverInit_WrongMechanismIsRefused proves a mechanism that does
// not support sign-recover (an ordinary hashed RSA signature mechanism) is
// refused with CKR_MECHANISM_INVALID.
func TestCSignRecoverInit_WrongMechanismIsRefused(t *testing.T) {
	m, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	enableRecoverAttributes(t, m, session, pub, priv)

	rv := signRecoverInitViaC(t, session, priv, module.CKM_SHA256_RSA_PKCS)
	if rv != module.CKR_MECHANISM_INVALID {
		t.Fatalf("C_SignRecoverInit(CKM_SHA256_RSA_PKCS) = %s, want CKR_MECHANISM_INVALID", rv)
	}
}

// TestCVerifyRecoverInit_WrongMechanismIsRefused mirrors
// TestCSignRecoverInit_WrongMechanismIsRefused for C_VerifyRecoverInit.
func TestCVerifyRecoverInit_WrongMechanismIsRefused(t *testing.T) {
	m, session := newCryptoFixture(t)
	pub, priv := generateRSAKeyPairViaC(t, session)
	enableRecoverAttributes(t, m, session, pub, priv)

	rv := verifyRecoverInitViaC(t, session, pub, module.CKM_SHA256_RSA_PKCS)
	if rv != module.CKR_MECHANISM_INVALID {
		t.Fatalf("C_VerifyRecoverInit(CKM_SHA256_RSA_PKCS) = %s, want CKR_MECHANISM_INVALID", rv)
	}
}

// TestCSignRecoverInit_NotLoggedInIsRefused proves C_SignRecoverInit enforces
// the token's CKF_LOGIN_REQUIRED.
func TestCSignRecoverInit_NotLoggedInIsRefused(t *testing.T) {
	m, session := newCryptoFixture(t)
	_, priv := generateRSAKeyPairViaC(t, session)

	if rv := m.Logout(session); rv != module.CKR_OK {
		t.Fatalf("Logout: %s", rv)
	}

	rv := signRecoverInitViaC(t, session, priv, module.CKM_RSA_PKCS)
	if rv != module.CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("C_SignRecoverInit(logged out) = %s, want CKR_USER_NOT_LOGGED_IN", rv)
	}
}
