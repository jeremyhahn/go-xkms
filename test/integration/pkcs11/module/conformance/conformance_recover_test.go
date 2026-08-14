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

//go:build integration && conformance
// +build integration,conformance

// Package conformance validates C_SignRecoverInit/C_SignRecover and
// C_VerifyRecoverInit/C_VerifyRecover, which previously had zero integration
// coverage.
//
// This module supports sign/verify-recover only for CKM_RSA_PKCS and
// CKM_RSA_X_509 (module.go's mechanismSupportsSignRecover/
// mechanismSupportsVerifyRecover). For CKM_RSA_PKCS the wire hash is "NONE"
// (crypto.go's mechanismToHashMap), i.e. the operation is textbook RSASSA-
// PKCS1-v1_5 applied directly to the caller's bytes with no digest step —
// exactly what crypto/rsa's rsa.SignPKCS1v15/VerifyPKCS1v15 do when called
// with crypto.Hash(0). That makes crypto/rsa a byte-exact independent oracle
// for both directions:
//   - C_SignRecover's output must be a signature crypto/rsa's VerifyPKCS1v15
//     (hash=0) accepts over the same data.
//   - C_VerifyRecover's recovered data, given a signature crypto/rsa produced
//     independently, must equal the data that was signed.
//
// Reference: OASIS PKCS#11 v3.2 §5.14.4 (C_SignRecoverInit), §5.14.5
// (C_SignRecover), §5.15.5 (C_VerifyRecoverInit), §5.15.6 (C_VerifyRecover),
// §6.6.1 (CKM_RSA_PKCS raw sign/verify).
//
// Build tags: integration,conformance
package conformance

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// generateRecoverRSAKeyPair generates an RSA key pair with the *_RECOVER
// gating attributes C_SignRecoverInit/C_VerifyRecoverInit require, and
// returns the public handle, private handle, and the parsed *rsa.PublicKey
// (rebuilt from CKA_MODULUS/CKA_PUBLIC_EXPONENT) for use as the independent
// oracle key.
func generateRecoverRSAKeyPair(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, label string) (pub, priv module.ObjectHandle, oraclePub *rsa.PublicKey) {
	t.Helper()

	pub, priv, rv := env.Module.GenerateKeyPair(session,
		&module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, label+"-pub"),
			module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
			module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
		},
		[]module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
			module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
			module.NewStringAttribute(module.CKA_LABEL, label+"-priv"),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true),
		})
	if rv != module.CKR_OK {
		t.Fatalf("C_GenerateKeyPair returned %s", rv.String())
	}
	t.Cleanup(func() {
		env.Module.DestroyObject(session, pub)
		env.Module.DestroyObject(session, priv)
	})

	modulus := readAttribute(t, env, session, pub, module.CKA_MODULUS)
	exponent := readAttribute(t, env, session, pub, module.CKA_PUBLIC_EXPONENT)

	expBig := new(big.Int).SetBytes(exponent)
	oraclePub = &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(expBig.Int64()),
	}
	return pub, priv, oraclePub
}

// TestSignRecover_MatchesRSAPKCS1v15Oracle proves that C_SignRecover produces
// a signature crypto/rsa independently accepts as a raw (unhashed) PKCS#1 v1.5
// signature over the same data.
//
// A sign-recover implementation that used the wrong padding scheme, prefixed
// a DigestInfo it should not have, or mishandled the block type would still
// return CKR_OK with a fixed-length blob; only asking an independent verifier
// to check it catches that.
func TestSignRecover_MatchesRSAPKCS1v15Oracle(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	_, priv, oraclePub := generateRecoverRSAKeyPair(t, env, session, "signrecover-oracle")

	// CKM_RSA_PKCS sign-recover pads the raw input directly (hash "NONE"), so
	// the data must be short enough to fit under a 2048-bit modulus's PKCS#1
	// v1.5 block: at most 245 bytes (256 - 11).
	data := []byte("conformance sign-recover payload, unhashed")

	if rv := env.Module.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, priv); rv != module.CKR_OK {
		t.Fatalf("C_SignRecoverInit returned %s", rv.String())
	}
	signature, rv := env.Module.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignRecover returned %s", rv.String())
	}
	if rv := env.Module.FinishOperation(session, module.OperationSign); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	if err := rsa.VerifyPKCS1v15(oraclePub, crypto.Hash(0), data, signature); err != nil {
		t.Errorf("crypto/rsa rejected the C_SignRecover signature as a raw PKCS#1 v1.5 "+
			"signature over the signed data: %v", err)
	}
}

// TestSignRecover_TwoCallConventionIsIdempotent proves a repeated
// C_SignRecover call returns the same bytes without re-running the
// operation, and that the operation only ends via FinishOperation.
//
// Reference: PKCS#11 v3.2 §5.2 two-call output convention, and §5.14.5
// which (like C_Sign) allows the length-query idiom.
func TestSignRecover_TwoCallConventionIsIdempotent(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	_, priv, _ := generateRecoverRSAKeyPair(t, env, session, "signrecover-twocall")

	data := []byte("two call convention payload")
	if rv := env.Module.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, priv); rv != module.CKR_OK {
		t.Fatalf("C_SignRecoverInit returned %s", rv.String())
	}

	first, rv := env.Module.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("the first C_SignRecover returned %s", rv.String())
	}
	second, rv := env.Module.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("the repeated C_SignRecover returned %s; the operation must stay active "+
			"until the caller has collected the output", rv.String())
	}
	if !bytes.Equal(first, second) {
		t.Errorf("the repeated call returned different bytes\nfirst  %x\nsecond %x", first, second)
	}

	if rv := env.Module.FinishOperation(session, module.OperationSign); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}
	if _, rv := env.Module.SignRecover(session, data); rv != module.CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("after the operation was finished C_SignRecover returned %s, want "+
			"CKR_OPERATION_NOT_INITIALIZED", rv.String())
	}
}

// TestSignRecover_RejectsKeyWithoutSignRecoverAttribute proves the gating
// attribute is CKA_SIGN_RECOVER specifically, not CKA_SIGN.
//
// Reference: v3.2 §5.14.4: "the CKA_SIGN_RECOVER attribute of the signature
// key ... MUST be CK_TRUE".
func TestSignRecover_RejectsKeyWithoutSignRecoverAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// A key with plain CKA_SIGN but not CKA_SIGN_RECOVER.
	_, priv := generateRSAKeyPair(t, env, session, "signrecover-wrongattr")

	rv := env.Module.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, priv)
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_SignRecoverInit with a CKA_SIGN-only (not CKA_SIGN_RECOVER) key returned %s, "+
			"want CKR_KEY_FUNCTION_NOT_PERMITTED", rv.String())
	}
}

// TestSignRecover_RejectsUnsupportedMechanism proves C_SignRecoverInit
// refuses a mechanism this module does not support for the recover variant
// (e.g. a hash-and-sign mechanism, which has no notion of recoverable data).
//
// Reference: v3.2 return values for C_SignRecoverInit include
// CKR_MECHANISM_INVALID.
func TestSignRecover_RejectsUnsupportedMechanism(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)
	_, priv, _ := generateRecoverRSAKeyPair(t, env, session, "signrecover-badmech")

	rv := env.Module.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_SHA256_RSA_PKCS}, priv)
	if rv != module.CKR_MECHANISM_INVALID {
		t.Errorf("C_SignRecoverInit with CKM_SHA256_RSA_PKCS returned %s, want CKR_MECHANISM_INVALID",
			rv.String())
	}
}

// TestVerifyRecover_RecoversDataFromAnIndependentlyProducedSignature proves
// C_VerifyRecover recovers exactly the data an independent crypto/rsa
// signature was produced over.
//
// The module never sees the plaintext except through the signature; if it
// recovered the wrong bytes (e.g. off-by-one padding stripping, or returning
// the padded block instead of the unpadded message) this is the only check
// that would notice, since C_VerifyRecover still returns CKR_OK either way.
func TestVerifyRecover_RecoversDataFromAnIndependentlyProducedSignature(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	pub, _, _ := generateRecoverRSAKeyPair(t, env, session, "verifyrecover-oracle")

	// Generate an independent RSA key pair whose public half is imported into
	// the module as the verify-recover key, so the corresponding private key
	// (known only to this test) can produce a signature the module never
	// helped create.
	oraclePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the independent oracle RSA key failed: %v", err)
	}

	data := []byte("independently signed payload for verify-recover")
	signature, err := rsa.SignPKCS1v15(rand.Reader, oraclePriv, crypto.Hash(0), data)
	if err != nil {
		t.Fatalf("crypto/rsa.SignPKCS1v15 failed: %v", err)
	}

	// Import the independent key's public half as the module's verify-recover
	// key, replacing the generated key pair's public key material so
	// verification runs against the key that actually produced the signature.
	importedPub, rv := env.Module.CreateObject(session, []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewStringAttribute(module.CKA_LABEL, "verifyrecover-imported-pub"),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
		module.NewAttribute(module.CKA_MODULUS, oraclePriv.PublicKey.N.Bytes()),
		module.NewAttribute(module.CKA_PUBLIC_EXPONENT, bigEndianExponent(oraclePriv.PublicKey.E)),
	})
	if rv != module.CKR_OK {
		t.Fatalf("C_CreateObject for the imported RSA public key returned %s", rv.String())
	}
	t.Cleanup(func() { env.Module.DestroyObject(session, importedPub) })
	_ = pub // the generated key pair's public half is unused; only the import matters here

	if rv := env.Module.VerifyRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, importedPub); rv != module.CKR_OK {
		t.Fatalf("C_VerifyRecoverInit returned %s", rv.String())
	}
	recovered, rv := env.Module.VerifyRecover(session, signature)
	if rv != module.CKR_OK {
		t.Fatalf("C_VerifyRecover returned %s", rv.String())
	}
	if rv := env.Module.FinishOperation(session, module.OperationVerify); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	if !bytes.Equal(recovered, data) {
		t.Errorf("C_VerifyRecover recovered the wrong data\n got  %q\nwant %q", recovered, data)
	}
}

// TestVerifyRecover_RejectsTamperedSignature proves a bit-flipped signature
// is rejected rather than recovering garbage under CKR_OK.
//
// Reference: v3.2 §5.15.6 return values include CKR_SIGNATURE_INVALID.
func TestVerifyRecover_RejectsTamperedSignature(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	pub, priv, _ := generateRecoverRSAKeyPair(t, env, session, "verifyrecover-tamper")

	data := []byte("payload that will be tampered after signing")
	if rv := env.Module.SignRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, priv); rv != module.CKR_OK {
		t.Fatalf("C_SignRecoverInit returned %s", rv.String())
	}
	signature, rv := env.Module.SignRecover(session, data)
	if rv != module.CKR_OK {
		t.Fatalf("C_SignRecover returned %s", rv.String())
	}
	if rv := env.Module.FinishOperation(session, module.OperationSign); rv != module.CKR_OK {
		t.Fatalf("FinishOperation returned %s", rv.String())
	}

	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0xff

	if rv := env.Module.VerifyRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, pub); rv != module.CKR_OK {
		t.Fatalf("C_VerifyRecoverInit returned %s", rv.String())
	}
	_, rv = env.Module.VerifyRecover(session, tampered)
	if rv != module.CKR_SIGNATURE_INVALID {
		t.Errorf("C_VerifyRecover of a tampered signature returned %s, want CKR_SIGNATURE_INVALID", rv.String())
	}
}

// TestVerifyRecover_RejectsKeyWithoutVerifyRecoverAttribute proves the gating
// attribute is CKA_VERIFY_RECOVER specifically, not CKA_VERIFY.
//
// Reference: v3.2 §5.15.5: "the CKA_VERIFY_RECOVER attribute of the
// verification key ... MUST be CK_TRUE".
func TestVerifyRecover_RejectsKeyWithoutVerifyRecoverAttribute(t *testing.T) {
	env, session := testutil.SetupAuthenticatedModule(t)

	// A key with plain CKA_VERIFY but not CKA_VERIFY_RECOVER.
	pub, _ := generateRSAKeyPair(t, env, session, "verifyrecover-wrongattr")

	rv := env.Module.VerifyRecoverInit(session, &module.Mechanism{Type: module.CKM_RSA_PKCS}, pub)
	if rv != module.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("C_VerifyRecoverInit with a CKA_VERIFY-only (not CKA_VERIFY_RECOVER) key returned %s, "+
			"want CKR_KEY_FUNCTION_NOT_PERMITTED", rv.String())
	}
}

// bigEndianExponent renders a positive int as the minimal big-endian byte
// slice x509 and PKCS#11 both use for CKA_PUBLIC_EXPONENT.
func bigEndianExponent(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
