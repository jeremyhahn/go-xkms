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

package pkcs11test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// gcmTagLen is the length in bytes of the AES-GCM authentication tag the suite
// requests through CK_GCM_PARAMS.ulTagBits = 128. PKCS#11 v3.2 §6.13.7 puts the
// tag at the end of the ciphertext, so every AES-GCM ciphertext this suite
// produces is exactly len(plaintext)+gcmTagLen bytes.
const gcmTagLen = 16

// attributeValue reads a single attribute off an object and fails the test if
// the token will not reveal it.
//
// C_GetAttributeValue is the suite's window into the token's own view of an
// object, and it is the only way to obtain the material an oracle outside the
// module needs: an RSA public key to check a signature against, or a secret
// key to reproduce a ciphertext with.
func attributeValue(t *testing.T, m *module.Module, sh module.SessionHandle,
	obj module.ObjectHandle, attrType module.AttributeType) []byte {
	t.Helper()

	attrs, rv := m.GetAttributeValue(sh, obj, []module.Attribute{{Type: attrType}})
	requireRV(t, module.CKR_OK, rv, "GetAttributeValue failed")

	if len(attrs) != 1 {
		t.Fatalf("GetAttributeValue returned %d attributes, want 1", len(attrs))
	}
	if attrs[0].Unavailable {
		t.Fatalf("the token would not reveal attribute %#x", uint64(attrType))
	}
	defer module.ReleaseAttributes(attrs)

	// A backend-held secret stays sealed in the attribute until read, so take
	// the test's own copy through the borrow.
	var value []byte
	if err := attrs[0].WithValue(func(v []byte) error {
		value = append([]byte(nil), v...)
		return nil
	}); err != nil {
		t.Fatalf("reading attribute %#x: %v", uint64(attrType), err)
	}
	if len(value) == 0 {
		t.Fatalf("attribute %#x came back empty", uint64(attrType))
	}
	return value
}

// rsaPublicKeyFor rebuilds an rsa.PublicKey from a public key object's
// CKA_MODULUS and CKA_PUBLIC_EXPONENT (PKCS#11 v3.2 §6.1.2, RSA public key
// object attributes).
//
// This is the suite's signature oracle. Checking a signature by feeding it back
// into C_Verify only proves the module agrees with itself: a Sign that returns
// a constant and a Verify that returns CKR_OK unconditionally pass that test.
// Rebuilding the public key here moves the check to crypto/rsa, outside the
// module and outside the backend.
func rsaPublicKeyFor(t *testing.T, m *module.Module, sh module.SessionHandle,
	pub module.ObjectHandle) *rsa.PublicKey {
	t.Helper()

	modulus := attributeValue(t, m, sh, pub, module.CKA_MODULUS)
	exponent := attributeValue(t, m, sh, pub, module.CKA_PUBLIC_EXPONENT)

	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() > int64(1<<31-1) {
		t.Fatalf("CKA_PUBLIC_EXPONENT %x does not fit in an rsa.PublicKey", exponent)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(e.Int64()),
	}
}

// assertRSASignature checks a PKCS#1 v1.5 signature against the public key the
// token published, using crypto/rsa rather than C_Verify.
//
// hash names the digest the mechanism prescribes; pass crypto.Hash(0) for
// CKM_RSA_PKCS, which signs the caller's bytes with no digest of its own.
//
// A signature that does not check here means the token signed something other
// than data under the key it claims -- the defect that no round trip through
// the module's own C_Verify can detect.
func assertRSASignature(t *testing.T, pub *rsa.PublicKey, hash crypto.Hash, data, signature []byte) {
	t.Helper()

	if len(signature) != pub.Size() {
		t.Fatalf("signature is %d bytes, want %d (the RSA modulus size)",
			len(signature), pub.Size())
	}

	if err := verifyPKCS1v15(pub, hash, data, signature); err != nil {
		t.Fatalf("the signature does not verify against the token's own public key "+
			"over %q: %v", data, err)
	}
}

// verifyPKCS1v15 checks a PKCS#1 v1.5 signature over data and reports the
// result, for the tests that need the oracle to say no.
//
// hash of crypto.Hash(0) means the signature covers data verbatim, which is
// what CKM_RSA_PKCS does.
func verifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, data, signature []byte) error {
	signed := data
	if hash != crypto.Hash(0) {
		h := hash.New()
		h.Write(data)
		signed = h.Sum(nil)
	}
	return rsa.VerifyPKCS1v15(pub, hash, signed, signature)
}

// aesGCMSeal reproduces, outside the module, the AES-GCM ciphertext the token
// must produce for the given key, IV and plaintext.
//
// PKCS#11 v3.2 §6.13.7 fixes the wire format as ciphertext || tag, which is
// exactly what crypto/cipher's GCM Seal returns, so the two are comparable byte
// for byte. This catches an encryption that silently returns the plaintext, one
// that ignores the caller's CK_GCM_PARAMS.pIv, and a multi-part chain that
// drops or reorders a part.
func aesGCMSeal(t *testing.T, key, iv, plaintext, aad []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("building the AES oracle failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("building the GCM oracle failed: %v", err)
	}
	if len(iv) != gcm.NonceSize() {
		t.Fatalf("IV is %d bytes, want %d", len(iv), gcm.NonceSize())
	}
	return gcm.Seal(nil, iv, plaintext, aad)
}
