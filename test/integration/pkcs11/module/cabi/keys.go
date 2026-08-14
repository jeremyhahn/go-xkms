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
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"
)

// generateRSAKeyPair creates a session RSA key pair usable for signing,
// verification, encryption and decryption, and registers both objects for
// cleanup.
func generateRSAKeyPair(t *testing.T, f *Fixture, bits uint) (uint, uint) {
	t.Helper()

	label := UniqueLabel(t, "cabi-rsa")
	pubTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PUBLIC_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_RSA),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_VERIFY, true),
		AttrBool(CKA_ENCRYPT, true),
		AttrULong(CKA_MODULUS_BITS, bits),
		AttrBytes(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		AttrString(CKA_LABEL, label),
	}
	privTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PRIVATE_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_RSA),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_PRIVATE, true),
		AttrBool(CKA_SIGN, true),
		AttrBool(CKA_DECRYPT, true),
		AttrBool(CKA_SENSITIVE, true),
		AttrString(CKA_LABEL, label),
	}

	pub, priv, err := f.Session.GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, nil, pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("C_GenerateKeyPair for a %d-bit RSA key: %v", bits, err)
	}
	return f.Track(pub), f.Track(priv)
}

// readRSAPublicKey reconstructs a crypto/rsa public key from the token's
// CKA_MODULUS and CKA_PUBLIC_EXPONENT, giving the tests a verification oracle
// that does not go through the module.
func readRSAPublicKey(t *testing.T, f *Fixture, pub uint) *rsa.PublicKey {
	t.Helper()

	modulus, err := f.Session.Attribute(pub, CKA_MODULUS)
	if err != nil {
		t.Fatalf("reading CKA_MODULUS: %v", err)
	}
	if len(modulus) == 0 {
		t.Fatal("CKA_MODULUS is empty; the public key cannot be reconstructed")
	}

	exponent, err := f.Session.Attribute(pub, CKA_PUBLIC_EXPONENT)
	if err != nil {
		t.Fatalf("reading CKA_PUBLIC_EXPONENT: %v", err)
	}
	if len(exponent) == 0 {
		t.Fatal("CKA_PUBLIC_EXPONENT is empty; the public key cannot be reconstructed")
	}

	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() {
		t.Fatalf("CKA_PUBLIC_EXPONENT does not fit in an int64: %x", exponent)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(e.Int64()),
	}
}

// generateAESKey creates a session AES key usable for encryption and
// decryption.
func generateAESKey(t *testing.T, f *Fixture, bytes uint) uint {
	t.Helper()

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_AES),
		AttrBool(CKA_TOKEN, false),
		AttrULong(CKA_VALUE_LEN, bytes),
		AttrBool(CKA_ENCRYPT, true),
		AttrBool(CKA_DECRYPT, true),
		// The oracle needs the key material, so this key is deliberately not
		// sensitive. Every test that uses it is comparing the module's cipher
		// against crypto/cipher, which is impossible without the key.
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-aes")),
	}

	key, err := f.Session.GenerateKey(CKM_AES_KEY_GEN, nil, template)
	if err != nil {
		t.Fatalf("C_GenerateKey for a %d-byte AES key: %v", bytes, err)
	}
	return f.Track(key)
}

// readSecretValue returns a secret key's CKA_VALUE. It is only meaningful for
// keys created with CKA_SENSITIVE false and CKA_EXTRACTABLE true.
func readSecretValue(t *testing.T, f *Fixture, key uint) []byte {
	t.Helper()

	value, err := f.Session.Attribute(key, CKA_VALUE)
	if err != nil {
		t.Fatalf("reading CKA_VALUE: %v", err)
	}
	if len(value) == 0 {
		t.Fatal("CKA_VALUE is empty; the derived key material cannot be compared against an oracle")
	}
	return value
}

// generateEd25519KeyPair creates a session Ed25519 key pair.
func generateEd25519KeyPair(t *testing.T, f *Fixture) (uint, uint) {
	t.Helper()

	label := UniqueLabel(t, "cabi-ed25519")
	pubTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PUBLIC_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_EC_EDWARDS),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_VERIFY, true),
		AttrBytes(CKA_EC_PARAMS, ed25519CurveParams(t)),
		AttrString(CKA_LABEL, label),
	}
	privTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PRIVATE_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_EC_EDWARDS),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_PRIVATE, true),
		AttrBool(CKA_SIGN, true),
		AttrBool(CKA_SENSITIVE, true),
		AttrString(CKA_LABEL, label),
	}

	pub, priv, err := f.Session.GenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil, pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("C_GenerateKeyPair for an Ed25519 key: %v", err)
	}
	return f.Track(pub), f.Track(priv)
}

// ed25519CurveParams returns the DER-encoded edwards25519 curve name that
// CKA_EC_PARAMS carries for Edwards keys (PKCS#11 v3.2 section 6.3.4 permits
// the PrintableString curve name form).
func ed25519CurveParams(t *testing.T) []byte {
	t.Helper()

	params, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 101, 112})
	if err != nil {
		t.Fatalf("encoding the Ed25519 curve OID: %v", err)
	}
	return params
}

// readEd25519PublicKey reconstructs an ed25519.PublicKey from CKA_EC_POINT.
//
// PKCS#11 wraps the point in a DER OCTET STRING (v3.2 section 6.3.3). Some
// tokens store the bare point instead, so both encodings are accepted; what
// matters to the caller is a key of the right length.
func readEd25519PublicKey(t *testing.T, f *Fixture, pub uint) ed25519.PublicKey {
	t.Helper()

	point, err := f.Session.Attribute(pub, CKA_EC_POINT)
	if err != nil {
		t.Fatalf("reading CKA_EC_POINT: %v", err)
	}

	raw := unwrapOctetString(point)
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("CKA_EC_POINT holds %d bytes, want a %d-byte Ed25519 public key (raw attribute: %x)",
			len(raw), ed25519.PublicKeySize, point)
	}
	return ed25519.PublicKey(raw)
}

// generateECKeyPair creates a session P-256 key pair. derive controls whether
// the private key carries CKA_DERIVE, which C_DeriveKey requires of its base
// key (PKCS#11 v3.2 section 5.18.5) and which defaults to CK_FALSE.
func generateECKeyPair(t *testing.T, f *Fixture, derive bool) (uint, uint) {
	t.Helper()

	label := UniqueLabel(t, "cabi-ecdh")
	pubTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PUBLIC_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_EC),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_VERIFY, true),
		AttrBytes(CKA_EC_PARAMS, p256CurveParams(t)),
		AttrString(CKA_LABEL, label),
	}
	privTemplate := []Attr{
		AttrULong(CKA_CLASS, CKO_PRIVATE_KEY),
		AttrULong(CKA_KEY_TYPE, CKK_EC),
		AttrBool(CKA_TOKEN, false),
		AttrBool(CKA_PRIVATE, true),
		AttrBool(CKA_SIGN, true),
		AttrBool(CKA_DERIVE, derive),
		AttrBool(CKA_SENSITIVE, true),
		AttrString(CKA_LABEL, label),
	}

	pub, priv, err := f.Session.GenerateKeyPair(CKM_EC_KEY_PAIR_GEN, nil, pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("C_GenerateKeyPair for a P-256 key (CKA_DERIVE=%v): %v", derive, err)
	}
	return f.Track(pub), f.Track(priv)
}

// p256CurveParams returns the DER-encoded prime256v1 OID for CKA_EC_PARAMS.
func p256CurveParams(t *testing.T) []byte {
	t.Helper()

	params, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatalf("encoding the P-256 curve OID: %v", err)
	}
	return params
}

// readECDHPublicKey reconstructs a crypto/ecdh P-256 public key from
// CKA_EC_POINT so a test can compute the same shared secret independently.
func readECDHPublicKey(t *testing.T, f *Fixture, pub uint) *ecdh.PublicKey {
	t.Helper()

	point, err := f.Session.Attribute(pub, CKA_EC_POINT)
	if err != nil {
		t.Fatalf("reading CKA_EC_POINT: %v", err)
	}

	raw := unwrapOctetString(point)
	key, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		t.Fatalf("CKA_EC_POINT is not a valid uncompressed P-256 point (%x): %v", point, err)
	}
	return key
}

// unwrapOctetString strips a DER OCTET STRING header when one is present.
//
// PKCS#11 stores CKA_EC_POINT as a DER-encoded OCTET STRING wrapping the
// point, but a token that stores the bare point is common enough that callers
// must tolerate both. Anything that does not parse as an OCTET STRING is
// returned unchanged.
func unwrapOctetString(der []byte) []byte {
	var inner []byte
	if rest, err := asn1.Unmarshal(der, &inner); err == nil && len(rest) == 0 {
		return inner
	}
	return der
}

// generateDerivableSecret creates a session generic-secret key marked
// CKA_DERIVE, for use as the base key of an HKDF or SP800-108 derivation.
func generateDerivableSecret(t *testing.T, f *Fixture, keyType uint, mechType uint, bytes uint) (uint, error) {
	t.Helper()

	template := []Attr{
		AttrULong(CKA_CLASS, CKO_SECRET_KEY),
		AttrULong(CKA_KEY_TYPE, keyType),
		AttrBool(CKA_TOKEN, false),
		AttrULong(CKA_VALUE_LEN, bytes),
		AttrBool(CKA_DERIVE, true),
		AttrBool(CKA_SENSITIVE, false),
		AttrBool(CKA_EXTRACTABLE, true),
		AttrString(CKA_LABEL, UniqueLabel(t, "cabi-secret")),
	}

	key, err := f.Session.GenerateKey(mechType, nil, template)
	if err != nil {
		return 0, err
	}
	return f.Track(key), nil
}

// signPKCS1v15ThroughModule produces a PKCS#1 v1.5 signature over data using
// the module's own CKM_RSA_PKCS.
//
// It exists so a test can present a validly signed but wrong-scheme signature
// to a PSS verification without needing the private key, which is sensitive
// and never leaves the token.
func signPKCS1v15ThroughModule(t *testing.T, f *Fixture, priv uint, data []byte) []byte {
	t.Helper()

	if err := f.Session.SignInit(CKM_RSA_PKCS, nil, priv); err != nil {
		t.Fatalf("C_SignInit with CKM_RSA_PKCS: %v", err)
	}
	sig, err := f.Session.Sign(data)
	if err != nil {
		t.Fatalf("C_Sign with CKM_RSA_PKCS: %v", err)
	}
	return sig
}
