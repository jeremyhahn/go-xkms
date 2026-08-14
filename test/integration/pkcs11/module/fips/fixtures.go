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

//go:build integration && fips

package fips

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// CKA_EC_PARAMS encodings for the curves this suite uses, as
// pkg/pkcs11/module's ecCurves table publishes them. P-256 is the named-curve
// OID 1.2.840.10045.3.1.7; Ed25519 is RFC 8410's id-Ed25519, 1.3.101.112.
var (
	ecParamsP256    = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	ecParamsEd25519 = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
)

// errAttributeMissing reports that the token returned an attribute with no
// value, which PKCS#11 signals by a length of -1 and which callers must not
// mistake for an empty value.
type errAttributeMissing struct {
	attribute string
}

func (e *errAttributeMissing) Error() string {
	return fmt.Sprintf("the token reported %s as unavailable", e.attribute)
}

// keyPair is a generated asymmetric key pair and the public half decoded into
// a crypto/* type, which is what makes an independent check of the token's
// output possible.
type keyPair struct {
	pub  pkcs11.ObjectHandle
	priv pkcs11.ObjectHandle

	rsaPub *rsa.PublicKey
	ecPub  *ecdsa.PublicKey
	edPub  ed25519.PublicKey
}

// uniqueLabel returns a label unlikely to collide with another test's objects
// on a token whose storage outlives a single run.
func uniqueLabel(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failure here means the process has no entropy source at all, which
		// no test can work around; fall back to the clock so the label is still
		// unique enough to avoid a collision.
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	}
	return fmt.Sprintf("%s-%x", prefix, b)
}

// attribute reads one attribute off an object and returns its raw value.
func attribute(t *testing.T, tok *token, obj pkcs11.ObjectHandle, attrType uint, name string) []byte {
	t.Helper()

	attrs, err := tok.ctx.GetAttributeValue(tok.session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(attrType, nil),
	})
	if err != nil {
		t.Fatalf("C_GetAttributeValue(%s): %v", name, err)
	}
	if len(attrs) != 1 {
		t.Fatalf("C_GetAttributeValue(%s) returned %d attributes, want 1", name, len(attrs))
	}
	if attrs[0].Value == nil {
		t.Fatal((&errAttributeMissing{attribute: name}).Error())
	}
	return attrs[0].Value
}

// generateRSA generates an RSA key pair of the requested modulus size and
// returns it with the public half decoded, so a signature the token produces
// can be checked against crypto/rsa rather than against the token itself.
func generateRSA(t *testing.T, tok *token, modulusBits uint) *keyPair {
	t.Helper()

	label := uniqueLabel("fips-rsa")
	pub, priv, err := tok.ctx.GenerateKeyPair(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
	if err != nil {
		t.Fatalf("C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, %d bits): %v", modulusBits, err)
	}

	modulus := attribute(t, tok, pub, pkcs11.CKA_MODULUS, "CKA_MODULUS")
	exponent := attribute(t, tok, pub, pkcs11.CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT")

	rsaPub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	}
	return &keyPair{pub: pub, priv: priv, rsaPub: rsaPub}
}

// generateEC generates a P-256 key pair and decodes CKA_EC_POINT into an
// ecdsa.PublicKey.
func generateEC(t *testing.T, tok *token) *keyPair {
	t.Helper()

	label := uniqueLabel("fips-ec")
	pub, priv, err := tok.ctx.GenerateKeyPair(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsP256),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
	if err != nil {
		t.Fatalf("C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN, P-256): %v", err)
	}

	point := attribute(t, tok, pub, pkcs11.CKA_EC_POINT, "CKA_EC_POINT")
	ecPub := decodeECPoint(t, point)
	return &keyPair{pub: pub, priv: priv, ecPub: ecPub}
}

// decodeECPoint decodes a CKA_EC_POINT value into a P-256 public key.
//
// PKCS#11 v3.2 §6.3.3 defines the attribute for a short-Weierstrass curve as
// the "DER-encoding of ANSI X9.62 ECPoint value Q", an OCTET STRING wrapping
// the point. Unwrapping it here rather than accepting whatever shape comes back
// is what makes a module that returns the bare point visible: such a module
// breaks every external consumer while still round-tripping against itself.
func decodeECPoint(t *testing.T, raw []byte) *ecdsa.PublicKey {
	t.Helper()

	var octets []byte
	rest, err := asn1.Unmarshal(raw, &octets)
	if err != nil {
		t.Fatalf("CKA_EC_POINT is not a DER OCTET STRING as PKCS#11 v3.2 §6.3.3 requires: %v (raw %x)", err, raw)
	}
	if len(rest) != 0 {
		t.Fatalf("CKA_EC_POINT has %d trailing bytes after the DER OCTET STRING", len(rest))
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), octets)
	if x == nil {
		t.Fatalf("CKA_EC_POINT does not decode as an uncompressed X9.62 point on P-256: %x", octets)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

// generateEd25519 generates an Ed25519 key pair and decodes its public half.
func generateEd25519(t *testing.T, tok *token) *keyPair {
	t.Helper()

	label := uniqueLabel("fips-ed")
	pub, priv, err := tok.ctx.GenerateKeyPair(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckmECEdwardsKeyPairGen, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParamsEd25519),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
	if err != nil {
		t.Fatalf("C_GenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, Ed25519): %v", err)
	}

	point := attribute(t, tok, pub, pkcs11.CKA_EC_POINT, "CKA_EC_POINT")
	return &keyPair{pub: pub, priv: priv, edPub: decodeEdwardsPoint(t, point)}
}

// decodeEdwardsPoint decodes a CKA_EC_POINT value into an Ed25519 public key.
//
// PKCS#11 v3.2 §6.3.5 Table 66 defines the Edwards CKA_EC_POINT as the raw
// public key bytes, but modules differ on whether they wrap them in an OCTET
// STRING, so both shapes are accepted and anything else is a failure rather
// than a guess.
func decodeEdwardsPoint(t *testing.T, raw []byte) ed25519.PublicKey {
	t.Helper()

	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw)
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(raw, &octets); err == nil && len(rest) == 0 &&
		len(octets) == ed25519.PublicKeySize {
		return ed25519.PublicKey(octets)
	}
	t.Fatalf("CKA_EC_POINT is neither %d raw Ed25519 public key bytes nor an OCTET STRING wrapping them: %x",
		ed25519.PublicKeySize, raw)
	return nil
}

// generateAESKey generates an AES key of the requested byte length on the
// token. The key is left readable so that a test can check the token's
// ciphertext against crypto/aes; a sensitive key could only be checked against
// the token's own inverse operation, which proves nothing about correctness.
func generateAESKey(t *testing.T, tok *token, keyBytes uint) pkcs11.ObjectHandle {
	t.Helper()

	handle, err := tok.ctx.GenerateKey(tok.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBytes),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			// CKA_DERIVE so that a probe of a KDF mechanism is stopped by the
			// mechanism policy rather than by key usage; without it, a FIPS
			// bypass in C_DeriveKey would hide behind
			// CKR_KEY_FUNCTION_NOT_PERMITTED.
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, uniqueLabel("fips-aes")),
		})
	if err != nil {
		t.Fatalf("C_GenerateKey(CKM_AES_KEY_GEN, %d bytes): %v", keyBytes, err)
	}
	return handle
}

// fixtures holds one key of every type the advertised mechanisms need, so a
// suite that exercises thirty mechanisms pays for key generation once.
type fixtures struct {
	rsa *keyPair
	ec  *keyPair
	ed  *keyPair

	// aesKey is generated on the token rather than imported, because the
	// module's crypto path resolves a secret key through the backend by its
	// key ID: a key created with C_CreateObject has no backend key and every
	// cipher operation on it fails with CKR_FUNCTION_FAILED. aesKeyValue is
	// its CKA_VALUE, which C_WrapKey independently confirms is the real key
	// material, and which therefore gives crypto/aes the same key the token
	// is using.
	aesKey      pkcs11.ObjectHandle
	aesKeyValue []byte
}

// newFixtures generates the key material the mechanism exercisers share.
func newFixtures(t *testing.T, tok *token) *fixtures {
	t.Helper()

	aesHandle := generateAESKey(t, tok, 32)
	return &fixtures{
		rsa:         generateRSA(t, tok, 2048),
		ec:          generateEC(t, tok),
		ed:          generateEd25519(t, tok),
		aesKey:      aesHandle,
		aesKeyValue: attribute(t, tok, aesHandle, pkcs11.CKA_VALUE, "CKA_VALUE"),
	}
}
