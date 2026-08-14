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

// Package conformance validates the elliptic-curve key attributes the module
// publishes, using the Go standard library as the oracle.
//
// This exists because the usual external check — exporting a public key with
// OpenSC's pkcs11-tool and parsing it — cannot be trusted for every curve:
// pkcs11-tool fails to build an EVP_PKEY for a P-384 key whose CKA_EC_PARAMS
// and CKA_EC_POINT are entirely correct, so a tool bug is indistinguishable
// from a module defect when it is the only witness.
//
// The checks here depend on nothing but crypto/elliptic, encoding/asn1 and
// crypto/x509. They read the attributes the module actually stores, rebuild a
// SubjectPublicKeyInfo from them, and require the standard library to parse it
// back to the curve that was requested. That is a stronger statement than "some
// external tool accepted it", and it holds for every curve equally.
//
// Reference: OASIS PKCS#11 v3.2 §6.3 (elliptic curve objects), RFC 5480 §2.2
// (uncompressed point encoding), SEC 1 §2.3.3.
//
// Build tags: integration,conformance
package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	testutil "github.com/jeremyhahn/go-xkms/test/integration/pkcs11/module"
)

// ecCurveCase describes one curve the module is expected to support.
type ecCurveCase struct {
	name string
	// oid is the named-curve OID that belongs in CKA_EC_PARAMS.
	oid asn1.ObjectIdentifier
	// curve is the standard-library curve the OID denotes.
	curve elliptic.Curve
	// fieldBytes is ceil(bitlen(p)/8): each of X and Y occupies exactly this
	// many bytes in an uncompressed point.
	fieldBytes int
}

// ecCurveCases are the curves the module advertises for key generation.
var ecCurveCases = []ecCurveCase{
	{"P-256", asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, elliptic.P256(), 32},
	{"P-384", asn1.ObjectIdentifier{1, 3, 132, 0, 34}, elliptic.P384(), 48},
	{"P-521", asn1.ObjectIdentifier{1, 3, 132, 0, 35}, elliptic.P521(), 66},
}

// ecPublicKeyAlgorithmOID is id-ecPublicKey (RFC 5480 §2.1.1).
var ecPublicKeyAlgorithmOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// generateECKeyPair generates a key pair on the given curve and returns the
// public and private object handles.
func generateECKeyPair(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, c ecCurveCase) (pub, priv module.ObjectHandle) {
	t.Helper()

	ecParams, err := asn1.Marshal(c.oid)
	if err != nil {
		t.Fatalf("%s: marshalling the curve OID failed: %v", c.name, err)
	}

	pubTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		module.NewAttribute(module.CKA_EC_PARAMS, ecParams),
		module.NewStringAttribute(module.CKA_LABEL, "ec-conformance-"+c.name),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
	}
	privTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
		module.NewStringAttribute(module.CKA_LABEL, "ec-conformance-"+c.name),
		module.NewBoolAttribute(module.CKA_SIGN, true),
	}

	mech := &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}
	pub, priv, rv := env.Module.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if rv != module.CKR_OK {
		t.Fatalf("%s: C_GenerateKeyPair returned %s", c.name, rv.String())
	}
	return pub, priv
}

// readAttribute reads a single attribute, failing the test if the token will
// not reveal it.
func readAttribute(t *testing.T, env *testutil.TestEnvironment, session module.SessionHandle, obj module.ObjectHandle, attrType module.AttributeType) []byte {
	t.Helper()

	attrs, rv := env.Module.GetAttributeValue(session, obj,
		[]module.Attribute{{Type: attrType}})
	if rv != module.CKR_OK {
		t.Fatalf("C_GetAttributeValue(%s) returned %s", attrType.String(), rv.String())
	}
	if len(attrs) != 1 {
		t.Fatalf("C_GetAttributeValue returned %d attributes for a one-entry template", len(attrs))
	}
	if attrs[0].Unavailable {
		t.Fatalf("the token would not reveal %s", attrType.String())
	}
	return attrs[0].Value
}

// TestECPublicKey_AttributesReconstructTheRequestedCurve proves that the
// CKA_EC_PARAMS and CKA_EC_POINT a generated public key carries describe
// exactly the curve that was asked for, and that a standards-compliant parser
// agrees.
//
// The point encoding is checked structurally as well: PKCS#11 wraps the SEC 1
// uncompressed point in an ASN.1 OCTET STRING, and the coordinates must be
// padded to the field length rather than trimmed, which is the mistake that
// makes a key work on one curve and fail on another.
func TestECPublicKey_AttributesReconstructTheRequestedCurve(t *testing.T) {
	for _, c := range ecCurveCases {
		t.Run(c.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)
			pub, _ := generateECKeyPair(t, env, session, c)

			ecParams := readAttribute(t, env, session, pub, module.CKA_EC_PARAMS)
			ecPoint := readAttribute(t, env, session, pub, module.CKA_EC_POINT)

			t.Run("ec_params_is_the_named_curve_oid", func(t *testing.T) {
				var got asn1.ObjectIdentifier
				rest, err := asn1.Unmarshal(ecParams, &got)
				if err != nil {
					t.Fatalf("CKA_EC_PARAMS is not a DER OBJECT IDENTIFIER: %v", err)
				}
				if len(rest) != 0 {
					t.Errorf("CKA_EC_PARAMS has %d trailing bytes after the OID", len(rest))
				}
				if !got.Equal(c.oid) {
					t.Errorf("CKA_EC_PARAMS names %v, want %v", got, c.oid)
				}
			})

			t.Run("ec_point_is_an_octet_string_wrapping_an_uncompressed_point", func(t *testing.T) {
				var raw []byte
				rest, err := asn1.Unmarshal(ecPoint, &raw)
				if err != nil {
					t.Fatalf("CKA_EC_POINT is not a DER OCTET STRING: %v", err)
				}
				if len(rest) != 0 {
					t.Errorf("CKA_EC_POINT has %d trailing bytes after the OCTET STRING", len(rest))
				}
				if len(raw) == 0 || raw[0] != 0x04 {
					t.Fatalf("the point must be uncompressed (leading 0x04); first byte is %#x", raw[0])
				}
				// 0x04 || X || Y, with X and Y each padded to the field length.
				// A shorter encoding means a leading zero byte was trimmed,
				// which parsers reject on some curves and silently mis-read on
				// others.
				want := 1 + 2*c.fieldBytes
				if len(raw) != want {
					t.Errorf("the uncompressed point is %d bytes, want %d "+
						"(0x04 plus two %d-byte coordinates)", len(raw), want, c.fieldBytes)
				}
			})

			t.Run("standard_library_parses_it_back_to_the_same_curve", func(t *testing.T) {
				pubKey := parseECPublicKey(t, ecParams, ecPoint)
				if pubKey.Curve != c.curve {
					t.Fatalf("the reconstructed key is on %s, want %s",
						pubKey.Curve.Params().Name, c.curve.Params().Name)
				}
				if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
					t.Error("the published point is not on the curve it claims")
				}
			})
		})
	}
}

// parseECPublicKey rebuilds a SubjectPublicKeyInfo from the module's
// CKA_EC_PARAMS and CKA_EC_POINT and parses it with crypto/x509.
//
// Going through SPKI rather than unpacking the coordinates by hand is
// deliberate: it is the encoding every real consumer receives, so a defect in
// what the module publishes shows up here the same way it would in the field.
func parseECPublicKey(t *testing.T, ecParams, ecPoint []byte) *ecdsa.PublicKey {
	t.Helper()

	var raw []byte
	if _, err := asn1.Unmarshal(ecPoint, &raw); err != nil {
		t.Fatalf("CKA_EC_POINT is not a DER OCTET STRING: %v", err)
	}

	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ecParams, &curveOID); err != nil {
		t.Fatalf("CKA_EC_PARAMS is not a DER OBJECT IDENTIFIER: %v", err)
	}

	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	paramBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		t.Fatalf("re-marshalling the curve OID failed: %v", err)
	}

	der, err := asn1.Marshal(spki{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  ecPublicKeyAlgorithmOID,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
	if err != nil {
		t.Fatalf("building the SubjectPublicKeyInfo failed: %v", err)
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("crypto/x509 rejected the key the module published: %v", err)
	}

	ecKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the module published a %T, want an ECDSA public key", parsed)
	}
	return ecKey
}

// TestECPrivateKey_CarriesPublicComponents verifies that an EC private key
// object also publishes CKA_EC_PARAMS.
//
// A consumer that holds only the private handle — which is all a PKCS#11 URI
// naming type=private yields — needs the curve to build the public half.
// OpenSSL's engine reads it straight off the private object and refuses to load
// the key when it is absent, so this is not merely a completeness check.
func TestECPrivateKey_CarriesPublicComponents(t *testing.T) {
	for _, c := range ecCurveCases {
		t.Run(c.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)
			_, priv := generateECKeyPair(t, env, session, c)

			ecParams := readAttribute(t, env, session, priv, module.CKA_EC_PARAMS)

			var got asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ecParams, &got); err != nil {
				t.Fatalf("the private key's CKA_EC_PARAMS is not a DER OID: %v", err)
			}
			if !got.Equal(c.oid) {
				t.Errorf("the private key names curve %v, want %v", got, c.oid)
			}
		})
	}
}

// TestECKeyPair_PublicAndPrivateAgreeOnTheCurve checks that the two halves of a
// generated pair describe the same curve.
//
// A mismatch here means the backend generated a key on a curve other than the
// one requested while the object metadata still claimed the requested one —
// the failure mode is a key that looks correct in every listing and produces
// signatures nothing can verify.
func TestECKeyPair_PublicAndPrivateAgreeOnTheCurve(t *testing.T) {
	for _, c := range ecCurveCases {
		t.Run(c.name, func(t *testing.T) {
			env, session := testutil.SetupAuthenticatedModule(t)
			pub, priv := generateECKeyPair(t, env, session, c)

			pubParams := readAttribute(t, env, session, pub, module.CKA_EC_PARAMS)
			privParams := readAttribute(t, env, session, priv, module.CKA_EC_PARAMS)

			if string(pubParams) != string(privParams) {
				t.Errorf("the public and private halves name different curves: %x vs %x",
					pubParams, privParams)
			}

			// The point length is the independent witness: it comes from the
			// key material the backend actually produced, not from the template
			// that was echoed back.
			ecPoint := readAttribute(t, env, session, pub, module.CKA_EC_POINT)
			var raw []byte
			if _, err := asn1.Unmarshal(ecPoint, &raw); err != nil {
				t.Fatalf("CKA_EC_POINT is not a DER OCTET STRING: %v", err)
			}
			if want := 1 + 2*c.fieldBytes; len(raw) != want {
				t.Errorf("the generated point is %d bytes, want %d: the backend "+
					"produced a key on a different curve than the template requested",
					len(raw), want)
			}
		})
	}
}
