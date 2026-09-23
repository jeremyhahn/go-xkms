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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// newECDSATestSigner generates a fresh ECDSA key pair on the backend's token
// and returns the concrete signer type.
func newECDSATestSigner(t *testing.T, b *Backend, cn string, curve elliptic.Curve) *pkcs11ECDSASigner {
	t.Helper()

	id := []byte(cn)
	signer, err := generateECDSAKeyPair(b.pool, id, id, curve, false, "", "")
	require.NoError(t, err, "ECDSA key generation on the provisioned token must succeed")
	require.NotNil(t, signer)

	return signer
}

// requireDEREncodedSignature asserts that sig is an ASN.1 DER SEQUENCE of two
// INTEGERs with no trailing data, and returns the parsed components.
//
// The encoding is asserted explicitly rather than inferred from a successful
// verification because the failure mode this guards against is a backend that
// returns IEEE P-1363 (raw R||S) where DER is expected — the exact defect that
// shipped in the Azure Key Vault backend. PKCS#11 v3.2 §6.3.1 specifies that
// CKM_ECDSA produces raw R||S, so the conversion in the signer is mandatory and
// its absence must be caught here.
func requireDEREncodedSignature(t *testing.T, sig []byte, curve elliptic.Curve) (r, s *big.Int) {
	t.Helper()

	require.NotEmpty(t, sig)
	require.Equal(t, byte(0x30), sig[0], "a DER ECDSA signature starts with a SEQUENCE tag")

	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err, "signature must be ASN.1 DER, not raw R||S")
	require.Empty(t, rest, "DER signature must have no trailing bytes")

	byteLen := (curve.Params().BitSize + 7) / 8
	require.NotEqual(t, 2*byteLen, len(sig),
		"a %d-byte signature would be raw P-1363 R||S for this curve", 2*byteLen)

	n := curve.Params().N
	require.Equal(t, 1, parsed.R.Sign(), "R must be positive")
	require.Equal(t, 1, parsed.S.Sign(), "S must be positive")
	require.Equal(t, -1, parsed.R.Cmp(n), "R must be less than the group order")
	require.Equal(t, -1, parsed.S.Cmp(n), "S must be less than the group order")

	return parsed.R, parsed.S
}

// TestECDSASigner_SignVerifiesAndIsDEREncoded is the core signer test. For each
// supported curve it signs a digest on the token and verifies the signature
// outside the signer with crypto/ecdsa against the exported public key, then
// asserts the encoding explicitly.
//
// The negative halves:
//   - a signature over a different digest must not verify, so the digest really
//     reaches the token;
//   - a signature must not verify against a different key on the same curve.
func TestECDSASigner_SignVerifiesAndIsDEREncoded(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-sign")

	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := newECDSATestSigner(t, b, "ecdsa-"+tc.name, tc.curve)

			pub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "Public must return *ecdsa.PublicKey")
			require.Equal(t, tc.curve.Params().Name, pub.Curve.Params().Name,
				"the exported key must be on the curve that was requested")
			require.True(t, tc.curve.IsOnCurve(pub.X, pub.Y), "the exported point must lie on the curve")

			digest := digestFor(t, crypto.SHA256, []byte("ecdsa payload "+tc.name))

			sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
			require.NoError(t, err)

			requireDEREncodedSignature(t, sig, tc.curve)
			require.True(t, ecdsa.VerifyASN1(pub, digest, sig),
				"signature must verify against the exported public key")

			otherDigest := digestFor(t, crypto.SHA256, []byte("a different message"))
			require.False(t, ecdsa.VerifyASN1(pub, otherDigest, sig),
				"the digest the caller supplied must be the digest that was signed")

			hostKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)
			require.False(t, ecdsa.VerifyASN1(&hostKey.PublicKey, digest, sig),
				"the signature must be bound to the token key, not merely well-formed")
		})
	}
}

// TestECDSASigner_SignIsNotRawP1363 states the encoding requirement as its own
// regression test: reinterpreting the DER output as raw R||S must not produce a
// valid signature. This is the assertion that fails first if the DER conversion
// in Sign is ever removed in favour of returning the token's raw output.
func TestECDSASigner_SignIsNotRawP1363(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-encoding")
	signer := newECDSATestSigner(t, b, "ecdsa-encoding", elliptic.P256())
	pub := signer.Public().(*ecdsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("encoding payload"))
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	r, s := requireDEREncodedSignature(t, sig, elliptic.P256())

	// Build what a P-1363 backend would have returned and prove the two
	// encodings are distinguishable by the verifier.
	byteLen := (elliptic.P256().Params().BitSize + 7) / 8
	raw := make([]byte, 2*byteLen)
	r.FillBytes(raw[:byteLen])
	s.FillBytes(raw[byteLen:])

	require.False(t, ecdsa.VerifyASN1(pub, digest, raw),
		"raw R||S must not verify as ASN.1, so DER output is observably required")
	require.True(t, ecdsa.Verify(pub, digest, r, s),
		"the R and S recovered from the DER output must be the real signature components")
}

// TestECDSASigner_SignAcceptsOversizedDigest verifies the PKCS#11 v3.2 §6.3.1
// rule that a hash longer than the base point order is truncated by the token:
// a SHA-512 digest signed by a P-256 key must still verify, because crypto/ecdsa
// applies the same leftmost-bits truncation.
func TestECDSASigner_SignAcceptsOversizedDigest(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-bigdigest")
	signer := newECDSATestSigner(t, b, "ecdsa-bigdigest", elliptic.P256())
	pub := signer.Public().(*ecdsa.PublicKey)

	digest := digestFor(t, crypto.SHA512, []byte("oversized digest payload"))
	require.Len(t, digest, 64)

	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA512)
	require.NoError(t, err)

	requireDEREncodedSignature(t, sig, elliptic.P256())
	require.True(t, ecdsa.VerifyASN1(pub, digest, sig),
		"the token must truncate an oversized digest the same way crypto/ecdsa does")
}

// TestECDSASigner_SignIgnoresSignerOpts documents that ECDSA over CKM_ECDSA
// takes a pre-computed digest and therefore does not consult crypto.SignerOpts:
// the same digest signed with different opts must produce signatures that all
// verify against the same digest.
func TestECDSASigner_SignIgnoresSignerOpts(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-opts")
	signer := newECDSATestSigner(t, b, "ecdsa-opts", elliptic.P256())
	pub := signer.Public().(*ecdsa.PublicKey)

	digest := digestFor(t, crypto.SHA256, []byte("opts payload"))

	for _, opts := range []crypto.SignerOpts{nil, crypto.SHA256, crypto.SHA512} {
		sig, err := signer.Sign(rand.Reader, digest, opts)
		require.NoError(t, err)
		require.True(t, ecdsa.VerifyASN1(pub, digest, sig))
	}
}

// TestECDSASigner_Sign_ClosedPool verifies that signing through a closed pool
// reports ErrSessionPoolClosed instead of blocking or dereferencing a session
// that no longer exists.
func TestECDSASigner_Sign_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-closed")
	signer := newECDSATestSigner(t, b, "ecdsa-closed", elliptic.P256())

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, secretValueString(b.config.PIN), 2)
	require.NoError(t, err)
	pool.Close()

	closedSigner := &pkcs11ECDSASigner{
		pool:          pool,
		privateHandle: signer.privateHandle,
		publicKey:     signer.publicKey,
		label:         signer.label,
	}

	_, err = closedSigner.Sign(rand.Reader, digestFor(t, crypto.SHA256, []byte("x")), crypto.SHA256)
	require.ErrorIs(t, err, ErrSessionPoolClosed)
}

// TestECDSASigner_Sign_InvalidHandle verifies that signing with a handle the
// token does not recognise fails at SignInit with the token's CKR value, rather
// than producing an empty signature that a caller might treat as valid.
func TestECDSASigner_Sign_InvalidHandle(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-signer-badhandle")
	signer := newECDSATestSigner(t, b, "ecdsa-badhandle", elliptic.P256())

	broken := &pkcs11ECDSASigner{
		pool:          b.pool,
		privateHandle: pkcs11.ObjectHandle(0xdeadbeef),
		publicKey:     signer.publicKey,
		label:         signer.label,
	}

	sig, err := broken.Sign(rand.Reader, digestFor(t, crypto.SHA256, []byte("x")), crypto.SHA256)
	require.Nil(t, sig)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: ECDSA SignInit", wrapped.Msg)

	// PKCS#11 v3.2 names CKR_KEY_HANDLE_INVALID for C_SignInit, but SoftHSM
	// reports the more general CKR_OBJECT_HANDLE_INVALID; both identify the
	// same condition, so the assertion accepts either rather than pinning one
	// module's choice.
	var ckr pkcs11.Error
	require.True(t, errors.As(err, &ckr))
	require.Contains(t,
		[]pkcs11.Error{pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID), pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)},
		ckr)
}

// TestExportECDSAPublicKey_MatchesSigningKey verifies exportECDSAPublicKey
// against the strongest available oracle: a signature made by the private half
// on the token must verify under the exported public half.
//
// P-521 is included deliberately. Its uncompressed EC point is 133 bytes, so
// CKA_EC_POINT uses the ASN.1 long-form length (04 81 85 ...) and takes the
// second parsing branch; the short-form heuristic used for P-256/P-384 does not
// apply.
func TestExportECDSAPublicKey_MatchesSigningKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export")

	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := []byte("ecdsa-export-" + tc.name)
			signer := newECDSATestSigner(t, b, string(id), tc.curve)

			session := openIntrospectionSession(t, b)
			handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			})

			exported, err := exportECDSAPublicKey(b.pool, handle)
			require.NoError(t, err)
			require.Equal(t, tc.curve.Params().Name, exported.Curve.Params().Name)

			cached := signer.Public().(*ecdsa.PublicKey)
			require.Equal(t, 0, cached.X.Cmp(exported.X))
			require.Equal(t, 0, cached.Y.Cmp(exported.Y))

			digest := digestFor(t, crypto.SHA256, []byte("export oracle "+tc.name))
			sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
			require.NoError(t, err)
			require.True(t, ecdsa.VerifyASN1(exported, digest, sig),
				"the independently exported point must be the public half of the signing key")
		})
	}
}

// TestExportECDSAPublicKey_InvalidHandle verifies the failure path for an
// object handle the token does not know.
func TestExportECDSAPublicKey_InvalidHandle(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-badhandle")

	pub, err := exportECDSAPublicKey(b.pool, pkcs11.ObjectHandle(0xdeadbeef))
	require.Nil(t, pub)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: get ECDSA public key attributes", wrapped.Msg)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
}

// TestExportECDSAPublicKey_NonECHandle verifies that an RSA public key object
// is rejected rather than parsed into a bogus EC point, since an RSA object has
// neither CKA_EC_PARAMS nor CKA_EC_POINT.
func TestExportECDSAPublicKey_NonECHandle(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-nonec")

	id := []byte("rsa-for-ec-export")
	_, err := generateRSAKeyPair(b.pool, id, id, rsaTestKeySize, false, "", "")
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})

	pub, err := exportECDSAPublicKey(b.pool, handle)
	require.Nil(t, pub)
	require.Error(t, err)
}

// TestExportECDSAPublicKey_ClosedPool verifies the pool state is surfaced.
func TestExportECDSAPublicKey_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-closed")

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, secretValueString(b.config.PIN), 1)
	require.NoError(t, err)
	pool.Close()

	pub, err := exportECDSAPublicKey(pool, pkcs11.ObjectHandle(1))
	require.Nil(t, pub)
	require.ErrorIs(t, err, ErrSessionPoolClosed)
}

// TestGenerateECDSAKeyPair_UnsupportedCurve verifies that a curve outside
// curveToOID is refused before any token call, with the curve named in the
// detail so the caller can act on it.
func TestGenerateECDSAKeyPair_UnsupportedCurve(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-gen-badcurve")

	id := []byte("ecdsa-badcurve")
	signer, err := generateECDSAKeyPair(b.pool, id, id, elliptic.P224(), false, "", "")
	require.Nil(t, signer)
	require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, elliptic.P224().Params().Name)
}

// TestGenerateECDSAKeyPair_YubiKeyPIVRequiresSOPIN verifies the guard that
// demands a management key before attempting PIV key generation.
func TestGenerateECDSAKeyPair_YubiKeyPIVRequiresSOPIN(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-gen-nosopin")

	id := []byte{0x9a}
	signer, err := generateECDSAKeyPair(b.pool, id, id, elliptic.P256(), true, "", "1234")
	require.Nil(t, signer)
	require.ErrorIs(t, err, ErrSOPINRequired)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate ECDSA key pair", wrapped.Msg)
}

// TestGenerateECDSAKeyPair_ClosedPool verifies that generation on a closed pool
// is reported as a wrapped pool-closed error rather than a partially created
// key pair.
func TestGenerateECDSAKeyPair_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-gen-closed")

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, secretValueString(b.config.PIN), 1)
	require.NoError(t, err)
	pool.Close()

	id := []byte("ecdsa-gen-closed")
	signer, err := generateECDSAKeyPair(pool, id, id, elliptic.P256(), false, "", "")
	require.Nil(t, signer)
	require.ErrorIs(t, err, ErrSessionPoolClosed)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: generate ECDSA key pair", wrapped.Msg)
}

// TestFindECDSASigner_RoundTrip verifies that a key located by CKA_ID is the
// same key that was generated: the found handle must produce signatures that
// verify under the generated public key.
func TestFindECDSASigner_RoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-find")

	id := []byte("ecdsa-find-me")
	generated := newECDSATestSigner(t, b, string(id), elliptic.P384())

	found, err := findECDSASigner(b.pool, id)
	require.NoError(t, err)
	require.NotNil(t, found)

	generatedPub := generated.Public().(*ecdsa.PublicKey)
	foundPub := found.Public().(*ecdsa.PublicKey)
	require.Equal(t, 0, generatedPub.X.Cmp(foundPub.X))
	require.Equal(t, 0, generatedPub.Y.Cmp(foundPub.Y))
	require.Equal(t, generatedPub.Curve.Params().Name, foundPub.Curve.Params().Name)

	digest := digestFor(t, crypto.SHA256, []byte("found ecdsa payload"))
	sig, err := found.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	requireDEREncodedSignature(t, sig, elliptic.P384())
	require.True(t, ecdsa.VerifyASN1(generatedPub, digest, sig))
}

// TestFindECDSASigner_NotFound verifies the documented (nil, nil) result for an
// absent key, which callers use to distinguish "no such key" from a lookup
// failure.
func TestFindECDSASigner_NotFound(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-find-missing")

	found, err := findECDSASigner(b.pool, []byte("no-such-ec-key"))
	require.NoError(t, err)
	require.Nil(t, found)
}

// TestFindECDSASigner_ClosedPool verifies that the pool state is surfaced
// instead of a nil-session panic.
func TestFindECDSASigner_ClosedPool(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-find-closed")

	slot, err := b.resolveSlot()
	require.NoError(t, err)
	pool, err := NewSessionPool(b.p11ctx, slot, secretValueString(b.config.PIN), 1)
	require.NoError(t, err)
	pool.Close()

	found, err := findECDSASigner(pool, []byte("anything"))
	require.Nil(t, found)
	require.ErrorIs(t, err, ErrSessionPoolClosed)
}

// TestCurveOIDTables verifies the curve OID tables against RFC 5480 §2.1.1.1
// and checks that oidToCurve is the exact inverse of curveToOID. A wrong OID
// would make key generation produce a key on a different curve than requested,
// which every downstream verification would then reject.
func TestCurveOIDTables(t *testing.T) {
	want := map[string]asn1.ObjectIdentifier{
		"P-256": {1, 2, 840, 10045, 3, 1, 7},
		"P-384": {1, 3, 132, 0, 34},
		"P-521": {1, 3, 132, 0, 35},
	}

	require.Len(t, curveToOID, len(want))
	require.Len(t, oidToCurve, len(want), "every curve OID must be invertible")

	for curve, oid := range curveToOID {
		name := curve.Params().Name
		expected, ok := want[name]
		require.True(t, ok, "unexpected curve %s in curveToOID", name)
		require.True(t, expected.Equal(oid), "OID for %s: want %v, got %v", name, expected, oid)

		encoded, err := asn1.Marshal(oid)
		require.NoError(t, err)
		back, ok := oidToCurve[string(encoded)]
		require.True(t, ok, "oidToCurve is missing the encoding for %s", name)
		require.Equal(t, name, back.Params().Name)
	}
}

// TestCurveOIDMatchesTokenAttribute verifies that the OID the generator writes
// into CKA_EC_PARAMS is the one the token stores, using the token as the
// oracle. A mismatch here would mean the key was created on a curve other than
// the one the caller asked for.
func TestCurveOIDMatchesTokenAttribute(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-ecparams")

	for curve, oid := range curveToOID {
		name := curve.Params().Name
		id := []byte("ecparams-" + name)
		_, err := generateECDSAKeyPair(b.pool, id, id, curve, false, "", "")
		require.NoError(t, err)

		session := openIntrospectionSession(t, b)
		handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})

		attrs, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		})
		require.NoError(t, err)

		var stored asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(attrs[0].Value, &stored)
		require.NoError(t, err, "CKA_EC_PARAMS must be a DER OID for %s", name)
		require.Empty(t, rest)
		require.True(t, oid.Equal(stored), "CKA_EC_PARAMS for %s: want %v, got %v", name, oid, stored)
	}
}

// createECPublicKeyObject creates a bare CKO_PUBLIC_KEY object with the given
// EC attributes. It exists so the export path can be driven with attribute
// combinations that key generation would never produce, which is the only way
// to reach the curve and point validation branches.
func createECPublicKeyObject(t *testing.T, b *Backend, id, ecParams, ecPoint []byte) pkcs11.ObjectHandle {
	t.Helper()

	var handle pkcs11.ObjectHandle
	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		created, err := b.p11ctx.CreateObject(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
		})
		if err != nil {
			return err
		}
		handle = created
		return nil
	}))

	return handle
}

// TestExportECDSAPublicKey_UnknownCurve verifies that a key on a curve this
// backend does not support is refused rather than mapped onto whichever curve
// happens to be handy. Accepting it would produce a public key on the wrong
// group, and every signature check against it would be meaningless.
//
// secp256k1 is used because it is a real, widely deployed curve that this
// backend deliberately does not support.
func TestExportECDSAPublicKey_UnknownCurve(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-unknown-curve")

	secp256k1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
	require.NoError(t, err)
	point, err := asn1.Marshal([]byte{0x04, 0x01, 0x02, 0x03})
	require.NoError(t, err)

	handle := createECPublicKeyObject(t, b, []byte("unknown-curve"), secp256k1, point)

	pub, err := exportECDSAPublicKey(b.pool, handle)
	require.Nil(t, pub)
	require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)

	var detail *errs.Detail
	require.True(t, errors.As(err, &detail))
	require.Equal(t, "unknown EC curve OID", detail.Detail)
}

// TestExportECDSAPublicKey_InvalidPoint verifies that CKA_EC_POINT contents
// that are not a valid uncompressed point on the named curve are rejected. A
// silently accepted bad point would yield an *ecdsa.PublicKey with nil
// coordinates, which panics the first time crypto/ecdsa touches it.
//
// The two cases fail at different checks. A wrapped point of the wrong size is
// caught on length, before any curve arithmetic; a correctly sized pair of
// coordinates that does not satisfy the curve equation is caught by Unmarshal.
// Both must surface as ErrInvalidKeyAttributes.
func TestExportECDSAPublicKey_InvalidPoint(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-bad-point")

	params, err := asn1.Marshal(oidP256)
	require.NoError(t, err)

	wrongLength, err := asn1.Marshal([]byte{0x04, 0xaa, 0xbb})
	require.NoError(t, err)

	// 0x04 || X=1 || Y=1: the right size for P-256, but not on the curve.
	offCurve := make([]byte, uncompressedPointLen(elliptic.P256()))
	offCurve[0] = 0x04
	offCurve[32] = 0x01
	offCurve[64] = 0x01

	for _, tc := range []struct {
		name   string
		point  []byte
		detail string
	}{
		{"wrapped point of the wrong size", wrongLength, "CKA_EC_POINT wraps 3 bytes, want a 65-byte uncompressed point on P-256"},
		{"correct size but off the curve", offCurve, "CKA_EC_POINT is not an uncompressed point on P-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle := createECPublicKeyObject(t, b, []byte("bad-point-"+tc.name), params, tc.point)

			pub, err := exportECDSAPublicKey(b.pool, handle)
			require.Nil(t, pub)
			require.ErrorIs(t, err, ErrInvalidKeyAttributes)

			var detail *errs.Detail
			require.True(t, errors.As(err, &detail))
			require.Equal(t, tc.detail, detail.Detail)
		})
	}
}

// TestFindECDSASigner_PrivateKeyWithoutPublicKey documents the lookup contract
// when a token holds a private key with no matching CKO_PUBLIC_KEY object: the
// signer cannot be constructed without the public half, so the lookup reports
// "not found" rather than returning a signer whose Public() is nil.
//
// A nil public key would surface much later, inside certificate issuance or TLS
// handshakes, as a nil dereference.
func TestFindECDSASigner_PrivateKeyWithoutPublicKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-find-no-public")

	id := []byte("ecdsa-orphan")
	newECDSATestSigner(t, b, string(id), elliptic.P256())

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := b.p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return err
		}
		handles, _, err := b.p11ctx.FindObjects(session, 1)
		if err != nil {
			return err
		}
		if err := b.p11ctx.FindObjectsFinal(session); err != nil {
			return err
		}
		require.Len(t, handles, 1)
		return b.p11ctx.DestroyObject(session, handles[0])
	}))

	found, err := findECDSASigner(b.pool, id)
	require.NoError(t, err, "a missing public half is not a lookup failure")
	require.Nil(t, found, "no signer may be returned without a public key")
}

// TestExportECDSAPublicKey_RawPointEncoding verifies interoperability with
// modules that store CKA_EC_POINT as a bare uncompressed point instead of
// wrapping it in a DER OCTET STRING. PKCS#11 v3.2 §6.3 describes the point as
// an octet string, and implementations differ on whether the DER wrapper is
// included; a backend that only understood the wrapped form would fail to
// export keys from those modules.
//
// The point used here is a real P-256 public key, so a successful export can be
// checked against the coordinates it was built from.
func TestExportECDSAPublicKey_RawPointEncoding(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-raw-point")

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rawPoint := elliptic.Marshal(elliptic.P256(), hostKey.PublicKey.X, hostKey.PublicKey.Y)
	require.Equal(t, byte(0x04), rawPoint[0], "the point must be in uncompressed form")

	params, err := asn1.Marshal(oidP256)
	require.NoError(t, err)

	handle := createECPublicKeyObject(t, b, []byte("raw-point"), params, rawPoint)

	exported, err := exportECDSAPublicKey(b.pool, handle)
	require.NoError(t, err, "an unwrapped CKA_EC_POINT must still parse")
	require.Equal(t, 0, hostKey.PublicKey.X.Cmp(exported.X))
	require.Equal(t, 0, hostKey.PublicKey.Y.Cmp(exported.Y))
	require.Equal(t, elliptic.P256().Params().Name, exported.Curve.Params().Name)
}

// TestExportECDSAPublicKey_RawPointWithHeaderLikePrefix drives the point that
// the old DER-unwrap heuristic misread all the way through a token, so the
// regression is covered at the export boundary and not only in decodeECPoint.
//
// The stored point is a real P-256 key whose X begins with 0x3f, which is
// exactly len(point)-2. The old code read those first two bytes as an OCTET
// STRING header, handed 63 bytes to Unmarshal, and failed the export. One key
// in 256 has that shape, which is why the failure looked intermittent.
func TestExportECDSAPublicKey_RawPointWithHeaderLikePrefix(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-export-headerlike-point")

	rawPoint := decodeHex(t, p256TriggerPoint)
	require.Equal(t, byte(len(rawPoint)-2), rawPoint[1], "this vector must reproduce the collision")

	wantX, wantY := elliptic.Unmarshal(elliptic.P256(), rawPoint)
	require.NotNil(t, wantX, "the test vector must be a valid P-256 point")

	params, err := asn1.Marshal(oidP256)
	require.NoError(t, err)

	handle := createECPublicKeyObject(t, b, []byte("raw-point-header-like"), params, rawPoint)

	exported, err := exportECDSAPublicKey(b.pool, handle)
	require.NoError(t, err, "a bare point whose X starts with len-2 must still export")
	require.Equal(t, 0, wantX.Cmp(exported.X))
	require.Equal(t, 0, wantY.Cmp(exported.Y))
}

// TestFindECDSASigner_DeadSession verifies that a session the module no longer
// recognises is reported as an error and not as "key not found".
//
// The distinction is important: findECDSASigner signals absence with
// (nil, nil), so a lookup that failed for an infrastructural reason must not
// take the same path — a caller would otherwise conclude the key had been
// deleted and could generate a replacement over a healthy key.
func TestFindECDSASigner_DeadSession(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-find-dead-session")
	pool := newTestPool(t, b, 1)

	// Close the pool's only session behind its back, simulating a module
	// reset or a token removal.
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		return b.p11ctx.CloseSession(session)
	}))

	found, err := findECDSASigner(pool, []byte("anything"))
	require.Nil(t, found)
	require.Error(t, err, "a broken session must not be reported as a missing key")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "pkcs11: FindObjectsInit for ECDSA private key", wrapped.Msg)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
}

// =============================================================================
// Generated key templates
//
// The two tests below cover attributes that C_GenerateKeyPair writes once, at
// creation, and that PKCS#11 3.2 §4.9 then makes unmodifiable or one-way. A
// mistake in the template is therefore permanent for every key the backend has
// ever generated, and it is invisible to the signing tests: a key with the
// wrong CKA_DERIVE still signs perfectly.
// =============================================================================

// findGeneratedPrivateKey returns the handle of the private key object that a
// generation call with this CKA_ID left on the token.
func findGeneratedPrivateKey(t *testing.T, b *Backend, session pkcs11.SessionHandle, id []byte) pkcs11.ObjectHandle {
	t.Helper()

	return findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
}

// TestGenerateECDSA_KeyAgreesWithPeerOverECDH is the production-path test for
// CKA_DERIVE: a key generated through Backend.GenerateECDSAWithCurve is handed
// straight to Backend.DeriveKeyECDH, which is the only combination of this
// backend's own calls a caller can make to reach hardware ECDH.
//
// That combination used to fail with CKR_KEY_FUNCTION_NOT_PERMITTED while the
// ECDH suite was green, because the suite provisioned its own key pairs with
// CKA_DERIVE instead of generating them the way a caller does.
//
// The oracle is crypto/ecdh computing the same agreement from the peer's side,
// never the backend's own inverse: the token derives from its private key and
// the peer's point, the test derives from the peer's private key and the
// token's point, and ECDH means those two values are equal.
func TestGenerateECDSA_KeyAgreesWithPeerOverECDH(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			b := newProvisionedBackend(t, "ecdsa-generate-ecdh")

			attrs := &types.KeyAttributes{
				CN:            "ecdh-from-generate-" + curve.Params().Name,
				KeyType:       backend.KEY_TYPE_TLS,
				StoreType:     backend.STORE_PKCS11,
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: curve},
			}

			signer, err := b.GenerateECDSAWithCurve(attrs, curve)
			require.NoError(t, err, "key generation on the provisioned token must succeed")

			tokenPublic, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "an EC signer reports an ECDSA public key")
			tokenECDHPublic, err := tokenPublic.ECDH()
			require.NoError(t, err)

			peerPrivate, err := ecdhCurveFor(t, curve).GenerateKey(rand.Reader)
			require.NoError(t, err)
			peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
			require.NoError(t, err)

			kdfParams := &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				Info:      []byte("pkcs11-generated-key-agreement"),
				KeyLength: 32,
			}

			derived, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, kdfParams)
			require.NoError(t, err,
				"a key this backend generated must be usable with this backend's own ECDH")

			peerSecret, err := peerPrivate.ECDH(tokenECDHPublic)
			require.NoError(t, err)
			require.Len(t, peerSecret, (curve.Params().BitSize+7)/8,
				"CKD_NULL agrees on the full field element, leading zeros included")

			expected, err := applyKDF(peerSecret, kdfParams)
			require.NoError(t, err)
			require.Equal(t, expected, derived,
				"the token and the peer disagree on the ECDH shared secret")

			// The peer's point has to reach the token: a second, unrelated peer
			// must not produce the same key. Without this a token that ignored
			// the mechanism parameter and returned a constant would still pass
			// the comparison above on the first peer alone.
			otherPeer, err := ecdhCurveFor(t, curve).GenerateKey(rand.Reader)
			require.NoError(t, err)
			otherSPKI, err := x509.MarshalPKIXPublicKey(otherPeer.PublicKey())
			require.NoError(t, err)

			otherDerived, err := b.DeriveKeyECDH(context.Background(), attrs, otherSPKI, kdfParams)
			require.NoError(t, err)
			require.NotEqual(t, derived, otherDerived,
				"a different peer key must produce a different shared secret")

			// Bad input on the same production path: a peer key that is neither
			// SubjectPublicKeyInfo nor an uncompressed point must be refused
			// rather than fed to the token.
			_, err = b.DeriveKeyECDH(context.Background(), attrs, []byte("not a public key"), kdfParams)
			require.Error(t, err, "a malformed peer public key must not derive a key")
		})
	}
}

// TestGenerateECDSA_PrivateKeyProtectionIsExplicit asserts the protection
// attributes of a generated EC private key, and then asserts that the token
// enforces them.
//
// The values are written into the template rather than left to the token
// because PKCS#11 3.2 §4.9 makes the generated defaults for CKA_SENSITIVE and
// CKA_EXTRACTABLE token-specific. SoftHSM2 happens to pick the same values this
// backend asks for, which is exactly why reading them back is not enough on its
// own -- the assertions below would hold on this token even if the template
// omitted both attributes. What they pin down is the contract every other
// module must now also meet.
func TestGenerateECDSA_PrivateKeyProtectionIsExplicit(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-protection")

	id := []byte("ecdsa-protection-key")
	_, err := generateECDSAKeyPair(b.pool, id, id, elliptic.P256(), false, "", "")
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle := findGeneratedPrivateKey(t, b, session, id)

	flags := readBoolAttributes(t, b, session, handle,
		pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_DERIVE,
		pkcs11.CKA_SIGN, pkcs11.CKA_NEVER_EXTRACTABLE)

	require.True(t, flags[0], "CKA_SENSITIVE must be true: the private key is never disclosed in plaintext")
	require.False(t, flags[1], "CKA_EXTRACTABLE must be false: a key born in the token may not be wrapped out")
	require.True(t, flags[2], "CKA_DERIVE must be true: an EC private key is the base key of CKM_ECDH1_DERIVE")
	require.True(t, flags[3], "CKA_SIGN must be true: the generated object is a signing key")
	require.True(t, flags[4], "CKA_NEVER_EXTRACTABLE records that the key was never wrappable")

	// Enforcement, not just the stored value. CKA_SENSITIVE is what stops
	// plaintext disclosure, so C_GetAttributeValue must refuse to read the
	// private scalar.
	_, err = b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE),
		"a sensitive key must not reveal CKA_VALUE")

	// CKA_EXTRACTABLE is the separate control over C_WrapKey, and it is the one
	// that governs backup and escrow. The token must refuse to wrap the key out
	// even under a key that is allowed to wrap.
	kek := generateAESWrappingKey(t, b, session)
	_, err = b.p11ctx.WrapKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}, kek, handle)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_KEY_UNEXTRACTABLE),
		"a non-extractable key must not be wrappable, whatever the wrapping key is")

	// PKCS#11 3.2 §4.9 allows CKA_EXTRACTABLE to move from CK_TRUE to CK_FALSE
	// and never back, so the choice made at generation is permanent. Asserting
	// it here is what makes the doc comment on generatedKeySensitive a
	// verifiable claim rather than a note.
	err = b.p11ctx.SetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	})
	require.Error(t, err, "CKA_EXTRACTABLE is one-way: false must not be relaxed back to true")
}

// generateAESWrappingKey creates a session-lifetime AES key that is allowed to
// wrap, for tests that need to prove the token refuses to wrap something.
func generateAESWrappingKey(t *testing.T, b *Backend, session pkcs11.SessionHandle) pkcs11.ObjectHandle {
	t.Helper()

	handle, err := b.p11ctx.GenerateKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		})
	require.NoError(t, err, "the token must generate an AES wrapping key")

	return handle
}
