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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/miekg/pkcs11"
)

// ECDSA curve OIDs (ASN.1 DER-encoded).
var (
	oidP256 asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521 asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// curveToOID maps elliptic.Curve to its ASN.1 OID.
var curveToOID = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P256(): oidP256,
	elliptic.P384(): oidP384,
	elliptic.P521(): oidP521,
}

// oidToCurve maps DER-encoded OID bytes to elliptic.Curve for public key parsing.
// Populated in init() from curveToOID.
var oidToCurve map[string]elliptic.Curve

func init() {
	oidToCurve = make(map[string]elliptic.Curve, len(curveToOID))
	for curve, oid := range curveToOID {
		encoded, err := asn1.Marshal(oid)
		if err != nil {
			continue
		}
		oidToCurve[string(encoded)] = curve
	}
}

// ecdsaSignature is the ASN.1 structure for an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// pkcs11ECDSASigner implements crypto.Signer for ECDSA keys stored in a PKCS#11 HSM.
// All signing operations are performed on the hardware; private key material
// never leaves the device.
type pkcs11ECDSASigner struct {
	pool          *SessionPool
	privateHandle pkcs11.ObjectHandle
	publicKey     *ecdsa.PublicKey
	label         string
}

// Compile-time interface check.
var _ crypto.Signer = (*pkcs11ECDSASigner)(nil)

// Public returns the ECDSA public key corresponding to the hardware-backed private key.
func (s *pkcs11ECDSASigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the ECDSA private key on the HSM.
// The raw R||S output from PKCS#11 CKM_ECDSA is converted to ASN.1 DER encoding
// as required by the Go crypto.Signer interface.
func (s *pkcs11ECDSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	var rawSig []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: ECDSA SignInit", Err: err}
		}

		var err error
		rawSig, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: ECDSA Sign", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// PKCS#11 CKM_ECDSA returns raw R||S (each component is half the signature length).
	// Convert to ASN.1 DER encoding.
	if len(rawSig)%2 != 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("pkcs11: ECDSA raw signature has odd length: %d", len(rawSig))}
	}
	componentLen := len(rawSig) / 2
	r := new(big.Int).SetBytes(rawSig[:componentLen])
	s2 := new(big.Int).SetBytes(rawSig[componentLen:])

	return asn1.Marshal(ecdsaSignature{R: r, S: s2})
}

// uncompressedPointLen returns the encoded length of a bare X9.62 uncompressed
// point on curve: the 0x04 marker followed by the two affine coordinates, each
// left-padded to the curve's field size.
func uncompressedPointLen(curve elliptic.Curve) int {
	return 1 + 2*((curve.Params().BitSize+7)/8)
}

// decodeECPoint returns the bare uncompressed point carried by a CKA_EC_POINT
// attribute value, unwrapping the DER OCTET STRING that PKCS#11 v3.2 §6.3.3
// Table 64 prescribes when the token supplied one.
//
// Tokens disagree about the wrapper — some store the DER OCTET STRING the
// standard names, others store the bare point — and the two forms cannot be
// told apart by their leading byte, because 0x04 is both the OCTET STRING tag
// and the uncompressed-point marker. The length is the discriminator, and it is
// exact rather than a heuristic: for a curve over a byteLen-byte field the bare
// point is always 1+2*byteLen bytes, while any DER OCTET STRING wrapping it
// carries at least a tag and a length octet on top of those bytes and is
// therefore strictly longer. No content byte of a point can move it from one
// case to the other, so the curve read from CKA_EC_PARAMS is all the
// information this decision needs.
//
// An attribute value that is neither form is reported rather than guessed at: a
// public key assembled from misread bytes verifies nothing.
func decodeECPoint(curve elliptic.Curve, ecPoint []byte) ([]byte, error) {
	want := uncompressedPointLen(curve)
	if len(ecPoint) == want {
		return ecPoint, nil
	}

	var wrapped []byte
	rest, err := asn1.Unmarshal(ecPoint, &wrapped)
	if err != nil {
		return nil, &errs.Detail{
			Err:    ErrInvalidKeyAttributes,
			Detail: fmt.Sprintf("CKA_EC_POINT holds %d bytes: neither a %d-byte uncompressed point on %s nor a DER OCTET STRING", len(ecPoint), want, curve.Params().Name),
		}
	}
	if len(rest) > 0 {
		return nil, &errs.Detail{
			Err:    ErrInvalidKeyAttributes,
			Detail: fmt.Sprintf("CKA_EC_POINT has %d trailing bytes after its DER OCTET STRING", len(rest)),
		}
	}
	if len(wrapped) != want {
		return nil, &errs.Detail{
			Err:    ErrInvalidKeyAttributes,
			Detail: fmt.Sprintf("CKA_EC_POINT wraps %d bytes, want a %d-byte uncompressed point on %s", len(wrapped), want, curve.Params().Name),
		}
	}
	return wrapped, nil
}

// exportECDSAPublicKey extracts the ECDSA public key from a PKCS#11 public key object.
// It reads CKA_EC_PARAMS (curve OID) and CKA_EC_POINT (uncompressed point) attributes.
func exportECDSAPublicKey(pool *SessionPool, pubHandle pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	var pub *ecdsa.PublicKey
	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		attrs, err := pool.Ctx().GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: get ECDSA public key attributes", Err: err}
		}

		if len(attrs) < 2 || len(attrs[0].Value) == 0 || len(attrs[1].Value) == 0 {
			return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "missing EC params or point"}
		}

		// Parse curve from OID
		curve, ok := oidToCurve[string(attrs[0].Value)]
		if !ok {
			return &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: "unknown EC curve OID"}
		}

		pointBytes, err := decodeECPoint(curve, attrs[1].Value)
		if err != nil {
			return err
		}

		// The length is already known to be right, so Unmarshal is now only
		// deciding whether the coordinates name a point that is actually on the
		// curve.
		x, y := elliptic.Unmarshal(curve, pointBytes) //nolint:staticcheck // SA1019: PKCS#11 CKA_EC_POINT is the uncompressed-point wire format elliptic.Unmarshal decodes directly; crypto/ecdh migration is a separate, behavior-sensitive change
		if x == nil {
			return &errs.Detail{
				Err:    ErrInvalidKeyAttributes,
				Detail: fmt.Sprintf("CKA_EC_POINT is not an uncompressed point on %s", curve.Params().Name),
			}
		}

		pub = &ecdsa.PublicKey{
			Curve: curve,
			X:     x, //nolint:staticcheck // SA1019: x/y are the coordinates elliptic.Unmarshal just decoded from CKA_EC_POINT above
			Y:     y, //nolint:staticcheck // SA1019: see X above
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// buildYubiKeyECDSATemplates returns the minimal ECDSA key pair templates required
// by YubiKey's libykcs11. YubiKey PIV slots set CKA_TOKEN, CKA_SIGN, CKA_VERIFY,
// CKA_PRIVATE, and CKA_SENSITIVE automatically based on the slot; supplying them
// explicitly causes CKR_ATTRIBUTE_VALUE_INVALID.
func buildYubiKeyECDSATemplates(id, encodedOID []byte) (pub, priv []*pkcs11.Attribute) {
	pub = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedOID),
	}
	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	return pub, priv
}

// generateECDSAKeyPair generates an ECDSA key pair on the HSM using the raw PKCS#11 API
// and returns a pkcs11ECDSASigner wrapping the handles.
//
// When isYubiKeyPIV is true, a minimal attribute template is used as required by
// YubiKey's libykcs11 (which rejects extra attributes with CKR_ATTRIBUTE_VALUE_INVALID).
// Otherwise, the full template suitable for SoftHSM and generic PKCS#11 modules is used.
//
// The generic private key template grants CKA_DERIVE as well as CKA_SIGN. An EC
// private key is the base key of CKM_ECDH1_DERIVE, and PKCS#11 3.2 §4.9 defaults
// CKA_DERIVE to CK_FALSE, so a template that omits it produces a key the token
// refuses to derive from: Backend.DeriveKeyECDH fails with
// CKR_KEY_FUNCTION_NOT_PERMITTED for every key this function generated. The flag
// has to be granted at generation because §4.9 makes CKA_DERIVE modifiable only
// while the object is being created.
//
// CKA_DERIVE is granted on the private half alone. C_DeriveKey takes the local
// private key as its base key and the peer's point as a mechanism parameter, so
// the public object is never a base key and does not need the permission.
//
// For CKA_SENSITIVE and CKA_EXTRACTABLE see generatedKeySensitive.
func generateECDSAKeyPair(pool *SessionPool, id, label []byte, curve elliptic.Curve, isYubiKeyPIV bool, soPIN, userPIN string) (*pkcs11ECDSASigner, error) {
	oid, ok := curveToOID[curve]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unsupported curve: %s", curve.Params().Name)}
	}

	encodedOID, err := asn1.Marshal(oid)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: marshal curve OID", Err: err}
	}

	var pubTemplate, privTemplate []*pkcs11.Attribute
	if isYubiKeyPIV {
		pubTemplate, privTemplate = buildYubiKeyECDSATemplates(id, encodedOID)
	} else {
		pubTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedOID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
		privTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, generatedKeySensitive),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, generatedKeyExtractable),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
	}

	var pubHandle, privHandle pkcs11.ObjectHandle
	genFn := func(session pkcs11.SessionHandle) error {
		var err error
		pubHandle, privHandle, err = pool.Ctx().GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			pubTemplate,
			privTemplate,
		)
		return err
	}
	if isYubiKeyPIV {
		if soPIN == "" {
			return nil, &errs.Wrapped{Msg: "pkcs11: generate ECDSA key pair", Err: ErrSOPINRequired}
		}
		err = pool.WithSOSession(soPIN, userPIN, genFn)
	} else {
		err = pool.WithSession(genFn)
	}
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: generate ECDSA key pair", Err: err}
	}

	pub, err := exportECDSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: export ECDSA public key after generation", Err: err}
	}

	return &pkcs11ECDSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(label),
	}, nil
}

// findECDSASigner locates an ECDSA key pair by CKA_ID and returns a pkcs11ECDSASigner.
func findECDSASigner(pool *SessionPool, id []byte) (*pkcs11ECDSASigner, error) {
	var privHandle, pubHandle pkcs11.ObjectHandle
	var found bool

	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		// Find private key
		priv, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: FindObjectsInit for ECDSA private key", Err: err}
		}
		if priv == 0 {
			return nil // not found
		}
		privHandle = priv

		// Find public key
		pub, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: FindObjectsInit for ECDSA public key", Err: err}
		}
		if pub == 0 {
			return nil
		}
		pubHandle = pub
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	pub, err := exportECDSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, err
	}

	return &pkcs11ECDSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(id),
	}, nil
}
