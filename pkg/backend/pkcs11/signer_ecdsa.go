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
			return fmt.Errorf("pkcs11: ECDSA SignInit: %w", err)
		}

		var err error
		rawSig, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return fmt.Errorf("pkcs11: ECDSA Sign: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// PKCS#11 CKM_ECDSA returns raw R||S (each component is half the signature length).
	// Convert to ASN.1 DER encoding.
	if len(rawSig)%2 != 0 {
		return nil, fmt.Errorf("pkcs11: ECDSA raw signature has odd length: %d", len(rawSig))
	}
	componentLen := len(rawSig) / 2
	r := new(big.Int).SetBytes(rawSig[:componentLen])
	s2 := new(big.Int).SetBytes(rawSig[componentLen:])

	return asn1.Marshal(ecdsaSignature{R: r, S: s2})
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
			return fmt.Errorf("pkcs11: get ECDSA public key attributes: %w", err)
		}

		if len(attrs) < 2 || len(attrs[0].Value) == 0 || len(attrs[1].Value) == 0 {
			return fmt.Errorf("%w: missing EC params or point", ErrInvalidKeyAttributes)
		}

		// Parse curve from OID
		curve, ok := oidToCurve[string(attrs[0].Value)]
		if !ok {
			return fmt.Errorf("%w: unknown EC curve OID", ErrUnsupportedKeyAlgorithm)
		}

		// Parse EC point
		// CKA_EC_POINT is a DER-encoded OCTET STRING containing the uncompressed point (0x04 || X || Y)
		ecPoint := attrs[1].Value

		// Unwrap DER OCTET STRING if present
		var pointBytes []byte
		if len(ecPoint) > 2 && ecPoint[0] == 0x04 && int(ecPoint[1]) == len(ecPoint)-2 {
			// DER-encoded OCTET STRING: 0x04 <length> <data>
			pointBytes = ecPoint[2:]
		} else {
			// Try ASN.1 decode
			var rawPoint []byte
			rest, err := asn1.Unmarshal(ecPoint, &rawPoint)
			if err != nil || len(rest) > 0 {
				// Not ASN.1 encoded — use raw bytes
				pointBytes = ecPoint
			} else {
				pointBytes = rawPoint
			}
		}

		// Parse uncompressed point: 0x04 || X || Y
		x, y := elliptic.Unmarshal(curve, pointBytes)
		if x == nil {
			return fmt.Errorf("%w: invalid EC point encoding", ErrInvalidKeyAttributes)
		}

		pub = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
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
func generateECDSAKeyPair(pool *SessionPool, id, label []byte, curve elliptic.Curve, isYubiKeyPIV bool, soPIN, userPIN string) (*pkcs11ECDSASigner, error) {
	oid, ok := curveToOID[curve]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported curve: %s", ErrUnsupportedKeyAlgorithm, curve.Params().Name)
	}

	encodedOID, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: marshal curve OID: %w", err)
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
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
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
	if isYubiKeyPIV && soPIN != "" {
		err = pool.WithSOSession(soPIN, userPIN, genFn)
	} else {
		err = pool.WithSession(genFn)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs11: generate ECDSA key pair: %w", err)
	}

	pub, err := exportECDSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: export ECDSA public key after generation: %w", err)
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
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for ECDSA private key: %w", err)
		}
		privObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for ECDSA private key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for ECDSA private key: %w", err)
		}
		if len(privObjs) == 0 {
			return nil // not found
		}
		privHandle = privObjs[0]

		// Find public key
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for ECDSA public key: %w", err)
		}
		pubObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for ECDSA public key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for ECDSA public key: %w", err)
		}
		if len(pubObjs) == 0 {
			return nil
		}
		pubHandle = pubObjs[0]
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
