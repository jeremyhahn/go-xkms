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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
)

// PKCS#11 ECDH mechanism constants
// These are defined in PKCS#11 specification for ECDH key derivation
const (
	// CKM_ECDH1_DERIVE is the mechanism for single-pass ECDH key derivation
	CKM_ECDH1_DERIVE = 0x00001050

	// CKM_ECDH1_COFACTOR_DERIVE is the mechanism for cofactor ECDH derivation
	CKM_ECDH1_COFACTOR_DERIVE = 0x00001051

	// CKD_NULL indicates no KDF is applied - raw shared secret is returned
	CKD_NULL = 0x00000001

	// CKD_SHA1_KDF uses SHA-1 based KDF (ANSI X9.63)
	CKD_SHA1_KDF = 0x00000002

	// CKD_SHA256_KDF uses SHA-256 based KDF (ANSI X9.63)
	CKD_SHA256_KDF = 0x00000006

	// CKD_SHA384_KDF uses SHA-384 based KDF (ANSI X9.63)
	CKD_SHA384_KDF = 0x00000007

	// CKD_SHA512_KDF uses SHA-512 based KDF (ANSI X9.63)
	CKD_SHA512_KDF = 0x00000008
)

// SupportedCurves returns the list of elliptic curves supported for ECDH key agreement.
// This queries the token's mechanism list to determine supported curves.
//
// Returns curve identifiers like "P-256", "P-384", "P-521" based on token capabilities.
func (b *Backend) SupportedCurves() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// If we don't have low-level context, return common defaults
	if b.p11ctx == nil {
		// Most HSMs support at least these NIST curves
		return []string{"P-256", "P-384", "P-521"}
	}

	// Get slot list
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return []string{"P-256", "P-384", "P-521"}
	}

	var slot uint
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	} else {
		slot = slots[0]
	}

	// Get mechanism list to check for ECDH support
	mechanisms, err := b.p11ctx.GetMechanismList(slot)
	if err != nil {
		return []string{"P-256", "P-384", "P-521"}
	}

	// Check if ECDH mechanisms are supported
	hasECDH := false
	for _, mech := range mechanisms {
		if mech.Mechanism == CKM_ECDH1_DERIVE || mech.Mechanism == CKM_ECDH1_COFACTOR_DERIVE {
			hasECDH = true
			break
		}
	}

	if !hasECDH {
		return []string{}
	}

	// Check for EC key pair generation to determine supported curves
	// The mechanism info will indicate the key size range
	hasECKeyGen := false
	for _, mech := range mechanisms {
		if mech.Mechanism == pkcs11.CKM_EC_KEY_PAIR_GEN {
			hasECKeyGen = true
			break
		}
	}

	if !hasECKeyGen {
		return []string{}
	}

	// Most PKCS#11 tokens that support EC support NIST curves
	// Return the standard set - actual capability depends on key attributes
	return []string{"P-256", "P-384", "P-521"}
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key using the HSM.
//
// This method uses the PKCS#11 CKM_ECDH1_DERIVE mechanism to perform the key agreement
// on the hardware security module. The private key never leaves the HSM.
//
// The operation:
//  1. Retrieves the private key identified by privateKeyAttrs from the HSM
//  2. Parses the peer's public key from peerPublicKey bytes
//  3. Uses CKM_ECDH1_DERIVE with CKD_NULL to compute the raw shared secret on HSM
//  4. Applies the software KDF specified in kdfParams to derive the final key
//
// Parameters:
//   - ctx: Context for cancellation and deadline propagation
//   - privateKeyAttrs: Attributes identifying the local private key on the HSM
//   - peerPublicKey: The peer's public key in DER-encoded SubjectPublicKeyInfo format
//     or uncompressed EC point format (0x04 || X || Y)
//   - kdfParams: Parameters for the key derivation function
//
// Returns the derived key bytes or an error if the operation fails.
//
// Security considerations:
//   - The private key remains in the HSM at all times
//   - The raw ECDH shared secret is computed in hardware
//   - The KDF is applied in software using the shared secret from HSM
//   - For maximum security, use HSM-based KDF if supported by your token
func (b *Backend) DeriveKeyECDH(
	ctx context.Context,
	privateKeyAttrs *types.KeyAttributes,
	peerPublicKey []byte,
	kdfParams *types.KDFParams,
) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Validate inputs
	if privateKeyAttrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if len(peerPublicKey) == 0 {
		return nil, ErrInvalidPeerPublicKey
	}
	if kdfParams == nil {
		return nil, ErrInvalidKDFParams
	}

	// Validate KDF parameters
	if err := kdfParams.Validate(); err != nil {
		return nil, &errs.Detail{Err: ErrInvalidKDFParams, Detail: fmt.Sprintf("%v", err)}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrNotInitialized
	}

	// Initialize low-level PKCS#11 context if needed
	if err := b.ensureP11Context(); err != nil {
		return nil, err
	}

	// Parse the peer's public key to extract the EC point
	peerPoint, curve, err := parsePeerPublicKey(peerPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse peer public key", Err: err}
	}

	// Resolve the slot through the backend's one label-aware resolver rather
	// than assuming the token is first in the module's enumeration.
	slot, err := b.resolveSlot()
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to open session", Err: err}
	}
	defer b.p11ctx.CloseSession(session)

	// Login if required
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, &errs.Wrapped{Msg: "failed to login", Err: err}
			}
		}
	}

	// Find the private key
	privKeyHandle, err := b.findPrivateKeyHandle(session, privateKeyAttrs)
	if err != nil {
		return nil, err
	}

	// Perform ECDH derivation on the HSM using CKD_NULL to get raw shared secret
	sharedSecret, err := b.deriveECDH(session, privKeyHandle, peerPoint, curve)
	if err != nil {
		return nil, err
	}

	// Apply software KDF to the shared secret
	derivedKey, err := applyKDF(sharedSecret, kdfParams)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to apply KDF", Err: err}
	}

	return derivedKey, nil
}

// ensureP11Context initializes the low-level PKCS#11 context if not already done.
// Must be called with b.mu held.
func (b *Backend) ensureP11Context() error {
	if b.p11ctx != nil {
		return nil
	}

	p := pkcs11.New(b.config.Library)
	if p == nil {
		return &errs.Message{Msg: fmt.Sprintf("failed to load PKCS#11 library: %s", b.config.Library)}
	}

	if err := p.Initialize(); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			return &errs.Wrapped{Msg: "failed to initialize PKCS#11", Err: err}
		}
	}

	b.p11ctx = p
	return nil
}

// findPrivateKeyHandle finds a private key object by its attributes.
func (b *Backend) findPrivateKeyHandle(session pkcs11.SessionHandle, attrs *types.KeyAttributes) (pkcs11.ObjectHandle, error) {
	label := createKeyID(attrs)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
		return 0, &errs.Wrapped{Msg: "failed to init find objects", Err: err}
	}
	defer b.p11ctx.FindObjectsFinal(session)

	handles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return 0, &errs.Wrapped{Msg: "failed to find objects", Err: err}
	}

	if len(handles) == 0 {
		return 0, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	return handles[0], nil
}

// namedCurveOIDs maps the curves this backend agrees on to their ASN.1 object
// identifiers. CKA_EC_PARAMS holds the DER encoding of the ECParameters CHOICE,
// which for these NIST curves is the namedCurve alternative: a bare OID.
var namedCurveOIDs = map[string]asn1.ObjectIdentifier{
	elliptic.P256().Params().Name: {1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384().Params().Name: {1, 3, 132, 0, 34},
	elliptic.P521().Params().Name: {1, 3, 132, 0, 35},
}

// requireMatchingCurve fails unless the token's private key sits on the same
// curve as the peer's public key.
//
// ECDH across two different curves is meaningless: the peer point is not even a
// member of the private key's group, and a token is free to return a value
// anyway. types.KeyAgreementProvider documents ErrCurveMismatch for this, and
// the software backend already returns it, so the hardware backend must agree.
func (b *Backend) requireMatchingCurve(
	session pkcs11.SessionHandle,
	privKeyHandle pkcs11.ObjectHandle,
	peerCurve elliptic.Curve,
) error {
	peerOID, ok := namedCurveOIDs[peerCurve.Params().Name]
	if !ok {
		return &errs.Detail{Err: ErrECDHNotSupported, Detail: fmt.Sprintf("curve %s", peerCurve.Params().Name)}
	}

	peerParams, err := asn1.Marshal(peerOID)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to encode peer curve OID", Err: err}
	}

	attrs, err := b.p11ctx.GetAttributeValue(session, privKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to read CKA_EC_PARAMS from the private key", Err: err}
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "private key exposes no CKA_EC_PARAMS; it is not an EC key"}
	}

	if !bytes.Equal(attrs[0].Value, peerParams) {
		return &errs.Detail{Err: ErrCurveMismatch, Detail: fmt.Sprintf(
			"peer public key uses %s, which does not match the private key's CKA_EC_PARAMS", peerCurve.Params().Name)}
	}

	return nil
}

// deriveECDH performs the ECDH key derivation on the HSM.
func (b *Backend) deriveECDH(
	session pkcs11.SessionHandle,
	privKeyHandle pkcs11.ObjectHandle,
	peerPoint []byte,
	curve elliptic.Curve,
) ([]byte, error) {
	// Determine the expected shared secret size based on the curve
	secretSize := (curve.Params().BitSize + 7) / 8

	// Refuse to derive against a peer key on a different curve. PKCS#11 leaves
	// the outcome of a cross-curve C_DeriveKey to the token, and the
	// types.KeyAgreementProvider contract requires ErrCurveMismatch here.
	if err := b.requireMatchingCurve(session, privKeyHandle, curve); err != nil {
		return nil, err
	}

	// Build CK_ECDH1_DERIVE_PARAMS.
	//
	// The struct holds two CK_BYTE_PTRs, so it cannot be serialized by hand
	// from Go: pSharedData and pPublicData are addresses of C memory, not
	// inline data, and CK_ULONG is 8 bytes on every platform this runs on.
	// NewECDH1DeriveParams builds the real C structure and keeps the pointed-to
	// buffers alive for the duration of the call.
	ecdhParams := pkcs11.NewECDH1DeriveParams(CKD_NULL, nil, peerPoint)

	// Create the mechanism with parameters
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_ECDH1_DERIVE, ecdhParams),
	}

	// Template for the derived key object
	// We derive a generic secret key to extract the raw shared secret
	derivedTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), // Session object
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, secretSize),
	}

	// Perform the derivation
	derivedHandle, err := b.p11ctx.DeriveKey(session, mechanism, privKeyHandle, derivedTemplate)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH derivation failed", Err: err}
	}
	defer b.p11ctx.DestroyObject(session, derivedHandle)

	// Extract the shared secret value
	secretAttrs, err := b.p11ctx.GetAttributeValue(session, derivedHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to extract shared secret", Err: err}
	}

	if len(secretAttrs) == 0 || len(secretAttrs[0].Value) == 0 {
		return nil, &errs.Message{Msg: "empty shared secret returned from HSM"}
	}

	return secretAttrs[0].Value, nil
}

// curveForUncompressedPoint returns the curve an uncompressed EC point of the
// given length belongs to. The length is unambiguous across the supported
// curves: 1 + 2*coordinate size, so 65, 97 and 133 bytes.
func curveForUncompressedPoint(length int) (elliptic.Curve, bool) {
	switch length {
	case 65:
		return elliptic.P256(), true
	case 97:
		return elliptic.P384(), true
	case 133:
		return elliptic.P521(), true
	}
	return nil, false
}

// uncompressedPoint validates a bare uncompressed EC point and returns it with
// its curve.
func uncompressedPoint(candidate []byte) ([]byte, elliptic.Curve, error) {
	curve, ok := curveForUncompressedPoint(len(candidate))
	if !ok {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("unsupported EC point size: %d", len(candidate))}
	}

	// Unmarshal rejects points that are not on the curve, which is what stops
	// an invalid-curve attack: a peer that submits a point on a weaker curve
	// can otherwise recover the private key from a sequence of derivations.
	if x, _ := elliptic.Unmarshal(curve, candidate); x == nil {
		return nil, nil, &errs.Message{Msg: "invalid EC point: not on curve"}
	}

	return candidate, curve, nil
}

// parsePeerPublicKey parses the peer's public key bytes into an EC point.
// Accepts, in order of preference:
//   - DER-encoded SubjectPublicKeyInfo (X.509 format)
//   - Raw uncompressed EC point (0x04 || X || Y)
//   - An ASN.1 OCTET STRING wrapping an uncompressed point, which is how
//     PKCS#11 tokens store CKA_EC_POINT and therefore how a peer that copies
//     that attribute verbatim sends its key
//
// Returns the uncompressed point bytes and the curve.
//
// The three encodings cannot be told apart by their first byte: 0x04 is both
// the uncompressed point marker and the ASN.1 OCTET STRING tag. Length is the
// discriminator, so a leading 0x04 that is not a valid point length falls
// through to the OCTET STRING attempt rather than being rejected outright.
func parsePeerPublicKey(pubKeyBytes []byte) ([]byte, elliptic.Curve, error) {
	if len(pubKeyBytes) == 0 {
		return nil, nil, ErrInvalidPeerPublicKey
	}

	// SubjectPublicKeyInfo.
	if pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes); err == nil {
		ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, &errs.Detail{Err: ErrInvalidPeerPublicKey, Detail: "public key is not an ECDSA key"}
		}
		return elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y), ecdsaPub.Curve, nil
	}

	// Bare uncompressed point.
	if pubKeyBytes[0] == 0x04 {
		if _, ok := curveForUncompressedPoint(len(pubKeyBytes)); ok {
			return uncompressedPoint(pubKeyBytes)
		}
	}

	// OCTET STRING wrapping an uncompressed point.
	var octetString []byte
	if _, err := asn1.Unmarshal(pubKeyBytes, &octetString); err == nil {
		if len(octetString) > 0 && octetString[0] == 0x04 {
			return uncompressedPoint(octetString)
		}
	}

	return nil, nil, &errs.Detail{Err: ErrInvalidPeerPublicKey, Detail: "unrecognized public key format"}
}

// applyKDF derives a key from an ECDH shared secret using the canonical KDF
// implementation in pkg/crypto/kdf, reached through types.KDFParams.Derive.
// Every backend derives through that one entry point, so the same parameters
// yield the same bytes here as on the TPM 2.0, software, and phone backends.
func applyKDF(sharedSecret []byte, params *types.KDFParams) ([]byte, error) {
	if params == nil {
		return nil, ErrInvalidKDFParams
	}
	return params.Derive(sharedSecret)
}

// GetPublicKeyBytes returns the DER-encoded public key for a key pair.
// This is useful for sharing the public key with peers for ECDH.
func (b *Backend) GetPublicKeyBytes(attrs *types.KeyAttributes) ([]byte, error) {
	signer, err := b.Signer(context.Background(), attrs)
	if err != nil {
		return nil, err
	}

	pubKey := signer.Public()
	return x509.MarshalPKIXPublicKey(pubKey)
}

// Ensure Backend implements KeyAgreementBackend at compile time
var _ types.KeyAgreementProvider = (*Backend)(nil)
