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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/hkdf"
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

// CK_ECDH1_DERIVE_PARAMS represents the parameters for CKM_ECDH1_DERIVE mechanism
// Per PKCS#11 v2.40/v3.0 specification, this structure contains:
//   - kdf: Key derivation function to apply (CKD_NULL, CKD_SHA256_KDF, etc.)
//   - pSharedData: Optional shared data for the KDF (typically nil)
//   - pPublicData: The peer's EC public key point (uncompressed format)
type ecdhDeriveParams struct {
	kdf        uint
	sharedData []byte
	publicData []byte
}

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
		return nil, fmt.Errorf("%w: %v", ErrInvalidKDFParams, err)
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
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Get slot
	slot, err := b.getSlot()
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login if required
	if b.config.PIN != "" {
		if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				return nil, fmt.Errorf("failed to login: %w", err)
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
		return nil, fmt.Errorf("failed to apply KDF: %w", err)
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
		return fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
	}

	if err := p.Initialize(); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			return fmt.Errorf("failed to initialize PKCS#11: %w", err)
		}
	}

	b.p11ctx = p
	return nil
}

// getSlot returns the configured slot or the first available slot.
// Must be called with b.mu held and p11ctx initialized.
func (b *Backend) getSlot() (uint, error) {
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}
	if len(slots) == 0 {
		return 0, ErrTokenNotFound
	}

	if b.config.Slot != nil {
		return uint(*b.config.Slot), nil
	}
	return slots[0], nil
}

// findPrivateKeyHandle finds a private key object by its attributes.
func (b *Backend) findPrivateKeyHandle(session pkcs11.SessionHandle, attrs *types.KeyAttributes) (pkcs11.ObjectHandle, error) {
	label := createKeyID(attrs)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := b.p11ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init find objects: %w", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	handles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(handles) == 0 {
		return 0, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return handles[0], nil
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

	// Build the CK_ECDH1_DERIVE_PARAMS structure
	// PKCS#11 requires this to be serialized as:
	// - 4 bytes: kdf (CK_EC_KDF_TYPE)
	// - 4 bytes: ulSharedDataLen
	// - pointer to shared data (we'll use 0/nil)
	// - 4 bytes: ulPublicDataLen
	// - pointer to public data
	//
	// However, miekg/pkcs11 expects the parameters differently.
	// We use the NewMechanism with raw parameter bytes.
	ecdhParams := buildECDH1DeriveParams(CKD_NULL, nil, peerPoint)

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
		return nil, fmt.Errorf("ECDH derivation failed: %w", err)
	}
	defer b.p11ctx.DestroyObject(session, derivedHandle)

	// Extract the shared secret value
	secretAttrs, err := b.p11ctx.GetAttributeValue(session, derivedHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to extract shared secret: %w", err)
	}

	if len(secretAttrs) == 0 || len(secretAttrs[0].Value) == 0 {
		return nil, fmt.Errorf("empty shared secret returned from HSM")
	}

	return secretAttrs[0].Value, nil
}

// buildECDH1DeriveParams constructs the CK_ECDH1_DERIVE_PARAMS byte slice
// for the miekg/pkcs11 library.
//
// Per PKCS#11 specification, the structure is:
//
//	typedef struct CK_ECDH1_DERIVE_PARAMS {
//	    CK_EC_KDF_TYPE kdf;
//	    CK_ULONG ulSharedDataLen;
//	    CK_BYTE_PTR pSharedData;
//	    CK_ULONG ulPublicDataLen;
//	    CK_BYTE_PTR pPublicData;
//	} CK_ECDH1_DERIVE_PARAMS;
//
// For miekg/pkcs11, we serialize this according to the library's expectations.
func buildECDH1DeriveParams(kdf uint, sharedData, publicData []byte) []byte {
	// miekg/pkcs11 expects the ECDH1 derive params in a specific format
	// The library handles the parameter structure internally when we pass:
	// - kdf type as uint32
	// - shared data length as uint32
	// - shared data bytes
	// - public data length as uint32
	// - public data bytes
	//
	// We'll construct this in little-endian format (platform-dependent, but most common)

	// For simplicity with miekg/pkcs11, we encode the parameters as the library expects
	// The library's Mechanism.Parameter expects a byte slice that it will parse
	//
	// Format: kdf(4 bytes) + sharedDataLen(4 bytes) + sharedData + pubDataLen(4 bytes) + pubData
	sharedLen := uint32(len(sharedData))
	pubLen := uint32(len(publicData))

	// Calculate total size
	size := 4 + 4 + len(sharedData) + 4 + len(publicData)
	params := make([]byte, size)

	offset := 0

	// KDF type (4 bytes, little-endian)
	params[offset] = byte(kdf)
	params[offset+1] = byte(kdf >> 8)
	params[offset+2] = byte(kdf >> 16)
	params[offset+3] = byte(kdf >> 24)
	offset += 4

	// Shared data length (4 bytes, little-endian)
	params[offset] = byte(sharedLen)
	params[offset+1] = byte(sharedLen >> 8)
	params[offset+2] = byte(sharedLen >> 16)
	params[offset+3] = byte(sharedLen >> 24)
	offset += 4

	// Shared data
	copy(params[offset:], sharedData)
	offset += len(sharedData)

	// Public data length (4 bytes, little-endian)
	params[offset] = byte(pubLen)
	params[offset+1] = byte(pubLen >> 8)
	params[offset+2] = byte(pubLen >> 16)
	params[offset+3] = byte(pubLen >> 24)
	offset += 4

	// Public data
	copy(params[offset:], publicData)

	return params
}

// parsePeerPublicKey parses the peer's public key bytes into an EC point.
// Accepts either:
//   - DER-encoded SubjectPublicKeyInfo (X.509 format)
//   - Raw uncompressed EC point (0x04 || X || Y)
//
// Returns the uncompressed point bytes and the curve.
func parsePeerPublicKey(pubKeyBytes []byte) ([]byte, elliptic.Curve, error) {
	if len(pubKeyBytes) == 0 {
		return nil, nil, fmt.Errorf("empty public key")
	}

	// Try to parse as DER-encoded SubjectPublicKeyInfo
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err == nil {
		ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("public key is not an ECDSA key")
		}
		// Marshal to uncompressed point format
		point := elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)
		return point, ecdsaPub.Curve, nil
	}

	// Try to parse as raw EC point
	// Uncompressed format: 0x04 || X || Y
	if pubKeyBytes[0] == 0x04 {
		// Determine curve from point size
		pointLen := len(pubKeyBytes)
		var curve elliptic.Curve

		switch pointLen {
		case 65: // P-256: 1 + 32 + 32
			curve = elliptic.P256()
		case 97: // P-384: 1 + 48 + 48
			curve = elliptic.P384()
		case 133: // P-521: 1 + 66 + 66
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported EC point size: %d", pointLen)
		}

		// Validate the point is on the curve
		x, _ := elliptic.Unmarshal(curve, pubKeyBytes)
		if x == nil {
			return nil, nil, fmt.Errorf("invalid EC point: not on curve")
		}

		return pubKeyBytes, curve, nil
	}

	// Try to unwrap ASN.1 OCTET STRING if present
	var octetString []byte
	if _, err := asn1.Unmarshal(pubKeyBytes, &octetString); err == nil {
		if len(octetString) > 0 && octetString[0] == 0x04 {
			return parsePeerPublicKey(octetString)
		}
	}

	return nil, nil, fmt.Errorf("unrecognized public key format")
}

// applyKDF applies the specified key derivation function to the shared secret.
func applyKDF(sharedSecret []byte, params *types.KDFParams) ([]byte, error) {
	// Get the hash function
	hashFunc, err := getHashFunc(params.Hash)
	if err != nil {
		return nil, err
	}

	switch params.Algorithm {
	case types.KDFAlgorithmHKDF:
		return applyHKDF(sharedSecret, params.Salt, params.Info, params.KeyLength, hashFunc)

	case types.KDFAlgorithmX963:
		// ANSI X9.63 KDF - commonly used with ECDH
		return applyX963KDF(sharedSecret, params.Info, params.KeyLength, hashFunc)

	case types.KDFAlgorithmSP80056A:
		// NIST SP 800-56A Concatenation KDF
		return applySP80056AKDF(sharedSecret, params.Info, params.KeyLength, hashFunc)

	default:
		return nil, fmt.Errorf("unsupported KDF algorithm for ECDH: %s", params.Algorithm)
	}
}

// getHashFunc returns a hash function constructor for the specified algorithm name.
func getHashFunc(hashName string) (func() hash.Hash, error) {
	switch hashName {
	case "SHA-256":
		return sha256.New, nil
	case "SHA-384":
		return sha512.New384, nil
	case "SHA-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashName)
	}
}

// applyHKDF applies HKDF (RFC 5869) to derive a key from the shared secret.
func applyHKDF(secret, salt, info []byte, keyLen int, hashFunc func() hash.Hash) ([]byte, error) {
	reader := hkdf.New(hashFunc, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("HKDF expansion failed: %w", err)
	}
	return key, nil
}

// applyX963KDF applies ANSI X9.63 KDF to derive a key from the shared secret.
// X9.63 KDF: Key = H(Z || Counter || SharedInfo)
func applyX963KDF(secret, sharedInfo []byte, keyLen int, hashFunc func() hash.Hash) ([]byte, error) {
	h := hashFunc()
	hashLen := h.Size()
	reps := (keyLen + hashLen - 1) / hashLen

	if reps > 0xFFFFFFFF {
		return nil, fmt.Errorf("requested key length too large")
	}

	var derivedKey []byte
	counter := make([]byte, 4)

	for i := uint32(1); i <= uint32(reps); i++ {
		// Counter is big-endian per X9.63
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		h.Reset()
		h.Write(secret)
		h.Write(counter)
		if len(sharedInfo) > 0 {
			h.Write(sharedInfo)
		}
		derivedKey = append(derivedKey, h.Sum(nil)...)
	}

	return derivedKey[:keyLen], nil
}

// applySP80056AKDF applies NIST SP 800-56A Concatenation KDF.
// Similar to X9.63 but with different structure: Key = H(Counter || Z || OtherInfo)
func applySP80056AKDF(secret, otherInfo []byte, keyLen int, hashFunc func() hash.Hash) ([]byte, error) {
	h := hashFunc()
	hashLen := h.Size()
	reps := (keyLen + hashLen - 1) / hashLen

	if reps > 0xFFFFFFFF {
		return nil, fmt.Errorf("requested key length too large")
	}

	var derivedKey []byte
	counter := make([]byte, 4)

	for i := uint32(1); i <= uint32(reps); i++ {
		// Counter is big-endian per SP 800-56A
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		h.Reset()
		h.Write(counter)
		h.Write(secret)
		if len(otherInfo) > 0 {
			h.Write(otherInfo)
		}
		derivedKey = append(derivedKey, h.Sum(nil)...)
	}

	return derivedKey[:keyLen], nil
}

// GetPublicKeyBytes returns the DER-encoded public key for a key pair.
// This is useful for sharing the public key with peers for ECDH.
func (b *Backend) GetPublicKeyBytes(attrs *types.KeyAttributes) ([]byte, error) {
	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, err
	}

	pubKey := signer.Public()
	return x509.MarshalPKIXPublicKey(pubKey)
}

// Ensure Backend implements KeyAgreementBackend at compile time
var _ types.KeyAgreementProvider = (*Backend)(nil)

// ecdhSigner wraps a crypto.Signer to provide ECDH capability.
// This is useful when you need to perform ECDH with a key that only exposes
// the crypto.Signer interface.
type ecdhSigner struct {
	backend *Backend
	attrs   *types.KeyAttributes
	signer  crypto.Signer
}
