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

package software

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// supportedCurves defines the elliptic curves supported for key agreement.
var supportedCurves = []string{"P-256", "P-384", "P-521", "X25519"}

// SupportedCurves returns the list of elliptic curves supported for key agreement.
//
// Supported curves:
//   - "P-256" (secp256r1, prime256v1) - 128-bit security
//   - "P-384" (secp384r1) - 192-bit security
//   - "P-521" (secp521r1) - 256-bit security
//   - "X25519" - Modern curve for key agreement (Curve25519)
func (b *SoftwareBackend) SupportedCurves() []string {
	return supportedCurves
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key using
// the specified KDF parameters.
//
// The operation:
//  1. Retrieves the private key identified by privateKeyAttrs
//  2. Parses the peer's public key from peerPublicKey bytes
//  3. Performs ECDH to compute the raw shared secret
//  4. Applies the KDF specified in kdfParams to derive the final key
//
// Parameters:
//   - ctx: Context for cancellation and deadline propagation
//   - privateKeyAttrs: Attributes identifying the local private key
//   - peerPublicKey: The peer's public key in DER (SubjectPublicKeyInfo) or raw format
//   - kdfParams: Parameters for the key derivation function
//
// The private key must be an ECDSA or X25519 key. The peer public key must use
// the same curve as the private key.
//
// For NIST curves (P-256, P-384, P-521), peerPublicKey can be:
//   - DER-encoded SubjectPublicKeyInfo (recommended)
//   - Uncompressed point format (0x04 || X || Y)
//
// For X25519, peerPublicKey should be:
//   - DER-encoded SubjectPublicKeyInfo (recommended)
//   - Raw 32-byte public key
func (b *SoftwareBackend) DeriveKeyECDH(
	ctx context.Context,
	privateKeyAttrs *types.KeyAttributes,
	peerPublicKey []byte,
	kdfParams *types.KDFParams,
) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	// Validate inputs
	if privateKeyAttrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "private key attributes cannot be nil"}
	}
	if len(peerPublicKey) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidPublicKey, Detail: "peer public key cannot be empty"}
	}
	if kdfParams == nil {
		return nil, &errs.Detail{Err: ErrInvalidKDFParams, Detail: "KDF parameters cannot be nil"}
	}

	// Validate and apply KDF defaults
	if err := kdfParams.Validate(); err != nil {
		return nil, &errs.Detail{Err: ErrInvalidKDFParams, Detail: fmt.Sprintf("%v", err)}
	}

	// Get the private key
	privateKey, err := b.pkcs8Backend.GetKey(ctx, privateKeyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get private key", Err: err}
	}

	// Perform ECDH based on key type
	var sharedSecret []byte
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		sharedSecret, err = b.deriveECDHWithNIST(key, peerPublicKey)
	case *x25519.PrivateKeyStorage:
		sharedSecret, err = b.deriveECDHWithX25519(key, peerPublicKey)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedKeyType, Detail: fmt.Sprintf("expected ECDSA or X25519 key, got %T", privateKey)}
	}

	if err != nil {
		return nil, err
	}

	// Apply KDF to derive the final key
	return b.applyKDF(sharedSecret, kdfParams)
}

// deriveECDHWithNIST performs ECDH with NIST curves (P-256, P-384, P-521).
func (b *SoftwareBackend) deriveECDHWithNIST(privateKey *ecdsa.PrivateKey, peerPublicKeyBytes []byte) ([]byte, error) {
	// Parse the peer's public key
	peerPublicKey, err := parseNISTPublicKey(peerPublicKeyBytes, privateKey.Curve)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidPublicKey, Detail: fmt.Sprintf("%v", err)}
	}

	// Verify curves match
	if privateKey.Curve != peerPublicKey.Curve {
		return nil, &errs.Detail{Err: ErrCurveMismatch, Detail: fmt.Sprintf("private key uses %s, peer public key uses %s", privateKey.Curve.Params().Name, peerPublicKey.Curve.Params().Name)}
	}

	// Convert to crypto/ecdh for the ECDH operation
	ecdhPrivate, err := privateKey.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert private key to ECDH", Err: err}
	}

	ecdhPeer, err := peerPublicKey.ECDH()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert peer public key to ECDH", Err: err}
	}

	// Perform ECDH
	sharedSecret, err := ecdhPrivate.ECDH(ecdhPeer)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH operation failed", Err: err}
	}

	return sharedSecret, nil
}

// deriveECDHWithX25519 performs ECDH with X25519.
func (b *SoftwareBackend) deriveECDHWithX25519(privateKey *x25519.PrivateKeyStorage, peerPublicKeyBytes []byte) ([]byte, error) {
	// Parse the peer's X25519 public key
	peerPublicKey, err := parseX25519PublicKey(peerPublicKeyBytes)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidPublicKey, Detail: fmt.Sprintf("%v", err)}
	}

	// Perform ECDH
	sharedSecret, err := privateKey.PrivateKey().ECDH(peerPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "X25519 ECDH operation failed", Err: err}
	}

	return sharedSecret, nil
}

// applyKDF derives a key from an ECDH shared secret using the canonical KDF
// implementation in pkg/crypto/kdf, reached through types.KDFParams.Derive.
// Every backend derives through that one entry point, so the same parameters
// yield the same bytes here as on the TPM 2.0, PKCS#11, and phone backends.
func (b *SoftwareBackend) applyKDF(sharedSecret []byte, params *types.KDFParams) ([]byte, error) {
	if params == nil {
		return nil, ErrInvalidKDFParams
	}
	return params.Derive(sharedSecret)
}

// parseNISTPublicKey parses a NIST curve public key from various formats.
// Supports:
//   - DER-encoded SubjectPublicKeyInfo
//   - Uncompressed point format (0x04 || X || Y)
func parseNISTPublicKey(data []byte, expectedCurve elliptic.Curve) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, &errs.Message{Msg: "public key data is empty"}
	}

	// Try DER-encoded SubjectPublicKeyInfo first
	if pubKey, err := x509.ParsePKIXPublicKey(data); err == nil {
		ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("DER data contains non-ECDSA key: %T", pubKey)}
		}
		return ecdsaPub, nil
	}

	// Try raw uncompressed point format (0x04 || X || Y)
	curveParams := expectedCurve.Params()
	keySize := (curveParams.BitSize + 7) / 8
	expectedLen := 1 + 2*keySize // 0x04 prefix + X + Y

	if len(data) == expectedLen && data[0] == 0x04 {
		// Use crypto/ecdh to parse the uncompressed point
		ecdhCurve, err := nistCurveToECDH(curveParams.Name)
		if err != nil {
			return nil, err
		}

		ecdhPub, err := ecdhCurve.NewPublicKey(data)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to parse uncompressed point", Err: err}
		}

		// Convert back to ECDSA public key by going through DER
		// This is a bit roundabout, but ensures proper validation
		derBytes, err := x509.MarshalPKIXPublicKey(ecdhPub)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal ECDH public key", Err: err}
		}

		pubKey, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to parse marshaled public key", Err: err}
		}

		ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("unexpected key type after conversion: %T", pubKey)}
		}

		return ecdsaPub, nil
	}

	return nil, &errs.Message{Msg: fmt.Sprintf("unrecognized public key format (length: %d)", len(data))}
}

// parseX25519PublicKey parses an X25519 public key from various formats.
// Supports:
//   - DER-encoded SubjectPublicKeyInfo
//   - Raw 32-byte public key
func parseX25519PublicKey(data []byte) (*ecdh.PublicKey, error) {
	if len(data) == 0 {
		return nil, &errs.Message{Msg: "public key data is empty"}
	}

	// Try DER-encoded SubjectPublicKeyInfo first
	if pubKey, err := x509.ParsePKIXPublicKey(data); err == nil {
		ecdhPub, ok := pubKey.(*ecdh.PublicKey)
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("DER data contains non-X25519 key: %T", pubKey)}
		}
		if ecdhPub.Curve() != ecdh.X25519() {
			return nil, &errs.Message{Msg: fmt.Sprintf("expected X25519 curve, got %v", ecdhPub.Curve())}
		}
		return ecdhPub, nil
	}

	// Try raw 32-byte format
	if len(data) == 32 {
		pubKey, err := ecdh.X25519().NewPublicKey(data)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to parse raw X25519 public key", Err: err}
		}
		return pubKey, nil
	}

	return nil, &errs.Message{Msg: fmt.Sprintf("unrecognized X25519 public key format (length: %d, expected 32 or DER)", len(data))}
}

// nistCurveToECDH returns the crypto/ecdh curve for a NIST curve name.
func nistCurveToECDH(name string) (ecdh.Curve, error) {
	switch name {
	case "P-256":
		return ecdh.P256(), nil
	case "P-384":
		return ecdh.P384(), nil
	case "P-521":
		return ecdh.P521(), nil
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedCurve, Detail: name}
	}
}

// =============================================================================
// SecureKeyAgreementBackend Implementation
// =============================================================================

// supportedDerivationModes defines the derivation modes supported by the software backend.
// Software backend only supports EXPORT mode since it has no hardware security boundary.
var supportedDerivationModes = []types.KeyDerivationMode{types.KeyDerivationModeExport}

// SupportedDerivationModes returns the list of derivation modes supported by this backend.
// The software backend only supports EXPORT mode since there is no hardware security
// boundary to protect derived keys.
//
// Returns: [KeyDerivationModeExport]
func (b *SoftwareBackend) SupportedDerivationModes() []types.KeyDerivationMode {
	return supportedDerivationModes
}

// DeriveKeyECDHSecure performs ECDH key agreement with configurable security modes.
// For the software backend, only EXPORT mode is supported since there is no hardware
// security boundary to protect derived keys.
//
// The operation varies based on kdfParams.DerivationMode:
//   - EXPORT: Same as DeriveKeyECDH, returns key bytes in ECDHResult.DerivedKey
//   - HSM_RESIDENT: Not supported, returns ErrDerivationModeNotSupported
//   - HSM_KDF: Not supported, returns ErrDerivationModeNotSupported
//   - TPM_WRAPPED: Not supported, returns ErrDerivationModeNotSupported
//
// Parameters:
//   - ctx: Context for cancellation and deadline propagation
//   - privateKeyAttrs: Attributes identifying the local private key
//   - peerPublicKey: The peer's public key in DER or uncompressed point format
//   - kdfParams: Parameters for KDF including DerivationMode
//
// Returns ECDHResult containing the derived key bytes for EXPORT mode.
func (b *SoftwareBackend) DeriveKeyECDHSecure(
	ctx context.Context,
	privateKeyAttrs *types.KeyAttributes,
	peerPublicKey []byte,
	kdfParams *types.KDFParams,
) (*types.ECDHResult, error) {
	// Check for supported derivation mode
	if kdfParams != nil && kdfParams.DerivationMode != types.KeyDerivationModeExport {
		return nil, &errs.Detail{Err: ErrDerivationModeNotSupported, Detail: fmt.Sprintf("software backend only supports EXPORT mode, got %s", kdfParams.DerivationMode)}
	}

	// Delegate to DeriveKeyECDH
	derivedKey, err := b.DeriveKeyECDH(ctx, privateKeyAttrs, peerPublicKey, kdfParams)
	if err != nil {
		return nil, err
	}

	return &types.ECDHResult{
		Mode:       types.KeyDerivationModeExport,
		DerivedKey: derivedKey,
	}, nil
}

// UseResidentKey performs a cryptographic operation using an HSM/TPM-resident key.
// This operation is not supported by the software backend since it has no hardware
// security boundary to store resident keys.
//
// Always returns ErrDerivationModeNotSupported.
func (b *SoftwareBackend) UseResidentKey(
	ctx context.Context,
	handle *types.DerivedKeyHandle,
	operation types.ResidentKeyOperation,
	data []byte,
	params *types.OperationParams,
) ([]byte, error) {
	return nil, &errs.Detail{Err: ErrDerivationModeNotSupported, Detail: "software backend does not support resident keys"}
}

// DestroyResidentKey destroys an HSM/TPM-resident derived key.
// This operation is not supported by the software backend since it has no hardware
// security boundary to store resident keys.
//
// Always returns ErrDerivationModeNotSupported.
func (b *SoftwareBackend) DestroyResidentKey(
	ctx context.Context,
	handle *types.DerivedKeyHandle,
) error {
	return &errs.Detail{Err: ErrDerivationModeNotSupported, Detail: "software backend does not support resident keys"}
}

// Verify KeyAgreementBackend interface compliance at compile time
var _ types.KeyAgreementProvider = (*SoftwareBackend)(nil)

// Verify SecureKeyAgreementBackend interface compliance at compile time
var _ types.SecureKeyAgreementProvider = (*SoftwareBackend)(nil)
