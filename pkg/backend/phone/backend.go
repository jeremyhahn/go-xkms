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

package phone

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Sender sends JSON-RPC requests to the phone and returns responses.
// This abstraction decouples the backend from the concrete PhoneKeyBackend
// transport, allowing the caller to provide any implementation that can
// deliver encrypted JSON-RPC messages to the phone.
type Sender interface {
	SendRequest(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error)
}

// SenderFunc adapts a plain function to the Sender interface. This enables
// callers to wrap PhoneKeyBackend.SendRequest (or any compatible function)
// as a Sender without creating a separate adapter struct.
type SenderFunc func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error)

// SendRequest implements Sender by calling the wrapped function.
func (f SenderFunc) SendRequest(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
	return f(ctx, req)
}

// Backend implements types.KeyProvider for phone hardware key storage.
// It proxies cryptographic operations to the phone via Noise-encrypted JSON-RPC
// using the local.* protocol methods defined in the xkey phone protocol.
//
// Private keys never leave the phone's secure hardware (TEE/StrongBox).
// The backend only receives public keys and signature/decryption results.
type Backend struct {
	config     *Config
	sender     Sender
	logger     *slog.Logger
	trustStore *truststore.TrustStore
	verifier   PlatformVerifier
	mu         sync.RWMutex
	closed     atomic.Bool
}

// algorithmMapping maps KeyAttributes to JSON-RPC algorithm identifiers using
// O(1) map-based dispatch for constant-time lookup.
var algorithmMapping = map[x509.PublicKeyAlgorithm]map[string]string{
	x509.ECDSA: {
		"P-256": "ES256",
		"P-384": "ES384",
		"P-521": "ES512",
	},
	x509.RSA: {
		"SHA-256": "RS256",
		"SHA-384": "RS384",
		"SHA-512": "RS512",
		"":        "RS256", // Default to RS256 for RSA
	},
	x509.Ed25519: {
		"": "EdDSA",
	},
}

// rpcErrorMapping maps JSON-RPC error codes from the phone protocol to
// phone backend typed errors using O(1) map-based dispatch.
var rpcErrorMapping = map[int]error{
	phoneproto.ErrorCodeKeyNotFound:       ErrKeyNotFound,
	phoneproto.ErrorCodeUserCancelled:     ErrUserCancelled,
	phoneproto.ErrorCodeBiometricFailed:   ErrBiometricFailed,
	phoneproto.ErrorCodeUnsupportedAlg:    ErrUnsupportedAlgorithm,
	phoneproto.ErrorCodeOperationTimeout:  ErrOperationTimeout,
	phoneproto.ErrorCodeKeyExists:         ErrKeyExists,
	phoneproto.ErrorCodeParseError:        ErrProtocolError,
	phoneproto.ErrorCodeInvalidRequest:    ErrProtocolError,
	phoneproto.ErrorCodeInvalidParams:     ErrProtocolError,
	phoneproto.ErrorCodeMethodNotFound:    ErrProtocolError,
	phoneproto.ErrorCodeInternalError:     ErrInvalidResponse,
	phoneproto.ErrorCodeBackendDenied:     ErrProtocolError,
	phoneproto.ErrorCodeAttestFailed:      ErrAttestationFailed,
	phoneproto.ErrorCodeAttestUnsupported: ErrProtocolError,
	phoneproto.ErrorCodeOperationDenied:   ErrProtocolError,
	phoneproto.ErrorCodeInvalidPublicKey:  ErrInvalidPublicKey,
	phoneproto.ErrorCodeDecryptFailed:     ErrProtocolError,
}

// Compile-time interface satisfaction checks.
var _ types.KeyProvider = (*Backend)(nil)

// NewBackend creates a new phone backend that proxies key operations to a
// phone via the provided Sender. The config must pass validation and the
// sender must not be nil.
func NewBackend(config *Config, sender Sender) (*Backend, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, ErrNotConnected
	}

	b := &Backend{
		config: config,
		sender: sender,
		logger: config.Logger.With("component", "phone_backend"),
	}

	if err := b.initAttestation(); err != nil {
		return nil, err
	}

	return b, nil
}

// initAttestation initializes the trust store and platform verifier for
// attestation verification. If no attestation config is present
// (config.Attestation is nil), this is a no-op and attestation verification
// will be skipped during AttestKey calls.
func (b *Backend) initAttestation() error {
	if b.config.Attestation == nil {
		return nil
	}

	if b.config.Attestation.TrustStore == nil {
		return nil
	}

	ts, err := truststore.New(b.config.Attestation.TrustStore)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustStoreInit, err)
	}

	b.trustStore = ts

	verifier, err := NewPlatformVerifier(
		b.config.Attestation.Platform,
		ts.CertPool(),
		b.config.Attestation,
	)
	if err != nil {
		return err
	}
	b.verifier = verifier

	b.logger.Info("attestation verification enabled",
		"platform", b.config.Attestation.Platform,
		"trust_store_roots", ts.Count(),
		"min_security_level", b.config.Attestation.MinSecurityLevel,
		"verify_boot_state", b.config.Attestation.VerifyBootState,
	)

	return nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return types.BackendTypePhone
}

// Capabilities returns the feature set supported by the phone backend.
// The phone provides hardware-backed key storage with signing, decryption,
// symmetric encryption, key agreement, and attestation. It does not support
// key rotation or private key import/export since keys never leave the
// phone's secure hardware.
// SecurityLevel is High - keys are protected by phone's TEE/StrongBox hardware.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      true,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         false,
		SymmetricEncryption: true,
		Sealing:             false,
		Import:              false,
		Export:              false,
		KeyAgreement:        true,
		Attestation:         true,
		SecurityLevel:       types.SecurityLevelHigh,
	}
}

// GenerateKey generates a new key pair on the phone's hardware keystore.
// The private key remains in the phone's TEE/StrongBox and is never exported.
// The returned crypto.PrivateKey is a phoneSigner that caches the public key
// and proxies Sign calls to the phone via JSON-RPC.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	algorithm, err := mapAlgorithm(attrs)
	if err != nil {
		return nil, err
	}

	params := &phoneproto.LocalGenerateKeyParams{
		KeyID:     attrs.CN,
		Algorithm: algorithm,
	}

	// Set RSA key size if applicable.
	if attrs.KeyAlgorithm == x509.RSA && attrs.RSAAttributes != nil {
		params.KeySizeBits = attrs.RSAAttributes.KeySize
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGenerateKey, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalGenerateKeyResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	pubKey, err := parsePublicKey(result.PublicKeyDER, result.Algorithm)
	if err != nil {
		return nil, err
	}

	return newPhoneSigner(b, attrs.CN, algorithm, pubKey), nil
}

// GetKey retrieves an existing key from the phone by querying its metadata
// and public key. The returned crypto.PrivateKey is a phoneSigner that proxies
// sign operations to the phone.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	// Verify the key exists on the phone.
	infoResp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetKeyInfo, &phoneproto.LocalGetKeyInfoParams{
		KeyID: attrs.CN,
	})
	if err != nil {
		return nil, err
	}

	keyInfo, err := phoneproto.DecodeResult[phoneproto.LocalGetKeyInfoResult](infoResp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	// Retrieve the public key in DER format.
	pubResp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetPublicKey, &phoneproto.LocalGetPublicKeyParams{
		KeyID:  attrs.CN,
		Format: "der",
	})
	if err != nil {
		return nil, err
	}

	pubResult, err := phoneproto.DecodeResult[phoneproto.LocalGetPublicKeyResult](pubResp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	pubKey, err := parsePublicKey(pubResult.PublicKey, keyInfo.Algorithm)
	if err != nil {
		return nil, err
	}

	return newPhoneSigner(b, attrs.CN, keyInfo.Algorithm, pubKey), nil
}

// DeleteKey removes a key from the phone's hardware keystore.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}
	if attrs == nil {
		return ErrInvalidConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalDeleteKey, &phoneproto.LocalDeleteKeyParams{
		KeyID: attrs.CN,
	})
	if err != nil {
		return err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalDeleteKeyResult](resp)
	if err != nil {
		return ErrInvalidResponse
	}

	if !result.Deleted {
		return ErrKeyNotFound
	}

	return nil
}

// ListKeys returns metadata for all keys stored on the phone.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalListKeys, &phoneproto.LocalListKeysParams{})
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalListKeysResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	keyAttrs := make([]*types.KeyAttributes, 0, len(result.Keys))
	for i := range result.Keys {
		ka := mapKeyInfoToAttributes(&result.Keys[i])
		keyAttrs = append(keyAttrs, ka)
	}

	return keyAttrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// The signer proxies sign operations to the phone via JSON-RPC.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	// Retrieve the key to get its public key and algorithm.
	privKey, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidPublicKey
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// The decrypter proxies decryption operations to the phone via JSON-RPC.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	// Retrieve key info to get the algorithm.
	infoResp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetKeyInfo, &phoneproto.LocalGetKeyInfoParams{
		KeyID: attrs.CN,
	})
	if err != nil {
		return nil, err
	}

	keyInfo, err := phoneproto.DecodeResult[phoneproto.LocalGetKeyInfoResult](infoResp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	// Retrieve the public key in DER format.
	pubResp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetPublicKey, &phoneproto.LocalGetPublicKeyParams{
		KeyID:  attrs.CN,
		Format: "der",
	})
	if err != nil {
		return nil, err
	}

	pubResult, err := phoneproto.DecodeResult[phoneproto.LocalGetPublicKeyResult](pubResp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	pubKey, err := parsePublicKey(pubResult.PublicKey, keyInfo.Algorithm)
	if err != nil {
		return nil, err
	}

	return newPhoneDecrypter(b, attrs.CN, keyInfo.Algorithm, pubKey), nil
}

// RotateKey is not supported by the phone backend. Keys stored in hardware
// secure elements cannot be rotated in-place. Create a new key and migrate
// references instead.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	return ErrRotationNotSupported
}

// Close marks the backend as closed. The backend does not own the Sender
// lifecycle, so the caller is responsible for closing the underlying transport.
func (b *Backend) Close() error {
	b.closed.Store(true)
	return nil
}

// sendLocalRequest creates a JSON-RPC request and sends it to the phone via
// the Sender interface. It applies the configured request timeout and maps
// any RPC errors to typed backend errors.
func (b *Backend) sendLocalRequest(ctx context.Context, method string, params interface{}) (*phoneproto.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	req := phoneproto.NewRequest(method, params)

	b.logger.Debug("sending local request",
		"method", method,
		"request_id", req.ID,
	)

	resp, err := b.sender.SendRequest(ctx, req)
	if err != nil {
		b.logger.Error("local request failed",
			"method", method,
			"error", err,
		)
		return nil, err
	}

	if resp.Error != nil {
		b.logger.Error("phone returned error",
			"method", method,
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
		)
		return nil, mapRPCError(resp.Error)
	}

	return resp, nil
}

// mapAlgorithm converts KeyAttributes algorithm and curve information into
// the JSON-RPC algorithm string expected by the phone protocol.
func mapAlgorithm(attrs *types.KeyAttributes) (string, error) {
	curves, ok := algorithmMapping[attrs.KeyAlgorithm]
	if !ok {
		return "", ErrUnsupportedAlgorithm
	}

	switch attrs.KeyAlgorithm {
	case x509.ECDSA:
		if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
			return "", ErrUnsupportedAlgorithm
		}
		curveName := attrs.ECCAttributes.Curve.Params().Name
		algo, found := curves[curveName]
		if !found {
			return "", ErrUnsupportedAlgorithm
		}
		return algo, nil

	case x509.RSA:
		hashKey := ""
		if attrs.Hash != 0 {
			hashKey = attrs.Hash.String()
		}
		algo, found := curves[hashKey]
		if !found {
			// Fall back to default RS256.
			algo = curves[""]
		}
		return algo, nil

	case x509.Ed25519:
		return curves[""], nil

	default:
		return "", ErrUnsupportedAlgorithm
	}
}

// parsePublicKey parses a DER-encoded public key into a crypto.PublicKey.
// It supports ECDSA, RSA, and Ed25519 key types.
func parsePublicKey(derBytes []byte, algorithm string) (crypto.PublicKey, error) {
	if len(derBytes) == 0 {
		return nil, ErrInvalidPublicKey
	}

	pubKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}

	// Validate that the parsed key type is consistent with the algorithm.
	switch pubKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return pubKey, nil
	default:
		// ed25519.PublicKey is not a pointer type; accept any valid PKIX key.
		return pubKey, nil
	}
}

// mapKeyInfoToAttributes converts phone KeyInfo metadata to a types.KeyAttributes struct.
func mapKeyInfoToAttributes(info *phoneproto.KeyInfo) *types.KeyAttributes {
	attrs := &types.KeyAttributes{
		CN:        info.KeyID,
		StoreType: types.StorePhone,
	}

	// Map algorithm to KeyAlgorithm and curve attributes.
	_, keyAlgo, eccAttrs, rsaAttrs := mapAlgorithmToAttributes(info.Algorithm, info.KeySizeBits)
	attrs.KeyAlgorithm = keyAlgo
	attrs.ECCAttributes = eccAttrs
	attrs.RSAAttributes = rsaAttrs

	// Map key type.
	attrs.KeyType = mapKeyType(info.KeyType)

	return attrs
}

// keyTypeMapping provides O(1) constant-time lookup for key type strings
// to types.KeyType values.
var keyTypeMapping = map[string]types.KeyType{
	"signing":    types.KeyTypeSigning,
	"encryption": types.KeyTypeEncryption,
	"tls":        types.KeyTypeTLS,
	"hmac":       types.KeyTypeHMAC,
	"fido2":      types.KeyTypeSigning,
	"ssh":        types.KeyTypeSigning,
}

// mapKeyType maps a phone key type string to a types.KeyType.
func mapKeyType(keyType string) types.KeyType {
	if kt, ok := keyTypeMapping[keyType]; ok {
		return kt
	}
	return types.KeyTypeSigning // Default to signing for unrecognized types.
}

// algorithmInfo pairs a key algorithm with its optional elliptic curve for
// reverse-mapping phone protocol algorithm strings to types.KeyAttributes fields.
type algorithmInfo struct {
	keyAlgorithm x509.PublicKeyAlgorithm
	curve        elliptic.Curve
}

// algorithmAttrMapping provides O(1) constant-time lookup for algorithm strings
// from the phone protocol to the corresponding curve and key algorithm.
var algorithmAttrMapping = map[string]algorithmInfo{
	"ES256": {keyAlgorithm: x509.ECDSA, curve: elliptic.P256()},
	"ES384": {keyAlgorithm: x509.ECDSA, curve: elliptic.P384()},
	"ES512": {keyAlgorithm: x509.ECDSA, curve: elliptic.P521()},
	"RS256": {keyAlgorithm: x509.RSA},
	"RS384": {keyAlgorithm: x509.RSA},
	"RS512": {keyAlgorithm: x509.RSA},
	"EdDSA": {keyAlgorithm: x509.Ed25519},
}

// mapAlgorithmToAttributes converts a phone algorithm string and key size into
// types-compatible KeyAlgorithm, ECCAttributes, and RSAAttributes.
func mapAlgorithmToAttributes(algorithm string, keySizeBits int) (string, x509.PublicKeyAlgorithm, *types.ECCAttributes, *types.RSAAttributes) {
	info, ok := algorithmAttrMapping[algorithm]
	if !ok {
		return algorithm, x509.UnknownPublicKeyAlgorithm, nil, nil
	}

	var eccAttrs *types.ECCAttributes
	var rsaAttrs *types.RSAAttributes

	if info.curve != nil {
		eccAttrs = &types.ECCAttributes{Curve: info.curve}
	}

	if info.keyAlgorithm == x509.RSA {
		keySize := keySizeBits
		if keySize == 0 {
			keySize = 2048 // Default RSA key size.
		}
		rsaAttrs = &types.RSAAttributes{KeySize: keySize}
	}

	return algorithm, info.keyAlgorithm, eccAttrs, rsaAttrs
}

// mapRPCError converts a phone protocol RPC error to a typed backend error.
func mapRPCError(rpcErr *phoneproto.RPCError) error {
	if rpcErr == nil {
		return nil
	}
	if err, ok := rpcErrorMapping[rpcErr.Code]; ok {
		return err
	}
	return ErrProtocolError
}
