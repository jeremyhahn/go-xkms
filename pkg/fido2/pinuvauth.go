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

package fido2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// PIN/UV auth protocol versions, as defined by CTAP 2.1 6.5.6 (protocol
// one) and 6.5.7 (protocol two).
const (
	// PINUVAuthProtocolV1 is PIN/UV auth protocol one: the shared secret is
	// SHA-256 of the ECDH point, AES-256-CBC uses an all-zero IV, and the
	// authentication tag is the leading 16 bytes of HMAC-SHA-256.
	PINUVAuthProtocolV1 uint64 = 1

	// PINUVAuthProtocolV2 is PIN/UV auth protocol two: the shared secret is
	// an HKDF-SHA-256 expansion of the ECDH point into separate HMAC and AES
	// keys, AES-256-CBC uses a random IV prefixed to the ciphertext, and the
	// authentication tag is the full HMAC-SHA-256 output.
	PINUVAuthProtocolV2 uint64 = 2
)

// authenticatorClientPIN subcommands, as defined by CTAP 2.1 6.5.5.
const (
	// ClientPINSubCmdGetPINRetries requests the remaining PIN attempts.
	ClientPINSubCmdGetPINRetries uint64 = 0x01

	// ClientPINSubCmdGetKeyAgreement requests the authenticator's ephemeral
	// ECDH public key, which is the input to the shared-secret derivation.
	ClientPINSubCmdGetKeyAgreement uint64 = 0x02

	// ClientPINSubCmdSetPIN sets an initial PIN.
	ClientPINSubCmdSetPIN uint64 = 0x03

	// ClientPINSubCmdChangePIN replaces an existing PIN.
	ClientPINSubCmdChangePIN uint64 = 0x04

	// ClientPINSubCmdGetPINToken requests a pinUvAuthToken using the PIN.
	ClientPINSubCmdGetPINToken uint64 = 0x05
)

// authenticatorClientPIN request and response field labels (CTAP 2.1 6.5.5).
const (
	clientPINFieldPinUVAuthProtocol = 0x01
	clientPINFieldSubCommand        = 0x02
	clientPINFieldKeyAgreement      = 0x03
	clientPINFieldPINHashEnc        = 0x06

	// clientPINRespKeyAgreement and clientPINRespPINToken are RESPONSE
	// labels. They collide numerically with request labels, which is why
	// they are named apart: 0x01 is keyAgreement in a response but
	// pinUvAuthProtocol in a request.
	clientPINRespKeyAgreement = 0x01
	clientPINRespPINToken     = 0x02
	clientPINRespPINRetries   = 0x03
)

// COSE_Key labels and values used by the PIN/UV auth key agreement
// (RFC 9052 7 and RFC 9053 7.1).
const (
	coseLabelKty = 1
	coseLabelAlg = 3
	coseLabelCrv = -1
	coseLabelX   = -2
	coseLabelY   = -3

	// coseKtyEC2 is the "EC2" key type: a two-coordinate elliptic curve key.
	coseKtyEC2 = 2

	// coseCrvP256 is the NIST P-256 curve identifier.
	coseCrvP256 = 1

	// COSEAlgECDHESHKDF256 is the algorithm identifier CTAP 2.1 6.5.6
	// requires in the key agreement COSE_Key.
	COSEAlgECDHESHKDF256 = -25

	// coseP256CoordinateLen is the size of a P-256 affine coordinate.
	coseP256CoordinateLen = 32

	// uncompressedPointPrefix marks a SEC 1 uncompressed point encoding.
	uncompressedPointPrefix = 0x04
)

// ctap2HKDFSalt is the all-zero 32-byte salt PIN/UV auth protocol two
// feeds to HKDF-Extract (CTAP 2.1 6.5.7).
var ctap2HKDFSalt = make([]byte, sha256.Size)

// PIN/UV auth protocol two HKDF info strings (CTAP 2.1 6.5.7).
const (
	ctap2HKDFInfoHMACKey = "CTAP2 HMAC key"
	ctap2HKDFInfoAESKey  = "CTAP2 AES key"
)

// COSEKeyEC2 is a two-coordinate elliptic curve COSE_Key. It carries the
// ephemeral P-256 public keys the platform and the authenticator exchange
// to establish a PIN/UV auth shared secret.
type COSEKeyEC2 struct {
	// Algorithm is the COSE algorithm identifier (label 3).
	Algorithm int

	// Curve is the COSE curve identifier (label -1).
	Curve int

	// X is the affine x-coordinate (label -2).
	X []byte

	// Y is the affine y-coordinate (label -3).
	Y []byte
}

// Map renders the key as the CBOR map an authenticator expects.
func (k *COSEKeyEC2) Map() map[int]interface{} {
	return map[int]interface{}{
		coseLabelKty: coseKtyEC2,
		coseLabelAlg: k.Algorithm,
		coseLabelCrv: k.Curve,
		coseLabelX:   k.X,
		coseLabelY:   k.Y,
	}
}

// ECDHPublicKey converts the COSE_Key to a P-256 ECDH public key. The
// conversion validates that the point lies on the curve, so a hostile
// authenticator cannot steer the key agreement onto a weak point.
func (k *COSEKeyEC2) ECDHPublicKey() (*ecdh.PublicKey, error) {
	if k.Curve != coseCrvP256 {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected curve %d (P-256), got %d", coseCrvP256, k.Curve),
		}
	}
	if len(k.X) != coseP256CoordinateLen || len(k.Y) != coseP256CoordinateLen {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected %d-byte coordinates, got x=%d y=%d", coseP256CoordinateLen, len(k.X), len(k.Y)),
		}
	}

	point := make([]byte, 1+2*coseP256CoordinateLen)
	point[0] = uncompressedPointPrefix
	copy(point[1:], k.X)
	copy(point[1+coseP256CoordinateLen:], k.Y)

	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidCOSEKeyAgreement, Cause: err}
	}
	return pub, nil
}

// NewCOSEKeyEC2 renders a P-256 ECDH public key as a key agreement
// COSE_Key.
func NewCOSEKeyEC2(pub *ecdh.PublicKey) (*COSEKeyEC2, error) {
	if pub == nil {
		return nil, &errs.Detail{Err: ErrInvalidCOSEKeyAgreement, Detail: "nil public key"}
	}

	point := pub.Bytes()
	if len(point) != 1+2*coseP256CoordinateLen || point[0] != uncompressedPointPrefix {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected a %d-byte uncompressed P-256 point, got %d bytes", 1+2*coseP256CoordinateLen, len(point)),
		}
	}

	return &COSEKeyEC2{
		Algorithm: COSEAlgECDHESHKDF256,
		Curve:     coseCrvP256,
		X:         point[1 : 1+coseP256CoordinateLen],
		Y:         point[1+coseP256CoordinateLen:],
	}, nil
}

// ParseCOSEKeyEC2 decodes a CBOR-decoded COSE_Key map into a COSEKeyEC2.
// The value is whatever the CBOR decoder produced for the map, so both
// interface-keyed and integer-keyed maps are accepted.
func ParseCOSEKeyEC2(value interface{}) (*COSEKeyEC2, error) {
	labels, err := coseLabelMap(value)
	if err != nil {
		return nil, err
	}

	kty, err := coseLabelInt(labels, coseLabelKty)
	if err != nil {
		return nil, err
	}
	if kty != coseKtyEC2 {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected key type %d (EC2), got %d", coseKtyEC2, kty),
		}
	}

	crv, err := coseLabelInt(labels, coseLabelCrv)
	if err != nil {
		return nil, err
	}

	x, err := coseLabelBytes(labels, coseLabelX)
	if err != nil {
		return nil, err
	}
	y, err := coseLabelBytes(labels, coseLabelY)
	if err != nil {
		return nil, err
	}

	// The algorithm label is optional: not every authenticator populates it
	// in the getKeyAgreement response, and the key agreement algorithm is
	// fixed by the protocol regardless.
	alg := COSEAlgECDHESHKDF256
	if _, ok := labels[coseLabelAlg]; ok {
		alg, err = coseLabelInt(labels, coseLabelAlg)
		if err != nil {
			return nil, err
		}
	}

	return &COSEKeyEC2{Algorithm: alg, Curve: crv, X: x, Y: y}, nil
}

// coseLabelMap normalizes a decoded CBOR map to integer COSE labels.
func coseLabelMap(value interface{}) (map[int]interface{}, error) {
	switch m := value.(type) {
	case map[interface{}]interface{}:
		out := make(map[int]interface{}, len(m))
		for k, v := range m {
			label, err := coseLabelKey(k)
			if err != nil {
				return nil, err
			}
			out[label] = v
		}
		return out, nil
	case map[int]interface{}:
		return m, nil
	case map[int64]interface{}:
		out := make(map[int]interface{}, len(m))
		for k, v := range m {
			out[int(k)] = v
		}
		return out, nil
	case nil:
		return nil, &errs.Detail{Err: ErrInvalidCOSEKeyAgreement, Detail: "key agreement key absent"}
	default:
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected a COSE_Key map, got %T", value),
		}
	}
}

// coseLabelKey converts a decoded CBOR map key to a COSE label.
func coseLabelKey(key interface{}) (int, error) {
	switch k := key.(type) {
	case int64:
		return int(k), nil
	case int:
		return k, nil
	case uint64:
		return int(k), nil
	default:
		return 0, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("expected an integer COSE label, got %T", key),
		}
	}
}

// coseLabelInt reads an integer-valued COSE label.
func coseLabelInt(labels map[int]interface{}, label int) (int, error) {
	value, ok := labels[label]
	if !ok {
		return 0, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("COSE label %d absent", label),
		}
	}
	switch v := value.(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	case uint64:
		return int(v), nil
	default:
		return 0, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("COSE label %d: expected an integer, got %T", label, value),
		}
	}
}

// coseLabelBytes reads a byte-string-valued COSE label.
func coseLabelBytes(labels map[int]interface{}, label int) ([]byte, error) {
	value, ok := labels[label]
	if !ok {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("COSE label %d absent", label),
		}
	}
	b, ok := value.([]byte)
	if !ok {
		return nil, &errs.Detail{
			Err:    ErrInvalidCOSEKeyAgreement,
			Detail: fmt.Sprintf("COSE label %d: expected a byte string, got %T", label, value),
		}
	}
	return b, nil
}

// PINUVAuthSession is the ECDH shared secret a platform establishes with an
// authenticator. Every hmac-secret salt sent to the authenticator is
// encrypted under this secret, and every hmac-secret output returned by the
// authenticator is decrypted with it, so the derived secret is reproducible
// only in the presence of the physical authenticator.
type PINUVAuthSession struct {
	version      uint64
	platformKey  *COSEKeyEC2
	sharedSecret []byte
}

// NewPINUVAuthSession derives a shared secret from a freshly generated
// platform key pair and the authenticator's key agreement key.
func NewPINUVAuthSession(version uint64, authenticatorKey *COSEKeyEC2) (*PINUVAuthSession, error) {
	if version != PINUVAuthProtocolV1 && version != PINUVAuthProtocolV2 {
		return nil, &errs.Detail{
			Err:    ErrUnsupportedPINUVAuthProtocol,
			Detail: fmt.Sprintf("version %d", version),
		}
	}
	if authenticatorKey == nil {
		return nil, &errs.Detail{Err: ErrInvalidCOSEKeyAgreement, Detail: "nil key agreement key"}
	}

	peer, err := authenticatorKey.ECDHPublicKey()
	if err != nil {
		return nil, err
	}

	platform, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	return newPINUVAuthSession(version, platform, peer)
}

// newPINUVAuthSession derives a shared secret from an explicit platform key
// pair. Tests use it to pin the key agreement; production callers use
// NewPINUVAuthSession so the platform key is always ephemeral.
func newPINUVAuthSession(version uint64, platform *ecdh.PrivateKey, peer *ecdh.PublicKey) (*PINUVAuthSession, error) {
	point, err := platform.ECDH(peer)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	sharedSecret, err := deriveSharedSecret(version, point)
	if err != nil {
		return nil, err
	}

	platformKey, err := NewCOSEKeyEC2(platform.PublicKey())
	if err != nil {
		return nil, err
	}

	return &PINUVAuthSession{
		version:      version,
		platformKey:  platformKey,
		sharedSecret: sharedSecret,
	}, nil
}

// deriveSharedSecret applies the protocol's KDF to the ECDH point.
func deriveSharedSecret(version uint64, point []byte) ([]byte, error) {
	switch version {
	case PINUVAuthProtocolV1:
		digest := sha256.Sum256(point)
		return digest[:], nil

	case PINUVAuthProtocolV2:
		hmacKey, err := hkdf.Key(sha256.New, point, ctap2HKDFSalt, ctap2HKDFInfoHMACKey, sha256.Size)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
		}
		aesKey, err := hkdf.Key(sha256.New, point, ctap2HKDFSalt, ctap2HKDFInfoAESKey, sha256.Size)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
		}
		return append(hmacKey, aesKey...), nil

	default:
		return nil, &errs.Detail{
			Err:    ErrUnsupportedPINUVAuthProtocol,
			Detail: fmt.Sprintf("version %d", version),
		}
	}
}

// Version reports the PIN/UV auth protocol the session speaks.
func (s *PINUVAuthSession) Version() uint64 { return s.version }

// PlatformKeyAgreement returns the platform's ephemeral public key, which
// accompanies every request encrypted under the session.
func (s *PINUVAuthSession) PlatformKeyAgreement() *COSEKeyEC2 { return s.platformKey }

// hmacKey returns the sub-key used for authentication tags.
func (s *PINUVAuthSession) hmacKey() []byte {
	if s.version == PINUVAuthProtocolV2 {
		return s.sharedSecret[:sha256.Size]
	}
	return s.sharedSecret
}

// aesKey returns the sub-key used for AES-256-CBC.
func (s *PINUVAuthSession) aesKey() []byte {
	if s.version == PINUVAuthProtocolV2 {
		return s.sharedSecret[sha256.Size:]
	}
	return s.sharedSecret
}

// Encrypt applies the protocol's AES-256-CBC encryption. Protocol one uses
// an all-zero IV; protocol two generates a random IV and prefixes it to the
// ciphertext. Neither protocol pads, so the plaintext must be a whole
// number of AES blocks.
func (s *PINUVAuthSession) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, &errs.Detail{
			Err:    ErrInvalidPINUVAuthPlaintext,
			Detail: fmt.Sprintf("expected a non-empty multiple of %d bytes, got %d", aes.BlockSize, len(plaintext)),
		}
	}

	block, err := aes.NewCipher(s.aesKey())
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	iv := make([]byte, aes.BlockSize)
	if s.version == PINUVAuthProtocolV2 {
		if _, err := rand.Read(iv); err != nil {
			return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
		}
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	if s.version == PINUVAuthProtocolV2 {
		return append(iv, ciphertext...), nil
	}
	return ciphertext, nil
}

// Decrypt reverses Encrypt.
func (s *PINUVAuthSession) Decrypt(ciphertext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	body := ciphertext

	if s.version == PINUVAuthProtocolV2 {
		if len(ciphertext) <= aes.BlockSize {
			return nil, &errs.Detail{
				Err:    ErrInvalidPINUVAuthCiphertext,
				Detail: fmt.Sprintf("expected more than %d bytes for an IV and ciphertext, got %d", aes.BlockSize, len(ciphertext)),
			}
		}
		copy(iv, ciphertext[:aes.BlockSize])
		body = ciphertext[aes.BlockSize:]
	}

	if len(body) == 0 || len(body)%aes.BlockSize != 0 {
		return nil, &errs.Detail{
			Err:    ErrInvalidPINUVAuthCiphertext,
			Detail: fmt.Sprintf("expected a non-empty multiple of %d bytes, got %d", aes.BlockSize, len(body)),
		}
	}

	block, err := aes.NewCipher(s.aesKey())
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	plaintext := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, body)
	return plaintext, nil
}

// Authenticate computes the protocol's authentication tag over message,
// keyed by the session's shared secret. This is the key CTAP 2.1 uses for
// request-scoped tags such as the hmac-secret extension's saltAuth.
func (s *PINUVAuthSession) Authenticate(message []byte) []byte {
	return pinUVAuthenticate(s.version, s.hmacKey(), message)
}

// AuthenticateWithToken computes the protocol's authentication tag over
// message, keyed by a pinUvAuthToken rather than the shared secret. This is
// the construction behind pinUvAuthParam: getPINToken returns a token, and
// every request that token authorizes carries a tag over its clientDataHash.
func (s *PINUVAuthSession) AuthenticateWithToken(token, message []byte) []byte {
	return pinUVAuthenticate(s.version, token, message)
}

// pinUVAuthenticate is the protocol's authenticate(key, message) primitive:
// the leading 16 bytes of HMAC-SHA-256 for protocol one, the full 32 bytes
// for protocol two.
func pinUVAuthenticate(version uint64, key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	tag := mac.Sum(nil)

	if version == PINUVAuthProtocolV1 {
		return tag[:16]
	}
	return tag
}

// KeyAgreement issues the authenticatorClientPIN getKeyAgreement subcommand
// and returns the authenticator's ephemeral public key. The subcommand
// requires neither a PIN nor user presence: it exists solely to seed the
// ECDH exchange.
func (a *Authenticator) KeyAgreement(version uint64) (*COSEKeyEC2, error) {
	if version != PINUVAuthProtocolV1 && version != PINUVAuthProtocolV2 {
		return nil, &errs.Detail{
			Err:    ErrUnsupportedPINUVAuthProtocol,
			Detail: fmt.Sprintf("version %d", version),
		}
	}

	reqMap := map[int]interface{}{
		clientPINFieldPinUVAuthProtocol: version,
		clientPINFieldSubCommand:        ClientPINSubCmdGetKeyAgreement,
	}

	resp, err := a.device.SendCBOR(CmdClientPIN, reqMap)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &respMap); err != nil {
		return nil, &errs.Joined{Lead: ErrKeyAgreementFailed, Cause: err}
	}

	return ParseCOSEKeyEC2(respMap[clientPINRespKeyAgreement])
}

// PINUVAuthProtocolVersion reports the newest PIN/UV auth protocol the
// authenticator advertises. Protocol two is preferred because it separates
// the HMAC and AES keys and randomizes the CBC IV. Authenticators that
// advertise no protocol are addressed with protocol one, which CTAP 2.0
// defines as the default.
func (a *Authenticator) PINUVAuthProtocolVersion() uint64 {
	if a.info == nil {
		return PINUVAuthProtocolV1
	}
	for _, version := range a.info.PINProtocols {
		if version == PINUVAuthProtocolV2 {
			return PINUVAuthProtocolV2
		}
	}
	return PINUVAuthProtocolV1
}

// EstablishPINUVAuthSession negotiates a protocol version, fetches the
// authenticator's key agreement key, and derives the shared secret.
func (a *Authenticator) EstablishPINUVAuthSession() (*PINUVAuthSession, error) {
	version := a.PINUVAuthProtocolVersion()

	authenticatorKey, err := a.KeyAgreement(version)
	if err != nil {
		return nil, err
	}

	return NewPINUVAuthSession(version, authenticatorKey)
}

// GetPINToken exchanges the user's PIN for a pinUvAuthToken (CTAP 2.1 6.5.5.7,
// authenticatorClientPIN subcommand 0x05).
//
// The PIN never crosses the wire. What is sent is the first 16 bytes of
// SHA-256(PIN), encrypted under the session's shared secret; the authenticator
// returns the token encrypted the same way. Both directions therefore depend on
// the session having been established with the SAME protocol version the
// authenticator will use to verify the resulting pinUvAuthParam.
//
// The returned token is the key for Authenticate() over a MakeCredential or
// GetAssertion clientDataHash. Treat it as secret and short-lived: a
// CTAP 2.1 authenticator stops the token after 30 seconds of disuse, 10 minutes
// of life, or the first credential operation that collects user presence
// (Section 6.5.2.1), so obtain a token per operation rather than caching one.
func (a *Authenticator) GetPINToken(session *PINUVAuthSession, pin *secure.Secret) ([]byte, error) {
	if session == nil {
		return nil, ErrPINTokenFailed
	}
	if pin == nil {
		return nil, &errs.Detail{Err: ErrPINTokenFailed, Detail: "PIN is empty"}
	}

	// The PIN is opened only for the instant the CTAP 2.1 6.5.5.7 pinHashEnc
	// computation needs its bytes: pinHashEnc is
	// encrypt(LEFT(SHA-256(pin), 16)).
	pinBuf, openErr := pin.Open()
	if openErr != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: openErr}
	}
	var pinHash [sha256.Size]byte
	hashErr := pinBuf.WithBytes(func(p []byte) error {
		pinHash = sha256.Sum256(p)
		return nil
	})
	pinBuf.Destroy()
	if hashErr != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: hashErr}
	}
	pinHashEnc, err := session.Encrypt(pinHash[:16])
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: err}
	}

	reqMap := map[int]interface{}{
		clientPINFieldPinUVAuthProtocol: session.Version(),
		clientPINFieldSubCommand:        ClientPINSubCmdGetPINToken,
		clientPINFieldKeyAgreement:      session.PlatformKeyAgreement().Map(),
		clientPINFieldPINHashEnc:        pinHashEnc,
	}

	resp, err := a.device.SendCBOR(CmdClientPIN, reqMap)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: err}
	}

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &respMap); err != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: err}
	}

	tokenEnc, ok := respMap[clientPINRespPINToken].([]byte)
	if !ok {
		return nil, &errs.Detail{Err: ErrPINTokenFailed, Detail: "response carried no pinUvAuthToken"}
	}

	token, err := session.Decrypt(tokenEnc)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPINTokenFailed, Cause: err}
	}
	return token, nil
}

// AuthorizeWithPIN exchanges the user's PIN for a pinUvAuthToken and returns
// the pinUvAuthParam / pinUvAuthProtocol pair that authorizes a request over
// message — the clientDataHash of a MakeCredential or GetAssertion.
//
// The protocol version is the newest the authenticator advertises, because
// the two constructions are FIDO Alliance spec versions rather than ours: a
// CTAP 2.0 key that speaks only protocol one must still work.
//
// A wrong PIN surfaces as ErrInvalidPIN and an exhausted retry counter as
// ErrPINBlocked, both reachable with errors.Is, so a caller can tell "the
// operator mistyped" from "the authenticator refused".
func (a *Authenticator) AuthorizeWithPIN(pin *secure.Secret, message []byte) (param []byte, protocol uint64, err error) {
	session, err := a.EstablishPINUVAuthSession()
	if err != nil {
		return nil, 0, err
	}

	token, err := a.GetPINToken(session, pin)
	if err != nil {
		return nil, 0, a.annotatePINFailure(err)
	}

	return session.AuthenticateWithToken(token, message), session.Version(), nil
}

// annotatePINFailure attaches the authenticator's remaining PIN attempts to a
// wrong-PIN failure, so an operator who mistyped learns how many tries are left
// before the key locks out rather than discovering the lockout by hitting it.
//
// Only a wrong PIN is annotated: every other failure — a key with no PIN set,
// an already-blocked key, a transport fault — carries no attempt count to
// report. When the authenticator will not answer the query the original error
// is returned unchanged; an unavailable counter must never displace the
// failure the caller actually needs to see.
func (a *Authenticator) annotatePINFailure(err error) error {
	if !errors.Is(err, ErrInvalidPIN) {
		return err
	}

	retries, retriesErr := a.PINRetries()
	if retriesErr != nil {
		return err
	}
	return &PINAttemptsError{Err: err, Retries: retries}
}

// PINRetries reports how many PIN attempts the authenticator will still accept
// before it locks out (CTAP 2.1 6.5.5.2, authenticatorClientPIN subcommand
// getPINRetries). Zero means the key is blocked and needs a power cycle or a
// reset, depending on which of the two counters it exhausted.
//
// The subcommand requires neither a PIN nor user presence, so asking is safe
// on a failure path: it consumes no attempt of its own.
func (a *Authenticator) PINRetries() (uint64, error) {
	reqMap := map[int]interface{}{
		clientPINFieldPinUVAuthProtocol: a.PINUVAuthProtocolVersion(),
		clientPINFieldSubCommand:        ClientPINSubCmdGetPINRetries,
	}

	resp, err := a.device.SendCBOR(CmdClientPIN, reqMap)
	if err != nil {
		return 0, &errs.Joined{Lead: ErrPINRetriesUnavailable, Cause: err}
	}

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp, &respMap); err != nil {
		return 0, &errs.Joined{Lead: ErrPINRetriesUnavailable, Cause: err}
	}

	retries, ok := respMap[clientPINRespPINRetries]
	if !ok {
		return 0, &errs.Detail{Err: ErrPINRetriesUnavailable, Detail: "response carried no retry counter"}
	}

	switch value := retries.(type) {
	case uint64:
		return value, nil
	case int64:
		if value < 0 {
			return 0, &errs.Detail{Err: ErrPINRetriesUnavailable, Detail: "response carried a negative retry counter"}
		}
		return uint64(value), nil
	default:
		return 0, &errs.Detail{Err: ErrPINRetriesUnavailable, Detail: "response carried a non-integer retry counter"}
	}
}
