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

package authenticator

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-enclave"
)

// HMACSecretSaltSize is the size of one hmac-secret salt, and of one output,
// in bytes (CTAP 2.1 §12.5).
const HMACSecretSaltSize = 32

// hmac-secret getAssertion extension input CBOR map keys (CTAP 2.1 §12.5).
const (
	hmacSecretKeyAgreement      = 0x01
	hmacSecretSaltEnc           = 0x02
	hmacSecretSaltAuth          = 0x03
	hmacSecretPinUvAuthProtocol = 0x04
)

// HKDF info labels that derive the two per-credential CredRandom values from
// the credential's stored hmac-secret key (StoredCredential.HMACSecretKey).
// Distinct labels make the two outputs independent: knowing one reveals
// nothing about the other or about the stored key.
const (
	credRandomWithUVInfo    = "xkey hmac-secret CredRandomWithUV"
	credRandomWithoutUVInfo = "xkey hmac-secret CredRandomWithoutUV"
)

// hmacSecretError is an hmac-secret refusal. It unwraps to the sentinel that
// errorToStatus maps to the CTAP status CTAP 2.1 §12.5 prescribes, so
// errors.Is matches both the specific refusal and its wire status.
type hmacSecretError struct {
	msg    string
	status error
}

// Error implements the error interface.
func (e *hmacSecretError) Error() string { return e.msg }

// Unwrap returns the status sentinel the refusal maps to.
func (e *hmacSecretError) Unwrap() error { return e.status }

// hmac-secret extension errors.
var (
	// ErrHMACSecretUserPresenceRequired reports an hmac-secret request whose
	// assertion does not collect user presence. CTAP 2.1 §12.5: "If "up" is
	// set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION."
	ErrHMACSecretUserPresenceRequired error = &hmacSecretError{
		msg:    "authenticator: hmac-secret requires user presence",
		status: ErrUnsupportedOption,
	}

	// ErrHMACSecretInvalidInput reports a malformed extension input: not an
	// integer-keyed map, a missing or mistyped field, an unsupported
	// pinUvAuthProtocol, or a keyAgreement key the authenticator cannot
	// complete ECDH with. Plaintext "salt1"/"salt2" inputs land here.
	ErrHMACSecretInvalidInput error = &hmacSecretError{
		msg:    "authenticator: hmac-secret invalid extension input",
		status: ErrInvalidParameter,
	}

	// ErrHMACSecretSaltAuthMismatch reports that saltAuth is not
	// authenticate(shared secret, saltEnc) (CTAP 2.1 §12.5).
	ErrHMACSecretSaltAuthMismatch error = &hmacSecretError{
		msg:    "authenticator: hmac-secret saltAuth verification failed",
		status: ErrPINAuthInvalid,
	}

	// ErrHMACSecretInvalidSalt reports that saltEnc did not decrypt to exactly
	// 32 or 64 bytes (CTAP 2.1 §12.5).
	ErrHMACSecretInvalidSalt error = &hmacSecretError{
		msg:    "authenticator: hmac-secret salts must decrypt to 32 or 64 bytes",
		status: ErrInvalidParameter,
	}
)

// hmacSecretInput is a parsed hmac-secret getAssertion extension input.
type hmacSecretInput struct {
	// keyAgreement is the platform's COSE_Key, CBOR-encoded.
	keyAgreement []byte

	// saltEnc is encrypt(shared secret, salt1 [|| salt2]).
	saltEnc []byte

	// saltAuth is authenticate(shared secret, saltEnc).
	saltAuth []byte

	// protocol is the PIN/UV auth protocol the shared secret was agreed
	// under; 1 when the platform omits it.
	protocol uint8
}

// processHMACSecret performs the hmac-secret getAssertion processing of
// CTAP 2.1 §12.5 for one credential and returns the extension output: the
// HMAC-SHA-256 of each salt under the credential's CredRandom, encrypted under
// the shared secret. Neither the salts nor the outputs cross the wire in
// plaintext.
//
// flags are the UP/UV flags this assertion reports. User presence must have
// been collected; whether user verification was performed selects
// CredRandomWithUV or CredRandomWithoutUV. A credential that has no
// hmac-secret key yields (nil, nil): CTAP 2.1 §12.5 says the authenticator
// then ignores the extension.
func (a *Authenticator) processHMACSecret(credential *StoredCredential, raw interface{}, flags AuthDataFlags) ([]byte, error) {
	if !flags.Has(FlagUP) {
		return nil, ErrHMACSecretUserPresenceRequired
	}

	input, err := parseHMACSecretInput(raw)
	if err != nil {
		return nil, err
	}

	// decapsulate(): ECDH with the key agreement key getKeyAgreement handed
	// out, then the protocol's kdf. pinState is guarded by a.mu.
	a.mu.RLock()
	secret, err := a.agreeSharedSecret(input.keyAgreement, input.protocol)
	a.mu.RUnlock()
	if err != nil {
		return nil, ErrHMACSecretInvalidInput
	}
	defer secret.wipe()

	if !a.verifyPinAuth(secret.hmacKey, secret.protocol, input.saltEnc, input.saltAuth) {
		return nil, ErrHMACSecretSaltAuthMismatch
	}

	salts, err := decryptData(secret.aesKey, secret.protocol, input.saltEnc)
	if err != nil {
		return nil, ErrHMACSecretInvalidSalt
	}
	defer enclave.Wipe(salts)
	if len(salts) != HMACSecretSaltSize && len(salts) != 2*HMACSecretSaltSize {
		return nil, ErrHMACSecretInvalidSalt
	}

	if len(credential.HMACSecretKey) != HMACSecretKeySize {
		return nil, nil
	}
	credRandom, err := deriveCredRandom(credential.HMACSecretKey, flags.Has(FlagUV))
	if err != nil {
		return nil, err
	}
	defer enclave.Wipe(credRandom)

	outputs := make([]byte, 0, len(salts))
	for salt := range slices.Chunk(salts, HMACSecretSaltSize) {
		mac := hmac.New(sha256.New, credRandom)
		mac.Write(salt)
		outputs = mac.Sum(outputs)
	}
	defer enclave.Wipe(outputs)

	return a.encryptData(secret.aesKey, secret.protocol, outputs)
}

// deriveCredRandom derives CredRandomWithUV (uv true) or CredRandomWithoutUV
// (uv false) from the credential's stored hmac-secret key with
// HKDF-Expand-SHA-256 under distinct info labels. The stored key is 32
// uniformly random bytes, so it serves directly as the HKDF pseudorandom key
// (RFC 5869 §3.3).
func deriveCredRandom(hmacSecretKey []byte, uv bool) ([]byte, error) {
	info := credRandomWithoutUVInfo
	if uv {
		info = credRandomWithUVInfo
	}
	credRandom, err := hkdf.Expand(sha256.New, hmacSecretKey, info, HMACSecretSaltSize)
	if err != nil {
		return nil, ErrCryptoError
	}
	return credRandom, nil
}

// parseHMACSecretInput parses the hmac-secret getAssertion extension input,
// an integer-keyed CBOR map (CTAP 2.1 §12.5): keyAgreement (1, a COSE_Key
// map), saltEnc (2), saltAuth (3) and the optional pinUvAuthProtocol (4),
// which defaults to 1.
func parseHMACSecretInput(raw interface{}) (*hmacSecretInput, error) {
	fields, err := hmacSecretFields(raw)
	if err != nil {
		return nil, err
	}

	keyAgreement, err := hmacSecretKeyAgreementBytes(fields[hmacSecretKeyAgreement])
	if err != nil {
		return nil, err
	}

	saltEnc, ok := fields[hmacSecretSaltEnc].([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidInput
	}
	saltAuth, ok := fields[hmacSecretSaltAuth].([]byte)
	if !ok {
		return nil, ErrHMACSecretInvalidInput
	}

	protocol := uint8(PINProtocol1)
	if rawProtocol, present := fields[hmacSecretPinUvAuthProtocol]; present {
		version, err := toInt(rawProtocol)
		if err != nil || (version != PINProtocol1 && version != PINProtocol2) {
			return nil, ErrHMACSecretInvalidInput
		}
		protocol = uint8(version)
	}

	return &hmacSecretInput{
		keyAgreement: keyAgreement,
		saltEnc:      saltEnc,
		saltAuth:     saltAuth,
		protocol:     protocol,
	}, nil
}

// hmacSecretFields normalizes the extension input map to integer keys. A
// CBOR-decoded map arrives as map[interface{}]interface{}; an in-process Go
// caller may pass map[int]interface{}. Any non-integer key -- such as the
// plaintext "salt1" and "salt2" of the WebAuthn client input, which is never
// the authenticator input -- rejects the whole input.
func hmacSecretFields(raw interface{}) (map[int]interface{}, error) {
	switch m := raw.(type) {
	case map[int]interface{}:
		return m, nil
	case map[interface{}]interface{}:
		fields := make(map[int]interface{}, len(m))
		for key, value := range m {
			label, err := toInt(key)
			if err != nil {
				return nil, ErrHMACSecretInvalidInput
			}
			fields[label] = value
		}
		return fields, nil
	default:
		return nil, ErrHMACSecretInvalidInput
	}
}

// hmacSecretKeyAgreementBytes CBOR-encodes the keyAgreement COSE_Key map so
// agreeSharedSecret decodes it exactly as it decodes a clientPin keyAgreement.
func hmacSecretKeyAgreementBytes(raw interface{}) ([]byte, error) {
	switch raw.(type) {
	case map[interface{}]interface{}, map[int]interface{}:
		encoded, err := cbor.Marshal(raw)
		if err != nil {
			return nil, ErrHMACSecretInvalidInput
		}
		return encoded, nil
	default:
		return nil, ErrHMACSecretInvalidInput
	}
}
