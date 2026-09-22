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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// HMACSecretExtension handles the hmac-secret extension for key derivation
type HMACSecretExtension struct {
	auth *Authenticator
}

// NewHMACSecretExtension creates a new HMAC-secret extension handler
func NewHMACSecretExtension(auth *Authenticator) (*HMACSecretExtension, error) {
	if !auth.SupportsHMACSecret() {
		return nil, ErrUnsupportedExtension
	}
	return &HMACSecretExtension{auth: auth}, nil
}

// EnrollCredential enrolls a new credential with hmac-secret extension
func (h *HMACSecretExtension) EnrollCredential(config *EnrollmentConfig) (*EnrollmentResult, error) {
	// Generate client data hash
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate challenge", Err: err}
	}
	clientDataHash := CreateClientDataHash(challenge)

	// Generate user ID
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate user ID", Err: err}
	}

	// Build MakeCredential request with hmac-secret extension
	req := &MakeCredentialRequest{
		ClientDataHash: clientDataHash,
		RP:             config.RelyingParty,
		User: User{
			ID:          userID,
			Name:        config.User.Name,
			DisplayName: config.User.DisplayName,
			Icon:        config.User.Icon,
		},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: true, // Request hmac-secret support
		},
		Options: AuthenticatorOptions{
			RK: false, // Non-resident key
			UV: config.RequireUserVerification,
		},
	}

	// Create credential
	resp, err := h.auth.MakeCredential(req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create credential", Err: err}
	}

	// Parse authenticator data to extract credential ID
	authData := resp.AuthData
	if len(authData) < 37 {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid authenticator data length: %d", len(authData))}
	}

	// AuthData structure:
	// rpIdHash: 32 bytes
	// flags: 1 byte
	// signCount: 4 bytes
	// attestedCredentialData (if present):
	//   - aaguid: 16 bytes
	//   - credentialIdLength: 2 bytes
	//   - credentialId: credentialIdLength bytes
	//   - credentialPublicKey: CBOR encoded

	flags := authData[authDataRPIDHashLen]
	attestedCredentialDataIncluded := flags&FlagAttestedCredentialData != 0

	if !attestedCredentialDataIncluded {
		return nil, &errs.Message{Msg: "attested credential data not included"}
	}

	// Extract AAGUID
	aaguid := authData[37:53]

	// Extract credential ID length
	credIDLen := int(authData[53])<<8 | int(authData[54])
	if len(authData) < 55+credIDLen {
		return nil, &errs.Message{Msg: "invalid credential ID length"}
	}

	// Extract credential ID
	credentialID := authData[55 : 55+credIDLen]

	// Extract public key (CBOR encoded, follows credential ID)
	publicKeyData := authData[55+credIDLen:]

	// Extract sign count
	signCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 |
		uint32(authData[35])<<8 | uint32(authData[36])

	// Use provided salt or generate one
	salt := config.Salt
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate salt", Err: err}
		}
	}

	result := &EnrollmentResult{
		CredentialID: credentialID,
		PublicKey:    publicKeyData,
		AAGUID:       aaguid,
		SignCount:    signCount,
		RelyingParty: config.RelyingParty,
		User: User{
			ID:          userID,
			Name:        config.User.Name,
			DisplayName: config.User.DisplayName,
			Icon:        config.User.Icon,
		},
		Salt: salt,
	}

	return result, nil
}

// hmac-secret extension parameters, as defined by CTAP 2.1 12.5.
const (
	// hmacSecretSaltLen is the size of a single hmac-secret salt, and
	// therefore of a single hmac-secret output.
	hmacSecretSaltLen = 32

	// hmacSecretInputKeyAgreement carries the platform's ephemeral public
	// key in the extension input.
	hmacSecretInputKeyAgreement = 0x01

	// hmacSecretInputSaltEnc carries the encrypted salt(s).
	hmacSecretInputSaltEnc = 0x02

	// hmacSecretInputSaltAuth carries the authentication tag over saltEnc.
	hmacSecretInputSaltAuth = 0x03

	// hmacSecretInputPinUVAuthProtocol names the protocol used to encrypt
	// and authenticate the salts.
	hmacSecretInputPinUVAuthProtocol = 0x04
)

// legacyDerivationWarning is emitted whenever the deprecated derivation is
// used. It is deliberately blunt: an operator who sees it is holding a key
// that any holder of the credential ID and salt can recompute.
const legacyDerivationWarning = "SECURITY: FIDO2 legacy hmac-secret derivation is in use. " +
	"The resulting key is NOT bound to the authenticator and can be recomputed from the credential ID and salt alone, " +
	"both of which are normally stored beside the encrypted volume. " +
	"Use this mode only to unlock a volume enrolled before the derivation was fixed, and re-enroll that volume immediately."

// DeriveSecret derives an HMAC secret from the credential.
//
// The secret is the authenticator's hmac-secret extension output: the
// platform encrypts the salt under a PIN/UV auth shared secret established
// by ECDH with the authenticator, the authenticator returns
// HMAC-SHA-256(CredRandom, salt) encrypted under the same secret, and the
// platform decrypts it. CredRandom never leaves the authenticator, so the
// result is reproducible only in its presence.
//
// When config.DerivationMode is DerivationModeLegacyInsecure the deprecated
// pre-fix derivation runs instead. See DerivationModeLegacyInsecure.
func (h *HMACSecretExtension) DeriveSecret(config *AuthenticationConfig) (*AuthenticationResult, error) {
	if config == nil {
		return nil, ErrAuthenticationConfigNil
	}

	if config.DerivationMode == DerivationModeLegacyInsecure {
		return h.deriveSecretLegacy(config)
	}
	return h.deriveSecretCTAP2(config)
}

// deriveSecretCTAP2 performs the hmac-secret derivation defined by
// CTAP 2.1 12.5.
func (h *HMACSecretExtension) deriveSecretCTAP2(config *AuthenticationConfig) (*AuthenticationResult, error) {
	if len(config.CredentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	salts, err := hmacSecretSalts(config)
	if err != nil {
		return nil, err
	}

	session, err := h.auth.EstablishPINUVAuthSession()
	if err != nil {
		return nil, err
	}

	saltEnc, err := session.Encrypt(salts)
	if err != nil {
		return nil, err
	}

	extensions := map[string]interface{}{
		ExtensionHMACSecret: map[int]interface{}{
			hmacSecretInputKeyAgreement:      session.PlatformKeyAgreement().Map(),
			hmacSecretInputSaltEnc:           saltEnc,
			hmacSecretInputSaltAuth:          session.Authenticate(saltEnc),
			hmacSecretInputPinUVAuthProtocol: session.Version(),
		},
	}

	resp, err := h.getAssertion(config, extensions)
	if err != nil {
		return nil, err
	}

	result, err := newAuthenticationResult(resp)
	if err != nil {
		return nil, err
	}

	output, err := hmacSecretOutput(resp.AuthData, session, len(salts))
	if err != nil {
		return nil, err
	}

	result.HMACSecret = output[:hmacSecretSaltLen]
	if len(output) > hmacSecretSaltLen {
		result.HMACSecret2 = output[hmacSecretSaltLen:]
	}

	return result, nil
}

// hmacSecretSalts concatenates the configured salts into the plaintext the
// extension input carries. CTAP 2.1 12.5 admits one or two salts, each
// exactly 32 bytes.
func hmacSecretSalts(config *AuthenticationConfig) ([]byte, error) {
	if len(config.Salt) != hmacSecretSaltLen {
		return nil, &errs.Detail{
			Err:    ErrInvalidSalt,
			Detail: fmt.Sprintf("expected a %d-byte salt, got %d", hmacSecretSaltLen, len(config.Salt)),
		}
	}

	if len(config.Salt2) == 0 {
		return append([]byte(nil), config.Salt...), nil
	}

	if len(config.Salt2) != hmacSecretSaltLen {
		return nil, &errs.Detail{
			Err:    ErrInvalidSalt,
			Detail: fmt.Sprintf("expected a %d-byte second salt, got %d", hmacSecretSaltLen, len(config.Salt2)),
		}
	}

	salts := make([]byte, 0, 2*hmacSecretSaltLen)
	salts = append(salts, config.Salt...)
	salts = append(salts, config.Salt2...)
	return salts, nil
}

// hmacSecretOutput extracts and decrypts the hmac-secret extension output.
// Every failure is terminal: a value that is not the authenticator's
// secret is not a key, so none is returned.
func hmacSecretOutput(authData []byte, session *PINUVAuthSession, saltsLen int) ([]byte, error) {
	extensions, err := ParseAuthDataExtensions(authData)
	if err != nil {
		return nil, err
	}

	value, ok := extensions[ExtensionHMACSecret]
	if !ok {
		return nil, ErrHMACSecretMissing
	}

	encrypted, ok := value.([]byte)
	if !ok {
		return nil, &errs.Detail{
			Err:    ErrHMACSecretOutputInvalid,
			Detail: fmt.Sprintf("expected a byte string, got %T", value),
		}
	}

	output, err := session.Decrypt(encrypted)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrHMACSecretOutputInvalid, Cause: err}
	}

	if len(output) != saltsLen {
		return nil, &errs.Detail{
			Err:    ErrHMACSecretOutputInvalid,
			Detail: fmt.Sprintf("expected %d bytes for %d salt(s), got %d", saltsLen, saltsLen/hmacSecretSaltLen, len(output)),
		}
	}

	return output, nil
}

// getAssertion issues the GetAssertion request that carries an hmac-secret
// extension input.
func (h *HMACSecretExtension) getAssertion(config *AuthenticationConfig, extensions map[string]interface{}) (*GetAssertionResponse, error) {
	challenge := config.Challenge
	if len(challenge) == 0 {
		challenge = make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to generate challenge", Err: err}
		}
	}

	req := &GetAssertionRequest{
		RPID:           config.RelyingPartyID,
		ClientDataHash: CreateClientDataHash(challenge),
		AllowList: []PublicKeyCredentialDescriptor{
			{
				Type: "public-key",
				ID:   config.CredentialID,
			},
		},
		Extensions: extensions,
		Options: AuthenticatorOptions{
			UP: true, // User presence required
			UV: config.RequireUserVerification,
		},
	}

	resp, err := h.auth.GetAssertion(req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get assertion", Err: err}
	}
	return resp, nil
}

// newAuthenticationResult populates the assertion metadata shared by every
// derivation mode. The HMAC secret is filled in by the caller.
func newAuthenticationResult(resp *GetAssertionResponse) (*AuthenticationResult, error) {
	authData := resp.AuthData
	if len(authData) < authDataHeaderLen {
		return nil, &errs.Detail{
			Err:    ErrAuthDataTooShort,
			Detail: fmt.Sprintf("got %d bytes", len(authData)),
		}
	}

	flags := authData[authDataRPIDHashLen]

	return &AuthenticationResult{
		SignCount:      binary.BigEndian.Uint32(authData[authDataRPIDHashLen+1 : authDataHeaderLen]),
		UserPresent:    flags&FlagUserPresent != 0,
		UserVerified:   flags&FlagUserVerified != 0,
		BackupEligible: flags&FlagBackupEligible != 0,
		BackupState:    flags&FlagBackupState != 0,
		Signature:      resp.Signature,
		AuthData:       authData,
	}, nil
}

// deriveSecretLegacy reproduces the derivation go-xkms performed before the
// hmac-secret extension output was parsed correctly, so that a volume
// enrolled against it can be unlocked once and re-enrolled.
//
// Deprecated: migration only. The value it returns is not hardware-bound.
func (h *HMACSecretExtension) deriveSecretLegacy(config *AuthenticationConfig) (*AuthenticationResult, error) {
	slog.Warn(legacyDerivationWarning,
		"relying_party_id", config.RelyingPartyID,
		"derivation_mode", "legacy-insecure",
	)

	// The legacy request sent the raw salt under a "salt1" key, which no
	// conforming authenticator interprets as an hmac-secret input. It is
	// reproduced verbatim so the legacy result is reproduced verbatim.
	extensions := map[string]interface{}{
		ExtensionHMACSecret: map[string]interface{}{
			"salt1": config.Salt,
		},
	}

	resp, err := h.getAssertion(config, extensions)
	if err != nil {
		return nil, err
	}

	result, err := newAuthenticationResult(resp)
	if err != nil {
		return nil, err
	}

	result.HMACSecret = legacyHMACSecret(resp.AuthData, config)
	return result, nil
}

// legacyHMACSecret reproduces the pre-fix extraction byte for byte: raw
// bytes from a fixed offset that ignores the AT flag and is never
// CBOR-decoded, falling back to SHA-256(credentialID || salt), which is
// computable from public data alone.
//
// Deprecated: migration only.
func legacyHMACSecret(authData []byte, config *AuthenticationConfig) []byte {
	var secret []byte

	if authData[authDataRPIDHashLen]&FlagExtensionData != 0 && len(authData) > authDataHeaderLen {
		if extensionData := authData[authDataHeaderLen:]; len(extensionData) >= hmacSecretSaltLen {
			secret = extensionData[:hmacSecretSaltLen]
		}
	}

	if len(secret) == 0 {
		hash := sha256.New()
		hash.Write(config.CredentialID)
		hash.Write(config.Salt)
		secret = hash.Sum(nil)
	}

	return secret
}

// GenerateDerivedKey generates a derived key from FIDO2 HMAC-secret
// This derives a 512-bit key suitable for encryption from the HMAC secret
func GenerateDerivedKey(hmacSecret []byte) ([]byte, error) {
	if len(hmacSecret) != 32 {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid HMAC secret length: expected 32, got %d", len(hmacSecret))}
	}

	// Derive a 512-bit key using SHA-256 based KDF
	kdf := sha256.New()
	kdf.Write(hmacSecret)
	kdf.Write([]byte("go-xkms-key-derivation-v1"))
	key1 := kdf.Sum(nil)

	kdf.Reset()
	kdf.Write(hmacSecret)
	kdf.Write([]byte("go-xkms-key-derivation-v2"))
	key2 := kdf.Sum(nil)

	// Concatenate to form 512-bit key
	derivedKey := make([]byte, 64)
	copy(derivedKey[:32], key1)
	copy(derivedKey[32:], key2)

	return derivedKey, nil
}

// VerifyHMACSecret verifies that an HMAC secret is valid
func VerifyHMACSecret(secret []byte) error {
	if len(secret) == 0 {
		return ErrInvalidHMACSecret
	}
	if len(secret) != 32 && len(secret) != 64 {
		return &errs.Message{Msg: fmt.Sprintf("invalid HMAC secret length: expected 32 or 64, got %d", len(secret))}
	}
	return nil
}
