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

package pairingproto

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// On-demand user verification (owner rulings 167 and 180).
//
// local.verifyUser asks the phone to verify its user NOW and to prove it did.
// The proof is a signature by a dedicated user-verification key (the UVK): an
// EC P-256 Android Keystore key generated with
// setUserAuthenticationRequired(true) and a validity of 0 seconds, so the
// TEE releases one signature per fresh user authentication and never two. The
// user authenticates with a strong biometric or the device credential, both
// of which are user verification under CTAP 2.1 (ruling 180). The UVK is a
// different key from the DAK on purpose: the DAK signs without a prompt,
// which is what reconnect liveness needs, and a key cannot be both. The phone
// generates the UVK for AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL, and the
// desktop accepts either from the attested userAuthType
// (android.RequireAttestedPerUseUserVerification); it does not choose the
// phone's prompt.
//
// The request names the relying party the verification is for (RPName), and
// the signed transcript binds it, as WebAuthn L2 §6.1 binds the RP into
// authenticator data through rpIdHash: a signature the user gave for one RP
// does not verify for another. The transcript is BuildVerifyUserTranscript:
// BuildAttestTranscript with the purpose AttestPurposeVerifyUser, the
// verifier's fresh nonce, the channel binding each side derives from its own
// Noise session (AttestChannelBinding) and the fingerprint of the UVK
// (AttestedKeyFingerprint of the UVK leaf), followed by SHA-256 of the RP
// name. The purpose is what keeps a verify-user signature apart from a pair
// or reattest one; the fingerprint is what commits it to the UVK.
//
// The result carries the UVK's attestation chain every time, and the desktop
// verifies it every time, against the Google hardware attestation roots,
// with the revocation status list checked and no intermediate pinned
// (ruling 180). So the desktop learns the key on first use and persists
// nothing: the pairing record does not change, and the record's
// attestation_protocol_version does not move. A later revision that pins the
// UVK fingerprint in the pairing record changes the record and must bump that
// version.

const (
	// MethodLocalVerifyUser is the desktop-to-phone request for a fresh,
	// hardware-enforced user verification.
	MethodLocalVerifyUser = "local.verifyUser"

	// AttestPurposeVerifyUser is the transcript purpose of a local.verifyUser
	// signature.
	AttestPurposeVerifyUser = "verify-user"

	// UserVerificationGenesisChallenge prefixes the attestation challenge the
	// UVK is generated under. Like AttestGenesisChallenge it is not a
	// freshness value; it marks the key as created for this role, so a DAK
	// chain cannot be presented as a UVK chain, nor a UVK chain as a DAK one.
	// Trailing bytes are reserved for the prover.
	UserVerificationGenesisChallenge = "xkey-user-verification-v1"

	// VerifyUserRPNameMaxLen bounds LocalVerifyUserParams.RPName, in bytes of
	// UTF-8. It is the 64 bytes WebAuthn L2 §5.4.1 lets an authenticator
	// truncate an RP entity's name to, so a name the authenticator would
	// keep always fits.
	VerifyUserRPNameMaxLen = 64
)

var (
	// ErrUserVerificationGenesisChallenge reports a key whose attestation
	// challenge does not begin with UserVerificationGenesisChallenge.
	ErrUserVerificationGenesisChallenge = errors.New("pairing: attested key was not generated as an xkey user-verification key")

	// ErrVerifyUserRPName reports an RP name that is empty, longer than
	// VerifyUserRPNameMaxLen, not UTF-8, or carries a control character.
	ErrVerifyUserRPName = errors.New("pairing: invalid verify-user RP name")
)

// VerifyUserFunc runs one local.verifyUser exchange on an established session
// for the relying party rpName, and returns nil only when the phone proved a
// fresh user verification for it. channelBinding is the session's
// AttestChannelBinding.
type VerifyUserFunc func(ctx context.Context, exchange RPCExchange, channelBinding []byte, rpName string) error

// LocalVerifyUserParams contains parameters for local.verifyUser.
//
// Like the version 2 local.attestDevice request it carries NO channel binding
// and no purpose: the purpose is fixed by the method, and each side derives
// the binding from its own session (see the note after
// LocalAttestDeviceParams).
type LocalVerifyUserParams struct {
	// ProtocolVersion is AttestProtocolV2, the transcript and channel-binding
	// construction the signature uses.
	ProtocolVersion int `json:"protocolVersion"`

	// Nonce is the verifier's fresh 32-byte challenge.
	Nonce []byte `json:"nonce"`

	// RPName names the relying party the verification is for; the phone
	// shows it in the prompt. It is required, and ValidateVerifyUserRPName
	// bounds it. The transcript binds it (BuildVerifyUserTranscript).
	RPName string `json:"rpName"`
}

// LocalVerifyUserResult contains the result of local.verifyUser.
//
// The phone answers only after the user authenticated and the UVK signed. A
// user who cancels, or a phone with no UVK, answers with an RPC error, never
// with a result.
type LocalVerifyUserResult struct {
	// ProtocolVersion is the model the phone answered under; anything but
	// AttestProtocolV2 is ErrAttestProtocolDowngrade.
	ProtocolVersion int `json:"protocolVersion"`

	// CertificateChain is the UVK's attestation chain, DER, leaf first:
	// [leaf(UVK), intermediate..., root].
	CertificateChain [][]byte `json:"certificateChain"`

	// Signature is the UVK's signature over the verify-user transcript,
	// SHA256withECDSA, ASN.1 DER.
	Signature []byte `json:"signature"`

	// SignatureAlgorithm names the signature scheme, AttestSignatureES256.
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

// VerifyUserVerificationGenesisChallenge checks the attestation challenge of a
// UVK certificate, read from its signed attestation extension.
func VerifyUserVerificationGenesisChallenge(challenge []byte) error {
	return verifyGenesisPrefix(challenge, UserVerificationGenesisChallenge,
		ErrUserVerificationGenesisChallenge, "user-verification")
}

// ValidateVerifyUserRPName checks the RP name of a local.verifyUser request.
// It must be non-empty, at most VerifyUserRPNameMaxLen bytes of valid UTF-8,
// and free of control characters, so the name the phone's prompt shows is a
// single line the desktop chose, not text that forges more of the prompt.
func ValidateVerifyUserRPName(rpName string) error {
	if rpName == "" {
		return &DetailError{Err: ErrVerifyUserRPName, Detail: ": empty"}
	}
	if len(rpName) > VerifyUserRPNameMaxLen {
		return &DetailError{
			Err: ErrVerifyUserRPName,
			Detail: ": " + strconv.Itoa(len(rpName)) + " bytes, want at most " +
				strconv.Itoa(VerifyUserRPNameMaxLen),
		}
	}
	if !utf8.ValidString(rpName) {
		return &DetailError{Err: ErrVerifyUserRPName, Detail: ": not valid UTF-8"}
	}
	for _, r := range rpName {
		if unicode.IsControl(r) {
			return &DetailError{Err: ErrVerifyUserRPName, Detail: ": carries a control character"}
		}
	}
	return nil
}

// BuildVerifyUserTranscript builds the transcript a UVK signs for
// local.verifyUser:
//
//	BuildAttestTranscript(AttestPurposeVerifyUser, nonce, channelBinding, uvkFingerprint)
//	    || SHA-256(rpName)
//
// The RP name hash is a fixed 32 bytes, as rpIdHash is in WebAuthn L2 §6.1
// authenticator data, so the transcript stays unambiguous without a length
// prefix.
func BuildVerifyUserTranscript(rpName string, nonce, channelBinding, uvkFingerprint []byte) ([]byte, error) {
	if err := ValidateVerifyUserRPName(rpName); err != nil {
		return nil, err
	}
	transcript, err := BuildAttestTranscript(AttestPurposeVerifyUser, nonce, channelBinding, uvkFingerprint)
	if err != nil {
		return nil, err
	}
	rpNameHash := sha256.Sum256([]byte(rpName))
	return append(transcript, rpNameHash[:]...), nil
}
