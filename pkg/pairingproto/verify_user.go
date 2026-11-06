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
	"errors"
	"strconv"
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
// which is what reconnect liveness needs, and a key cannot be both.
//
// The request carries the name of the relying party the verification is for,
// and the phone's prompt shows it, as WebAuthn shows the RP (ruling 180).
//
// The signed transcript is BuildVerifyUserTranscript: the protocol version 2
// transcript (BuildAttestTranscript) with the purpose AttestPurposeVerifyUser,
// the verifier's fresh nonce, the channel binding each side derives from its
// own Noise session (AttestChannelBinding) and the fingerprint of the UVK
// (AttestedKeyFingerprint of the UVK leaf), followed by the length-prefixed
// RP name. The purpose is what keeps a verify-user signature apart from a pair
// or reattest one; the fingerprint is what commits it to the UVK; the RP name
// is what commits it to the relying party the user was shown, so a signature
// the user gave for one RP cannot be presented for another.
//
// The result carries the UVK's attestation chain every time, and the desktop
// verifies it every time, so the desktop learns the key on first use and
// persists nothing: the pairing record does not change, and the record's
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

	// VerifyUserRPNameMaxLen bounds the RP name of a local.verifyUser
	// request, in bytes of UTF-8, so its single-byte length prefix in the
	// transcript can always encode it. A WebAuthn RP ID, a domain name, is
	// at most 253 bytes.
	VerifyUserRPNameMaxLen = 255
)

var (
	// ErrUserVerificationGenesisChallenge reports a key whose attestation
	// challenge does not begin with UserVerificationGenesisChallenge.
	ErrUserVerificationGenesisChallenge = errors.New("pairing: attested key was not generated as an xkey user-verification key")

	// ErrVerifyUserRPName reports an RP name that is empty, longer than
	// VerifyUserRPNameMaxLen bytes, or not valid UTF-8. The name is shown to
	// the user and signed, so a name the phone could render differently
	// from the bytes the desktop signs over is refused rather than repaired.
	ErrVerifyUserRPName = errors.New("pairing: verify-user RP name is invalid")
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

	// RPName is the relying party the verification is for, which the
	// phone's prompt shows (ruling 180). Required: 1 to
	// VerifyUserRPNameMaxLen bytes of UTF-8. It is bound into the signed
	// transcript (BuildVerifyUserTranscript).
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

// ValidateVerifyUserRPName checks the RP name of a local.verifyUser request:
// 1 to VerifyUserRPNameMaxLen bytes of valid UTF-8.
func ValidateVerifyUserRPName(rpName string) error {
	if rpName == "" || len(rpName) > VerifyUserRPNameMaxLen {
		return &DetailError{Err: ErrVerifyUserRPName, Detail: ": length " + strconv.Itoa(len(rpName))}
	}
	if !utf8.ValidString(rpName) {
		return &DetailError{Err: ErrVerifyUserRPName, Detail: ": not valid UTF-8"}
	}
	return nil
}

// BuildVerifyUserTranscript serializes the bytes the UVK signs for a
// local.verifyUser answer: the version 2 transcript under
// AttestPurposeVerifyUser, then the RP name with a one-byte length prefix.
//
//	offset  size  field
//	0       133   BuildAttestTranscript(AttestPurposeVerifyUser, nonce, channelBinding, uvkFingerprint)
//	133     1     len(rpName)
//	134     n     rpName, UTF-8
//
// The prefix keeps the encoding unique, and the RP name comes last so the
// transcript of every other purpose is unchanged: no pair or reattest
// transcript can parse as a verify-user one, since the purpose differs.
func BuildVerifyUserTranscript(nonce, channelBinding, uvkFingerprint []byte, rpName string) ([]byte, error) {
	if err := ValidateVerifyUserRPName(rpName); err != nil {
		return nil, err
	}
	transcript, err := BuildAttestTranscript(AttestPurposeVerifyUser, nonce, channelBinding, uvkFingerprint)
	if err != nil {
		return nil, err
	}
	transcript = append(transcript, byte(len(rpName)))
	return append(transcript, rpName...), nil
}
