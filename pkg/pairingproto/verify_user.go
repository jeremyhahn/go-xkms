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

import "errors"

// On-demand user verification (owner ruling 167).
//
// local.verifyUser asks the phone to verify its user NOW and to prove it did.
// The proof is a signature by a dedicated user-verification key (the UVK): an
// EC P-256 Android Keystore key generated with
// setUserAuthenticationRequired(true) and a validity of 0 seconds, so the
// TEE releases one signature per fresh user authentication and never two. The
// UVK is a different key from the DAK on purpose: the DAK signs without a
// prompt, which is what reconnect liveness needs, and a key cannot be both.
//
// The request and the signed transcript reuse protocol version 2 unchanged.
// The transcript is BuildAttestTranscript with the purpose
// AttestPurposeVerifyUser, the verifier's fresh nonce, the channel binding
// each side derives from its own Noise session (AttestChannelBinding), and the
// fingerprint of the UVK (AttestedKeyFingerprint of the UVK leaf). The
// purpose is what keeps a verify-user signature apart from a pair or
// reattest one; the fingerprint is what commits it to the UVK.
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
)

// ErrUserVerificationGenesisChallenge reports a key whose attestation
// challenge does not begin with UserVerificationGenesisChallenge.
var ErrUserVerificationGenesisChallenge = errors.New("pairing: attested key was not generated as an xkey user-verification key")

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
