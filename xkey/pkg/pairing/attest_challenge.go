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

package pairing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strconv"
)

// Device attestation, protocol version 2 — the challenge-response model
// (issue #129). It replaces version 1's "freshness comes from the nonce baked
// into the attestation certificate".
//
// Version 1 asked the device to generate a key with THIS pairing's nonce as
// the Android attestation challenge, then compared that nonce against the
// challenge inside the signed leaf. That makes freshness and a stable device
// identity mutually exclusive on Android: Keystore fixes the attestation
// challenge at key GENERATION (setAttestationChallenge) and offers no way to
// re-attest an existing key, so a per-pairing challenge forces a per-pairing
// key, whose public half is a new value every time. Measured on xkey-android;
// the same key cannot be both stable and carry this session's challenge.
//
// Version 2 separates the two properties that version 1 conflated:
//
//   - IDENTITY is a Device Attestation Key (DAK): one persistent hardware key
//     per device, generated and attested once. Its SubjectPublicKeyInfo hashes
//     to the DeviceFingerprint, which therefore survives re-attestation and
//     changes only on a genuine key rotation.
//   - FRESHNESS is a live signature by that same DAK over a transcript
//     carrying this exchange's nonce. Nothing about it is baked into a
//     certificate, so it can be repeated for the life of the key.
//
// The verifier checks the attestation chain to establish "this key lives in
// that device's secure hardware", and checks the signature to establish "the
// peer on this connection holds it, right now". TPM devices prove the same two
// things with an AK certificate and a TPM2_Sign over the same transcript, so
// the model is one protocol rather than two.

const (
	// AttestProtocolV1 is the legacy embedded-challenge model: freshness came
	// from the nonce inside the attestation certificate. Records bound under
	// it keep working, but no new pairing may use it (#129).
	AttestProtocolV1 = 1

	// AttestProtocolV2 is the challenge-response model: a persistent attested
	// key plus a live signature over the nonce.
	AttestProtocolV2 = 2

	// AttestPurposePair is the transcript purpose for the attestation that
	// establishes a pairing.
	AttestPurposePair = "pair"

	// AttestPurposeReattest is the transcript purpose for the attestation that
	// re-proves an existing binding — at reconnect, and for
	// `xkey device attest-device`.
	AttestPurposeReattest = "reattest"

	// AttestSignatureES256 is the only signature algorithm this verifier
	// implements: ECDSA on P-256 over a SHA-256 digest, ASN.1 DER encoded.
	// It is what Android's Signature("SHA256withECDSA") produces over a
	// StrongBox/TEE EC key and what crypto/ecdsa.VerifyASN1 consumes.
	AttestSignatureES256 = "ES256"

	// AttestTranscriptDomain is the domain-separation prefix of the signed
	// transcript. It is what stops a signature produced for some other xkey
	// protocol — or some other protocol entirely that happens to sign with the
	// same key — from being presented here.
	AttestTranscriptDomain = "xkey-attest-transcript-v1"

	// AttestGenesisChallenge is the Android attestation challenge the DAK must
	// have been GENERATED under. It is not a freshness value and must never be
	// compared against a live nonce: it is fixed for the life of the key and
	// public in the certificate. What it establishes is that the key was
	// created to be an xkey device key, so a chain minted for an unrelated
	// purpose cannot be replayed into this protocol.
	//
	// The verifier requires it as a PREFIX rather than the whole challenge, so
	// a prover may append install-unique bytes without a protocol version bump.
	// Provers SHOULD send exactly this value.
	AttestGenesisChallenge = "xkey-device-attestation-v1"

	// AttestChannelBindingDomain is the domain-separation prefix of the
	// channel binding.
	AttestChannelBindingDomain = "xkey-attest-channel-v1"

	// AttestStaticKeySize is the length of a Noise Curve25519 static public
	// key, in bytes.
	AttestStaticKeySize = 32

	// AttestNonceSize is the length of the verifier's challenge nonce, in
	// bytes. Fixed width: the transcript is parsed by position, so a
	// variable-length field here would let two different (nonce, binding)
	// pairs serialize identically.
	AttestNonceSize = 32

	// AttestChannelBindingSize is the length of the channel binding, in bytes —
	// the SHA-256 ComputeAttestChannelBinding produces.
	AttestChannelBindingSize = 32

	// AttestFingerprintSize is the length of the raw DeviceFingerprint, in
	// bytes — a SHA-256 over the DAK's SubjectPublicKeyInfo.
	AttestFingerprintSize = 32

	// attestMaxPurposeLen bounds the purpose field so its single-byte length
	// prefix can always encode it.
	attestMaxPurposeLen = 255
)

// Attestation challenge-response errors. Every one of them is a refusal: there
// is no path through this file that reports a weaker result instead of failing.
var (
	// ErrAttestProtocolDowngrade indicates the peer answered a version 2
	// challenge with something other than a version 2 response. It is a
	// refusal, never a fallback to version 1 — an active attacker chooses
	// which version to claim, so accepting the older one on request would
	// hand the choice of checks to the party being checked.
	ErrAttestProtocolDowngrade = errors.New("pairing: device answered with an unsupported attestation protocol version - it must be upgraded to prove liveness")

	// ErrAttestSignatureMissing indicates a version 2 response carried no
	// challenge signature, which is the entire freshness proof.
	ErrAttestSignatureMissing = errors.New("pairing: attestation response carries no challenge signature")

	// ErrAttestSignatureAlgorithm indicates the response named a signature
	// algorithm this verifier does not implement.
	ErrAttestSignatureAlgorithm = errors.New("pairing: unsupported attestation signature algorithm")

	// ErrAttestSignatureInvalid indicates the challenge signature did not
	// verify under the attested key — the peer did not prove it holds the key
	// the chain describes.
	ErrAttestSignatureInvalid = errors.New("pairing: attestation challenge signature is invalid - the peer did not prove possession of the attested key")

	// ErrAttestKeyNotECDSA indicates the attested leaf carries a public key
	// this verifier cannot check an ES256 signature with.
	ErrAttestKeyNotECDSA = errors.New("pairing: attested key is not an ECDSA public key")

	// ErrAttestGenesisChallenge indicates the attested key was not generated
	// as an xkey device attestation key.
	ErrAttestGenesisChallenge = errors.New("pairing: attested key was not generated as an xkey device attestation key")

	// ErrAttestTranscriptField indicates a transcript input was the wrong
	// size or absent. Building a transcript from short inputs would silently
	// produce a shorter one both sides could still agree on, so it fails.
	ErrAttestTranscriptField = errors.New("pairing: attestation transcript field has the wrong size")

	// ErrAttestPurpose indicates the purpose string is empty or too long to
	// length-prefix.
	ErrAttestPurpose = errors.New("pairing: attestation transcript purpose is invalid")

	// ErrAttestNilCertificate indicates a helper was handed no certificate at
	// all. These helpers are exported and re-exported through pkg/phone, so
	// they are reachable from callers this package does not control: a nil
	// must be a refusal they can handle, not a panic that takes down a
	// long-running process. Absence of evidence is a verification failure like
	// any other.
	ErrAttestNilCertificate = errors.New("pairing: no attested certificate supplied")
)

// BuildAttestTranscript serializes the bytes both peers sign and verify.
//
// The layout is fixed-width except for purpose, which carries a one-byte
// length prefix, so exactly one byte string encodes any given set of inputs.
// That matters more than it looks: without the prefix, ("pair", nonce N) and
// ("pairX", nonce N') could serialize identically for some N, N', and a
// signature obtained for one exchange would verify for the other.
//
//	offset      size  field
//	0           25    domain, ASCII "xkey-attest-transcript-v1"
//	25          1     len(purpose)
//	26          n     purpose, ASCII
//	26+n        32    nonce
//	58+n        32    channelBinding
//	90+n        32    deviceFingerprint
//
// Each field earns its place:
//
//   - domain separates this signature from every other use of the key.
//   - purpose separates pairing from re-attestation, so a signature captured
//     during pairing cannot be replayed to satisfy a reconnect.
//   - nonce is the verifier's fresh random challenge: it is what makes the
//     signature impossible to precompute or replay across exchanges.
//   - channelBinding is ComputeAttestChannelBinding's value for the session
//     carrying the exchange — the two Noise static public keys and the
//     prologue, NOT the Noise handshake hash; see that function for why not.
//     It is the anti-relay term. Without it, an attacker completing
//     its OWN Noise session with the desktop could forward the desktop's
//     challenge to a genuine phone on a second session and relay the answer
//     back, presenting that phone's hardware identity as its own. With it, the
//     phone signs the hash of the session it is actually speaking on, which is
//     not the session the attacker holds.
//   - deviceFingerprint makes the signature commit to the identity being
//     claimed, so it cannot be lifted onto a chain for a different key.
func BuildAttestTranscript(purpose string, nonce, channelBinding, deviceFingerprint []byte) ([]byte, error) {
	if purpose == "" || len(purpose) > attestMaxPurposeLen {
		return nil, &DetailError{Err: ErrAttestPurpose, Detail: ": length " + strconv.Itoa(len(purpose))}
	}
	if len(nonce) != AttestNonceSize {
		return nil, attestFieldError("nonce", len(nonce), AttestNonceSize)
	}
	if len(channelBinding) != AttestChannelBindingSize {
		return nil, attestFieldError("channelBinding", len(channelBinding), AttestChannelBindingSize)
	}
	if len(deviceFingerprint) != AttestFingerprintSize {
		return nil, attestFieldError("deviceFingerprint", len(deviceFingerprint), AttestFingerprintSize)
	}

	size := len(AttestTranscriptDomain) + 1 + len(purpose) +
		AttestNonceSize + AttestChannelBindingSize + AttestFingerprintSize

	transcript := make([]byte, 0, size)
	transcript = append(transcript, AttestTranscriptDomain...)
	transcript = append(transcript, byte(len(purpose)))
	transcript = append(transcript, purpose...)
	transcript = append(transcript, nonce...)
	transcript = append(transcript, channelBinding...)
	transcript = append(transcript, deviceFingerprint...)

	return transcript, nil
}

// ComputeAttestChannelBinding derives the 32-byte value that ties an
// attestation signature to the connection it was produced on.
//
// It is a hash over the two Noise static public keys that authenticated this
// connection, plus the prologue the identity exchange agreed. Both peers hold
// all three the moment the XX handshake completes — the initiator learns the
// responder's static key from the handshake, and the responder learns the
// initiator's — so neither has to be told what to bind to.
//
// WHY THIS AND NOT THE NOISE HANDSHAKE HASH. The handshake hash `h` would be
// strictly stronger: it commits to the ephemeral keys as well, so it is unique
// per SESSION rather than per key PAIR. It is not used here because
// go-truststrap's noiseproto.Session keeps its *noise.HandshakeState
// unexported and offers no ChannelBinding accessor, and reaching for the
// handshake hash on the Android side would mean depending on a hand-written
// Kotlin Noise implementation agreeing byte-for-byte with flynn/noise at a
// specific point in the transcript — an interop hazard on a value that must
// match exactly or every connection fails. Filed upstream; a future protocol
// version can swap the derivation without changing the field's size or place.
//
// The security difference is small and bounded. What the binding must defeat
// is RELAY: an attacker completing its own Noise session with the desktop,
// forwarding the desktop's challenge to a genuine phone over a second session,
// and passing that phone's answer off as its own. To make the phone sign the
// desktop's binding, the attacker would have to present the desktop's static
// key as its own to the phone (it cannot — XX proves possession by DH) and the
// phone's static key as its own to the desktop (likewise). Both directions are
// closed by key possession, which is what the binding rests on either way.
// What the weaker derivation does not separate is two concurrent sessions
// between the SAME pair of keys — and there the fresh per-exchange nonce, which
// an attacker cannot predict, is what keeps a signature from moving between
// them.
//
// prologue may be empty: that is the first-pairing case, where the identity
// exchange has no fingerprint to bind yet. It is length-prefixed so an empty
// prologue and a 32-byte one cannot serialize to the same bytes.
func ComputeAttestChannelBinding(initiatorStatic, responderStatic, prologue []byte) ([]byte, error) {
	if len(initiatorStatic) != AttestStaticKeySize {
		return nil, attestFieldError("initiatorStatic", len(initiatorStatic), AttestStaticKeySize)
	}
	if len(responderStatic) != AttestStaticKeySize {
		return nil, attestFieldError("responderStatic", len(responderStatic), AttestStaticKeySize)
	}
	if len(prologue) > attestMaxPurposeLen {
		return nil, attestFieldError("prologue", len(prologue), attestMaxPurposeLen)
	}

	h := sha256.New()
	h.Write([]byte(AttestChannelBindingDomain))
	h.Write([]byte{byte(len(initiatorStatic))})
	h.Write(initiatorStatic)
	h.Write([]byte{byte(len(responderStatic))})
	h.Write(responderStatic)
	h.Write([]byte{byte(len(prologue))})
	h.Write(prologue)

	return h.Sum(nil), nil
}

func attestFieldError(name string, got, want int) error {
	return &DetailError{
		Err:    ErrAttestTranscriptField,
		Detail: ": " + name + " is " + strconv.Itoa(got) + " bytes, want " + strconv.Itoa(want),
	}
}

// AttestedKeyFingerprint returns the raw DeviceFingerprint of an attested
// leaf: the SHA-256 of its SubjectPublicKeyInfo.
//
// Hashing the SPKI rather than the leaf DER is what makes the value an
// identity instead of a certificate serial number. Re-attesting the same key
// reissues the leaf with a fresh serial and validity window while the key
// itself is unchanged, so an SPKI hash is stable across honest re-attestation
// and moves only when the device regenerates its DAK — which is exactly the
// event a pairing must be re-established for.
//
// It is neither the trust ANCHOR's hash — a vendor root shared by every
// handset attesting under it, and so not device-unique — nor a hash of the
// last certificate the peer sent, which the peer chooses.
//
// This derives an identifier from material the caller has already VERIFIED. It
// verifies nothing itself.
//
// It returns an error rather than panicking on a nil leaf: the value it
// produces becomes a device's stored identity, so every path that can fail to
// produce one has to be a path the caller must handle.
func AttestedKeyFingerprint(leaf *x509.Certificate) ([AttestFingerprintSize]byte, error) {
	if leaf == nil {
		return [AttestFingerprintSize]byte{}, ErrAttestNilCertificate
	}
	return sha256.Sum256(leaf.RawSubjectPublicKeyInfo), nil
}

// AttestedKeyFingerprintHex is AttestedKeyFingerprint in the lower-case hex
// encoding the pairing record stores and the identity exchange carries.
func AttestedKeyFingerprintHex(leaf *x509.Certificate) (string, error) {
	sum, err := AttestedKeyFingerprint(leaf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

// VerifyGenesisChallenge checks that an attested key was generated as an xkey
// device attestation key.
//
// challenge is the attestationChallenge from the leaf's SIGNED attestation
// extension, and it is a GENESIS value: fixed when the key was created. Under
// protocol version 2 it is never compared against a live nonce, because it
// cannot be — that impossibility is why version 2 exists. What it still
// usefully binds is purpose, which is why it is checked at all.
func VerifyGenesisChallenge(challenge []byte) error {
	prefix := []byte(AttestGenesisChallenge)
	if len(challenge) < len(prefix) {
		return &DetailError{
			Err:    ErrAttestGenesisChallenge,
			Detail: ": challenge is " + strconv.Itoa(len(challenge)) + " bytes, want at least " + strconv.Itoa(len(prefix)),
		}
	}
	// A plain comparison: the genesis challenge is a public, non-secret field
	// of a certificate anyone can read, so there is no secret here for a
	// timing side channel to leak.
	if string(challenge[:len(prefix)]) != AttestGenesisChallenge {
		return &DetailError{Err: ErrAttestGenesisChallenge, Detail: ": challenge does not carry the xkey device-key prefix"}
	}
	return nil
}

// VerifyAttestChallengeSignature checks the peer's live proof that it holds
// the attested key.
//
// leaf must already have been verified: chained to a trusted hardware
// attestation anchor, at an acceptable security level, on a verified boot
// state. This function establishes only the remaining half of the claim — that
// whoever is on the other end of THIS session holds the private key that leaf
// certifies — and it is meaningless without the other half. A signature by an
// unverified key proves possession of a key nobody vouched for.
//
// algorithm is checked rather than inferred so that a peer cannot select a
// weaker verification path by mislabelling its signature.
func VerifyAttestChallengeSignature(leaf *x509.Certificate, algorithm string, signature, transcript []byte) error {
	if len(signature) == 0 {
		return ErrAttestSignatureMissing
	}
	if algorithm != AttestSignatureES256 {
		return &DetailError{Err: ErrAttestSignatureAlgorithm, Detail: ": " + algorithm + ", want " + AttestSignatureES256}
	}
	// Checked before the dereference below. A caller with no certificate has
	// nothing to verify the signature AGAINST, which is a refusal — and this
	// is exported, so "the caller would never do that" is not a property this
	// function can rely on.
	if leaf == nil {
		return ErrAttestNilCertificate
	}

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrAttestKeyNotECDSA
	}
	// ES256 names P-256, not "ECDSA with a SHA-256 digest on whatever curve
	// the certificate happens to carry". Accepting another curve under the
	// ES256 label would let the peer decide the security level of its own
	// proof while the audit record still reads ES256.
	if pub.Curve != elliptic.P256() {
		return &DetailError{Err: ErrAttestKeyNotECDSA, Detail: ": curve is " + pub.Curve.Params().Name + ", want P-256"}
	}

	digest := sha256.Sum256(transcript)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return ErrAttestSignatureInvalid
	}
	return nil
}

// RPCExchange performs one encrypted JSON-RPC round trip over an established
// session.
type RPCExchange func(ctx context.Context, req *Request) (*Response, error)

// LiveAttestFunc re-proves, on a freshly handshaken session, that the peer
// still holds the per-device attested key bound at pairing (#129).
//
// It returns nil only when the peer produced a valid live proof for the
// identity the caller expects. Every other outcome is an error that must fail
// the connection.
//
// It is defined here rather than beside the backend that calls it so that the
// package owning the attestation DECISION can produce one without importing
// the transport that consumes it.
type LiveAttestFunc func(ctx context.Context, exchange RPCExchange, channelBinding []byte) error
