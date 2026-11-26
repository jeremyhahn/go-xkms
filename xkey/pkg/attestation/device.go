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

package attestation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Device attestation: the security decision that judges whether a phone is the
// hardware-backed device a pairing record says it is (#95, #93, #129).
//
// WHY IT LIVES HERE. It used to live in cmd/xkey/cmd, which meant the GUI
// could not reach it: pkg/gui/services cannot import a main package. The
// result was two surfaces establishing device trust by different rules, and
// the drift was not hypothetical — pairing verified chains that
// `device attest-device` did not (#95), the two derived the device identity
// differently (#93), the GUI performed no attestation at all, and the GUI's
// record mirror silently dropped the attestation protocol version so a
// CLI-paired v2 device read as unbound. Every one of those is the same defect:
// a security decision with more than one implementation.
//
// There is one implementation now, and both surfaces consume it. Anything that
// needs to decide whether a device is trusted calls into this file; what stays
// with each surface is what genuinely differs — how it loads its trust store,
// how it persists a record, and what it prints.

// Attestation decision errors.
var (
	// ErrDeviceAttestVerifyFailed is the umbrella refusal for a device
	// attestation that could not be verified. Callers match it to distinguish
	// "the device failed the check" from a transport or encoding failure.
	ErrDeviceAttestVerifyFailed = errors.New("attestation: device attestation verification failed")

	// ErrDeviceAttestFailed indicates the attestation exchange itself failed —
	// transport, encoding or an RPC error — rather than the evidence being bad.
	ErrDeviceAttestFailed = errors.New("attestation: device attestation exchange failed")

	// ErrDeviceAttestNonceFailed indicates the verifier could not draw a
	// challenge nonce. It is fatal: a predictable challenge is not a challenge.
	ErrDeviceAttestNonceFailed = errors.New("attestation: failed to generate an attestation challenge nonce")

	// ErrDeviceBindingIncomplete indicates a record claims to have been bound
	// under challenge-response but carries no usable device identity to check
	// the proof against. It is an internally inconsistent record: a version 2
	// binding is only ever written by a successful attestation, which always
	// records a fingerprint.
	ErrDeviceBindingIncomplete = errors.New("attestation: record requires live attestation but carries no valid device fingerprint - re-pair the device")

	// ErrDeviceIdentityChanged indicates the device's attested key no longer
	// matches the one bound at pairing. Re-attestation refuses fail-closed on
	// this; rebinding a legitimately rotated key is an explicit re-pair (#93).
	ErrDeviceIdentityChanged = errors.New("attestation: attested key changed since pairing - re-pair to rebind, or investigate if unexpected")

	// ErrDeviceAttestationVersionUnsupported indicates the record predates
	// the challenge-response attestation model (#129) or carries no protocol
	// version at all. There is no live-attestation grace period for such a
	// record anymore (BREAKING, go-xkms compat cleanup PR5, removing the
	// original #129/#130 backward-compat grace) -- the operator re-pairs the
	// device so a fresh version 2 binding is established.
	ErrDeviceAttestationVersionUnsupported = errors.New("attestation: record predates the challenge-response attestation model - re-pair the device")
)

// DeviceBinding is everything the verifier needs to know about a pairing
// record: which device identity was bound, and under which attestation model.
//
// It is a small value rather than the record itself on purpose. #130 unified
// the CLI's and the GUI's persisted record into one owned type,
// pairing.PairedDevice, but the verifier still takes only the two fields it
// actually reads rather than the whole record — see DeviceBindingFor — so
// this package's contract stays narrow and neither surface can pass a record
// whose other fields the verifier might quietly start depending on.
type DeviceBinding struct {
	// Fingerprint is the hex-encoded SHA-256 of the attested key's
	// SubjectPublicKeyInfo bound at pairing. Empty means never attested.
	Fingerprint string

	// ProtocolVersion is the attestation model that established the binding:
	// 2 for challenge-response (#129), absent or 1 for older records.
	ProtocolVersion int
}

// DeviceBindingFor projects the persisted pairing record onto what the
// verifier needs: which device identity was bound, and under which
// attestation model (#130).
//
// It lives here rather than as a method on pairing.PairedDevice because
// pkg/attestation already imports pkg/pairing to build the binding's
// contents, and the reverse import would cycle: pkg/pairing owns the record,
// this package owns the decision the record is judged by.
func DeviceBindingFor(d pairing.PairedDevice) DeviceBinding {
	return DeviceBinding{
		Fingerprint:     d.DeviceFingerprint,
		ProtocolVersion: d.AttestationProtocolVersion,
	}
}

// ApplyVerifiedAttestation applies a VERIFIED attestation result to a paired
// device record — the one place every surface writes an attestation claim,
// so a claim applied on the CLI and a claim applied by the GUI cannot drift
// (#130). It mirrors what pairing (device_pair.go), re-attestation
// (device_attest_device.go) and the GUI's connect-time proof all used to
// implement separately field for field.
//
// It is never called with an unverified result. Whether an unattestable
// device may still be paired is policy; that no unverified claim is ever
// written down is not, and the caller enforces it by not calling this
// function at all when attestation failed.
func ApplyVerifiedAttestation(d *pairing.PairedDevice, result *Result) {
	d.LastDeviceAttestationTime = result.AttestationTime
	d.SecurityLevel = result.SecurityLevel
	d.BootStateVerified = result.BootStateVerified
	d.DeviceBootHashHex = result.BootHashHex
	d.DeviceFingerprint = result.DeviceFingerprint

	// The recorded protocol version only ever moves UP. A successful version 2
	// attestation upgrades a legacy record; nothing here can walk a record
	// back to the weaker model, because the version is the anti-downgrade
	// term and a term an attacker could lower is not one (#129).
	if result.ProtocolVersion > d.AttestationProtocolVersion {
		d.AttestationProtocolVersion = result.ProtocolVersion
	}
}

// Validate refuses a record that predates the challenge-response attestation
// model, or that demands the liveness proof but has nothing to judge the
// answer against.
//
// Every record is now required to carry a version 2 (challenge-response)
// binding (BREAKING, go-xkms compat cleanup PR5, removing the #129/#130
// grace period for absent/version-1 records): ProtocolVersion < 2 refuses
// with ErrDeviceAttestationVersionUnsupported, telling the operator to
// re-pair the device rather than connecting under the weaker model.
//
// A version 2 binding with an empty or malformed fingerprint used to FAIL OPEN,
// and the path there is short: the version says "require the proof", so the
// chain and the signature are verified — and then the identity comparison sees
// an empty stored fingerprint, reads it as a first attestation, and accepts
// whichever trusted Android device just answered. The pre-handshake comparison
// does not catch it either, because DecodeDeviceFingerprint("") deliberately
// means "no fingerprint configured". So emptying one YAML field turned a
// device-bound record into "any hardware-attested handset will do", for anyone
// holding the copied paired Noise key. (Codex, #124.)
//
// The binding is therefore validated AS A WHOLE, before the proof is even
// requested: what makes a version 2 record safe is the pair of claims
// together, and half of that pair is not a weaker version of it.
func (b DeviceBinding) Validate() error {
	if b.ProtocolVersion < pairingproto.AttestProtocolV2 {
		return ErrDeviceAttestationVersionUnsupported
	}
	if b.Fingerprint == "" {
		return fmt.Errorf("%w: fingerprint is empty", ErrDeviceBindingIncomplete)
	}
	raw, err := hex.DecodeString(b.Fingerprint)
	if err != nil {
		return fmt.Errorf("%w: fingerprint is not valid hex", ErrDeviceBindingIncomplete)
	}
	if len(raw) != pairingproto.AttestFingerprintSize {
		return fmt.Errorf("%w: fingerprint is %d bytes, want %d",
			ErrDeviceBindingIncomplete, len(raw), pairingproto.AttestFingerprintSize)
	}
	return nil
}

// ValidateAttestedKeyMatch refuses a re-attestation whose attested key differs
// from the one bound at pairing (#93).
//
// Re-attestation REVALIDATES an existing binding, so a changed attested key is
// a fail-closed refusal — never a silent rebind. Without this, a peer holding
// the paired Noise key plus a separately valid hardware attestation of its own
// device could turn an operator's revalidation into a rebind onto that device.
// Legitimate key rotation is an explicit re-pair, which establishes a fresh
// binding on purpose.
//
// Validate() guarantees that if it returns nil, b.Fingerprint is a non-empty,
// well-formed hex string (every valid binding is now version 2 — BREAKING,
// go-xkms compat cleanup PR5 — and Validate rejects a version 2 record with
// an empty fingerprint as incomplete), so the comparison below is always
// against a real stored identity.
func (b DeviceBinding) ValidateAttestedKeyMatch(freshFingerprint string) error {
	// Completeness before comparison, and the ORDER carries the diagnosis. A
	// malformed stored fingerprint can never equal a real one, so comparing
	// first still refuses — but it refuses with "the attested key changed",
	// which tells an operator to treat a corrupt record as a possible attack
	// on their device. Those call for opposite actions: re-pair, versus
	// investigate. Getting the reason right is part of failing closed usefully.
	if err := b.Validate(); err != nil {
		return err
	}
	if b.Fingerprint != freshFingerprint {
		return ErrDeviceIdentityChanged
	}
	return nil
}

// Result is what a verified device attestation yields for persistence.
type Result struct {
	AttestationTime   time.Time
	SecurityLevel     string
	BootStateVerified bool
	BootHashHex       string
	DeviceFingerprint string

	// ProtocolVersion is the attestation model this result was established
	// under. It is recorded rather than assumed so that a device bound by
	// challenge-response can never later be admitted on the weaker version 1
	// evidence: the version is part of what was verified, so downgrading it is
	// a change to the binding, not a property of the next connection.
	ProtocolVersion int
}

// Verified is a verified attestation: the record that may be persisted, plus
// the two display strings derived from the same verified material so nothing
// shown to an operator comes from an unverified source.
type Verified struct {
	Result      *Result
	TrustAnchor string
	BootState   string
}

// LoadTrust builds the Android hardware-attestation trust material from a
// trust store merged with the embedded roots, and the application
// allow-list (#1305): the pool alone says the key lives in some locked
// handset's secure hardware, the allow-list says which application builds
// on that handset may hold it.
//
// Load it BEFORE asking a phone for an attestation, and treat failure as
// fatal. Discovering that no anchor is available only after the challenge has
// gone out leaves the caller holding evidence it has no way to judge, and the
// only safe thing to do with unjudgeable evidence is refuse it — so refuse
// earlier, where the message is about this machine's trust store rather than
// about the phone.
//
// The same holds for apps, the application allow-list: an empty one refuses
// here with pairing.ErrApplicationPolicyUnconfigured, before any phone is
// asked for evidence that could only be refused (#1305).
//
// revocation is the attestation certificate revocation status list every
// chain certificate is checked against (RevocationSource resolves the
// configured one); nil refuses with xkms.ErrNoAndroidRevocationSource, as
// the check is not optional (ruling 180).
func LoadTrust(store truststore.TrustStore, apps pairing.ApplicationPolicy, revocation xkms.AndroidStatusListSource) (*xkms.AndroidDeviceTrust, error) {
	if !apps.Configured() {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: pairing.ErrApplicationPolicyUnconfigured}
	}
	if revocation == nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: xkms.ErrNoAndroidRevocationSource}
	}

	verifier := xkms.NewAttestationVerifier(nil, xkms.WithAttestationTrustStore(store, truststore.LoadEmbeddedRoots))

	pool, err := verifier.BuildTrustPool(truststore.PurposeAndroidHardware)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	return &xkms.AndroidDeviceTrust{Roots: pool, Applications: apps, Revocation: revocation}, nil
}

// Challenge is what the verifier committed to when it issued a challenge: the
// purpose it asked about, the nonce it drew, and the connection it expects the
// answer to be bound to (#129).
//
// It travels as one value because the transcript the device signs must be
// rebuilt from what the VERIFIER asked for, never from what the device echoed
// back. Keeping the three together makes "rebuild from our own record" the
// path of least resistance; taking them out of the response would verify a
// signature over the attacker's choice of message.
type Challenge struct {
	Purpose        string
	Nonce          []byte
	ChannelBinding []byte
}

// NewChallenge draws a fresh challenge for one attestation exchange.
//
// The nonce comes from crypto/rand and is used exactly once: it is what makes
// the device's signature impossible to precompute or to replay from an earlier
// exchange. channelBinding comes from the session the exchange will run on, so
// the signature is also useless on any other connection.
func NewChallenge(purpose string, channelBinding []byte) (*Challenge, error) {
	nonce := make([]byte, pairingproto.AttestNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestNonceFailed, err)
	}
	return &Challenge{Purpose: purpose, Nonce: nonce, ChannelBinding: channelBinding}, nil
}

// Params renders the challenge as the local.attestDevice request.
//
// The channel binding is deliberately NOT sent. The transcript commits to one
// and each side derives it from its own session; supplying ours would make a
// prover that signs the value it was handed byte-indistinguishable from one
// that derived its own, right up until the relay attack the binding exists to
// stop. See the note in protocol_local.go.
func (c *Challenge) Params() *pairingproto.LocalAttestDeviceParams {
	return &pairingproto.LocalAttestDeviceParams{
		ProtocolVersion: pairingproto.AttestProtocolV2,
		Nonce:           c.Nonce,
		Purpose:         c.Purpose,
	}
}

// VerifyDeviceAttestation is the security decision, separated from the RPC
// that fetches the evidence so it can be exercised directly.
//
// It returns an error unless ALL of the following hold, and every field of the
// returned record is derived from material that satisfied them:
//
//  1. the device answered under attestation protocol version 2 (#129) — a
//     version 1 answer is refused, never accepted as a fallback;
//  2. the certificate chain verifies to a trusted Android hardware attestation
//     root, at or above the required security level, on a verified and locked
//     boot state;
//  3. the attested key's genesis challenge marks it as generated for this
//     protocol (see VerifyGenesisChallenge below);
//  4. the attested key's TEE-enforced authorization list says the key was
//     GENERATED inside secure hardware and is authorized to SIGN (#132);
//  5. the attestationApplicationId names an allow-listed package signed by an
//     allow-listed key (#1305);
//  6. the device produced a live signature, by that same attested key, over a
//     transcript carrying this exchange's nonce, purpose and channel binding.
//
// (2), (4) and (5) are the SDK's VerifyAndroidDeviceKey; (1), (3) and (6)
// belong to the pairing protocol and are checked here.
//
// (2), (3) and (4) together say the key lives in that handset's secure
// hardware and was made to be an xkey device key there, never imported into
// it. (5) says the application that generated it is the xkey build this
// machine trusts rather than any other app on a genuine handset. (6) says the
// party on this connection holds it right now. None of these
// is worth much alone: a chain without a signature is a public document
// anyone can replay, a signature without a chain is possession of a key
// nobody vouched for, and a chain plus a signature for a key that was
// IMPORTED into the TEE proves only that the hardware safeguards a key that
// existed somewhere else first.
func VerifyDeviceAttestation(
	result *pairingproto.LocalAttestDeviceResult,
	challenge *Challenge,
	trust *xkms.AndroidDeviceTrust,
) (*Verified, error) {
	if trust == nil || trust.Roots == nil {
		return nil, fmt.Errorf("%w: no attestation trust material", ErrDeviceAttestVerifyFailed)
	}
	if result == nil {
		return nil, fmt.Errorf("%w: no attestation response", ErrDeviceAttestVerifyFailed)
	}
	if challenge == nil || len(challenge.Nonce) == 0 {
		return nil, fmt.Errorf("%w: no challenge to verify freshness against", ErrDeviceAttestVerifyFailed)
	}
	if trust.Applications == nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: pairing.ErrApplicationPolicyUnconfigured}
	}

	// Version first. A device that cannot do challenge-response has nothing to
	// offer this path, and everything below assumes a signature will arrive —
	// so refusing here is clearer than letting it fail later on a missing
	// field, and it makes the downgrade an explicit, named outcome.
	if result.ProtocolVersion != pairingproto.AttestProtocolV2 {
		return nil, fmt.Errorf("%w: %w (device answered version %d)",
			ErrDeviceAttestVerifyFailed, pairingproto.ErrAttestProtocolDowngrade, result.ProtocolVersion)
	}

	// The hardware policy: anchored, TEE or StrongBox, generated, able to
	// sign, locked and verified boot, an allowed application. The anchor it
	// reports is the one the chain verified UNDER, never chain[len-1], which
	// the peer chooses (#95); it is for DISPLAY only, because an anchor is a
	// vendor CA shared by every handset attesting under it.
	key, err := xkms.VerifyAndroidDeviceKey(result.CertificateChain, trust)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}
	chain, desc, rot := key.Chain, key.Description, key.RootOfTrust

	// The genesis challenge, read from the SIGNED extension. Not a freshness
	// value — see xkms.AndroidDeviceVerifyOptions — but it does establish
	// that the key was created for this protocol, so a chain minted for some
	// unrelated Android attestation cannot be presented here.
	if err := pairingproto.VerifyGenesisChallenge(desc.AttestationChallenge); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// The device identity: the SHA-256 of the verified leaf's
	// SubjectPublicKeyInfo — the per-device key generated inside this
	// handset's TEE/StrongBox (#93).
	fingerprint, err := pairingproto.AttestedKeyFingerprint(chain[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// The liveness proof. The transcript is rebuilt from the challenge WE
	// issued and the fingerprint WE derived, so the only thing the device
	// contributes is the signature itself.
	transcript, err := pairingproto.BuildAttestTranscript(
		challenge.Purpose, challenge.Nonce, challenge.ChannelBinding, fingerprint[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}
	if err := pairingproto.VerifyAttestChallengeSignature(
		chain[0], result.SignatureAlgorithm, result.Signature, transcript); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// Claims taken from the verified extension, not from the peer's JSON.
	return &Verified{
		TrustAnchor: xkms.FormatAttestationTrustAnchor(key.TrustAnchor),
		BootState:   rot.VerifiedBootState.String(),
		Result: &Result{
			AttestationTime:   time.Now().UTC(),
			SecurityLevel:     desc.AttestationSecurityLevel.String(),
			DeviceFingerprint: hex.EncodeToString(fingerprint[:]),
			BootStateVerified: true,
			BootHashHex:       hex.EncodeToString(rot.VerifiedBootHash),
			ProtocolVersion:   pairingproto.AttestProtocolV2,
		},
	}, nil
}

// attestRequestGeneration is the generation AttestOverSession stamps on its
// request (go-xkms#128). The exchange runs outside the MessageRouter, so no
// router assigns one. It is the top of the generation space: a router later
// started on the same connection counts up from 1 and never reaches it, so
// the value is not reused within the connection, and it is non-zero because
// zero means a response that echoed no generation at all.
const attestRequestGeneration = math.MaxUint64

// AttestOverSession runs one complete challenge-response attestation exchange
// on an already-established Noise session and returns what was verified (#129).
//
// It is the whole of the protocol in one place: derive the channel binding from
// the session, draw a fresh challenge, ask the device, and judge the answer
// against the challenge THIS function issued. Splitting the exchange from its
// verification would mean a caller could pair the two up wrongly — verify one
// challenge's answer against another's record — and the two together are the
// only combination that means anything.
//
// It takes trust as a parameter rather than loading it, so the decision can be
// exercised against stated trust material instead of whatever the running
// machine's trust store happens to hold.
func AttestOverSession(
	ctx context.Context,
	transport pairingproto.Transport,
	session *bootstrap.NoiseSession,
	trust *xkms.AndroidDeviceTrust,
	purpose string,
	logger *slog.Logger,
) (*Verified, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// The challenge is bound to THIS session. Deriving it from the session
	// rather than passing a constant is what makes the device's answer useless
	// to anyone relaying it onto a different connection.
	channelBinding, err := pairingproto.AttestChannelBinding(session)
	if err != nil {
		logger.Error("attestation refused: channel binding unavailable", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	challenge, err := NewChallenge(purpose, channelBinding)
	if err != nil {
		logger.Error("attestation refused: nonce generation failed", "error", err)
		return nil, err
	}

	// Each side logs the binding it DERIVED, and neither sends one. When two
	// implementations disagree, an operator diffing the two logs learns which
	// one is wrong — which the discarded "the peer's value differs from mine"
	// warning could never say, because it could not know which side to blame.
	// Suggested by the xkey-android lane when the wire field was removed.
	logger.Debug("attestation channel binding derived",
		"purpose", purpose, "binding", hex.EncodeToString(channelBinding))

	req := pairingproto.NewRequest(pairingproto.MethodLocalAttestDevice, challenge.Params())
	req.Generation = attestRequestGeneration

	plaintext, err := pairingproto.EncodeRequest(req)
	if err != nil {
		logger.Error("attestation refused: request encoding failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		logger.Error("attestation refused: request encryption failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	responseCiphertext, err := transport.SendAndReceive(ctx, ciphertext)
	if err != nil {
		logger.Error("attestation refused: transport error", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	responsePlaintext, err := session.Decrypt(responseCiphertext)
	if err != nil {
		logger.Error("attestation refused: response decryption failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	resp, err := pairingproto.DecodeResponse(responsePlaintext)
	if err != nil {
		logger.Error("attestation refused: response decode failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	// The router's contract, applied by hand: a response answers this request
	// only if it echoes both its ID and its generation. Checked before the
	// RPC error too, since a refusal of some other request is not ours.
	if resp.ID != req.ID || resp.Generation != req.Generation {
		mismatch := &ResponseMismatchError{
			RequestID: req.ID, RequestGeneration: req.Generation,
			ResponseID: resp.ID, ResponseGeneration: resp.Generation,
		}
		logger.Error("attestation refused: response does not answer the request", "error", mismatch)
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestFailed, Cause: mismatch}
	}

	if resp.Error != nil {
		logger.Error("attestation refused: RPC error",
			"code", resp.Error.Code, "message", resp.Error.Message)
		return nil, fmt.Errorf("%w: %s", ErrDeviceAttestFailed, resp.Error.Message)
	}

	result, err := pairingproto.DecodeResult[pairingproto.LocalAttestDeviceResult](resp)
	if err != nil {
		logger.Error("attestation refused: result decode failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	return VerifyDeviceAttestation(result, challenge, trust)
}

// VerifyReattestation runs the liveness proof on a freshly handshaken session
// and confirms the identity has not changed.
//
// A record predating #129, or otherwise below version 2, is refused by
// binding.Validate() before the proof is even requested (BREAKING, go-xkms
// compat cleanup PR5): those devices have no attested key registered to
// prove possession of, so there is nothing to run the proof against, and
// the operator must re-pair rather than connect under the weaker model.
//
// For a version 2 record the proof is mandatory and every failure is fatal to
// the connection. That includes a device that answers with protocol version 1:
// a peer must not be able to opt out of a check by declaring itself unable to
// satisfy it.
//
// The fingerprint comparison at the end is not redundant with the identity ack.
// The ack compares bytes the peer SENT; this compares the identity derived from
// a chain that was just verified and whose key just signed a live challenge.
func VerifyReattestation(
	ctx context.Context,
	transport pairingproto.Transport,
	session *bootstrap.NoiseSession,
	binding DeviceBinding,
	trust *xkms.AndroidDeviceTrust,
	logger *slog.Logger,
) error {
	// Before the proof is requested, not after it is judged: a record with
	// nothing to compare against cannot be made safe by a valid signature from
	// someone.
	if err := binding.Validate(); err != nil {
		return err
	}

	verified, err := AttestOverSession(ctx, transport, session, trust, pairingproto.AttestPurposeReattest, logger)
	if err != nil {
		return err
	}

	return binding.ValidateAttestedKeyMatch(verified.Result.DeviceFingerprint)
}

// NewLiveAttestor builds the verifier a phone backend calls after its
// handshake, for surfaces that connect through a backend rather than driving
// the session themselves (#129).
//
// It closes over the binding so the decision is the same one
// VerifyReattestation makes: the chain must verify, the attested key must sign
// this session's challenge, and the identity must be the one bound at pairing.
// The transport layer cannot make that decision itself — it has the session,
// not the trust store or the record — so the policy is injected and the
// transport stays policy-free.
//
// loadTrust is called per connection rather than captured once because an
// operator can install an attestation root between connections, and a verifier
// holding a stale pool would keep refusing a device the machine now trusts.
func NewLiveAttestor(
	binding DeviceBinding,
	loadTrust func() (*xkms.AndroidDeviceTrust, error),
	logger *slog.Logger,
) pairingproto.LiveAttestFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, exchange pairingproto.RPCExchange, channelBinding []byte) error {
		if err := binding.Validate(); err != nil {
			return err
		}

		trust, err := loadTrust()
		if err != nil {
			return err
		}

		challenge, err := NewChallenge(pairingproto.AttestPurposeReattest, channelBinding)
		if err != nil {
			return err
		}

		resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalAttestDevice, challenge.Params()))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
		}
		if resp.Error != nil {
			logger.Error("live attestation refused by the device",
				"code", resp.Error.Code, "message", resp.Error.Message)
			return fmt.Errorf("%w: %s", ErrDeviceAttestFailed, resp.Error.Message)
		}

		result, err := pairingproto.DecodeResult[pairingproto.LocalAttestDeviceResult](resp)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
		}

		verified, err := VerifyDeviceAttestation(result, challenge, trust)
		if err != nil {
			return err
		}

		return binding.ValidateAttestedKeyMatch(verified.Result.DeviceFingerprint)
	}
}
