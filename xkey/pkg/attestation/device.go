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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
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
)

// DeviceBinding is everything the verifier needs to know about a pairing
// record: which device identity was bound, and under which attestation model.
//
// It is a small value rather than the record itself on purpose. The persisted
// record differs per surface — the CLI's YAML struct, the GUI's mirror of the
// same file — and unifying those is a separate, open decision (#130). Taking
// only the two fields the decision actually reads means this package does not
// have to wait on that, and means neither surface can pass a record whose
// other fields the verifier might quietly start depending on.
type DeviceBinding struct {
	// Fingerprint is the hex-encoded SHA-256 of the attested key's
	// SubjectPublicKeyInfo bound at pairing. Empty means never attested.
	Fingerprint string

	// ProtocolVersion is the attestation model that established the binding:
	// 2 for challenge-response (#129), absent or 1 for older records.
	ProtocolVersion int
}

// RequiresLiveAttestation reports whether this binding was established under
// the challenge-response model and must therefore prove liveness on every
// connect.
//
// The answer comes from the RECORD, never from anything the peer says. A
// device that could talk its way out of the requirement by claiming an older
// protocol version would make the check optional at the peer's choice, which
// is the defect the identity-ack "unknown" path was fixed for.
func (b DeviceBinding) RequiresLiveAttestation() bool {
	return b.ProtocolVersion >= pairing.AttestProtocolV2
}

// Validate refuses a record that demands the liveness proof but has nothing to
// judge the answer against.
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
//
// A legacy record claims nothing and is left alone — it has no attested key
// registered, which is a different state from having one and losing it.
func (b DeviceBinding) Validate() error {
	if !b.RequiresLiveAttestation() {
		return nil
	}
	if b.Fingerprint == "" {
		return fmt.Errorf("%w: fingerprint is empty", ErrDeviceBindingIncomplete)
	}
	raw, err := hex.DecodeString(b.Fingerprint)
	if err != nil {
		return fmt.Errorf("%w: fingerprint is not valid hex", ErrDeviceBindingIncomplete)
	}
	if len(raw) != pairing.AttestFingerprintSize {
		return fmt.Errorf("%w: fingerprint is %d bytes, want %d",
			ErrDeviceBindingIncomplete, len(raw), pairing.AttestFingerprintSize)
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
// An empty stored fingerprint is the first attestation and matches nothing yet
// — but ONLY for a record that does not claim a version 2 binding. For one that
// does, an empty fingerprint is an incomplete record, not an enrolment: see
// Validate. Keeping that distinction here as well as at the entry points means
// a future caller that reaches this method directly cannot reintroduce the
// fail-open by skipping Validate.
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
	if b.Fingerprint == "" {
		return nil // First attestation of a device that has never been attested
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

// Trust is the Android hardware-attestation material a decision is made
// against.
//
// It is a single pool, deliberately. An earlier version carried a flat list of
// roots beside the pool so the anchor could be looked up by fingerprint; the
// list was built from the store's certificates for EVERY purpose while the
// pool held the Android-hardware ones alone, so a peer could append a
// certificate stored under an unrelated purpose and have it named as the
// anchor. Verification succeeded through the genuine root and the lookup
// selected the appended certificate. Two sets that must agree are two sets
// that can disagree, so there is now only one, and the anchor is read back out
// of the verification instead of being inferred — see VerifiedTrustAnchor.
type Trust struct {
	Pool *x509.CertPool
}

// LoadTrust builds the Android hardware-attestation trust material from a
// trust store merged with the embedded roots.
//
// Load it BEFORE asking a phone for an attestation, and treat failure as
// fatal. Discovering that no anchor is available only after the challenge has
// gone out leaves the caller holding evidence it has no way to judge, and the
// only safe thing to do with unjudgeable evidence is refuse it — so refuse
// earlier, where the message is about this machine's trust store rather than
// about the phone.
func LoadTrust(store truststore.TrustStore) (*Trust, error) {
	verifier, err := NewVerifier(store, truststore.LoadEmbeddedRoots)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	pool, err := verifier.BuildTrustPool(truststore.PurposeAndroidHardware)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	return &Trust{Pool: pool}, nil
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
	nonce := make([]byte, pairing.AttestNonceSize)
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
func (c *Challenge) Params() *pairing.LocalAttestDeviceParams {
	return &pairing.LocalAttestDeviceParams{
		ProtocolVersion: pairing.AttestProtocolV2,
		Nonce:           c.Nonce,
		Purpose:         c.Purpose,
	}
}

// VerifyOptions is the policy every device attestation is judged against.
//
// It exists as a function because two of these fields are enforced inside the
// SDK against material a caller's fixtures cannot easily construct, so a test
// can pin WHICH policy is requested even where it cannot exercise the refusal.
// The refusals themselves are covered by pkg/attestation/android's own suite
// (ErrInsufficientSecurityLevel, ErrUnverifiedBoot).
func VerifyOptions(pool *x509.CertPool) *xkms.AndroidVerifyOptions {
	return &xkms.AndroidVerifyOptions{
		TrustedRoots: pool,

		// ExpectedNonce is deliberately UNSET, and this is the whole of the
		// #129 change to this call.
		//
		// It compares the live challenge against the attestationChallenge
		// baked into the leaf. That worked only while the device generated a
		// NEW key per pairing, because Android fixes the challenge at key
		// generation. Under the persistent-key model the leaf carries the
		// key's GENESIS challenge, which is fixed for the life of the key, so
		// comparing it against this exchange's nonce could only ever fail.
		//
		// Freshness has not been dropped, it has moved: the device proves it
		// by SIGNING this exchange's nonce with the very key this chain
		// certifies. That proof is strictly stronger than the old one — the
		// old comparison showed a certificate had been minted for this nonce
		// at some point, the new one shows the key's holder is on this
		// connection now — and unlike the old one it can be repeated without
		// rotating the device identity.
		//
		// The genesis challenge is still checked, for what it can still say:
		// that the key was generated to be an xkey device key at all.
		// TrustedRoots must stay non-nil; a nil there skips chain verification
		// outright, which is a different and much larger hole, and the caller
		// guards it.

		// The same bar `device attest-device` enforces, and that alignment is
		// the point rather than a new policy: without it pairing ADMITTED a
		// device that its own first re-attestation would refuse, so the weaker
		// gate was the one establishing the binding. A software-protected key
		// is not a phone acting as an HSM.
		MinSecurityLevel: xkms.AndroidSecurityLevelTrustedEnvironment,

		// Refuses an explicitly unverified boot state. Note what it does NOT
		// do: a chain whose extension carries no RootOfTrust at all passes it,
		// because the SDK's check is "if present, it must be verified". That
		// is the SDK's documented contract, so the requirement that the claim
		// be PRESENT is enforced at the point of consumption instead, in
		// RequireAttestedBootState below.
		VerifyBootState: true,
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
//  3. the attested key was GENERATED as an xkey device attestation key;
//  4. the device produced a live signature, by that same attested key, over a
//     transcript carrying this exchange's nonce, purpose and channel binding.
//
// (2) and (3) say the key lives in that handset's secure hardware. (4) says
// the party on this connection holds it right now. Neither is worth much
// alone: a chain without a signature is a public document anyone can replay,
// and a signature without a chain is possession of a key nobody vouched for.
func VerifyDeviceAttestation(
	result *pairing.LocalAttestDeviceResult,
	challenge *Challenge,
	trust *Trust,
) (*Verified, error) {
	if trust == nil || trust.Pool == nil {
		return nil, fmt.Errorf("%w: no attestation trust material", ErrDeviceAttestVerifyFailed)
	}
	if result == nil {
		return nil, fmt.Errorf("%w: no attestation response", ErrDeviceAttestVerifyFailed)
	}
	if challenge == nil || len(challenge.Nonce) == 0 {
		return nil, fmt.Errorf("%w: no challenge to verify freshness against", ErrDeviceAttestVerifyFailed)
	}

	// Version first. A device that cannot do challenge-response has nothing to
	// offer this path, and everything below assumes a signature will arrive —
	// so refusing here is clearer than letting it fail later on a missing
	// field, and it makes the downgrade an explicit, named outcome.
	if result.ProtocolVersion != pairing.AttestProtocolV2 {
		return nil, fmt.Errorf("%w: %w (device answered version %d)",
			ErrDeviceAttestVerifyFailed, pairing.ErrAttestProtocolDowngrade, result.ProtocolVersion)
	}

	chain, err := ParseDERChain(result.CertificateChain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	desc, err := xkms.VerifyAndroidKeyAttestation(chain, VerifyOptions(trust.Pool))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// The genesis challenge, read from the SIGNED extension. Not a freshness
	// value — see VerifyOptions — but it does establish that the key was
	// created for this protocol, so a chain minted for some unrelated Android
	// attestation cannot be presented here.
	if err := pairing.VerifyGenesisChallenge(desc.AttestationChallenge); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// Which anchor the chain verified UNDER, taken from the verification
	// itself. Never chain[len-1] — that is the value #95 found being
	// persisted, and it is chosen by the peer. It is used for DISPLAY only:
	// the persisted identity is the attested key below, because an anchor is a
	// vendor CA shared by every handset attesting under it.
	matchedRoot, err := VerifiedTrustAnchor(chain, trust.Pool)
	if err != nil {
		return nil, err
	}

	rot, err := RequireAttestedBootState(desc)
	if err != nil {
		return nil, err
	}

	// The device identity: the SHA-256 of the verified leaf's
	// SubjectPublicKeyInfo — the per-device key generated inside this
	// handset's TEE/StrongBox (#93).
	fingerprint, err := pairing.AttestedKeyFingerprint(chain[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// The liveness proof. The transcript is rebuilt from the challenge WE
	// issued and the fingerprint WE derived, so the only thing the device
	// contributes is the signature itself.
	transcript, err := pairing.BuildAttestTranscript(
		challenge.Purpose, challenge.Nonce, challenge.ChannelBinding, fingerprint[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}
	if err := pairing.VerifyAttestChallengeSignature(
		chain[0], result.SignatureAlgorithm, result.Signature, transcript); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}

	// Claims taken from the verified extension, not from the peer's JSON.
	return &Verified{
		TrustAnchor: FormatTrustAnchor(matchedRoot),
		BootState:   rot.VerifiedBootState.String(),
		Result: &Result{
			AttestationTime:   time.Now().UTC(),
			SecurityLevel:     desc.AttestationSecurityLevel.String(),
			DeviceFingerprint: hex.EncodeToString(fingerprint[:]),
			BootStateVerified: true,
			BootHashHex:       hex.EncodeToString(rot.VerifiedBootHash),
			ProtocolVersion:   pairing.AttestProtocolV2,
		},
	}, nil
}

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
	transport pairing.Transport,
	session *pairing.NoiseSession,
	trust *Trust,
	purpose string,
	logger *slog.Logger,
) (*Verified, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// The challenge is bound to THIS session. Deriving it from the session
	// rather than passing a constant is what makes the device's answer useless
	// to anyone relaying it onto a different connection.
	channelBinding, err := session.AttestChannelBinding()
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

	req := pairing.NewRequest(pairing.MethodLocalAttestDevice, challenge.Params())

	plaintext, err := pairing.EncodeRequest(req)
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

	resp, err := pairing.DecodeResponse(responsePlaintext)
	if err != nil {
		logger.Error("attestation refused: response decode failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	if resp.Error != nil {
		logger.Error("attestation refused: RPC error",
			"code", resp.Error.Code, "message", resp.Error.Message)
		return nil, fmt.Errorf("%w: %s", ErrDeviceAttestFailed, resp.Error.Message)
	}

	result, err := pairing.DecodeResult[pairing.LocalAttestDeviceResult](resp)
	if err != nil {
		logger.Error("attestation refused: result decode failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
	}

	return VerifyDeviceAttestation(result, challenge, trust)
}

// VerifyReattestation runs the liveness proof on a freshly handshaken session
// for a device whose record requires it, and confirms the identity has not
// changed.
//
// A record predating #129 carries no protocol version and is left alone: those
// devices have no attested key registered to prove possession of, so demanding
// a proof would refuse every legacy pairing rather than protect it. They are
// upgraded by re-pairing, or by an explicit re-attestation.
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
	transport pairing.Transport,
	session *pairing.NoiseSession,
	binding DeviceBinding,
	trust *Trust,
	logger *slog.Logger,
) error {
	if !binding.RequiresLiveAttestation() {
		return nil
	}
	// Before the proof is requested, not after it is judged: a record with
	// nothing to compare against cannot be made safe by a valid signature from
	// someone.
	if err := binding.Validate(); err != nil {
		return err
	}

	verified, err := AttestOverSession(ctx, transport, session, trust, pairing.AttestPurposeReattest, logger)
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
	loadTrust func() (*Trust, error),
	logger *slog.Logger,
) pairing.LiveAttestFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, exchange pairing.RPCExchange, channelBinding []byte) error {
		if err := binding.Validate(); err != nil {
			return err
		}

		trust, err := loadTrust()
		if err != nil {
			return err
		}

		challenge, err := NewChallenge(pairing.AttestPurposeReattest, channelBinding)
		if err != nil {
			return err
		}

		resp, err := exchange(ctx, pairing.NewRequest(pairing.MethodLocalAttestDevice, challenge.Params()))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDeviceAttestFailed, err)
		}
		if resp.Error != nil {
			logger.Error("live attestation refused by the device",
				"code", resp.Error.Code, "message", resp.Error.Message)
			return fmt.Errorf("%w: %s", ErrDeviceAttestFailed, resp.Error.Message)
		}

		result, err := pairing.DecodeResult[pairing.LocalAttestDeviceResult](resp)
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

// RequireAttestedBootState refuses an attestation that does not actually make a
// boot-state claim, or makes an unacceptable one.
//
// AndroidVerifyOptions.VerifyBootState is "if a RootOfTrust is present, it must
// say verified". Absence therefore PASSES it, and an earlier version of this
// check turned that into a successful pairing: the CLI printed
// "Chain Status: VERIFIED", the record stored a security level and an
// attestation timestamp, and the device was admitted having claimed nothing
// whatsoever about its boot chain. A phone-as-HSM pairing is exactly the case
// where that claim is the product.
//
// The check lives at the point of CONSUMPTION rather than in
// pkg/attestation/android because absence versus refusal is the consumer's
// policy: the SDK's contract is deliberately "verify what is claimed", other
// callers depend on it, and widening it would change every one of them.
//
// DeviceLocked is required for the same reason. An unlocked bootloader can run
// an arbitrary image, so "verified boot" from one is a statement about a chain
// that can be replaced at will.
func RequireAttestedBootState(desc *xkms.AndroidKeyDescription) (*xkms.AndroidRootOfTrust, error) {
	rot := desc.TeeEnforced.RootOfTrust
	if rot == nil {
		return nil, fmt.Errorf(
			"%w: the attestation carries no root of trust, so it makes no claim about the device's boot chain",
			ErrDeviceAttestVerifyFailed)
	}
	if !rot.DeviceLocked {
		return nil, fmt.Errorf(
			"%w: the device's bootloader is unlocked, so its boot chain can be replaced at will",
			ErrDeviceAttestVerifyFailed)
	}
	if rot.VerifiedBootState != xkms.AndroidVerifiedBootVerified {
		return nil, fmt.Errorf("%w: the device reports boot state %q, not verified",
			ErrDeviceAttestVerifyFailed, rot.VerifiedBootState.String())
	}
	return rot, nil
}

// VerifiedTrustAnchor returns the trust anchor x509 ACTUALLY used to verify the
// chain, read out of the chain it built, rather than inferred from the last
// certificate the peer sent.
//
// The distinction is the whole point. x509 verification proves the leaf chains
// to some certificate in the pool; it constrains nothing about what follows
// that anchor in the presented slice, so a valid chain with anything appended
// still verifies. Asking the verifier which anchor it used cannot be fooled by
// an appended certificate and cannot drift from the pool, because there is no
// second list to keep in step with it.
//
// The options MUST mirror the ones android.VerifyKeyAttestation verifies with
// — same roots, same intermediates, ExtKeyUsageAny — or this would report the
// anchor of a different verification than the one that was accepted.
func VerifiedTrustAnchor(chain []*x509.Certificate, pool *x509.CertPool) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty certificate chain", ErrDeviceAttestVerifyFailed)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	built, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceAttestVerifyFailed, err)
	}
	if len(built) == 0 || len(built[0]) == 0 {
		return nil, fmt.Errorf("%w: verification returned no chain", ErrDeviceAttestVerifyFailed)
	}

	verified := built[0]
	return verified[len(verified)-1], nil
}

// ParseDERChain parses a DER certificate chain as it arrives on the wire.
//
// It was written out separately in the CLI and the GUI, which is the same
// duplication this file exists to end.
func ParseDERChain(derChain [][]byte) ([]*x509.Certificate, error) {
	if len(derChain) == 0 {
		return nil, ErrEmptyCertChain
	}

	chain := make([]*x509.Certificate, 0, len(derChain))
	for i, der := range derChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %w", ErrDeviceAttestVerifyFailed, i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// FormatTrustAnchor renders a trust anchor for display.
func FormatTrustAnchor(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.String()
}
