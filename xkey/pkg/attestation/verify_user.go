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
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// On-demand user verification (ruling 167): the desktop asks the phone to
// verify its user now, and judges the user-verification key's (UVK) answer
// before the FIDO2 authenticator mints a pinUvAuthToken. The wire contract and
// the check order are xkey/docs/phone-hsm/engineering.md, "On-demand user
// verification".
//
// Nothing is persisted. The UVK chain travels in every answer and is verified
// on every use, so a UVK the phone regenerated after a biometric enrollment
// needs no re-pairing.

// UserVerificationChallengeLifetime bounds how long a verify-user challenge
// may wait for its answer. It matches the phone's biometric prompt bound,
// phone.DefaultLiveAttestTimeout: an answer arriving later than the prompt
// could have been shown is not an answer to this request.
const UserVerificationChallengeLifetime = 120 * time.Second

// User-verification decision errors.
var (
	// ErrUserVerificationFailed is the umbrella refusal for a verify-user
	// answer that could not be verified. The specific reason is joined to it.
	ErrUserVerificationFailed = errors.New("attestation: user verification refused")

	// ErrUserVerificationExchangeFailed indicates the verify-user exchange
	// itself failed — transport, encoding, a mismatched response or an RPC
	// error such as a cancelled prompt — rather than the evidence being bad.
	ErrUserVerificationExchangeFailed = errors.New("attestation: user verification exchange failed")

	// ErrUserVerificationChallengeAnswered indicates a challenge that was
	// already answered once. A nonce is consumed by its first verification.
	ErrUserVerificationChallengeAnswered = errors.New("attestation: user-verification challenge already answered")

	// ErrUserVerificationChallengeExpired indicates an answer that arrived
	// after UserVerificationChallengeLifetime.
	ErrUserVerificationChallengeExpired = errors.New("attestation: user-verification challenge expired")

	// ErrUserVerificationIncomplete indicates the decision was called without
	// trust material, an answer, or a well-formed challenge to judge it by.
	ErrUserVerificationIncomplete = errors.New("attestation: user verification has nothing to judge")
)

// UserVerificationChallenge is what the desktop committed to when it asked the
// phone to verify its user: the nonce it drew, the session binding the answer
// must carry, the relying party the phone's prompt names, and the deadline
// the answer must meet. It is answered once.
type UserVerificationChallenge struct {
	Nonce          []byte
	ChannelBinding []byte
	RPName         string
	Expires        time.Time

	answered atomic.Bool
}

// NewUserVerificationChallenge draws a fresh 32-byte nonce for one verify-user
// exchange for the relying party rpName, on the session channelBinding was
// derived from. rpName must pass pairingproto.ValidateVerifyUserRPName.
func NewUserVerificationChallenge(channelBinding []byte, rpName string) (*UserVerificationChallenge, error) {
	if err := pairingproto.ValidateVerifyUserRPName(rpName); err != nil {
		return nil, err
	}
	challenge, err := NewChallenge(pairingproto.AttestPurposeVerifyUser, channelBinding)
	if err != nil {
		return nil, err
	}
	return &UserVerificationChallenge{
		Nonce:          challenge.Nonce,
		ChannelBinding: challenge.ChannelBinding,
		RPName:         rpName,
		Expires:        time.Now().Add(UserVerificationChallengeLifetime),
	}, nil
}

// Params renders the challenge as the local.verifyUser request. As for
// local.attestDevice, the channel binding is not sent: each side derives it
// from its own session.
func (c *UserVerificationChallenge) Params() *pairingproto.LocalVerifyUserParams {
	return &pairingproto.LocalVerifyUserParams{
		ProtocolVersion: pairingproto.AttestProtocolV2,
		Nonce:           c.Nonce,
		RPName:          c.RPName,
	}
}

// consume marks the challenge answered and refuses a second answer or a late
// one (engineering.md step 7).
func (c *UserVerificationChallenge) consume() error {
	if !c.answered.CompareAndSwap(false, true) {
		return ErrUserVerificationChallengeAnswered
	}
	if time.Now().After(c.Expires) {
		return ErrUserVerificationChallengeExpired
	}
	return nil
}

// VerifyUserVerification is the security decision on a local.verifyUser
// answer, separated from the RPC that fetches it so it can be exercised
// directly. It returns nil only if, in the order engineering.md gives:
//
//  2. the phone answered under attestation protocol version 2;
//  3. the chain verifies to a trusted Android hardware root under the DAK's
//     policy (VerifyAndroidDeviceKey): TEE or StrongBox, locked and verified
//     boot, generated origin, signing purpose, an allowed application;
//  4. the leaf's attestation challenge marks it a UVK, so a DAK chain cannot
//     stand in for one;
//  5. the leaf's teeEnforced list binds every use to a fresh user
//     verification: userAuthType 1 (device credential), 2 (biometric) or 3
//     (either), as ruling 180 reads CTAP 2.1; no authTimeout, no
//     allowWhileOnBody, no noAuthRequired;
//  6. the UVK signed the verify-user transcript rebuilt from this challenge's
//     nonce, binding and RP name and the verified leaf's fingerprint, as
//     ES256 on P-256;
//  7. the challenge is answered once and before it expired.
//
// Step 1, the response echo and the RPC error, is the exchange's
// (NewUserVerifier). Every refusal wraps ErrUserVerificationFailed.
func VerifyUserVerification(
	result *pairingproto.LocalVerifyUserResult,
	challenge *UserVerificationChallenge,
	trust *xkms.AndroidDeviceTrust,
) error {
	if err := verifyUserVerification(result, challenge, trust); err != nil {
		return &SentinelCauseError{Sentinel: ErrUserVerificationFailed, Cause: err}
	}
	return nil
}

func verifyUserVerification(
	result *pairingproto.LocalVerifyUserResult,
	challenge *UserVerificationChallenge,
	trust *xkms.AndroidDeviceTrust,
) error {
	if trust == nil || trust.Roots == nil {
		return fmt.Errorf("%w: no attestation trust material", ErrUserVerificationIncomplete)
	}
	if trust.Applications == nil {
		return pairing.ErrApplicationPolicyUnconfigured
	}
	if result == nil {
		return fmt.Errorf("%w: no answer", ErrUserVerificationIncomplete)
	}
	if challenge == nil || len(challenge.Nonce) != pairingproto.AttestNonceSize {
		return fmt.Errorf("%w: no well-formed challenge", ErrUserVerificationIncomplete)
	}

	if result.ProtocolVersion != pairingproto.AttestProtocolV2 {
		return fmt.Errorf("%w (phone answered version %d)",
			pairingproto.ErrAttestProtocolDowngrade, result.ProtocolVersion)
	}

	key, err := xkms.VerifyAndroidDeviceKey(result.CertificateChain, trust)
	if err != nil {
		return err
	}
	if err := pairingproto.VerifyUserVerificationGenesisChallenge(key.Description.AttestationChallenge); err != nil {
		return err
	}
	if err := xkms.RequireAndroidAttestedPerUseUserVerification(key.Description); err != nil {
		return err
	}

	leaf := key.Chain[0]
	fingerprint, err := pairingproto.AttestedKeyFingerprint(leaf)
	if err != nil {
		return err
	}
	transcript, err := pairingproto.BuildVerifyUserTranscript(
		challenge.Nonce, challenge.ChannelBinding, fingerprint[:], challenge.RPName)
	if err != nil {
		return err
	}
	if err := pairingproto.VerifyAttestChallengeSignature(
		leaf, result.SignatureAlgorithm, result.Signature, transcript); err != nil {
		return err
	}

	return challenge.consume()
}

// NewUserVerifier builds the verify-user exchange a phone backend runs on its
// established session when the authenticator needs a user verification. It
// draws a fresh challenge for the relying party, sends local.verifyUser, refuses a response that
// does not answer the request, and judges the answer with
// VerifyUserVerification.
//
// loadTrust is called per verification, as for NewLiveAttestor, so a root the
// operator installs takes effect on the next use.
func NewUserVerifier(
	loadTrust func() (*xkms.AndroidDeviceTrust, error),
	logger *slog.Logger,
) pairingproto.VerifyUserFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, exchange pairingproto.RPCExchange, channelBinding []byte, rpName string) error {
		trust, err := loadTrust()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationFailed, Cause: err}
		}

		challenge, err := NewUserVerificationChallenge(channelBinding, rpName)
		if err != nil {
			return err
		}

		req := pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, challenge.Params())
		req.Generation = attestRequestGeneration

		resp, err := exchange(ctx, req)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: err}
		}

		// Step 1. Checked before the RPC error, since a refusal of some other
		// request is not ours.
		if resp.ID != req.ID || resp.Generation != req.Generation {
			mismatch := &ResponseMismatchError{
				RequestID: req.ID, RequestGeneration: req.Generation,
				ResponseID: resp.ID, ResponseGeneration: resp.Generation,
			}
			logger.Error("user verification refused: response does not answer the request", "error", mismatch)
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: mismatch}
		}
		if resp.Error != nil {
			logger.Error("user verification refused by the phone",
				"code", resp.Error.Code, "message", resp.Error.Message)
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: resp.Error}
		}

		result, err := pairingproto.DecodeResult[pairingproto.LocalVerifyUserResult](resp)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrUserVerificationExchangeFailed, Cause: err}
		}

		if err := VerifyUserVerification(result, challenge, trust); err != nil {
			logger.Error("user verification refused", "error", err)
			return err
		}
		return nil
	}
}
