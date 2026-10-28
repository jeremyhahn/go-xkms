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

// Package userverify is the desktop's decision on an on-demand user
// verification (ruling 167): it draws the local.verifyUser challenge and
// judges the user-verification key's (UVK) answer before a FIDO2
// authenticator mints a pinUvAuthToken. The wire contract and the check order
// are xkey/docs/phone-hsm/engineering.md, "On-demand user verification".
//
// Nothing is persisted. The UVK chain travels in every answer and is verified
// on every use, so a UVK the phone regenerated after a biometric enrollment
// needs no re-pairing.
package userverify

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// ChallengeLifetime bounds how long a verify-user challenge may wait for its
// answer. It matches the phone's biometric prompt bound,
// phone.DefaultLiveAttestTimeout: an answer arriving later than the prompt
// could have been shown is not an answer to this request.
const ChallengeLifetime = 120 * time.Second

// Challenge is what the desktop committed to when it asked the phone to
// verify its user: the nonce it drew, the session binding the answer must
// carry, the relying party the phone's prompt names, and the deadline the
// answer must meet. It is answered once.
type Challenge struct {
	Nonce          []byte
	ChannelBinding []byte
	RPName         string
	Expires        time.Time

	answered atomic.Bool
}

// NewChallenge draws a fresh 32-byte nonce for one verify-user exchange for
// the relying party rpName, on the session channelBinding was derived from.
// rpName must pass pairingproto.ValidateVerifyUserRPName.
func NewChallenge(channelBinding []byte, rpName string) (*Challenge, error) {
	if err := pairingproto.ValidateVerifyUserRPName(rpName); err != nil {
		return nil, err
	}
	nonce := make([]byte, pairingproto.AttestNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &errs.Joined{Lead: ErrNonceFailed, Cause: err}
	}
	return &Challenge{
		Nonce:          nonce,
		ChannelBinding: channelBinding,
		RPName:         rpName,
		Expires:        time.Now().Add(ChallengeLifetime),
	}, nil
}

// Params renders the challenge as the local.verifyUser request. As for
// local.attestDevice, the channel binding is not sent: each side derives it
// from its own session.
func (c *Challenge) Params() *pairingproto.LocalVerifyUserParams {
	return &pairingproto.LocalVerifyUserParams{
		ProtocolVersion: pairingproto.AttestProtocolV2,
		Nonce:           c.Nonce,
		RPName:          c.RPName,
	}
}

// consume marks the challenge answered and refuses a second answer or a late
// one (engineering.md step 7).
func (c *Challenge) consume() error {
	if !c.answered.CompareAndSwap(false, true) {
		return ErrChallengeAnswered
	}
	if time.Now().After(c.Expires) {
		return ErrChallengeExpired
	}
	return nil
}

// Verify is the security decision on a local.verifyUser answer, separated
// from the RPC that fetches it so it can be exercised directly. It returns
// nil only if, in the order engineering.md gives:
//
//  2. the phone answered under attestation protocol version 2;
//  3. the chain verifies to a trusted Android hardware root under the DAK's
//     policy (attestation.VerifyAndroidDeviceKey): TEE or StrongBox, locked
//     and verified boot, generated origin, signing purpose, an allowed
//     application;
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
// Step 1, the response echo and the RPC error, is the exchange's. Every
// refusal wraps ErrVerificationFailed.
func Verify(
	result *pairingproto.LocalVerifyUserResult,
	challenge *Challenge,
	trust *attestation.AndroidDeviceTrust,
) error {
	if err := verify(result, challenge, trust); err != nil {
		return &errs.Joined{Lead: ErrVerificationFailed, Cause: err}
	}
	return nil
}

func verify(
	result *pairingproto.LocalVerifyUserResult,
	challenge *Challenge,
	trust *attestation.AndroidDeviceTrust,
) error {
	if trust == nil || trust.Roots == nil {
		return &errs.Detail{Err: ErrIncomplete, Detail: "no attestation trust material"}
	}
	if trust.Applications == nil {
		return android.ErrNilApplicationMatcher
	}
	if result == nil {
		return &errs.Detail{Err: ErrIncomplete, Detail: "no answer"}
	}
	if challenge == nil || len(challenge.Nonce) != pairingproto.AttestNonceSize {
		return &errs.Detail{Err: ErrIncomplete, Detail: "no well-formed challenge"}
	}

	if result.ProtocolVersion != pairingproto.AttestProtocolV2 {
		return &errs.Affix{
			Err:    pairingproto.ErrAttestProtocolDowngrade,
			Suffix: fmt.Sprintf(" (phone answered version %d)", result.ProtocolVersion),
		}
	}

	key, err := attestation.VerifyAndroidDeviceKey(result.CertificateChain, trust)
	if err != nil {
		return err
	}
	if err := pairingproto.VerifyUserVerificationGenesisChallenge(key.Description.AttestationChallenge); err != nil {
		return err
	}
	if err := android.RequireAttestedPerUseUserVerification(key.Description); err != nil {
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
