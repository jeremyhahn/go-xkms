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

package userverify_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/userverify"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// rpName is the relying party every test names.
const rpName = "example.com"

// newChallenge draws a real challenge bound to a fixed channel binding.
func newChallenge(t *testing.T) *userverify.Challenge {
	t.Helper()

	challenge, err := userverify.NewChallenge(fixedBytes(0x5a, pairingproto.AttestChannelBindingSize), rpName)
	require.NoError(t, err)
	return challenge
}

func TestNewChallenge_DrawsAFreshNonce(t *testing.T) {
	first := newChallenge(t)
	second := newChallenge(t)

	assert.Len(t, first.Nonce, pairingproto.AttestNonceSize)
	assert.NotEqual(t, first.Nonce, second.Nonce, "every challenge draws its own nonce")
	assert.True(t, first.Expires.After(time.Now()))
	assert.False(t, first.Expires.After(time.Now().Add(userverify.ChallengeLifetime)))

	params := first.Params()
	assert.Equal(t, pairingproto.AttestProtocolV2, params.ProtocolVersion)
	assert.Equal(t, first.Nonce, params.Nonce)
	assert.Equal(t, rpName, params.RPName)
}

func TestNewChallenge_RefusesAnInvalidRPName(t *testing.T) {
	binding := fixedBytes(0x5a, pairingproto.AttestChannelBindingSize)

	for _, name := range []string{"", strings.Repeat("a", pairingproto.VerifyUserRPNameMaxLen+1)} {
		challenge, err := userverify.NewChallenge(binding, name)

		require.ErrorIs(t, err, pairingproto.ErrVerifyUserRPName)
		assert.Nil(t, challenge)
	}
}

// TestVerify_AcceptsAPerUseUserVerificationKey accepts every userAuthType
// ruling 180 allows: device credential, biometric, or either.
func TestVerify_AcceptsAPerUseUserVerificationKey(t *testing.T) {
	ca := newCA(t, "Trusted Attestation Root")

	tests := []struct {
		name         string
		userAuthType int
	}{
		{"device credential", android.UserAuthTypePassword},
		{"biometric", android.UserAuthTypeFingerprint},
		{"biometric or device credential", android.UserAuthTypeFingerprint | android.UserAuthTypePassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := uvkClaims()
			claims.UserAuthType = tt.userAuthType
			uvk := newUVK(t, ca, claims)
			challenge := newChallenge(t)

			result := uvk.respond(t, challenge.Nonce, challenge.ChannelBinding, rpName)

			require.NoError(t, userverify.Verify(result, challenge, trustOf(ca)))
		})
	}
}

// TestVerify_Refuses walks every refusal the decision makes, each against an
// otherwise valid answer.
func TestVerify_Refuses(t *testing.T) {
	ca := newCA(t, "Trusted Attestation Root")
	rogue := newCA(t, "Untrusted Root")

	withClaims := func(mutate func(*android.AttestationExtensionOptions)) *phoneKey {
		claims := uvkClaims()
		mutate(claims)
		return newUVK(t, ca, claims)
	}
	honest := newUVK(t, ca, uvkClaims())

	tests := []struct {
		name    string
		answer  func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult
		wantErr error
	}{
		{
			name: "chain to an untrusted root",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return newUVK(t, rogue, uvkClaims()).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrChainVerificationFailed,
		},
		{
			name: "a DAK chain instead of a UVK",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return newPhoneKey(t, ca, []byte(pairingproto.AttestGenesisChallenge), uvkClaims()).
					respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: pairingproto.ErrUserVerificationGenesisChallenge,
		},
		{
			name: "a key that needs no authentication",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *android.AttestationExtensionOptions) {
					o.UserAuthType = 0
					o.NoAuthRequired = true
				}).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrKeyNoAuthRequired,
		},
		{
			name: "a key with no user authentication type",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *android.AttestationExtensionOptions) {
					o.UserAuthType = 0
				}).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "a key with an unknown user authentication type",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *android.AttestationExtensionOptions) {
					o.UserAuthType = 4
				}).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "a key one authentication unlocks for 30 seconds",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *android.AttestationExtensionOptions) {
					o.HasAuthTimeout = true
					o.AuthTimeout = 30
				}).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrKeyAuthTimeout,
		},
		{
			name: "a key usable while on body",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *android.AttestationExtensionOptions) {
					o.AllowWhileOnBody = true
				}).respond(t, c.Nonce, c.ChannelBinding, rpName)
			},
			wantErr: android.ErrKeyAllowWhileOnBody,
		},
		{
			name: "a signature over a stale nonce",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return honest.respond(t, fixedBytes(0x01, pairingproto.AttestNonceSize), c.ChannelBinding, rpName)
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a signature relayed from another session",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return honest.respond(t, c.Nonce, fixedBytes(0x02, pairingproto.AttestChannelBindingSize), rpName)
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a signature for another relying party",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				return honest.respond(t, c.Nonce, c.ChannelBinding, "attacker.example")
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a signature for another purpose",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				result := honest.respond(t, c.Nonce, c.ChannelBinding, rpName)
				result.Signature = honest.sign(t, pairingproto.AttestPurposeReattest, c.Nonce, c.ChannelBinding, "")
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a corrupted signature",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				result := honest.respond(t, c.Nonce, c.ChannelBinding, rpName)
				result.Signature = bytes.Repeat([]byte{0x30}, len(result.Signature))
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "no signature",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				result := honest.respond(t, c.Nonce, c.ChannelBinding, rpName)
				result.Signature = nil
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureMissing,
		},
		{
			name: "a protocol downgrade",
			answer: func(c *userverify.Challenge) *pairingproto.LocalVerifyUserResult {
				result := honest.respond(t, c.Nonce, c.ChannelBinding, rpName)
				result.ProtocolVersion = 1
				return result
			},
			wantErr: pairingproto.ErrAttestProtocolDowngrade,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := newChallenge(t)

			err := userverify.Verify(tt.answer(challenge), challenge, trustOf(ca))

			require.ErrorIs(t, err, userverify.ErrVerificationFailed)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVerify_AnswersAChallengeOnce(t *testing.T) {
	ca := newCA(t, "Trusted Attestation Root")
	uvk := newUVK(t, ca, uvkClaims())
	challenge := newChallenge(t)
	result := uvk.respond(t, challenge.Nonce, challenge.ChannelBinding, rpName)

	require.NoError(t, userverify.Verify(result, challenge, trustOf(ca)))

	err := userverify.Verify(result, challenge, trustOf(ca))
	require.ErrorIs(t, err, userverify.ErrChallengeAnswered,
		"a replayed answer to a consumed challenge must not verify the user again")
}

func TestVerify_RefusesAnExpiredChallenge(t *testing.T) {
	ca := newCA(t, "Trusted Attestation Root")
	uvk := newUVK(t, ca, uvkClaims())
	challenge := newChallenge(t)
	challenge.Expires = time.Now().Add(-time.Second)

	err := userverify.Verify(
		uvk.respond(t, challenge.Nonce, challenge.ChannelBinding, rpName), challenge, trustOf(ca))

	require.ErrorIs(t, err, userverify.ErrVerificationFailed)
	require.ErrorIs(t, err, userverify.ErrChallengeExpired)
}

func TestVerify_RefusesMissingInputs(t *testing.T) {
	ca := newCA(t, "Trusted Attestation Root")
	uvk := newUVK(t, ca, uvkClaims())
	challenge := newChallenge(t)
	result := uvk.respond(t, challenge.Nonce, challenge.ChannelBinding, rpName)

	tests := []struct {
		name      string
		result    *pairingproto.LocalVerifyUserResult
		challenge *userverify.Challenge
		trust     *attestation.AndroidDeviceTrust
		wantErr   error
	}{
		{"no trust", result, challenge, nil, userverify.ErrIncomplete},
		{"no roots", result, challenge, &attestation.AndroidDeviceTrust{Applications: appMatcher{}}, userverify.ErrIncomplete},
		{"no application policy", result, challenge, &attestation.AndroidDeviceTrust{Roots: ca.pool(), Revocation: &android.StatusList{}}, android.ErrNilApplicationMatcher},
		{"no revocation status list", result, challenge, &attestation.AndroidDeviceTrust{Roots: ca.pool(), Applications: appMatcher{}}, attestation.ErrNoRevocationSource},
		{"no answer", nil, challenge, trustOf(ca), userverify.ErrIncomplete},
		{"no challenge", result, nil, trustOf(ca), userverify.ErrIncomplete},
		{"a short nonce", result, &userverify.Challenge{Nonce: []byte{1}}, trustOf(ca), userverify.ErrIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userverify.Verify(tt.result, tt.challenge, tt.trust)

			require.ErrorIs(t, err, userverify.ErrVerificationFailed)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
