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

package attestation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// uvTrust is the trust material every user-verification test judges under.
func uvTrust(ca *attesttest.CA) *xkms.AndroidDeviceTrust {
	return &xkms.AndroidDeviceTrust{Roots: ca.Pool(), Applications: attesttest.Applications()}
}

// uvChallenge draws a real challenge bound to a fixed channel binding.
func uvChallenge(t *testing.T) *attestation.UserVerificationChallenge {
	t.Helper()

	challenge, err := attestation.NewUserVerificationChallenge(
		attesttest.FixedBytes(0x5a, pairingproto.AttestChannelBindingSize))
	require.NoError(t, err)
	return challenge
}

func TestNewUserVerificationChallenge_DrawsAFreshNonce(t *testing.T) {
	first := uvChallenge(t)
	second := uvChallenge(t)

	assert.Len(t, first.Nonce, pairingproto.AttestNonceSize)
	assert.NotEqual(t, first.Nonce, second.Nonce, "every challenge draws its own nonce")
	assert.True(t, first.Expires.After(time.Now()))
	assert.False(t, first.Expires.After(time.Now().Add(attestation.UserVerificationChallengeLifetime)))

	params := first.Params()
	assert.Equal(t, pairingproto.AttestProtocolV2, params.ProtocolVersion)
	assert.Equal(t, first.Nonce, params.Nonce)
}

func TestVerifyUserVerification_AcceptsAPerUseBiometricKey(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	challenge := uvChallenge(t)

	result := uvk.RespondVerifyUser(t, challenge.Nonce, challenge.ChannelBinding)

	require.NoError(t, attestation.VerifyUserVerification(result, challenge, uvTrust(ca)))
}

// TestVerifyUserVerification_Refuses walks every refusal the decision makes,
// each against an otherwise valid answer.
func TestVerifyUserVerification_Refuses(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	rogue := attesttest.NewCA(t, "Untrusted Root")

	withClaims := func(mutate func(*xkms.AndroidAttestationExtensionOptions)) *attesttest.DAK {
		claims := attesttest.UserVerificationKeyClaims()
		mutate(claims)
		return attesttest.NewUVK(t, ca, claims)
	}
	honest := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())

	tests := []struct {
		name    string
		answer  func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult
		wantErr error
	}{
		{
			name: "chain to an untrusted root",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return attesttest.NewUVK(t, rogue, attesttest.UserVerificationKeyClaims()).
					RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
		},
		{
			name: "a DAK chain instead of a UVK",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return attesttest.NewDAKWithClaims(t, ca, attesttest.GenesisChallenge(),
					xkms.AndroidSecurityLevelStrongBox, attesttest.UserVerificationKeyClaims()).
					RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
			wantErr: pairingproto.ErrUserVerificationGenesisChallenge,
		},
		{
			name: "a key that needs no authentication",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *xkms.AndroidAttestationExtensionOptions) {
					o.UserAuthType = 0
					o.NoAuthRequired = true
				}).RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
			wantErr: xkms.ErrAndroidKeyNoAuthRequired,
		},
		{
			name: "a key a PIN can unlock",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *xkms.AndroidAttestationExtensionOptions) {
					o.UserAuthType = xkms.AndroidUserAuthTypeFingerprint | xkms.AndroidUserAuthTypePassword
				}).RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
			wantErr: xkms.ErrAndroidKeyUserAuthTypeNotBiometric,
		},
		{
			name: "a key one authentication unlocks for 30 seconds",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *xkms.AndroidAttestationExtensionOptions) {
					o.HasAuthTimeout = true
					o.AuthTimeout = 30
				}).RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
			wantErr: xkms.ErrAndroidKeyAuthTimeout,
		},
		{
			name: "a key usable while on body",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				return withClaims(func(o *xkms.AndroidAttestationExtensionOptions) {
					o.AllowWhileOnBody = true
				}).RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
			},
			wantErr: xkms.ErrAndroidKeyAllowWhileOnBody,
		},
		{
			name: "a signature over a stale nonce",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				stale := attesttest.FixedBytes(0x01, pairingproto.AttestNonceSize)
				return honest.RespondVerifyUser(t, stale, c.ChannelBinding)
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a signature relayed from another session",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				other := attesttest.FixedBytes(0x02, pairingproto.AttestChannelBindingSize)
				return honest.RespondVerifyUser(t, c.Nonce, other)
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a signature for another purpose",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				result := honest.RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
				result.Signature = honest.Sign(t, pairingproto.AttestPurposeReattest, c.Nonce, c.ChannelBinding)
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "a corrupted signature",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				result := honest.RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
				result.Signature = bytes.Repeat([]byte{0x30}, len(result.Signature))
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureInvalid,
		},
		{
			name: "no signature",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				result := honest.RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
				result.Signature = nil
				return result
			},
			wantErr: pairingproto.ErrAttestSignatureMissing,
		},
		{
			name: "a protocol downgrade",
			answer: func(c *attestation.UserVerificationChallenge) *pairingproto.LocalVerifyUserResult {
				result := honest.RespondVerifyUser(t, c.Nonce, c.ChannelBinding)
				result.ProtocolVersion = 1
				return result
			},
			wantErr: pairingproto.ErrAttestProtocolDowngrade,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := uvChallenge(t)

			err := attestation.VerifyUserVerification(tt.answer(challenge), challenge, uvTrust(ca))

			require.ErrorIs(t, err, attestation.ErrUserVerificationFailed)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyUserVerification_AnswersAChallengeOnce(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	challenge := uvChallenge(t)
	result := uvk.RespondVerifyUser(t, challenge.Nonce, challenge.ChannelBinding)

	require.NoError(t, attestation.VerifyUserVerification(result, challenge, uvTrust(ca)))

	err := attestation.VerifyUserVerification(result, challenge, uvTrust(ca))
	require.ErrorIs(t, err, attestation.ErrUserVerificationChallengeAnswered,
		"a replayed answer to a consumed challenge must not verify the user again")
}

func TestVerifyUserVerification_RefusesAnExpiredChallenge(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	challenge := uvChallenge(t)
	challenge.Expires = time.Now().Add(-time.Second)

	err := attestation.VerifyUserVerification(
		uvk.RespondVerifyUser(t, challenge.Nonce, challenge.ChannelBinding), challenge, uvTrust(ca))

	require.ErrorIs(t, err, attestation.ErrUserVerificationFailed)
	require.ErrorIs(t, err, attestation.ErrUserVerificationChallengeExpired)
}

func TestVerifyUserVerification_RefusesMissingInputs(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	challenge := uvChallenge(t)
	result := uvk.RespondVerifyUser(t, challenge.Nonce, challenge.ChannelBinding)

	tests := []struct {
		name      string
		result    *pairingproto.LocalVerifyUserResult
		challenge *attestation.UserVerificationChallenge
		trust     *xkms.AndroidDeviceTrust
		wantErr   error
	}{
		{"no trust", result, challenge, nil, attestation.ErrUserVerificationIncomplete},
		{"no roots", result, challenge, &xkms.AndroidDeviceTrust{Applications: attesttest.Applications()}, attestation.ErrUserVerificationIncomplete},
		{"no application policy", result, challenge, &xkms.AndroidDeviceTrust{Roots: ca.Pool()}, pairing.ErrApplicationPolicyUnconfigured},
		{"no answer", nil, challenge, uvTrust(ca), attestation.ErrUserVerificationIncomplete},
		{"no challenge", result, nil, uvTrust(ca), attestation.ErrUserVerificationIncomplete},
		{"a short nonce", result, &attestation.UserVerificationChallenge{Nonce: []byte{1}}, uvTrust(ca), attestation.ErrUserVerificationIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attestation.VerifyUserVerification(tt.result, tt.challenge, tt.trust)

			require.ErrorIs(t, err, attestation.ErrUserVerificationFailed)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// verifyUserExchange answers local.verifyUser with uvk, echoing the request's
// id and generation; mutate damages the response after it is built.
func verifyUserExchange(
	t *testing.T,
	uvk *attesttest.DAK,
	channelBinding []byte,
	mutate func(*pairingproto.Response),
) pairingproto.RPCExchange {
	t.Helper()

	return func(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		require.Equal(t, pairingproto.MethodLocalVerifyUser, req.Method)

		var params pairingproto.LocalVerifyUserParams
		raw, err := json.Marshal(req.Params)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &params))

		resultJSON, err := json.Marshal(uvk.RespondVerifyUser(t, params.Nonce, channelBinding))
		require.NoError(t, err)

		resp := &pairingproto.Response{JSONRPC: "2.0", ID: req.ID, Generation: req.Generation, Result: resultJSON}
		if mutate != nil {
			mutate(resp)
		}
		return resp, nil
	}
}

func TestNewUserVerifier_Succeeds(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	channelBinding := attesttest.FixedBytes(0x77, pairingproto.AttestChannelBindingSize)
	loads := 0

	verify := attestation.NewUserVerifier(func() (*xkms.AndroidDeviceTrust, error) {
		loads++
		return uvTrust(ca), nil
	}, discardLogger())

	require.NoError(t, verify(context.Background(), verifyUserExchange(t, uvk, channelBinding, nil), channelBinding))
	require.NoError(t, verify(context.Background(), verifyUserExchange(t, uvk, channelBinding, nil), channelBinding))
	assert.Equal(t, 2, loads, "the trust material is loaded on every use, nothing is kept")
}

func TestNewUserVerifier_Refuses(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	uvk := attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())
	channelBinding := attesttest.FixedBytes(0x77, pairingproto.AttestChannelBindingSize)
	errTransport := errors.New("transport down")
	errNoStore := errors.New("trust store unavailable")

	honestTrust := func() (*xkms.AndroidDeviceTrust, error) { return uvTrust(ca), nil }

	tests := []struct {
		name      string
		loadTrust func() (*xkms.AndroidDeviceTrust, error)
		exchange  pairingproto.RPCExchange
		wantErr   error
		wantCause error
	}{
		{
			name:      "the trust store cannot be loaded",
			loadTrust: func() (*xkms.AndroidDeviceTrust, error) { return nil, errNoStore },
			exchange:  verifyUserExchange(t, uvk, channelBinding, nil),
			wantErr:   attestation.ErrUserVerificationFailed,
			wantCause: errNoStore,
		},
		{
			name:      "the exchange fails",
			loadTrust: honestTrust,
			exchange: func(context.Context, *pairingproto.Request) (*pairingproto.Response, error) {
				return nil, errTransport
			},
			wantErr:   attestation.ErrUserVerificationExchangeFailed,
			wantCause: errTransport,
		},
		{
			name:      "the response answers another request",
			loadTrust: honestTrust,
			exchange: verifyUserExchange(t, uvk, channelBinding, func(r *pairingproto.Response) {
				r.Generation = 7
			}),
			wantErr: attestation.ErrUserVerificationExchangeFailed,
		},
		{
			name:      "the phone cancelled the prompt",
			loadTrust: honestTrust,
			exchange: verifyUserExchange(t, uvk, channelBinding, func(r *pairingproto.Response) {
				r.Result = nil
				r.Error = &pairingproto.RPCError{Code: -32000, Message: "biometric prompt cancelled"}
			}),
			wantErr: attestation.ErrUserVerificationExchangeFailed,
		},
		{
			name:      "the result is malformed",
			loadTrust: honestTrust,
			exchange: verifyUserExchange(t, uvk, channelBinding, func(r *pairingproto.Response) {
				r.Result = json.RawMessage(`"not an object"`)
			}),
			wantErr: attestation.ErrUserVerificationExchangeFailed,
		},
		{
			name:      "the answer is bound to another session",
			loadTrust: honestTrust,
			exchange: verifyUserExchange(t, uvk,
				attesttest.FixedBytes(0x78, pairingproto.AttestChannelBindingSize), nil),
			wantErr:   attestation.ErrUserVerificationFailed,
			wantCause: pairingproto.ErrAttestSignatureInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := attestation.NewUserVerifier(tt.loadTrust, discardLogger())

			err := verify(context.Background(), tt.exchange, channelBinding)

			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantCause != nil {
				require.ErrorIs(t, err, tt.wantCause)
			}
		})
	}
}

// TestNewUserVerifier_OverANoiseSession is the exchange end to end: a real
// Noise XX session to the fixture phone, which derives its own channel binding
// and signs with its UVK, judged by the desktop verifier.
func TestNewUserVerifier_OverANoiseSession(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	device := attesttest.NewPhone(t, attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState()))
	device.UVK = attesttest.NewUVK(t, ca, attesttest.UserVerificationKeyClaims())

	desktopKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer desktopKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initiator, responder := attesttest.NewMemTransportPair()
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey: desktopKey,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	device.Serve(ctx, t, responder, false, 1, done)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:            initiator,
		Session:              session,
		Logger:               discardLogger(),
		LocalStaticPublicKey: session.LocalStaticPublicKey(),
	}))

	channelBinding, err := pairingproto.AttestChannelBinding(session)
	require.NoError(t, err)

	exchange := func(ctx context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		plaintext, err := pairingproto.EncodeRequest(req)
		if err != nil {
			return nil, err
		}
		ciphertext, err := session.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
		reply, err := initiator.SendAndReceive(ctx, ciphertext)
		if err != nil {
			return nil, err
		}
		replyPlaintext, err := session.Decrypt(reply)
		if err != nil {
			return nil, err
		}
		return pairingproto.DecodeResponse(replyPlaintext)
	}

	verify := attestation.NewUserVerifier(func() (*xkms.AndroidDeviceTrust, error) {
		return uvTrust(ca), nil
	}, discardLogger())

	require.NoError(t, verify(ctx, exchange, channelBinding))
	require.NoError(t, <-done, "phone responder failed")
}
