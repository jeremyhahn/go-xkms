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
	"github.com/jeremyhahn/go-xkms/sdk/go/userverify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
)

// uvTrust is the trust material every user-verification test judges under.
func uvTrust(ca *attesttest.CA) *xkms.AndroidDeviceTrust {
	return &xkms.AndroidDeviceTrust{Roots: ca.Pool(), Applications: attesttest.Applications(), Revocation: attesttest.NoRevocations()}
}

// uvRPName is the relying party every user-verification test names.
const uvRPName = "example.com"

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

		require.Equal(t, uvRPName, params.RPName, "the request names the relying party")

		resultJSON, err := json.Marshal(uvk.RespondVerifyUser(t, params.Nonce, channelBinding, params.RPName))
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

	require.NoError(t, verify(context.Background(), verifyUserExchange(t, uvk, channelBinding, nil), channelBinding, uvRPName))
	require.NoError(t, verify(context.Background(), verifyUserExchange(t, uvk, channelBinding, nil), channelBinding, uvRPName))
	assert.Equal(t, 2, loads, "the trust material is loaded on every use, nothing is kept")
}

func TestNewUserVerifier_RefusesAnInvalidRPNameBeforeAsking(t *testing.T) {
	asked := false
	exchange := func(context.Context, *pairingproto.Request) (*pairingproto.Response, error) {
		asked = true
		return nil, errors.New("unreachable")
	}
	verify := attestation.NewUserVerifier(func() (*xkms.AndroidDeviceTrust, error) {
		return &xkms.AndroidDeviceTrust{}, nil
	}, discardLogger())

	err := verify(context.Background(), exchange,
		attesttest.FixedBytes(0x77, pairingproto.AttestChannelBindingSize), "")

	require.ErrorIs(t, err, pairingproto.ErrVerifyUserRPName)
	assert.False(t, asked, "an invalid RP name never reaches the phone")
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
			wantErr:   attestation.ErrUserVerificationTrustUnavailable,
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
			wantErr:   userverify.ErrVerificationFailed,
			wantCause: pairingproto.ErrAttestSignatureInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := attestation.NewUserVerifier(tt.loadTrust, discardLogger())

			err := verify(context.Background(), tt.exchange, channelBinding, uvRPName)

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

	require.NoError(t, verify(ctx, exchange, channelBinding, uvRPName))
	require.NoError(t, <-done, "phone responder failed")
	assert.Equal(t, uvRPName, device.VerifyUserRPName(), "the phone was asked on behalf of the relying party")
}
