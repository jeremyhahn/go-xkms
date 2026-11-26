// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package phone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/stretchr/testify/require"
)

var errVerifierRefused = errors.New("verifier refused the answer")

// connectedVerifyUserBackend is a backend connected over an established
// Noise session whose phone answers every request with {"ok": true}.
func connectedVerifyUserBackend(t *testing.T, verify pairingproto.VerifyUserFunc) *PhoneKeyBackend {
	t.Helper()
	client, server := establishedNoiseSessionPair(t)
	backend := &PhoneKeyBackend{
		cfg:     &PhoneKeyBackendConfig{VerifyUser: verify},
		session: client,
		transport: &scriptedTransport{respond: func(_ context.Context, sent []byte) ([]byte, error) {
			plaintext, err := server.Decrypt(sent)
			if err != nil {
				return nil, err
			}
			req, err := pairingproto.DecodeRequest(plaintext)
			if err != nil {
				return nil, err
			}
			resultJSON, err := json.Marshal(map[string]bool{"ok": true})
			if err != nil {
				return nil, err
			}
			respBytes, err := pairingproto.EncodeResponse(req.ID, req.Generation, json.RawMessage(resultJSON))
			if err != nil {
				return nil, err
			}
			return server.Encrypt(respBytes)
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)
	return backend
}

// TestVerifyUser_RoundTripsOverTheSessionWithItsBinding proves the verifier
// is handed the live session's channel binding and an exchange that reaches
// the phone through it.
func TestVerifyUser_RoundTripsOverTheSessionWithItsBinding(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	var gotBinding []byte
	var gotRPName string
	var gotResp *pairingproto.Response
	backend := connectedVerifyUserBackend(t, func(ctx context.Context, exchange pairingproto.RPCExchange, binding []byte, rpName string) error {
		gotBinding = binding
		gotRPName = rpName
		resp, err := exchange(ctx, pairingproto.NewRequest(pairingproto.MethodLocalVerifyUser, nil))
		gotResp = resp
		return err
	})

	require.NoError(t, backend.VerifyUser(context.Background(), "example.com"))

	want, err := pairingproto.AttestChannelBinding(backend.session)
	require.NoError(t, err)
	require.Equal(t, want, gotBinding)
	require.Equal(t, "example.com", gotRPName, "the RP the token is for is sent as asked")
	require.NotNil(t, gotResp)
	require.Nil(t, gotResp.Error)
}

// TestVerifyUser_NoRPNamesTheAuthenticator proves a token with no RP scope
// is asked for on behalf of the authenticator, never with an empty RP name
// the verifier would refuse.
func TestVerifyUser_NoRPNamesTheAuthenticator(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	var gotRPName string
	backend := connectedVerifyUserBackend(t, func(_ context.Context, _ pairingproto.RPCExchange, _ []byte, rpName string) error {
		gotRPName = rpName
		return nil
	})

	require.NoError(t, backend.VerifyUser(context.Background(), ""))
	require.Equal(t, VerifyUserAuthenticatorName, gotRPName)
}

// TestVerifyUser_VerifierRefusalIsReturned proves a refused answer is never
// reported as a verified user.
func TestVerifyUser_VerifierRefusalIsReturned(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	backend := connectedVerifyUserBackend(t, func(context.Context, pairingproto.RPCExchange, []byte, string) error {
		return errVerifierRefused
	})

	require.ErrorIs(t, backend.VerifyUser(context.Background(), "example.com"), errVerifierRefused)
}

// TestVerifyUser_NoVerifierRefuses proves a backend built without a
// verifier fails closed instead of treating the user as verified.
func TestVerifyUser_NoVerifierRefuses(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	backend.connected.Store(true)

	require.ErrorIs(t, backend.VerifyUser(context.Background(), "example.com"), ErrUserVerifierUnavailable)
}

// TestVerifyUser_NotConnectedNeverCallsTheVerifier proves no exchange is
// attempted before a session exists.
func TestVerifyUser_NotConnectedNeverCallsTheVerifier(t *testing.T) {
	called := false
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{VerifyUser: func(context.Context, pairingproto.RPCExchange, []byte, string) error {
			called = true
			return nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	require.ErrorIs(t, backend.VerifyUser(context.Background(), "example.com"), ErrNotConnected)
	require.False(t, called)
}
