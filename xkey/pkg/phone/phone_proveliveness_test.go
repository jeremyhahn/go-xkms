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
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/stretchr/testify/require"
)

// This file exercises proveLiveness's exchange closure -- the part
// live_attestation_test.go's fixtures cannot reach, because none of its
// backends have a completed handshake to derive a channel binding from.
// Everything here is in-memory: two real Noise sessions handshaken against
// each other, and a fake pairingproto.Transport (an interface, so no BLE hardware
// is ever touched).

// establishedNoiseSessionPair returns two Noise sessions that completed a
// real XX handshake against each other, mirroring the pattern used in
// pkg/attestation's device_session_test.go.
func establishedNoiseSessionPair(t *testing.T) (client, server *bootstrap.NoiseSession) {
	t.Helper()

	client, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	server, err = bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	require.NoError(t, client.InitHandshake())
	require.NoError(t, server.InitHandshake())

	msg1, complete, err := client.HandshakeMessage(nil)
	require.NoError(t, err)
	require.False(t, complete)

	msg2, complete, err := server.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)

	msg3, complete, err := client.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)

	_, complete, err = server.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	return client, server
}

// scriptedTransport is a pairingproto.Transport whose SendAndReceive is supplied
// by the test, so proveLiveness's exchange closure can be driven through
// every branch without a real connection.
type scriptedTransport struct {
	respond func(ctx context.Context, sent []byte) ([]byte, error)
}

func (s *scriptedTransport) Send(context.Context, []byte) error { return nil }
func (s *scriptedTransport) Receive(context.Context) ([]byte, error) {
	return nil, errors.New("scriptedTransport: Receive is unused")
}
func (s *scriptedTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	return s.respond(ctx, m)
}
func (s *scriptedTransport) IsConnected() bool { return true }
func (s *scriptedTransport) Close() error      { return nil }

// callThroughExchange is a LiveAttest stub that does exactly one thing: call
// the exchange callback proveLiveness built, and return whatever it got.
// This is what makes the closure's internal branches reachable -- the real
// verifier (attestation.NewLiveAttestor) does the same thing, but pulling
// one layer further away would blur which package's test is pinning what.
func callThroughExchange(gotResp **pairingproto.Response, gotErr *error) pairingproto.LiveAttestFunc {
	return func(ctx context.Context, exchange pairingproto.RPCExchange, _ []byte) error {
		resp, err := exchange(ctx, pairingproto.NewRequest("test.liveness", nil))
		*gotResp, *gotErr = resp, err
		return err
	}
}

func TestProveLiveness_ExchangeTransportFailure(t *testing.T) {
	client, _ := establishedNoiseSessionPair(t)
	transportErr := errors.New("link dropped")

	var gotResp *pairingproto.Response
	var gotErr error
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{
			RequireLiveAttestation: true,
			LiveAttest:             callThroughExchange(&gotResp, &gotErr),
		},
		session:   client,
		transport: &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) { return nil, transportErr }},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.proveLiveness(context.Background())

	require.ErrorIs(t, err, transportErr)
	require.Nil(t, gotResp)
}

func TestProveLiveness_ExchangeUndecryptableResponse(t *testing.T) {
	client, _ := establishedNoiseSessionPair(t)

	var gotResp *pairingproto.Response
	var gotErr error
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{
			RequireLiveAttestation: true,
			LiveAttest:             callThroughExchange(&gotResp, &gotErr),
		},
		session: client,
		transport: &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
			return []byte("not a noise ciphertext"), nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.proveLiveness(context.Background())

	require.Error(t, err)
	require.Nil(t, gotResp)
}

func TestProveLiveness_ExchangeMalformedResponseJSON(t *testing.T) {
	client, server := establishedNoiseSessionPair(t)

	var gotResp *pairingproto.Response
	var gotErr error
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{
			RequireLiveAttestation: true,
			LiveAttest:             callThroughExchange(&gotResp, &gotErr),
		},
		session: client,
		transport: &scriptedTransport{respond: func(context.Context, []byte) ([]byte, error) {
			return server.Encrypt([]byte("not json"))
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.proveLiveness(context.Background())

	require.Error(t, err)
	require.Nil(t, gotResp)
}

// TestProveLiveness_ExchangeSuccessRoundTrip drives the whole closure to its
// accept path: the request goes out encrypted through the transport, and a
// well-formed encrypted response comes back decrypted and decoded, exactly
// as attestation.NewLiveAttestor's exchange call expects to receive it.
func TestProveLiveness_ExchangeSuccessRoundTrip(t *testing.T) {
	client, server := establishedNoiseSessionPair(t)

	var gotResp *pairingproto.Response
	var gotErr error
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{
			RequireLiveAttestation: true,
			LiveAttest:             callThroughExchange(&gotResp, &gotErr),
		},
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
			respBytes, err := pairingproto.EncodeResponse(req.ID, json.RawMessage(resultJSON))
			if err != nil {
				return nil, err
			}
			return server.Encrypt(respBytes)
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.proveLiveness(context.Background())

	require.NoError(t, err)
	require.NoError(t, gotErr)
	require.NotNil(t, gotResp)
	require.Nil(t, gotResp.Error)
}
