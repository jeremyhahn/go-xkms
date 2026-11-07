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

//go:build ble

package cmd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
)

// callPeer is the phone end of a completed Noise XX session: it owns the
// responder session and the responder half of the in-memory link.
type callPeer struct {
	transport *attesttest.MemTransport
	session   *bootstrap.NoiseSession
}

// newCallSession completes a real Noise XX handshake between two in-process
// sessions and returns the desktop's deviceSession and the phone's end.
func newCallSession(t *testing.T) (*deviceSession, *callPeer) {
	t.Helper()

	initiator, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	responder, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{})
	require.NoError(t, err)
	require.NoError(t, initiator.InitHandshake())
	require.NoError(t, responder.InitHandshake())

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	desktop, phone := attesttest.NewMemTransportPair()
	return &deviceSession{
		transport: desktop,
		session:   initiator,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, &callPeer{
		transport: phone,
		session:   responder,
	}
}

// answer receives one request on the phone end, hands its plaintext to
// reply, and sends back what reply returns encrypted under the session (or
// raw, when encrypt is false). The decoded request is delivered on the
// returned channel once the reply is sent.
func (p *callPeer) answer(
	ctx context.Context,
	encrypt bool,
	reply func(req *pairingproto.Request) []byte,
) <-chan *pairingproto.Request {
	seen := make(chan *pairingproto.Request, 1)
	go func() {
		defer close(seen)
		ciphertext, err := p.transport.Receive(ctx)
		if err != nil {
			return
		}
		plaintext, err := p.session.Decrypt(ciphertext)
		if err != nil {
			return
		}
		req, err := pairingproto.DecodeRequest(plaintext)
		if err != nil {
			return
		}
		out := reply(req)
		if encrypt {
			if out, err = p.session.Encrypt(out); err != nil {
				return
			}
		}
		if p.transport.Send(ctx, out) == nil {
			seen <- req
		}
	}()
	return seen
}

func TestDeviceSessionCall_ReturnsThePhonesResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, phone := newCallSession(t)

	seen := phone.answer(ctx, true, func(req *pairingproto.Request) []byte {
		out, err := pairingproto.EncodeResponse(req.ID, req.Generation, map[string]string{"status": "stored"})
		assert.NoError(t, err)
		return out
	})

	raw, err := session.Call(ctx, pairingproto.MethodLocalStoreDeviceCredential, map[string]string{"name": "laptop"})
	require.NoError(t, err)

	var result map[string]string
	require.NoError(t, json.Unmarshal(raw, &result))
	assert.Equal(t, map[string]string{"status": "stored"}, result)

	req := <-seen
	require.NotNil(t, req, "the phone must have received and decrypted the request")
	assert.Equal(t, pairingproto.MethodLocalStoreDeviceCredential, req.Method)
	assert.Equal(t, map[string]interface{}{"name": "laptop"}, req.Params)
}

func TestDeviceSessionCall_PhoneRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, phone := newCallSession(t)

	phone.answer(ctx, true, func(req *pairingproto.Request) []byte {
		out, err := pairingproto.EncodeErrorResponse(req.ID, req.Generation, -32001, "user declined", nil)
		assert.NoError(t, err)
		return out
	})

	raw, err := session.Call(ctx, pairingproto.MethodLocalGetDeviceEnrollmentRequest, nil)
	require.ErrorIs(t, err, ErrSessionRPC)
	assert.Contains(t, err.Error(), pairingproto.MethodLocalGetDeviceEnrollmentRequest)
	assert.Contains(t, err.Error(), "-32001")
	assert.Contains(t, err.Error(), "user declined")
	assert.Nil(t, raw)
}

func TestDeviceSessionCall_Failures(t *testing.T) {
	const method = pairingproto.MethodLocalStoreDeviceCredential

	t.Run("params that cannot be encoded", func(t *testing.T) {
		session, _ := newCallSession(t)
		raw, err := session.Call(context.Background(), method, make(chan int))
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to encode "+method, wrapped.Msg)
		assert.Nil(t, raw)
	})

	t.Run("a session whose handshake never completed", func(t *testing.T) {
		pending, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
		require.NoError(t, err)
		desktop, _ := attesttest.NewMemTransportPair()
		session := &deviceSession{transport: desktop, session: pending}

		raw, err := session.Call(context.Background(), method, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to encrypt "+method, wrapped.Msg)
		assert.Nil(t, raw)
	})

	t.Run("a link that drops before the answer", func(t *testing.T) {
		session, _ := newCallSession(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		raw, err := session.Call(ctx, method, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, method+" failed", wrapped.Msg)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, raw)
	})

	t.Run("an answer not sealed under the session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		session, phone := newCallSession(t)
		phone.answer(ctx, false, func(*pairingproto.Request) []byte {
			return []byte("plaintext the phone forgot to encrypt")
		})

		raw, err := session.Call(ctx, method, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to decrypt the "+method+" response", wrapped.Msg)
		assert.Nil(t, raw)
	})

	t.Run("an answer that is not a JSON-RPC response", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		session, phone := newCallSession(t)
		phone.answer(ctx, true, func(*pairingproto.Request) []byte {
			return []byte("not json")
		})

		raw, err := session.Call(ctx, method, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to decode the "+method+" response", wrapped.Msg)
		assert.Nil(t, raw)
	})
}
