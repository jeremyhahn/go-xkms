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

package pairing

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errExchangeSend    = errors.New("exchange test: send failed")
	errExchangeReceive = errors.New("exchange test: receive failed")
)

// echoPhone is the far end of an InlineExchange: it decrypts each request
// with its own Noise session and answers it with the request's method name.
type echoPhone struct {
	t       *testing.T
	session *bootstrap.NoiseSession
	reply   []byte
	method  string
}

func (p *echoPhone) send(_ context.Context, ciphertext []byte) error {
	plaintext, err := p.session.Decrypt(ciphertext)
	require.NoError(p.t, err)
	req, err := pairingproto.DecodeRequest(plaintext)
	require.NoError(p.t, err)
	p.method = req.Method

	resp, err := pairingproto.EncodeResponse(req.ID, req.Generation, map[string]string{"echo": req.Method})
	require.NoError(p.t, err)
	p.reply, err = p.session.Encrypt(resp)
	require.NoError(p.t, err)
	return nil
}

func (p *echoPhone) receive(context.Context) ([]byte, error) {
	return p.reply, nil
}

func TestInlineExchange_RoundTripsThroughTheSession(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	laptop, phoneSession := setupHandshakedNoiseSessions(t)
	phone := &echoPhone{t: t, session: phoneSession}
	exchange := InlineExchange(laptop, phone.send, phone.receive)

	req := pairingproto.NewRequest(pairingproto.MethodLocalSyncStatus, nil)
	resp, err := exchange(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, pairingproto.MethodLocalSyncStatus, phone.method)
	assert.Equal(t, req.ID, resp.ID)
	result, err := pairingproto.DecodeResult[map[string]string](resp)
	require.NoError(t, err)
	assert.Equal(t, pairingproto.MethodLocalSyncStatus, (*result)["echo"])
}

func TestInlineExchange_PropagatesTransportErrors(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	// Each case needs its own session pair: a failed send consumes a nonce
	// the phone never sees.
	laptop, phoneSession := setupHandshakedNoiseSessions(t)
	phone := &echoPhone{t: t, session: phoneSession}

	failSend := func(context.Context, []byte) error { return errExchangeSend }
	_, err := InlineExchange(laptop, failSend, phone.receive)(
		context.Background(), pairingproto.NewRequest(pairingproto.MethodLocalSyncStatus, nil))
	assert.ErrorIs(t, err, errExchangeSend)

	laptop, phoneSession = setupHandshakedNoiseSessions(t)
	phone = &echoPhone{t: t, session: phoneSession}
	failReceive := func(context.Context) ([]byte, error) { return nil, errExchangeReceive }
	_, err = InlineExchange(laptop, phone.send, failReceive)(
		context.Background(), pairingproto.NewRequest(pairingproto.MethodLocalSyncStatus, nil))
	assert.ErrorIs(t, err, errExchangeReceive)
}

func TestInlineExchange_RefusesAReplyTheSessionCannotDecrypt(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	laptop, _ := setupHandshakedNoiseSessions(t)
	sent := false
	send := func(context.Context, []byte) error { sent = true; return nil }
	receive := func(context.Context) ([]byte, error) {
		return []byte("not a noise ciphertext, just bytes on the wire"), nil
	}

	_, err := InlineExchange(laptop, send, receive)(
		context.Background(), pairingproto.NewRequest(pairingproto.MethodLocalSyncStatus, nil))
	assert.True(t, sent)
	assert.Error(t, err)
}

func TestInlineExchange_RefusesARequestThatDoesNotEncode(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	laptop, _ := setupHandshakedNoiseSessions(t)
	send := func(context.Context, []byte) error {
		t.Fatal("an unencodable request must not reach the transport")
		return nil
	}

	_, err := InlineExchange(laptop, send, nil)(
		context.Background(), pairingproto.NewRequest(pairingproto.MethodLocalSyncStatus, make(chan int)))
	assert.Error(t, err)
}
