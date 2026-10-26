// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// attestReply builds the phone's raw wire answer to the desktop's attestation
// request. responder is the phone's end of the Noise session and req the
// decrypted request it is answering.
type attestReply func(responder *bootstrap.NoiseSession, req *pairingproto.Request) ([]byte, error)

// attestAgainstScriptedPhone runs the manual "Attest Device" exchange
// (attestOverTransport) against a phone that answers its one request with
// whatever reply builds, over an established Noise session. The trust store
// holds a CA and the fixture application is allow-listed, so the exchange
// reaches the wire and every outcome below is the answer's doing.
func attestAgainstScriptedPhone(t *testing.T, reply attestReply) (*AttestationResult, error) {
	t.Helper()

	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "Trusted Attestation Root"))
	h.allowFixtureApplication()

	initiator, responder := establishedNoisePair(t)
	desktop, phone := attesttest.NewMemTransportPair()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	phoneDone := make(chan error, 1)
	go func() {
		ciphertext, err := phone.Receive(ctx)
		if err != nil {
			phoneDone <- err
			return
		}
		plaintext, err := responder.Decrypt(ciphertext)
		if err != nil {
			phoneDone <- err
			return
		}
		req, err := pairingproto.DecodeRequest(plaintext)
		if err != nil {
			phoneDone <- err
			return
		}
		answer, err := reply(responder, req)
		if err != nil {
			phoneDone <- err
			return
		}
		phoneDone <- phone.Send(ctx, answer)
	}()

	result, err := h.svc.attestOverTransport(ctx, desktop, initiator, &phoneConfigDevice{Name: "Pixel 9"})
	require.NoError(t, <-phoneDone, "the phone must receive a decryptable attestation request")
	return result, err
}

// establishedNoisePair completes a Noise_XX handshake between a desktop
// initiator and a phone responder, both with fresh static keys.
func establishedNoisePair(t *testing.T) (initiator, responder *bootstrap.NoiseSession) {
	t.Helper()

	initiator, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	responder, err = bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{})
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
	return initiator, responder
}

// encryptedReply is an attestReply that sends plaintext under the session.
func encryptedReply(plaintext func(req *pairingproto.Request) ([]byte, error)) attestReply {
	return func(responder *bootstrap.NoiseSession, req *pairingproto.Request) ([]byte, error) {
		answer, err := plaintext(req)
		if err != nil {
			return nil, err
		}
		return responder.Encrypt(answer)
	}
}

// attestResultReply answers with a well-formed attestation result.
func attestResultReply(result *pairingproto.LocalAttestDeviceResult) attestReply {
	return encryptedReply(func(req *pairingproto.Request) ([]byte, error) {
		return pairingproto.EncodeResponse(req.ID, req.Generation, result)
	})
}

func TestAttestOverTransport_RequestsALocalDeviceAttestation(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	var method string
	_, err := attestAgainstScriptedPhone(t, encryptedReply(func(req *pairingproto.Request) ([]byte, error) {
		method = req.Method
		return pairingproto.EncodeErrorResponse(req.ID, req.Generation, -32000, "user declined", nil)
	}))

	require.Equal(t, pairingproto.MethodLocalAttestDevice, method)
	require.ErrorIs(t, err, ErrPhoneAttestFailed)
	require.ErrorContains(t, err, "user declined", "the phone's refusal reaches the operator")
}

func TestAttestOverTransport_RefusesAnAnswerItCannotRead(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	tests := []struct {
		name   string
		reply  attestReply
		detail string
	}{
		{
			name: "not encrypted under the session",
			reply: func(*bootstrap.NoiseSession, *pairingproto.Request) ([]byte, error) {
				return []byte("plaintext the session never sealed"), nil
			},
			detail: "decrypt failed",
		},
		{
			name: "not a JSON-RPC response",
			reply: encryptedReply(func(*pairingproto.Request) ([]byte, error) {
				return []byte("{not json"), nil
			}),
			detail: "decode response failed",
		},
		{
			name: "a result that is not an attestation",
			reply: encryptedReply(func(req *pairingproto.Request) ([]byte, error) {
				return pairingproto.EncodeResponse(req.ID, req.Generation, "attested")
			}),
			detail: "decode result failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := attestAgainstScriptedPhone(t, tt.reply)

			require.ErrorIs(t, err, ErrPhoneAttestFailed)
			require.ErrorContains(t, err, tt.detail)
			require.Nil(t, result)
		})
	}
}

func TestAttestOverTransport_ReportsAnUnverifiableChainAsNotVerified(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	untrusted := attesttest.NewCA(t, "Untrusted Root")
	tests := []struct {
		name        string
		chain       [][]byte
		chainLength int
	}{
		{name: "chain that is not DER", chain: [][]byte{[]byte("not a certificate")}, chainLength: 0},
		{name: "certificate without a key description", chain: [][]byte{untrusted.Cert.Raw}, chainLength: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := attestAgainstScriptedPhone(t, attestResultReply(&pairingproto.LocalAttestDeviceResult{
				ProtocolVersion:  2,
				Format:           "android-keystore",
				CertificateChain: tt.chain,
				SecurityLevel:    "strongbox",
			}))

			require.NoError(t, err, "a failed attestation is reported in the result, not as an error")
			require.False(t, result.Verified)
			require.NotEmpty(t, result.ErrorMessage)
			require.Equal(t, "Pixel 9", result.DeviceName)
			require.Equal(t, tt.chainLength, result.ChainLength)
			require.Len(t, result.Certificates, tt.chainLength)
			require.Empty(t, result.SecurityLevel, "display fields come only from a parsed key description")
		})
	}
}

func TestAttestOverTransport_RefusesBeforeTheWire(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	initiator, _ := establishedNoisePair(t)
	unhandshaken, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	tests := []struct {
		name      string
		allowList bool
		session   *bootstrap.NoiseSession
		cause     error
		detail    string
	}{
		{name: "no application allow-listed", allowList: false, session: initiator, cause: pairing.ErrApplicationPolicyUnconfigured},
		{name: "session without a handshake", allowList: true, session: unhandshaken, cause: ErrPhoneAttestFailed, detail: "channel binding unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newPairingHarness(t)
			h.trust(ca)
			if tt.allowList {
				h.allowFixtureApplication()
			}
			desktop, phone := attesttest.NewMemTransportPair()

			result, err := h.svc.attestOverTransport(context.Background(), desktop, tt.session, &phoneConfigDevice{Name: "Pixel 9"})

			require.ErrorIs(t, err, ErrPhoneAttestFailed)
			require.ErrorIs(t, err, tt.cause)
			require.ErrorContains(t, err, tt.detail)
			require.Nil(t, result)
			received, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, recvErr := phone.Receive(received)
			require.ErrorIs(t, recvErr, context.DeadlineExceeded, "nothing may be sent once the exchange is refused")
		})
	}
}

func TestAttestOverTransport_RefusesWhenTheTransportFails(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "Trusted Attestation Root"))
	h.allowFixtureApplication()
	initiator, _ := establishedNoisePair(t)
	desktop, _ := attesttest.NewMemTransportPair()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := h.svc.attestOverTransport(ctx, desktop, initiator, &phoneConfigDevice{Name: "Pixel 9"})

	require.ErrorIs(t, err, ErrPhoneAttestFailed)
	require.ErrorContains(t, err, "send/receive failed")
	require.Nil(t, result)
}
