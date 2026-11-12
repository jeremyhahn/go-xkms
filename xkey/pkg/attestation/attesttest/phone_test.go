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

package attesttest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

func TestMemTransportPair_DeliversInBothDirections(t *testing.T) {
	ctx := context.Background()
	initiator, responder := NewMemTransportPair()

	require.NoError(t, initiator.Send(ctx, []byte("ping")))
	got, err := responder.Receive(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), got)

	require.NoError(t, responder.Send(ctx, []byte("pong")))
	got, err = initiator.Receive(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), got)

	// A message one side sends never comes back to itself.
	require.NoError(t, responder.Send(ctx, []byte("reply")))
	got, err = initiator.SendAndReceive(ctx, []byte("request"))
	require.NoError(t, err)
	require.Equal(t, []byte("reply"), got)
	got, err = responder.Receive(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("request"), got)

	require.True(t, initiator.IsConnected())
	require.NoError(t, initiator.Close())
}

func TestMemTransport_HonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	initiator, _ := NewMemTransportPair()

	_, err := initiator.Receive(ctx)
	require.ErrorIs(t, err, context.Canceled, "Receive on an empty transport ignored a cancelled context")

	// Fill the buffer so a send can only complete by cancellation.
	for i := 0; i < 8; i++ {
		require.NoError(t, initiator.Send(context.Background(), []byte{byte(i)}))
	}
	require.ErrorIs(t, initiator.Send(ctx, []byte("overflow")), context.Canceled)

	_, err = initiator.SendAndReceive(ctx, []byte("overflow"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestChannelBinding_MatchesTheProductionDerivation(t *testing.T) {
	initiatorPub := FixedBytes(0x01, pairingproto.AttestStaticKeySize)
	responderPub := FixedBytes(0x02, pairingproto.AttestStaticKeySize)
	prologue := FixedBytes(0x03, 32)

	for name, p := range map[string][]byte{"first pairing": nil, "known device": prologue} {
		t.Run(name, func(t *testing.T) {
			want, err := pairingproto.ComputeAttestChannelBinding(initiatorPub, responderPub, p)
			require.NoError(t, err)
			require.Equal(t, want, ChannelBinding(initiatorPub, responderPub, p))
			require.NotEqual(t, want, ChannelBinding(responderPub, initiatorPub, p),
				"swapping the roles left the binding unchanged")
		})
	}
}

// TestPhoneRun_ServesAProductionInitiator pairs the phone with the desktop's
// own handshake and checks that what it hands back verifies under the
// production attestation code: the phone's hand-derived prologue and channel
// binding must agree with the initiator's, or the handshake or the signature
// fails.
func TestPhoneRun_ServesAProductionInitiator(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	for _, known := range []bool{false, true} {
		name := "new device"
		if known {
			name = "known device"
		}
		t.Run(name, func(t *testing.T) {
			dak := NewDAK(t, NewCA(t, "root"), GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
			phone := NewPairedPhone(t, dak, dak.Fingerprint())
			session, tr, done := startPhone(t, phone, known, 2)

			var expected []byte
			if known {
				expected = dak.Fingerprint()
			}
			require.NoError(t, pairingproto.PerformHandshake(context.Background(), &pairingproto.HandshakeConfig{
				Transport:                 tr,
				Session:                   session,
				LocalStaticPublicKey:      session.LocalStaticPublicKey(),
				ExpectedDeviceFingerprint: expected,
			}))
			require.Equal(t, phone.StaticPublicKey(), session.RemoteStaticPublicKey())

			confirm := exchange(t, session, tr, pairingproto.MethodPairingConfirm,
				&pairingproto.PairingConfirmParams{DeviceName: "desktop", PublicKeyHex: "00ff"})
			confirmed, err := pairingproto.DecodeResult[pairingproto.PairingConfirmResult](confirm)
			require.NoError(t, err)
			require.True(t, confirmed.Confirmed)
			require.Equal(t, phone.Name, confirmed.DeviceName)

			nonce := FixedBytes(0x77, pairingproto.AttestNonceSize)
			attest := exchange(t, session, tr, pairingproto.MethodLocalAttestDevice, &pairingproto.LocalAttestDeviceParams{
				ProtocolVersion: pairingproto.AttestProtocolV2, Nonce: nonce, Purpose: pairingproto.AttestPurposePair,
			})
			res, err := pairingproto.DecodeResult[pairingproto.LocalAttestDeviceResult](attest)
			require.NoError(t, err)

			binding, err := pairingproto.AttestChannelBinding(session)
			require.NoError(t, err)
			transcript, err := pairingproto.BuildAttestTranscript(res.Purpose, res.Nonce, binding, dak.FP)
			require.NoError(t, err)
			require.NoError(t, pairingproto.VerifyAttestChallengeSignature(dak.Leaf, res.SignatureAlgorithm, res.Signature, transcript),
				"the phone signed a channel binding the initiator does not share")

			require.NoError(t, <-done)
		})
	}
}

func TestPhoneRun_MutateDamagesTheResponseOnTheWire(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	dak := NewDAK(t, NewCA(t, "root"), GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
	phone := NewPhone(t, dak)
	phone.Mutate = func(res *pairingproto.LocalAttestDeviceResult) { res.Purpose = pairingproto.AttestPurposeReattest }
	session, tr, done := startPhone(t, phone, false, 1)
	handshake(t, session, tr)

	resp := exchange(t, session, tr, pairingproto.MethodLocalAttestDevice, &pairingproto.LocalAttestDeviceParams{
		ProtocolVersion: pairingproto.AttestProtocolV2, Nonce: FixedBytes(0x01, pairingproto.AttestNonceSize),
		Purpose: pairingproto.AttestPurposePair,
	})
	res, err := pairingproto.DecodeResult[pairingproto.LocalAttestDeviceResult](resp)
	require.NoError(t, err)
	require.Equal(t, pairingproto.AttestPurposeReattest, res.Purpose)

	binding, err := pairingproto.AttestChannelBinding(session)
	require.NoError(t, err)
	transcript, err := pairingproto.BuildAttestTranscript(res.Purpose, res.Nonce, binding, dak.FP)
	require.NoError(t, err)
	require.Error(t, pairingproto.VerifyAttestChallengeSignature(dak.Leaf, res.SignatureAlgorithm, res.Signature, transcript),
		"a mutated response still verified, so the damage happened before signing")
	require.NoError(t, <-done)
}

func TestPhoneRun_RefusesWhatTheContractDoesNotAllow(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	tests := map[string]struct {
		method string
		params any
	}{
		"unknown method":             {"local.somethingElse", map[string]string{}},
		"legacy attestation version": {pairingproto.MethodLocalAttestDevice, &pairingproto.LocalAttestDeviceParams{ProtocolVersion: 1}},
		"confirm without a key":      {pairingproto.MethodPairingConfirm, &pairingproto.PairingConfirmParams{DeviceName: "desktop"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dak := NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
			session, tr, done := startPhone(t, NewPhone(t, dak), false, 1)
			handshake(t, session, tr)

			send(t, session, tr, tt.method, tt.params)

			require.Error(t, <-done)
		})
	}
}

func TestPhoneRun_RefusesGarbageOnTheWire(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Run("handshake message", func(t *testing.T) {
		dak := NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
		session, tr, done := startPhone(t, NewPhone(t, dak), false, 1)
		ctx := timed(t)

		ack, err := tr.SendAndReceive(ctx, append([]byte{pairingproto.IdentityMsgVersion}, session.LocalStaticPublicKey()...))
		require.NoError(t, err)
		require.Equal(t, []byte{pairingproto.IdentityAckUnknown}, ack)
		require.NoError(t, tr.Send(ctx, []byte("not a noise message")))

		require.Error(t, <-done)
	})
	t.Run("exchange ciphertext", func(t *testing.T) {
		dak := NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
		session, tr, done := startPhone(t, NewPhone(t, dak), false, 1)
		handshake(t, session, tr)

		require.NoError(t, tr.Send(timed(t), []byte("not encrypted under the session")))

		require.Error(t, <-done)
	})
}

func TestPhoneRun_RefusesAMalformedIdentityMessage(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	phone := NewPhone(t, NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState()))
	initiator, responder := NewMemTransportPair()
	require.NoError(t, initiator.Send(context.Background(), []byte{0x02, 0x00}))

	require.Error(t, phone.Run(context.Background(), responder, false, 0))
}

func TestPhoneRun_StopsWhenTheContextEnds(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	phone := NewPhone(t, NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, responder := NewMemTransportPair()

	require.ErrorIs(t, phone.Run(ctx, responder, false, 0), context.Canceled)
}

// startPhone runs the phone on one end of a fresh transport pair and returns
// an initiator session for the other end.
func startPhone(t *testing.T, phone *Phone, known bool, exchanges int) (*bootstrap.NoiseSession, *MemTransport, chan error) {
	t.Helper()

	initiator, responder := NewMemTransportPair()
	done := make(chan error, 1)
	phone.Serve(timed(t), t, responder, known, exchanges, done)

	key, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{LocalStaticKey: key, IsInitiator: true})
	require.NoError(t, err)
	return session, initiator, done
}

// handshake runs the initiator's side of a first pairing by hand: the identity
// exchange and the three Noise XX messages, without PerformHandshake's
// settling delay.
func handshake(t *testing.T, session *bootstrap.NoiseSession, tr *MemTransport) {
	t.Helper()
	ctx := timed(t)

	ack, err := tr.SendAndReceive(ctx, append([]byte{pairingproto.IdentityMsgVersion}, session.LocalStaticPublicKey()...))
	require.NoError(t, err)
	require.Equal(t, []byte{pairingproto.IdentityAckUnknown}, ack)

	require.NoError(t, session.InitHandshake())
	msg1, _, err := session.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, err := tr.SendAndReceive(ctx, msg1)
	require.NoError(t, err)
	msg3, complete, err := session.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)
	require.NoError(t, tr.Send(ctx, msg3))
}

func send(t *testing.T, session *bootstrap.NoiseSession, tr *MemTransport, method string, params any) {
	t.Helper()

	plaintext, err := pairingproto.EncodeRequest(pairingproto.NewRequest(method, params))
	require.NoError(t, err)
	ciphertext, err := session.Encrypt(plaintext)
	require.NoError(t, err)
	require.NoError(t, tr.Send(context.Background(), ciphertext))
}

func exchange(t *testing.T, session *bootstrap.NoiseSession, tr *MemTransport, method string, params any) *pairingproto.Response {
	t.Helper()

	send(t, session, tr, method, params)
	ciphertext, err := tr.Receive(timed(t))
	require.NoError(t, err)
	plaintext, err := session.Decrypt(ciphertext)
	require.NoError(t, err)
	resp, err := pairingproto.DecodeResponse(plaintext)
	require.NoError(t, err)
	return resp
}

// timed bounds a wait on the phone, so a phone that stopped answering fails
// the test instead of hanging it.
func timed(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
