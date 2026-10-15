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

//go:build ble

package phone

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// newTestPeripheralWithLiveAttest is newTestPeripheral, but lets the test
// choose the LiveAttest verifier explicitly instead of the package's
// always-approve stand-in -- for the tests in this file, which exercise the
// gate itself.
func newTestPeripheralWithLiveAttest(t *testing.T, handler PeripheralRequestHandler, writer FragmentWriter, liveAttest pairingproto.LiveAttestFunc) *BLEPeripheral {
	t.Helper()

	p, err := NewBLEPeripheral(&BLEPeripheralConfig{
		DeviceName:     "xKey-test",
		RequestHandler: handler,
		LiveAttest:     liveAttest,
	})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	p.notifier = writer
	p.fragmenter = pairingproto.NewFragmenter(p.mtu - bleNotifyOverhead)
	p.reassembler = pairingproto.NewReassembler()
	p.sender = newFragmentSender(p.notifier, p.fragmenter, p.log)
	return p
}

// clientHandshakeBLE drives a simulated phone through the Noise XX handshake
// against peripheral p over its in-memory notify/incomingData plumbing, and
// returns the client's completed session.
func clientHandshakeBLE(t *testing.T, p *BLEPeripheral, writer *fragmentChannelWriter, ctx context.Context) *bootstrap.NoiseSession {
	t.Helper()

	clientKey, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	client, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey: clientKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	if err := client.InitHandshake(); err != nil {
		t.Fatalf("client init: %v", err)
	}

	msg1, _, err := client.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("client msg1: %v", err)
	}
	deliverToPeripheral(t, p, p.mtu, msg1)

	msg2 := writer.nextMessage(ctx, t)
	msg3, complete, err := client.HandshakeMessage(msg2)
	if err != nil {
		t.Fatalf("client msg3: %v", err)
	}
	if !complete {
		t.Fatal("client did not complete on its third message")
	}
	deliverToPeripheral(t, p, p.mtu, msg3)

	return client
}

// TestBLEPeripheral_LiveAttestNil_RefusesConnection verifies AcceptConnection
// returns an error and never enters the request loop when no LiveAttest is
// configured -- go-xkms#1306.
func TestBLEPeripheral_LiveAttestNil_RefusesConnection(t *testing.T) {
	handler := &echoHandler{}
	writer := newFragmentChannelWriter()
	p := newTestPeripheralWithLiveAttest(t, handler, writer, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	acceptDone := make(chan error, 1)
	go func() { acceptDone <- p.AcceptConnection(ctx) }()

	clientHandshakeBLE(t, p, writer, ctx)

	select {
	case err := <-acceptDone:
		if !errors.Is(err, ErrLiveAttestationUnavailable) {
			t.Fatalf("AcceptConnection error = %v, want ErrLiveAttestationUnavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptConnection did not return after an unattested handshake")
	}
}

// TestBLEPeripheral_LiveAttest_DeniedRefusesConnection verifies a configured
// verifier that refuses the request ends the connection before the request
// loop runs, and the handler never sees a request.
func TestBLEPeripheral_LiveAttest_DeniedRefusesConnection(t *testing.T) {
	handler := &mockRequestHandler{}
	writer := newFragmentChannelWriter()
	denyErr := errors.New("test: attestation refused")
	p := newTestPeripheralWithLiveAttest(t, handler, writer, func(context.Context, pairingproto.RPCExchange, []byte) error {
		return denyErr
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	acceptDone := make(chan error, 1)
	go func() { acceptDone <- p.AcceptConnection(ctx) }()

	clientHandshakeBLE(t, p, writer, ctx)

	select {
	case err := <-acceptDone:
		if err == nil {
			t.Fatal("AcceptConnection must return an error when live attestation is denied")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptConnection did not return after a denied attestation")
	}

	if len(handler.receivedRequests()) != 0 {
		t.Fatal("RequestHandler must not run when live attestation is denied")
	}
}

// TestBLEPeripheral_LiveAttest_ChallengeExchange drives the verifier's
// exchange over the real notify/incomingData plumbing: the peripheral sends
// a request through InlineExchange, a fake phone answers it, and only then
// does the request loop start.
func TestBLEPeripheral_LiveAttest_ChallengeExchange(t *testing.T) {
	handler := &echoHandler{}
	writer := newFragmentChannelWriter()

	var sawMethod string
	p := newTestPeripheralWithLiveAttest(t, handler, writer, func(ctx context.Context, exchange pairingproto.RPCExchange, binding []byte) error {
		if len(binding) == 0 {
			return errors.New("test: empty channel binding")
		}
		resp, err := exchange(ctx, pairingproto.NewRequest("local.attestDevice", map[string]string{"nonce": "test"}))
		if err != nil {
			return err
		}
		if resp.Error != nil {
			return errors.New("test: phone refused the challenge")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	acceptDone := make(chan error, 1)
	go func() { acceptDone <- p.AcceptConnection(ctx) }()

	client := clientHandshakeBLE(t, p, writer, ctx)

	// The fake phone: read the peripheral's challenge, decrypt, answer.
	challengeCiphertext := writer.nextMessage(ctx, t)
	challengePlaintext, err := client.Decrypt(challengeCiphertext)
	if err != nil {
		t.Fatalf("decrypt challenge: %v", err)
	}
	req, err := pairingproto.DecodeRequest(challengePlaintext)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sawMethod = req.Method

	respBytes, err := pairingproto.EncodeResponse(req.ID, map[string]bool{"ok": true})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	respCiphertext, err := client.Encrypt(respBytes)
	if err != nil {
		t.Fatalf("encrypt response: %v", err)
	}
	deliverToPeripheral(t, p, p.mtu, respCiphertext)

	if sawMethod != "local.attestDevice" {
		t.Fatalf("expected the peripheral to challenge with local.attestDevice, got %q", sawMethod)
	}

	// With the gate satisfied, the ordinary request loop now serves requests.
	plaintext := []byte("ping-from-simulated-phone")
	ciphertext, err := client.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	deliverToPeripheral(t, p, p.mtu, ciphertext)

	respCiphertext2 := writer.nextMessage(ctx, t)
	respPlaintext2, err := client.Decrypt(respCiphertext2)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if got := string(respPlaintext2); got != `{"jsonrpc":"2.0","result":"ping-from-simulated-phone"}` {
		t.Fatalf("unexpected echoed response: %q", got)
	}

	cancel()
	select {
	case err := <-acceptDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("AcceptConnection error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptConnection did not return after its context was cancelled")
	}
}
