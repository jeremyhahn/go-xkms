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

package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Session errors.
var (
	// ErrSessionKeyDecode means the stored pairing keys will not decode, so
	// the pairing record is unusable and re-pairing is the only fix.
	ErrSessionKeyDecode = errors.New("device: stored pairing key is malformed")

	// ErrSessionRPC means the phone answered with a JSON-RPC error. The
	// phone's own code and message travel with it.
	ErrSessionRPC = errors.New("device: the phone refused the request")
)

// deviceSession is a connected, handshaken channel to a paired phone.
//
// It exists because every command that talks to a phone otherwise repeats the
// same sequence -- load the pairing keys, open BLE, connect, run the Noise
// handshake, then for each call encode, encrypt, send, decrypt, decode. That
// was written out three times before this, and each copy is a place where a
// step can be dropped: forgetting to check resp.Error, say, reads a nil result
// as success.
type deviceSession struct {
	transport phone.Transport
	session   *phone.NoiseSession
	logger    *slog.Logger
}

// openDeviceSession connects to device and completes the Noise handshake.
//
// The returned close function disconnects the transport and destroys the
// session's protected static key; it is safe to call once and must be called
// even when a later step fails.
func openDeviceSession(
	ctx context.Context,
	device *PairedDevice,
	logger *slog.Logger,
) (*deviceSession, func(), error) {
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: local key: %v", ErrSessionKeyDecode, err)
	}
	// Wiped here, at the decode, not at the LoadStaticKey below: a decode
	// failure on any other field returns in between, and the raw scalar
	// would be left sitting in garbage-collected memory.
	defer phone.WipeBytes(localPrivateKey)
	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: local key: %v", ErrSessionKeyDecode, err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		localKey.Destroy()
		return nil, nil, fmt.Errorf("%w: remote key: %v", ErrSessionKeyDecode, err)
	}

	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout: defaultDeviceScanTimeout,
		Logger:      logger,
	})
	if err != nil {
		localKey.Destroy()
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return nil, nil, ErrDeviceBLEUnavailable
		}
		return nil, nil, &WrappedError{Msg: "failed to initialize Bluetooth", Err: err}
	}

	closed := false
	cleanup := func() {
		if closed {
			return
		}
		closed = true
		transport.Disconnect()
		_ = transport.Close()
		// The session reads the key's protected pages, so release them only
		// after the transport is down and no handshake can still be running.
		localKey.Destroy()
	}

	if err := transport.Connect(ctx, device.Address); err != nil {
		cleanup()
		return nil, nil, &WrappedError{Msg: "connection failed", Err: err}
	}

	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		IsInitiator:          true,
	})
	if err != nil {
		cleanup()
		return nil, nil, &WrappedError{Msg: "failed to create noise session", Err: err}
	}

	if err := phone.PerformHandshake(ctx, &phone.HandshakeConfig{
		Transport:           transport,
		Session:             session,
		Logger:              logger,
		StripEnvelopeHeader: false,
		EnvelopeHeaderSize:  0,
	}); err != nil {
		cleanup()
		return nil, nil, &WrappedError{Msg: "handshake failed", Err: err}
	}

	return &deviceSession{transport: transport, session: session, logger: logger}, cleanup, nil
}

// Call sends one request over the encrypted channel and returns the phone's
// result payload.
//
// A JSON-RPC error from the phone is returned as an error rather than an empty
// result, so a caller cannot mistake a refusal for an answer. The phone's code
// travels in the message because the codes are meaningful -- -32036 says this
// platform can never serve the method, which is not something to retry.
func (s *deviceSession) Call(ctx context.Context, method string, params any) ([]byte, error) {
	req := phone.NewRequest(method, params)

	plaintext, err := phone.EncodeRequest(req)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to encode " + method, Err: err}
	}

	ciphertext, err := s.session.Encrypt(plaintext)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to encrypt " + method, Err: err}
	}

	responseCiphertext, err := s.transport.SendAndReceive(ctx, ciphertext)
	if err != nil {
		return nil, &WrappedError{Msg: method + " failed", Err: err}
	}

	responsePlaintext, err := s.session.Decrypt(responseCiphertext)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to decrypt the " + method + " response", Err: err}
	}

	resp, err := phone.DecodeResponse(responsePlaintext)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to decode the " + method + " response", Err: err}
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("%w: %s returned %d: %s",
			ErrSessionRPC, method, resp.Error.Code, resp.Error.Message)
	}

	return resp.Result, nil
}

// defaultSessionTimeout bounds a whole connect-and-call exchange. Attestation
// and enrollment both prompt the user on the phone, so this has to allow for a
// biometric prompt being answered, not just for radio latency.
const defaultSessionTimeout = 120 * time.Second
