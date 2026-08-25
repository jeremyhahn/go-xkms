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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
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
		_ = transport.Disconnect()
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

	// The stored identity, decoded fail-closed: a corrupt record yields an
	// error and no bytes, never the "no fingerprint configured" signal that
	// would silently drop the comparison.
	expectedFingerprint, err := phone.DecodeDeviceFingerprint(device.DeviceFingerprint)
	if err != nil {
		cleanup()
		return nil, nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}

	// LocalStaticPublicKey and ExpectedDeviceFingerprint are what make the
	// pre-handshake identity exchange run. Without them PerformHandshake
	// matches neither case in its switch and skips the exchange entirely, so
	// this opener connected with an empty prologue and no fingerprint
	// comparison — while the code it replaced, and the backend path, bound
	// both.
	if err := phone.PerformHandshake(ctx, &phone.HandshakeConfig{
		Transport:                 transport,
		Session:                   session,
		Logger:                    logger,
		StripEnvelopeHeader:       false,
		EnvelopeHeaderSize:        0,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expectedFingerprint,
	}); err != nil {
		cleanup()
		return nil, nil, &WrappedError{Msg: "handshake failed", Err: err}
	}

	// The #129 liveness proof, before the session is usable for anything.
	//
	// Recording AttestationProtocolVersion without enforcing it here would
	// make the field a claim the code does not keep: possession of a COPIED
	// paired Noise key would still be sufficient to reconnect and drive every
	// device operation, which is the exact gap the persistent attested key
	// exists to close. The handshake proves key possession; only this proves
	// the key is in the hardware that was attested, and that its holder is on
	// this connection now.
	//
	// It is enforced HERE, in the one opener every CLI device command goes
	// through, rather than at each call site — a check per call site is a
	// check one missed call site can be absent from. (Codex, #124.)
	if err := enforceReattestation(ctx, transport, session, device, logger); err != nil {
		cleanup()
		return nil, nil, err
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

// enforceReattestation runs the challenge-response liveness proof on a freshly
// handshaken session, for devices whose record says they were bound under it.
//
// The decision is attestation.VerifyReattestation — the same one the backend
// path, `device attest-device` and the GUI use. What stays here is opening
// THIS machine's trust store, and only for a record that actually requires the
// proof: a legacy pairing on a machine with no Android roots installed must
// still connect.
func enforceReattestation(
	ctx context.Context,
	transport phone.Transport,
	session *phone.NoiseSession,
	device *PairedDevice,
	logger *slog.Logger,
) error {
	binding := device.attestationBinding()
	if !binding.RequiresLiveAttestation() {
		return nil
	}

	trust, err := loadPairingAttestationTrust()
	if err != nil {
		return err
	}

	return attestation.VerifyReattestation(ctx, transport, session, binding, trust, logger)
}

// newLiveAttestor builds the verifier the phone backend calls after its
// handshake, for surfaces that connect through PhoneKeyBackend rather than
// openDeviceSession (#129).
//
// The trust loader is passed rather than a pool: attestation.NewLiveAttestor
// calls it per connection, so a root installed with `xkey trust` between
// connections takes effect instead of a stale pool refusing a device the
// machine now trusts.
func newLiveAttestor(device *PairedDevice, logger *slog.Logger) phone.LiveAttestFunc {
	return attestation.NewLiveAttestor(
		device.attestationBinding(), loadPairingAttestationTrust, logger)
}

// newPairedDeviceBackendConfig builds the phone-backend configuration for a
// paired device, with every identity check the record supports, in one place.
//
// It exists because five commands built this configuration independently —
// OATH sync, backup, sharing, attest, FIDO2 — and every one of them was a
// place a check could be, and was, left out. None set
// ExpectedDeviceFingerprint, so none bound the prologue; none required the
// #129 liveness proof once it existed, so a protocol-v2 device could be driven
// through any of them by a peer holding only a COPIED paired Noise key
// (Codex, #124). Wiring the flag into one of the five and calling it done is
// how the gap survived a round of review.
//
// The obligation this leaves the caller is the one it already had: the
// returned config owns a loaded static key (OwnsStaticKey), so the caller must
// hand it to phone.NewPhoneKeyBackend — which takes over releasing it — rather
// than returning early with it.
func newPairedDeviceBackendConfig(
	device *PairedDevice,
	timeout time.Duration,
	logger *slog.Logger,
) (*phone.PhoneKeyBackendConfig, error) {
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return nil, &WrappedError{Msg: "invalid local noise key", Err: err}
	}
	// Wiped at the decode, not at the LoadStaticKey below: a decode failure on
	// any other field returns in between, and the raw scalar would be left
	// sitting in garbage-collected memory.
	defer phone.WipeBytes(localPrivateKey)

	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return nil, &WrappedError{Msg: "invalid phone noise key", Err: err}
	}

	// Validated BEFORE the key is loaded: this is pure config validation with
	// nothing to release, whereas every return after LoadStaticKey abandons
	// protected pages that only the backend's ownership transfer frees.
	expectedFingerprint, err := phone.DecodeDeviceFingerprint(device.DeviceFingerprint)
	if err != nil {
		logger.Error("stored device fingerprint is invalid; refusing to build a backend without identity binding",
			"device", device.Name, "error", err)
		return nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return nil, &WrappedError{Msg: "invalid local noise key", Err: err}
	}

	return &phone.PhoneKeyBackendConfig{
		DeviceAddress: device.Address,
		// These helpers hand the backend to their caller and keep nothing, so
		// the backend has to own the key or it would never be released.
		LocalStaticKey:            localKey,
		OwnsStaticKey:             true,
		ExpectedRemoteStatic:      remotePublicKey,
		ExpectedDeviceFingerprint: expectedFingerprint,

		// Set together: RequireLiveAttestation without LiveAttest is a
		// refusal, so an edit that drops the verifier fails closed rather than
		// silently skipping the proof.
		RequireLiveAttestation: device.attestationBinding().RequiresLiveAttestation(),
		LiveAttest:             newLiveAttestor(device, logger),

		ScanTimeout:      30 * time.Second,
		ConnectTimeout:   30 * time.Second,
		OperationTimeout: timeout,
		Logger:           logger,
	}, nil
}
