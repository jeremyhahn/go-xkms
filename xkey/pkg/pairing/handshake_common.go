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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// HandshakeEnvelope defines message envelope constants for Android compatibility.
// Android may wrap Noise handshake messages in an envelope with a header.
const (
	// EnvelopeHeaderSize is the size of the optional message envelope header.
	// Set to 0 to disable envelope handling (raw Noise messages).
	// Android app may add a 12-byte header to handshake messages.
	EnvelopeHeaderSize = 0

	// Expected Noise XX message sizes (with empty payload encryption per spec).
	// Per Noise protocol, even empty payloads are encrypted with a 16-byte AEAD tag.
	NoiseXXMsg1Size = 32 // Initiator's ephemeral public key (no encryption yet)
	NoiseXXMsg2Size = 96 // e (32) + encrypted s (48) + encrypted empty payload (16)
	NoiseXXMsg3Size = 64 // encrypted s (48) + encrypted empty payload (16)
	NoiseTagSize    = 16 // ChaCha20-Poly1305 AEAD tag

	// Pre-handshake identity exchange constants
	IdentityMsgVersion   = 0x01
	IdentityMsgSize      = 33 // 1-byte version + 32-byte public key
	IdentityAckKnown     = 0x01
	IdentityAckUnknown   = 0x00
	IdentityAckKnownSize = 33 // 1-byte status + 32-byte fingerprint
)

// HandshakeConfig configures the Noise handshake process.
type HandshakeConfig struct {
	// Transport is the transport for sending/receiving messages.
	Transport Transport

	// Session is the Noise session to perform handshake on.
	Session *NoiseSession

	// Logger for debug output.
	Logger *slog.Logger

	// StripEnvelopeHeader enables stripping of envelope headers from received messages.
	// Enable this if the Android app adds headers to Noise messages.
	StripEnvelopeHeader bool

	// EnvelopeHeaderSize is the size of the envelope header to strip (if enabled).
	// Default is 12 bytes (Android compatibility).
	EnvelopeHeaderSize int

	// LocalStaticPublicKey is the initiator's static public key for identity exchange.
	// If set, a pre-handshake identity exchange is performed to enable prologue binding.
	LocalStaticPublicKey []byte

	// ExpectedDeviceFingerprint is the expected Android device's attestation fingerprint.
	// If set, the prologue will be computed from public key + fingerprint.
	// If the received fingerprint doesn't match, the handshake will fail.
	ExpectedDeviceFingerprint []byte
}

// PerformHandshake executes the Noise XX handshake as the initiator.
// This is the canonical implementation - use this instead of duplicating handshake code.
//
// If LocalStaticPublicKey is set, a pre-handshake identity exchange is performed:
// 1. Go sends its public key to Android
// 2. Android looks up the device and returns its attestation fingerprint
// 3. Both sides compute prologue from public key + fingerprint
// 4. Noise handshake proceeds with prologue binding
func PerformHandshake(ctx context.Context, cfg *HandshakeConfig) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	logger := cfg.Logger.With("component", "noise_handshake")

	if cfg.EnvelopeHeaderSize == 0 {
		cfg.EnvelopeHeaderSize = 12 // Default Android header size
	}

	// Pre-handshake identity exchange for trusted device binding.
	//
	// EVERY fingerprint check lives inside performIdentityExchange, and this
	// used to run it only when a local public key happened to be set. So
	// whether a configured ExpectedDeviceFingerprint was enforced depended on
	// an unrelated field being populated by the caller, not on whether a
	// fingerprint was configured -- and an empty LocalStaticPublicKey skipped
	// the binding in silence. Both current callers do set it, so this was not
	// reachable through them, but a security control that fails OPEN on a
	// caller's omission is one omission away from being absent.
	//
	// The condition is now the fingerprint itself: if one is configured, the
	// exchange must run, and if it cannot, the handshake is refused.
	switch {
	case len(cfg.LocalStaticPublicKey) > 0:
		prologue, err := performIdentityExchange(ctx, cfg, logger)
		if err != nil {
			return err
		}
		if len(prologue) > 0 {
			cfg.Session.SetPrologue(prologue)
			logger.Debug("prologue set from identity exchange", "prologue_len", len(prologue))
		}
	case len(cfg.ExpectedDeviceFingerprint) > 0:
		logger.Error("a device fingerprint is configured but no local static public key was supplied, " +
			"so the identity exchange that enforces it cannot run")
		return &DetailError{
			Err:    ErrUntrustedDevice,
			Detail: ": a device fingerprint is configured but the identity exchange cannot run without a local static public key; refusing rather than connecting with that check silently skipped",
		}
	}

	logger.Debug("initializing Noise XX handshake")

	// Initialize handshake state
	if err := cfg.Session.InitHandshake(); err != nil {
		logger.Error("failed to initialize handshake", "error", err)
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": init: %v", err)}
	}

	// Step 1: Generate and send first message (e)
	logger.Debug("generating handshake message 1 (ephemeral key)")
	msg1, complete, err := cfg.Session.HandshakeMessage(nil)
	if err != nil {
		logger.Error("failed to generate message 1", "error", err)
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": write msg1: %v", err)}
	}
	if complete {
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: ": unexpected completion after msg1"}
	}

	logger.Debug("sending handshake message 1", "size", len(msg1))
	if err := cfg.Transport.Send(ctx, msg1); err != nil {
		logger.Error("failed to send message 1", "error", err)
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": send msg1: %v", err)}
	}

	// Step 2: Receive response (e, ee, s, es)
	logger.Debug("waiting for handshake message 2")
	msg2, err := cfg.Transport.Receive(ctx)
	if err != nil {
		logger.Error("failed to receive message 2", "error", err)
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": recv msg2: %v", err)}
	}

	logger.Debug("received handshake message 2",
		"size", len(msg2),
		"expected", NoiseXXMsg2Size,
		"hex_prefix", hex.EncodeToString(safeSlice(msg2, 0, 16)),
	)

	// Handle envelope header stripping if enabled
	msg2 = stripEnvelopeHeader(msg2, cfg, logger)

	// Debug: print Go's sent ephemeral key for comparison with Android's received key
	logger.Debug("Go sent ephemeral key (msg1)",
		"local_e_pub", hex.EncodeToString(msg1),
	)

	// Debug: print received msg2 structure
	if len(msg2) >= 32 {
		remoteE := msg2[:32]
		encryptedS := msg2[32:]
		logger.Debug("msg2 structure",
			"remote_e", hex.EncodeToString(remoteE),
			"encrypted_s", hex.EncodeToString(encryptedS),
			"encrypted_s_len", len(encryptedS),
		)
	}

	// Step 3: Process response and generate final message (s, se)
	logger.Debug("processing message 2, generating message 3")
	msg3, complete, err := cfg.Session.HandshakeMessage(msg2)
	if err != nil {
		logger.Error("failed to process message 2",
			"error", err,
			"msg2_size", len(msg2),
			"msg2_hex", hex.EncodeToString(msg2),
		)
		return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": read msg2: %v", err)}
	}

	// Send message 3 if we have one
	if len(msg3) > 0 {
		logger.Debug("sending handshake message 3", "size", len(msg3))
		if err := cfg.Transport.Send(ctx, msg3); err != nil {
			logger.Error("failed to send message 3", "error", err)
			return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": send msg3: %v", err)}
		}
	}

	// If handshake isn't complete, wait for final message
	if !complete {
		logger.Debug("waiting for handshake message 4")
		msg4, err := cfg.Transport.Receive(ctx)
		if err != nil {
			logger.Error("failed to receive message 4", "error", err)
			return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": recv msg4: %v", err)}
		}

		msg4 = stripEnvelopeHeader(msg4, cfg, logger)

		logger.Debug("processing handshake message 4", "size", len(msg4))
		_, complete, err = cfg.Session.HandshakeMessage(msg4)
		if err != nil {
			logger.Error("failed to process message 4", "error", err)
			return &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": read msg4: %v", err)}
		}
		if !complete {
			return ErrNoiseHandshakeFailed
		}
	}

	logger.Info("Noise handshake completed successfully")

	// Brief stabilization delay to allow the BLE stack on both sides to
	// fully transition from handshake to application mode. This prevents
	// a race where the first application message arrives before the phone's
	// GATT server has finished processing the handshake completion.
	time.Sleep(100 * time.Millisecond)

	return nil
}

// stripEnvelopeHeader removes any envelope header from a received message.
// This handles Android compatibility where messages may be wrapped.
func stripEnvelopeHeader(msg []byte, cfg *HandshakeConfig, logger *slog.Logger) []byte {
	if !cfg.StripEnvelopeHeader {
		return msg
	}

	headerSize := cfg.EnvelopeHeaderSize

	// Check if message has extra bytes that could be an envelope header
	expectedSizes := []int{NoiseXXMsg1Size, NoiseXXMsg2Size, NoiseXXMsg3Size}
	for _, expected := range expectedSizes {
		if len(msg) == expected+headerSize {
			logger.Debug("stripping envelope header",
				"original_size", len(msg),
				"header_size", headerSize,
				"header_hex", hex.EncodeToString(msg[:headerSize]),
			)
			return msg[headerSize:]
		}
		// Also check with empty payload tag (80 or 96 bytes for msg2)
		if len(msg) == expected+NoiseTagSize+headerSize {
			logger.Debug("stripping envelope header (with payload tag)",
				"original_size", len(msg),
				"header_size", headerSize,
				"header_hex", hex.EncodeToString(msg[:headerSize]),
			)
			return msg[headerSize:]
		}
	}

	// If message size doesn't match expected patterns, try stripping anyway
	if len(msg) > headerSize {
		extraBytes := len(msg) - NoiseXXMsg2Size
		if extraBytes > 0 && extraBytes <= headerSize*2 {
			logger.Warn("message size doesn't match expected, attempting header strip",
				"size", len(msg),
				"extra_bytes", extraBytes,
				"stripping", headerSize,
			)
			return msg[headerSize:]
		}
	}

	return msg
}

// safeSlice returns a slice of data up to maxLen, or the full slice if shorter.
func safeSlice(data []byte, start, maxLen int) []byte {
	if start >= len(data) {
		return nil
	}
	end := start + maxLen
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}

// performIdentityExchange sends the initiator's public key and receives the
// responder's device fingerprint. This enables prologue binding for trusted
// device verification.
//
// Protocol:
// 1. Initiator sends: [0x01, public_key_32_bytes]
// 2. Responder replies: [0x01, fingerprint_32_bytes] (known) or [0x00] (new)
// 3. Both compute: SHA256(public_key || fingerprint || "xkey-v1")
func performIdentityExchange(ctx context.Context, cfg *HandshakeConfig, logger *slog.Logger) ([]byte, error) {
	logger.Debug("starting identity exchange")

	// Send identity message: version + public key
	identityMsg := make([]byte, IdentityMsgSize)
	identityMsg[0] = IdentityMsgVersion
	copy(identityMsg[1:], cfg.LocalStaticPublicKey)

	logger.Debug("sending identity message",
		"public_key", hex.EncodeToString(cfg.LocalStaticPublicKey),
	)

	if err := cfg.Transport.Send(ctx, identityMsg); err != nil {
		logger.Error("failed to send identity message", "error", err)
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": send identity: %v", err)}
	}

	// Receive identity acknowledgment
	ack, err := cfg.Transport.Receive(ctx)
	if err != nil {
		logger.Error("failed to receive identity ack", "error", err)
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": recv identity ack: %v", err)}
	}

	if len(ack) == 0 {
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: ": empty identity ack"}
	}

	// Parse acknowledgment
	status := ack[0]
	if status == IdentityAckUnknown {
		// A device we have a fingerprint for CANNOT legitimately be unknown.
		//
		// This path returns success with an empty prologue, and it used to do
		// so before the ExpectedDeviceFingerprint comparison further down --
		// which made the whole fingerprint binding optional AT THE PEER'S
		// CHOICE. Anyone able to complete the Noise handshake with the
		// configured remote static key could send this one status byte and
		// skip the attestation-root check the pairing record carries.
		//
		// Letting a peer select which checks apply to it defeats the control
		// whatever the control proves, so this refuses regardless. Once a
		// record carries a fingerprint, "unknown" is not a state the device
		// can return to: it was paired.
		//
		// WHAT the fingerprint proves, and where the real proof now lives.
		//
		// For pairings established after #93 the value is the SHA-256 of the
		// phone's per-device ATTESTED KEY -- the leaf's SubjectPublicKeyInfo,
		// derived from a chain this repository VERIFIED at pairing time
		// (chain-to-anchor, security level, boot state; #95). It is
		// device-unique: the key is generated inside that handset's
		// TEE/StrongBox, unlike the older SHA-256-of-the-anchor value, which
		// was a vendor root shared by every handset under it. Records from
		// before #93 still carry the older value until the device is
		// re-paired; the comparison here is byte-for-byte either way.
		//
		// The comparison itself is still against bytes THE PEER SENDS, and no
		// chain is presented or verified at this point in the connection --
		// there cannot be, the encrypted channel does not exist yet. So this
		// remains a CONTINUITY check: it notices a peer that changed its
		// answer, and it supplies the prologue that binds the identity into
		// the handshake.
		//
		// What it is no longer is the strongest thing the connection
		// establishes. Two checks stand behind it:
		//
		//   - ExpectedRemoteStatic, enforced by the handshake below, proves
		//     the peer holds the Noise private key paired earlier. Nothing
		//     here establishes that key is hardware-bound, so on its own it is
		//     key possession, not handset identity.
		//   - The #129 challenge-response re-attestation, which runs on the
		//     ESTABLISHED session once this handshake completes: the device
		//     presents its attestation chain and signs a fresh nonce with the
		//     attested key that chain certifies. That is the live, hardware-
		//     bound proof, and it is what a peer echoing a captured
		//     fingerprint cannot produce.
		//
		// A legitimate attested-key rotation is handled by re-pairing.
		//
		// An empty ExpectedDeviceFingerprint is the legitimate first-pairing
		// case and still proceeds -- refusing it would make pairing
		// impossible.
		if len(cfg.ExpectedDeviceFingerprint) > 0 {
			logger.Error("device reported itself unknown while a device fingerprint is configured",
				"expected", hex.EncodeToString(cfg.ExpectedDeviceFingerprint),
			)
			return nil, &DetailError{
				Err:    ErrUntrustedDevice,
				Detail: ": device reported itself unknown, but this pairing is bound to a device fingerprint; re-pair the device if its identity legitimately changed",
			}
		}

		// New device - use empty prologue
		logger.Info("new device detected, using empty prologue for pairing")
		return nil, nil
	}

	if status != IdentityAckKnown {
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": invalid identity ack status: %d", status)}
	}

	// Known device - extract fingerprint
	if len(ack) != IdentityAckKnownSize {
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: fmt.Sprintf(": invalid identity ack size: %d", len(ack))}
	}

	receivedFingerprint := ack[1:]
	logger.Debug("received device fingerprint",
		"fingerprint", hex.EncodeToString(receivedFingerprint),
	)

	// Verify fingerprint matches expected if we have one
	if len(cfg.ExpectedDeviceFingerprint) > 0 {
		if !bytes.Equal(receivedFingerprint, cfg.ExpectedDeviceFingerprint) {
			logger.Error("device fingerprint mismatch",
				"expected", hex.EncodeToString(cfg.ExpectedDeviceFingerprint),
				"received", hex.EncodeToString(receivedFingerprint),
			)
			return nil, &DetailError{Err: ErrUntrustedDevice, Detail: ": device fingerprint mismatch"}
		}
		logger.Debug("device fingerprint verified")
	}

	// Compute prologue: SHA256(public_key || fingerprint || "xkey-v1")
	prologue := computePrologueFromIdentity(cfg.LocalStaticPublicKey, receivedFingerprint)
	logger.Debug("computed prologue",
		"prologue", hex.EncodeToString(prologue),
	)

	return prologue, nil
}

// computePrologueFromIdentity computes the Noise prologue from identity exchange data.
// Prologue = SHA256(initiator_public_key || responder_fingerprint || "xkey-v1")
func computePrologueFromIdentity(publicKey, fingerprint []byte) []byte {
	h := sha256.New()
	h.Write(publicKey)
	h.Write(fingerprint)
	h.Write([]byte(prologueVersion))
	return h.Sum(nil)
}
