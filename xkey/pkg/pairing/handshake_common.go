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

	// Pre-handshake identity exchange for trusted device binding
	if len(cfg.LocalStaticPublicKey) > 0 {
		prologue, err := performIdentityExchange(ctx, cfg, logger)
		if err != nil {
			return err
		}
		if len(prologue) > 0 {
			cfg.Session.SetPrologue(prologue)
			logger.Debug("prologue set from identity exchange", "prologue_len", len(prologue))
		}
	}

	logger.Debug("initializing Noise XX handshake")

	// Initialize handshake state
	if err := cfg.Session.InitHandshake(); err != nil {
		logger.Error("failed to initialize handshake", "error", err)
		return fmt.Errorf("%w: init: %v", ErrNoiseHandshakeFailed, err)
	}

	// Step 1: Generate and send first message (e)
	logger.Debug("generating handshake message 1 (ephemeral key)")
	msg1, complete, err := cfg.Session.HandshakeMessage(nil)
	if err != nil {
		logger.Error("failed to generate message 1", "error", err)
		return fmt.Errorf("%w: write msg1: %v", ErrNoiseHandshakeFailed, err)
	}
	if complete {
		return fmt.Errorf("%w: unexpected completion after msg1", ErrNoiseHandshakeFailed)
	}

	logger.Debug("sending handshake message 1", "size", len(msg1))
	if err := cfg.Transport.Send(ctx, msg1); err != nil {
		logger.Error("failed to send message 1", "error", err)
		return fmt.Errorf("%w: send msg1: %v", ErrNoiseHandshakeFailed, err)
	}

	// Step 2: Receive response (e, ee, s, es)
	logger.Debug("waiting for handshake message 2")
	msg2, err := cfg.Transport.Receive(ctx)
	if err != nil {
		logger.Error("failed to receive message 2", "error", err)
		return fmt.Errorf("%w: recv msg2: %v", ErrNoiseHandshakeFailed, err)
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
		return fmt.Errorf("%w: read msg2: %v", ErrNoiseHandshakeFailed, err)
	}

	// Send message 3 if we have one
	if len(msg3) > 0 {
		logger.Debug("sending handshake message 3", "size", len(msg3))
		if err := cfg.Transport.Send(ctx, msg3); err != nil {
			logger.Error("failed to send message 3", "error", err)
			return fmt.Errorf("%w: send msg3: %v", ErrNoiseHandshakeFailed, err)
		}
	}

	// If handshake isn't complete, wait for final message
	if !complete {
		logger.Debug("waiting for handshake message 4")
		msg4, err := cfg.Transport.Receive(ctx)
		if err != nil {
			logger.Error("failed to receive message 4", "error", err)
			return fmt.Errorf("%w: recv msg4: %v", ErrNoiseHandshakeFailed, err)
		}

		msg4 = stripEnvelopeHeader(msg4, cfg, logger)

		logger.Debug("processing handshake message 4", "size", len(msg4))
		_, complete, err = cfg.Session.HandshakeMessage(msg4)
		if err != nil {
			logger.Error("failed to process message 4", "error", err)
			return fmt.Errorf("%w: read msg4: %v", ErrNoiseHandshakeFailed, err)
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
		return nil, fmt.Errorf("%w: send identity: %v", ErrNoiseHandshakeFailed, err)
	}

	// Receive identity acknowledgment
	ack, err := cfg.Transport.Receive(ctx)
	if err != nil {
		logger.Error("failed to receive identity ack", "error", err)
		return nil, fmt.Errorf("%w: recv identity ack: %v", ErrNoiseHandshakeFailed, err)
	}

	if len(ack) == 0 {
		return nil, fmt.Errorf("%w: empty identity ack", ErrNoiseHandshakeFailed)
	}

	// Parse acknowledgment
	status := ack[0]
	if status == IdentityAckUnknown {
		// New device - use empty prologue
		logger.Info("new device detected, using empty prologue for pairing")
		return nil, nil
	}

	if status != IdentityAckKnown {
		return nil, fmt.Errorf("%w: invalid identity ack status: %d", ErrNoiseHandshakeFailed, status)
	}

	// Known device - extract fingerprint
	if len(ack) != IdentityAckKnownSize {
		return nil, fmt.Errorf("%w: invalid identity ack size: %d", ErrNoiseHandshakeFailed, len(ack))
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
			return nil, fmt.Errorf("%w: device fingerprint mismatch", ErrUntrustedDevice)
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
