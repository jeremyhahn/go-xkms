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

package nativemsg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	// MaxMessageSize is the maximum message size (1 MB) as per Chrome's limit.
	MaxMessageSize = 1024 * 1024

	// NativeHostName is the name used in browser manifests.
	NativeHostName = "com.automatethethings.xkey"

	// headerSize is the number of bytes in the length prefix.
	headerSize = 4
)

// NativeMessage represents a message in the native messaging protocol.
// Before handshake: {type: "handshake", pubkey: "base64..."}
// After handshake: {type: "encrypted", nonce: uint64, ciphertext: "base64..."}
type NativeMessage struct {
	Type            string `json:"type"`                       // "handshake", "handshake_ok", "encrypted", "error", "pairing_confirm", etc.
	PubKey          string `json:"pubkey,omitempty"`           // base64 X25519 public key (handshake)
	Nonce           uint64 `json:"nonce,omitempty"`            // nonce counter (encrypted)
	Ciphertext      string `json:"ciphertext,omitempty"`       // base64 ciphertext (encrypted)
	Error           string `json:"error,omitempty"`            // error message
	IdentityKey     string `json:"identity_key,omitempty"`     // Ed25519 public key (base64)
	IdentitySig     string `json:"identity_sig,omitempty"`     // Ed25519 signature (base64)
	Origin          string `json:"origin,omitempty"`           // chrome-extension://ID/
	PairingRequired bool   `json:"pairing_required,omitempty"` // host -> extension: need pairing
	Code            string `json:"code,omitempty"`             // pairing code (pairing_confirm)
}

// Native message types.
const (
	MsgTypeHandshake         = "handshake"
	MsgTypeHandshakeOK       = "handshake_ok"
	MsgTypeHandshakePair     = "handshake_pair"     // host -> ext: pairing required
	MsgTypeHandshakeRejected = "handshake_rejected" // host -> ext: identity rejected
	MsgTypePairingConfirm    = "pairing_confirm"    // ext -> host: submit pairing code
	MsgTypePairingOK         = "pairing_ok"         // host -> ext: pairing succeeded
	MsgTypePairingFailed     = "pairing_failed"     // host -> ext: pairing failed
	MsgTypeEncrypted         = "encrypted"
	MsgTypeError             = "error"
)

// ReadMessage reads a length-prefixed JSON message from a reader.
// Format: [4-byte little-endian uint32 length][JSON payload]
// Chrome uses native byte order which is little-endian on x86/x64/arm64.
func ReadMessage(r io.Reader) (*NativeMessage, error) {
	var lengthBuf [headerSize]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	length := binary.LittleEndian.Uint32(lengthBuf[:])
	if length == 0 {
		return nil, fmt.Errorf("%w: zero-length message", ErrReadFailed)
	}
	if length > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d byte limit",
			ErrMessageTooLarge, length, MaxMessageSize)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	var msg NativeMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	return &msg, nil
}

// WriteMessage writes a length-prefixed JSON message to a writer.
func WriteMessage(w io.Writer, msg *NativeMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	if len(payload) > MaxMessageSize {
		return fmt.Errorf("%w: %d bytes exceeds %d byte limit",
			ErrMessageTooLarge, len(payload), MaxMessageSize)
	}

	var lengthBuf [headerSize]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], uint32(len(payload)))

	if _, err := w.Write(lengthBuf[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}

	return nil
}

// WriteError writes an error message to the writer using the native messaging
// protocol format.
func WriteError(w io.Writer, errMsg string) error {
	return WriteMessage(w, &NativeMessage{
		Type:  MsgTypeError,
		Error: errMsg,
	})
}
