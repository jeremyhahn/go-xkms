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
	"errors"
	"fmt"

	flynnNoise "github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// Noise protocol configuration.
const (
	// NoiseProtocolName is the Noise protocol pattern used for phone communication.
	// XX pattern provides mutual authentication with public keys transmitted in handshake.
	NoiseProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

	// NoiseKeySize is the size of Curve25519 keys.
	NoiseKeySize = noiseproto.KeySize

	// NoiseMaxMessageSize is the maximum plaintext message size.
	NoiseMaxMessageSize = noiseproto.MaxMessageSize
)

// NoiseSession manages an encrypted Noise protocol session for phone communication.
// It wraps the shared noiseproto.Session with phone-domain error mapping and the
// backward-compatible RemoteStaticPublicKey accessor.
type NoiseSession struct {
	inner *noiseproto.Session
}

// NoiseSessionConfig configures a Noise session for phone communication.
type NoiseSessionConfig struct {
	// LocalStaticKey is the persistent local static key pair.
	// If nil, a new ephemeral key will be generated.
	LocalStaticKey *flynnNoise.DHKey

	// ExpectedRemoteStatic is the expected remote static public key.
	// If set, the session will verify the remote key matches during handshake.
	ExpectedRemoteStatic []byte

	// IsInitiator indicates whether this side initiates the handshake.
	IsInitiator bool

	// Prologue is optional data that must match on both sides for the
	// handshake to succeed. This provides binding to channel context.
	// Default is empty (no prologue).
	Prologue []byte
}

// NewNoiseSession creates a new Noise session configured for the XX handshake pattern.
func NewNoiseSession(cfg *NoiseSessionConfig) (*NoiseSession, error) {
	session, err := noiseproto.NewSession(&noiseproto.SessionConfig{
		Pattern:        flynnNoise.HandshakeXX,
		LocalStaticKey: cfg.LocalStaticKey,
		PeerStaticKey:  cfg.ExpectedRemoteStatic,
		IsInitiator:    cfg.IsInitiator,
		Prologue:       cfg.Prologue,
	})
	if err != nil {
		return nil, ErrNoiseHandshakeFailed
	}

	return &NoiseSession{inner: session}, nil
}

// LocalStaticPublicKey returns the local static public key.
func (s *NoiseSession) LocalStaticPublicKey() []byte {
	return s.inner.LocalStaticPublicKey()
}

// LocalStaticPrivateKey returns the local static private key.
func (s *NoiseSession) LocalStaticPrivateKey() []byte {
	return s.inner.LocalStaticPrivateKey()
}

// RemoteStaticPublicKey returns the remote static public key after handshake.
func (s *NoiseSession) RemoteStaticPublicKey() []byte {
	return s.inner.PeerStaticPublicKey()
}

// IsHandshakeComplete returns true if the handshake has completed.
func (s *NoiseSession) IsHandshakeComplete() bool {
	return s.inner.IsHandshakeComplete()
}

// SetPrologue updates the prologue for the session.
// Must be called before InitHandshake.
func (s *NoiseSession) SetPrologue(prologue []byte) {
	s.inner.SetPrologue(prologue)
}

// InitHandshake initializes the handshake state.
func (s *NoiseSession) InitHandshake() error {
	if err := s.inner.InitHandshake(); err != nil {
		return ErrNoiseHandshakeFailed
	}
	return nil
}

// HandshakeMessage processes a handshake message.
// For initiator: call with nil to get first message, then with responses.
// For responder: call with received messages.
// Returns the outgoing message (may be empty) and whether handshake is complete.
func (s *NoiseSession) HandshakeMessage(incoming []byte) ([]byte, bool, error) {
	outgoing, complete, err := s.inner.HandshakeMessage(incoming)
	if err != nil {
		return nil, false, mapNoiseError(err)
	}
	return outgoing, complete, nil
}

// Encrypt encrypts a plaintext message.
func (s *NoiseSession) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := s.inner.Encrypt(plaintext)
	if err != nil {
		return nil, mapNoiseError(err)
	}
	return ciphertext, nil
}

// Decrypt decrypts a ciphertext message.
func (s *NoiseSession) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.inner.Decrypt(ciphertext)
	if err != nil {
		return nil, mapNoiseError(err)
	}
	return plaintext, nil
}

// GenerateStaticKey generates a new Curve25519 static key pair.
func GenerateStaticKey() (*flynnNoise.DHKey, error) {
	return noiseproto.GenerateStaticKey()
}

// LoadStaticKey creates a DHKey from raw private key bytes.
func LoadStaticKey(privateKey []byte) (*flynnNoise.DHKey, error) {
	key, err := noiseproto.LoadStaticKey(privateKey)
	if err != nil {
		return nil, ErrInvalidNoiseMessage
	}
	return key, nil
}

// EncodeStaticKey encodes a static key to hex string for storage.
func EncodeStaticKey(key *flynnNoise.DHKey) string {
	return noiseproto.EncodeStaticKey(key)
}

// DecodeStaticKey decodes a hex-encoded static key.
func DecodeStaticKey(encoded string) (*flynnNoise.DHKey, error) {
	key, err := noiseproto.DecodeStaticKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNoiseMessage, err)
	}
	return key, nil
}

// noiseErrorMap translates shared noise package errors to phone-domain errors.
var noiseErrorMap = map[error]error{
	noiseproto.ErrHandshakeFailed:   ErrNoiseHandshakeFailed,
	noiseproto.ErrStaticKeyMismatch: ErrStaticKeyMismatch,
	noiseproto.ErrEncryptionFailed:  ErrEncryptionFailed,
	noiseproto.ErrDecryptionFailed:  ErrDecryptionFailed,
	noiseproto.ErrInvalidMessage:    ErrInvalidNoiseMessage,
	noiseproto.ErrInvalidKeySize:    ErrInvalidNoiseMessage,
	noiseproto.ErrSessionNotReady:   ErrNoiseHandshakeFailed,
}

// mapNoiseError translates a shared noise package error to the corresponding
// phone-domain error. It checks both direct equality and wrapped errors.
func mapNoiseError(err error) error {
	for noiseErr, phoneErr := range noiseErrorMap {
		if errors.Is(err, noiseErr) {
			return phoneErr
		}
	}
	return ErrNoiseHandshakeFailed
}
