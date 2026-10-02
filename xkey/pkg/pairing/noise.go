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

	flynnNoise "github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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

	// NoiseHexKeySize is the length in bytes of a hex-encoded static private
	// key. It is the minimum size of the destination buffer EncodeStaticKey
	// writes into.
	NoiseHexKeySize = noiseproto.HexKeySize
)

// StaticKey is a Curve25519 static identity key pair whose private scalar is
// held in protected memory outside the Go heap. Callers own the key and must
// Destroy it once every session built from it has finished; Destroy frees the
// pages the session's key pair aliases.
type StaticKey = noiseproto.StaticKey

// NoiseSession manages an encrypted Noise protocol session for phone communication.
// It wraps the shared noiseproto.Session with phone-domain error mapping and the
// backward-compatible RemoteStaticPublicKey accessor.
type NoiseSession struct {
	inner *noiseproto.Session

	// prologue mirrors what SetPrologue handed the inner session, which keeps
	// it unexported and offers no accessor. The attestation channel binding
	// (#129) needs it, and it is not a secret: both peers derive it from the
	// identity exchange, which runs in the clear before the handshake.
	prologue []byte

	// isInitiator records the handshake role. The channel binding hashes the
	// two static keys in initiator-then-responder order, which is the only
	// ordering both peers can agree on without exchanging anything further —
	// "mine then theirs" would give the two ends different values. This
	// package builds sessions in both roles (ble_peripheral.go and
	// tcp_server.go are responders), so the role has to be remembered rather
	// than assumed.
	isInitiator bool
}

// NoiseSessionConfig configures a Noise session for phone communication.
type NoiseSessionConfig struct {
	// LocalStaticKey is the persistent local static key pair, held in
	// protected memory. If nil, a new ephemeral key will be generated.
	// The key must outlive the session: destroying it frees the pages the
	// session's handshake state reads from.
	LocalStaticKey *StaticKey

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
	// The embedded DHKey aliases the protected private scalar, so the session
	// reads the key in place rather than copying it onto the Go heap.
	var localStatic *flynnNoise.DHKey
	if cfg.LocalStaticKey != nil {
		localStatic = &cfg.LocalStaticKey.DHKey
	}

	session, err := noiseproto.NewSession(&noiseproto.SessionConfig{
		Pattern:        flynnNoise.HandshakeXX,
		LocalStaticKey: localStatic,
		PeerStaticKey:  cfg.ExpectedRemoteStatic,
		IsInitiator:    cfg.IsInitiator,
		Prologue:       cfg.Prologue,
	})
	if err != nil {
		return nil, ErrNoiseHandshakeFailed
	}

	return &NoiseSession{
		inner:       session,
		prologue:    append([]byte(nil), cfg.Prologue...),
		isInitiator: cfg.IsInitiator,
	}, nil
}

// LocalStaticPublicKey returns the local static public key.
func (s *NoiseSession) LocalStaticPublicKey() []byte {
	return s.inner.LocalStaticPublicKey()
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
	s.prologue = append([]byte(nil), prologue...)
	s.inner.SetPrologue(prologue)
}

// Prologue returns the prologue bound into this session's handshake, or nil
// when none was set. The copy is defensive: a caller that mutated the returned
// slice would silently desynchronize the attestation channel binding from the
// value the handshake actually ran under.
func (s *NoiseSession) Prologue() []byte {
	return append([]byte(nil), s.prologue...)
}

// AttestChannelBinding returns the value an attestation transcript on this
// session must commit to (#129).
//
// It is available only after the handshake, for the reason the binding exists:
// before the handshake completes there is no authenticated peer static key to
// bind to, so a value computed early would bind to a key nobody has proved
// they hold.
func (s *NoiseSession) AttestChannelBinding() ([]byte, error) {
	if !s.IsHandshakeComplete() {
		return nil, &DetailError{Err: ErrNoiseHandshakeFailed, Detail: ": channel binding requested before the handshake completed"}
	}

	initiator, responder := s.LocalStaticPublicKey(), s.RemoteStaticPublicKey()
	if !s.isInitiator {
		initiator, responder = responder, initiator
	}
	return ComputeAttestChannelBinding(initiator, responder, s.prologue)
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

// GenerateStaticKey generates a new Curve25519 static key pair. The private
// scalar is drawn straight into protected memory and never reaches the Go
// heap. The caller owns the key and must Destroy it.
func GenerateStaticKey() (*StaticKey, error) {
	return noiseproto.GenerateStaticKey()
}

// LoadStaticKey creates a static key pair from raw private key bytes by
// copying them into protected memory. The caller's slice is left untouched
// and remains the caller's to wipe.
func LoadStaticKey(privateKey []byte) (*StaticKey, error) {
	key, err := noiseproto.LoadStaticKey(privateKey)
	if err != nil {
		return nil, ErrInvalidNoiseMessage
	}
	return key, nil
}

// LoadStaticKeyFromBuffer creates a static key pair from a private scalar
// held in protected memory. The scalar is read inside the source buffer's
// borrow and copied straight into the key's own protected pages, so it never
// reaches the Go heap. The source stays the caller's to destroy.
//
// Returns ErrInvalidNoiseMessage when the scalar is not a valid key, and the
// secure package's error when src is nil or already destroyed.
func LoadStaticKeyFromBuffer(src *secure.Buffer) (*StaticKey, error) {
	var key *StaticKey
	if err := src.WithBytes(func(privateKey []byte) error {
		var loadErr error
		key, loadErr = LoadStaticKey(privateKey)
		return loadErr
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// EncodeStaticKey hex-encodes the private component of key into dst for
// persistent storage. dst must be at least NoiseHexKeySize bytes long and
// should itself be protected memory: the encoded form is as sensitive as the
// key, and a Go string could not be wiped after use.
func EncodeStaticKey(dst []byte, key *StaticKey) error {
	if err := noiseproto.EncodeStaticKey(dst, key); err != nil {
		return &SentinelCauseError{Sentinel: ErrInvalidNoiseMessage, Cause: err}
	}
	return nil
}

// WipeBytes zeroes a buffer that held key material. Decoding a stored key
// leaves the raw scalar on the Go heap; LoadStaticKey copies it into protected
// memory but cannot wipe the caller's slice, so the caller must.
func WipeBytes(b []byte) {
	noiseproto.WipeBytes(b)
}

// DecodeStaticKey decodes a hex-encoded static private key into protected
// memory and derives the public component. encoded stays the caller's to wipe.
func DecodeStaticKey(encoded []byte) (*StaticKey, error) {
	key, err := noiseproto.DecodeStaticKey(encoded)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidNoiseMessage, Cause: err}
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
