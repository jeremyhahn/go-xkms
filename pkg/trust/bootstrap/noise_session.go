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

package bootstrap

import (
	"errors"

	flynnNoise "github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// NoiseXXProtocolName is the Noise protocol of an interactive NoiseSession.
// The XX pattern authenticates both peers, each transmitting its static
// public key inside the handshake.
const NoiseXXProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

// NoiseKeySize is the size of a Curve25519 key.
const NoiseKeySize = noiseproto.KeySize

// NoiseMaxMessageSize is the largest plaintext a NoiseSession encrypts.
const NoiseMaxMessageSize = noiseproto.MaxMessageSize

// Noise session errors. A NoiseSession returns exactly one of these, so a
// caller can match the failure without depending on go-truststrap.
var (
	ErrNoiseHandshakeFailed   = noiseproto.ErrHandshakeFailed
	ErrNoiseStaticKeyMismatch = noiseproto.ErrStaticKeyMismatch
	ErrNoiseEncryptionFailed  = noiseproto.ErrEncryptionFailed
	ErrNoiseDecryptionFailed  = noiseproto.ErrDecryptionFailed
	ErrNoiseInvalidMessage    = noiseproto.ErrInvalidMessage

	// ErrNoiseFIPSUnsupported reports that the Noise suite was refused
	// because FIPS is enforced: X25519 (SP 800-56A Rev. 3) and
	// ChaCha20-Poly1305 are not approved, so a `fips` build compiles them
	// out and GODEBUG=fips140=only makes the Go Cryptographic Module refuse
	// them at run time. The approved suite is SuiteP256AESGCM.
	ErrNoiseFIPSUnsupported = noiseproto.ErrFIPSUnsupported
)

// NoiseSession is an interactive Noise_XX session between two peers that
// each hold a static key, such as a host and the phone it is paired with. It
// wraps the shared noiseproto.Session, records the prologue and handshake
// role a channel binding needs, and reports failures as this package's
// ErrNoise* sentinels.
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
	// "mine then theirs" would give the two ends different values. Sessions
	// are built in both roles (a phone transport's peripheral and server
	// sides are responders), so the role has to be remembered rather than
	// assumed.
	isInitiator bool
}

// NoiseSessionConfig configures a NoiseSession.
type NoiseSessionConfig struct {
	// LocalStaticKey is the persistent local static key pair, held in
	// protected memory. If nil, a new ephemeral key will be generated.
	// The key must outlive the session: destroying it frees the pages the
	// session's handshake state reads from.
	LocalStaticKey *NoiseStaticKey

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
	// The session borrows the protected private scalar in place rather than
	// copying it onto the Go heap.
	session, err := noiseproto.NewSession(&noiseproto.SessionConfig{
		Pattern:        flynnNoise.HandshakeXX,
		LocalStaticKey: cfg.LocalStaticKey,
		PeerStaticKey:  cfg.ExpectedRemoteStatic,
		IsInitiator:    cfg.IsInitiator,
		Prologue:       cfg.Prologue,
	})
	if err != nil {
		// A FIPS refusal keeps go-truststrap's error, which wraps
		// ErrNoiseFIPSUnsupported and the module's own reason, so the
		// caller learns the suite is unavailable rather than broken.
		if errors.Is(err, ErrNoiseFIPSUnsupported) {
			return nil, err
		}
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

// IsInitiator reports whether this side initiates the handshake. A channel
// binding over the two static keys orders them initiator first, which is
// the only order both peers agree on without exchanging anything further.
func (s *NoiseSession) IsInitiator() bool {
	return s.isInitiator
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

// LoadNoiseStaticKey creates a static key pair from raw private key bytes by
// copying them into protected memory. The caller's slice is left untouched
// and remains the caller's to wipe.
//
// Returns ErrNoiseInvalidMessage when the bytes are not a valid key.
func LoadNoiseStaticKey(privateKey []byte) (*NoiseStaticKey, error) {
	key, err := noiseproto.LoadStaticKey(privateKey)
	if err != nil {
		if errors.Is(err, ErrNoiseFIPSUnsupported) {
			return nil, err
		}
		return nil, ErrNoiseInvalidMessage
	}
	return key, nil
}

// LoadNoiseStaticKeyFromBuffer creates a static key pair from a private
// scalar held in protected memory. The scalar is read inside the source
// buffer's borrow and copied straight into the key's own protected pages, so
// it never reaches the Go heap. The source stays the caller's to destroy.
//
// Returns ErrNoiseInvalidMessage when the scalar is not a valid key, and the
// secure package's error when src is nil or already destroyed.
func LoadNoiseStaticKeyFromBuffer(src *secure.Buffer) (*NoiseStaticKey, error) {
	var key *NoiseStaticKey
	if err := src.WithBytes(func(privateKey []byte) error {
		var loadErr error
		key, loadErr = LoadNoiseStaticKey(privateKey)
		return loadErr
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// WithNoisePrivateKey lends key's private scalar to fn for exactly the
// duration of the call. The slice aliases the key's protected pages and the
// key's borrow is held throughout, so a concurrent Destroy waits for fn; fn
// must not retain the slice or destroy key. A destroyed key returns an error
// and fn is not called.
func WithNoisePrivateKey(key *NoiseStaticKey, fn func(privateKey []byte) error) error {
	return key.WithDHKey(func(dh flynnNoise.DHKey) error {
		return fn(dh.Private)
	})
}

// CloneNoiseStaticKey copies key into a new, independently owned
// NoiseStaticKey, so a holder can destroy its copy without freeing pages the
// original's owner still reads. The scalar goes from key's protected pages
// straight into the clone's, never touching the Go heap. The caller owns the
// clone and must Destroy it.
func CloneNoiseStaticKey(key *NoiseStaticKey) (*NoiseStaticKey, error) {
	var clone *NoiseStaticKey
	if err := WithNoisePrivateKey(key, func(privateKey []byte) error {
		var loadErr error
		clone, loadErr = LoadNoiseStaticKey(privateKey)
		return loadErr
	}); err != nil {
		return nil, err
	}
	return clone, nil
}

// noiseSessionErrors folds the shared noise package's errors onto the
// sentinels a NoiseSession reports.
var noiseSessionErrors = map[error]error{
	noiseproto.ErrHandshakeFailed:   ErrNoiseHandshakeFailed,
	noiseproto.ErrStaticKeyMismatch: ErrNoiseStaticKeyMismatch,
	noiseproto.ErrEncryptionFailed:  ErrNoiseEncryptionFailed,
	noiseproto.ErrDecryptionFailed:  ErrNoiseDecryptionFailed,
	noiseproto.ErrInvalidMessage:    ErrNoiseInvalidMessage,
	noiseproto.ErrInvalidKeySize:    ErrNoiseInvalidMessage,
	noiseproto.ErrSessionNotReady:   ErrNoiseHandshakeFailed,
}

// mapNoiseError translates a shared noise package error to the sentinel a
// NoiseSession reports. It checks both direct equality and wrapped errors.
func mapNoiseError(err error) error {
	// go-truststrap wraps a FIPS refusal together with the failure it caused
	// (ErrHandshakeFailed), so the refusal is matched before the map, whose
	// iteration order is random.
	if errors.Is(err, ErrNoiseFIPSUnsupported) {
		return ErrNoiseFIPSUnsupported
	}
	for noiseErr, sessionErr := range noiseSessionErrors {
		if errors.Is(err, noiseErr) {
			return sessionErr
		}
	}
	return ErrNoiseHandshakeFailed
}
