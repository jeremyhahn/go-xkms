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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

const (
	// SessionKeySize is the size of the AES-256-GCM key in bytes.
	SessionKeySize = 32

	// NonceSize is the size of the AES-256-GCM nonce in bytes.
	NonceSize = 12

	// HKDFInfo is the context string for HKDF key derivation.
	HKDFInfo = "xkey-nativemsg-v1"

	// X25519KeySize is the size of an X25519 public key.
	X25519KeySize = 32

	// hkdfInfoSend is the HKDF info string for the lower-pubkey peer's send key.
	hkdfInfoSend = HKDFInfo + "-send"

	// hkdfInfoRecv is the HKDF info string for the lower-pubkey peer's recv key.
	hkdfInfoRecv = HKDFInfo + "-recv"
)

// SessionCrypto handles per-connection X25519 ECDH key exchange and
// AES-256-GCM message encryption with replay protection.
//
// After construction via NewSessionCrypto, the caller must exchange public
// keys with the peer and call CompleteHandshake before Encrypt/Decrypt
// become available.
type SessionCrypto struct {
	privKey   *ecdh.PrivateKey
	pubKey    []byte
	sendKey   [SessionKeySize]byte
	recvKey   [SessionKeySize]byte
	sendNonce atomic.Uint64
	recvNonce atomic.Uint64
	ready     atomic.Bool
}

// NewSessionCrypto generates a new ephemeral X25519 keypair and returns
// the SessionCrypto instance along with the raw public key bytes that
// must be sent to the peer during the handshake.
func NewSessionCrypto() (*SessionCrypto, []byte, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, ErrHandshakeFailed
	}
	pubBytes := privKey.PublicKey().Bytes()
	sc := &SessionCrypto{
		privKey: privKey,
		pubKey:  pubBytes,
	}
	return sc, pubBytes, nil
}

// CompleteHandshake performs the ECDH computation with the peer's public
// key and derives directional send/recv session keys via HKDF-SHA256.
//
// Key direction is determined by lexicographic comparison of the two
// public keys. The peer whose public key is lexicographically lower
// uses HKDF(shared, "xkey-nativemsg-v1-send") as its sendKey and
// HKDF(shared, "xkey-nativemsg-v1-recv") as its recvKey. The other
// peer reverses these assignments. This guarantees both sides derive
// identical keying material with opposite send/recv roles.
//
// CompleteHandshake may only be called once. Subsequent calls return
// ErrHandshakeFailed.
func (sc *SessionCrypto) CompleteHandshake(peerPubKey []byte) error {
	if sc.ready.Load() {
		return ErrHandshakeFailed
	}
	if len(peerPubKey) != X25519KeySize {
		return ErrInvalidPublicKey
	}
	curve := ecdh.X25519()
	peerKey, err := curve.NewPublicKey(peerPubKey)
	if err != nil {
		return ErrInvalidPublicKey
	}
	shared, err := sc.privKey.ECDH(peerKey)
	if err != nil {
		return ErrHandshakeFailed
	}

	// Derive two directional keys from the shared secret.
	keySend, err := deriveKey(shared, hkdfInfoSend)
	if err != nil {
		return ErrHandshakeFailed
	}
	keyRecv, err := deriveKey(shared, hkdfInfoRecv)
	if err != nil {
		return ErrHandshakeFailed
	}

	// The peer with the lexicographically lower public key uses
	// keySend as its sendKey and keyRecv as its recvKey. The other
	// peer swaps them so that each side's send corresponds to the
	// other's recv.
	if bytes.Compare(sc.pubKey, peerPubKey) <= 0 {
		sc.sendKey = keySend
		sc.recvKey = keyRecv
	} else {
		sc.sendKey = keyRecv
		sc.recvKey = keySend
	}

	sc.ready.Store(true)
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the send key and a
// monotonically increasing nonce counter. The returned nonce value and
// ciphertext must both be transmitted to the peer.
//
// The 12-byte GCM nonce is constructed as: 8-byte little-endian counter
// followed by 4 zero bytes.
func (sc *SessionCrypto) Encrypt(plaintext []byte) (nonce uint64, ciphertext []byte, err error) {
	if !sc.ready.Load() {
		return 0, nil, ErrHandshakeRequired
	}
	block, err := aes.NewCipher(sc.sendKey[:])
	if err != nil {
		return 0, nil, ErrEncryptionFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, ErrEncryptionFailed
	}

	// Increment first so nonces start at 1; 0 is reserved as "no message
	// received yet" on the receiver side.
	counter := sc.sendNonce.Add(1)
	nonceBytes := counterToNonce(counter)

	sealed := gcm.Seal(nil, nonceBytes[:], plaintext, nil)
	return counter, sealed, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the recv key.
// Messages with a nonce counter less than or equal to the last
// successfully-received nonce are rejected with ErrReplayDetected.
func (sc *SessionCrypto) Decrypt(nonce uint64, ciphertext []byte) ([]byte, error) {
	if !sc.ready.Load() {
		return nil, ErrHandshakeRequired
	}

	// Replay protection: reject nonces that have already been seen.
	for {
		last := sc.recvNonce.Load()
		if nonce <= last {
			return nil, ErrReplayDetected
		}
		if sc.recvNonce.CompareAndSwap(last, nonce) {
			break
		}
	}

	block, err := aes.NewCipher(sc.recvKey[:])
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	nonceBytes := counterToNonce(nonce)
	plaintext, err := gcm.Open(nil, nonceBytes[:], ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// PublicKey returns the raw X25519 public key bytes for this session.
func (sc *SessionCrypto) PublicKey() []byte {
	out := make([]byte, len(sc.pubKey))
	copy(out, sc.pubKey)
	return out
}

// Ready returns true after CompleteHandshake has successfully derived
// the session keys.
func (sc *SessionCrypto) Ready() bool {
	return sc.ready.Load()
}

// deriveKey uses HKDF-SHA256 to derive a 32-byte key from the shared
// secret and an info string.
func deriveKey(shared []byte, info string) ([SessionKeySize]byte, error) {
	var key [SessionKeySize]byte
	r := hkdf.New(sha256.New, shared, nil, []byte(info))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// counterToNonce constructs a 12-byte GCM nonce from an 8-byte
// little-endian counter followed by 4 zero bytes.
func counterToNonce(counter uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], counter)
	return nonce
}
