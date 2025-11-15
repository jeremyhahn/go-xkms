// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package x25519

import (
	"crypto"
	"crypto/ecdh"
	"fmt"
)

// PrivateKeyStorage wraps an X25519 private key to implement crypto.PrivateKey.
// This allows X25519 keys to be stored and managed by backends that expect crypto.PrivateKey.
type PrivateKeyStorage struct {
	privateKey *ecdh.PrivateKey
}

// NewPrivateKeyStorage creates a new PrivateKeyStorage from an X25519 private key.
func NewPrivateKeyStorage(privateKey *ecdh.PrivateKey) (*PrivateKeyStorage, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if privateKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("private key must be X25519, got %v", privateKey.Curve())
	}
	return &PrivateKeyStorage{privateKey: privateKey}, nil
}

// Public returns the public key corresponding to the private key.
func (k *PrivateKeyStorage) Public() crypto.PublicKey {
	return &PublicKeyStorage{publicKey: k.privateKey.PublicKey()}
}

// PrivateKey returns the underlying X25519 private key.
func (k *PrivateKeyStorage) PrivateKey() *ecdh.PrivateKey {
	return k.privateKey
}

// Bytes returns the raw X25519 private key bytes (32 bytes).
func (k *PrivateKeyStorage) Bytes() []byte {
	return k.privateKey.Bytes()
}

// PublicKeyStorage wraps an X25519 public key to implement crypto.PublicKey.
// This allows X25519 keys to be used with backends that expect crypto.PublicKey.
type PublicKeyStorage struct {
	publicKey *ecdh.PublicKey
}

// NewPublicKeyStorage creates a new PublicKeyStorage from an X25519 public key.
func NewPublicKeyStorage(publicKey *ecdh.PublicKey) (*PublicKeyStorage, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if publicKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("public key must be X25519, got %v", publicKey.Curve())
	}
	return &PublicKeyStorage{publicKey: publicKey}, nil
}

// PublicKey returns the underlying X25519 public key.
func (k *PublicKeyStorage) PublicKey() *ecdh.PublicKey {
	return k.publicKey
}

// Bytes returns the raw X25519 public key bytes (32 bytes).
func (k *PublicKeyStorage) Bytes() []byte {
	return k.publicKey.Bytes()
}
