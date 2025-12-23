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

//go:build !frost

// Package frost provides FROST threshold signature support (RFC 9591).
// This is a stub implementation when the frost build tag is not enabled.
package frost

import (
	"crypto"
	"errors"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ErrNotCompiled is returned when FROST support is not compiled in.
var ErrNotCompiled = errors.New("frost: not compiled (build with -tags frost)")

// Config is a stub configuration struct.
type Config struct {
	PublicStorage       storage.Backend
	SecretBackend       types.Backend
	Algorithm           types.FrostAlgorithm
	ParticipantID       uint32
	DefaultThreshold    int
	DefaultTotal        int
	Participants        []string
	EnableNonceTracking bool
}

// FrostBackend is a stub implementation.
type FrostBackend struct{}

// NewBackend returns an error indicating FROST is not compiled.
func NewBackend(config *Config) (*FrostBackend, error) {
	return nil, ErrNotCompiled
}

// Type returns the backend type.
func (b *FrostBackend) Type() types.BackendType {
	return types.BackendTypeFrost
}

// Capabilities returns empty capabilities.
func (b *FrostBackend) Capabilities() types.Capabilities {
	return types.Capabilities{}
}

// GenerateKey returns an error.
func (b *FrostBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrNotCompiled
}

// GetKey returns an error.
func (b *FrostBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, ErrNotCompiled
}

// DeleteKey returns an error.
func (b *FrostBackend) DeleteKey(attrs *types.KeyAttributes) error {
	return ErrNotCompiled
}

// ListKeys returns an error.
func (b *FrostBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, ErrNotCompiled
}

// Signer returns an error.
func (b *FrostBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, ErrNotCompiled
}

// Decrypter returns an error.
func (b *FrostBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrNotCompiled
}

// RotateKey returns an error.
func (b *FrostBackend) RotateKey(attrs *types.KeyAttributes) error {
	return ErrNotCompiled
}

// Close is a no-op.
func (b *FrostBackend) Close() error {
	return nil
}

// GenerateNonces returns an error.
func (b *FrostBackend) GenerateNonces(keyID string) (*NoncePackage, error) {
	return nil, ErrNotCompiled
}

// SignRound returns an error.
func (b *FrostBackend) SignRound(keyID string, message []byte, nonces *NoncePackage, commitments []*Commitment) (*SignatureShare, error) {
	return nil, ErrNotCompiled
}

// Aggregate returns an error.
func (b *FrostBackend) Aggregate(keyID string, message []byte, commitments []*Commitment, shares []*SignatureShare) ([]byte, error) {
	return nil, ErrNotCompiled
}

// Verify returns an error.
func (b *FrostBackend) Verify(keyID string, message, signature []byte) error {
	return ErrNotCompiled
}

// Stub types for compilation

// NoncePackage is a stub type.
type NoncePackage struct {
	ParticipantID uint32
	SessionID     string
}

// Commitment is a stub type.
type Commitment struct {
	ParticipantID uint32
}

// SignatureShare is a stub type.
type SignatureShare struct {
	ParticipantID uint32
	Share         []byte
}
