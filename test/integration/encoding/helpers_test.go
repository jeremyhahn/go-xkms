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

//go:build integration
// +build integration

package integration

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/require"
)

var ErrUnsupportedOperation = errors.New("unsupported operation")

// testBackendSetup creates a test backend with in-memory storage
type testBackendSetup struct {
	backend types.SymmetricBackend
}

// createTestBackend creates a software backend for testing
func createTestBackend(t *testing.T) *testBackendSetup {
	t.Helper()

	keyStorage := memory.New()
	backendCfg := &software.Config{
		KeyStorage: keyStorage,
		Tracker:    backend.NewMemoryAEADTracker(),
	}

	be, err := software.NewBackend(backendCfg)
	require.NoError(t, err)

	return &testBackendSetup{
		backend: be,
	}
}

// Close closes the backend
func (s *testBackendSetup) Close() {
	if s.backend != nil {
		s.backend.Close()
	}
}

// Helper function to get a key by CN (common name)
// This tries different key algorithms since we don't know which one was used.
func (s *testBackendSetup) GetKeyByID(cn string) (crypto.PrivateKey, error) {
	// Try RSA first
	attrs := &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048, // Default size, actual size doesn't matter for retrieval
		},
		Hash: crypto.SHA256,
	}
	key, err := s.backend.GetKey(attrs)
	if err == nil {
		return key, nil
	}

	// Try ECDSA P-256
	attrs = &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash: crypto.SHA256,
	}
	key, err = s.backend.GetKey(attrs)
	if err == nil {
		return key, nil
	}

	// Try ECDSA P-384
	attrs.ECCAttributes.Curve = elliptic.P384()
	key, err = s.backend.GetKey(attrs)
	if err == nil {
		return key, nil
	}

	// Try ECDSA P-521
	attrs.ECCAttributes.Curve = elliptic.P521()
	key, err = s.backend.GetKey(attrs)
	if err == nil {
		return key, nil
	}

	// Try Ed25519
	attrs = &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.Ed25519,
	}
	return s.backend.GetKey(attrs)
}

// Helper function to get a crypto.Signer by CN
func (s *testBackendSetup) GetSignerByID(cn string) (crypto.Signer, error) {
	key, err := s.GetKeyByID(cn)
	if err != nil {
		return nil, err
	}
	if signer, ok := key.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, ErrUnsupportedOperation
}

// Helper function to get a crypto.Decrypter by CN
func (s *testBackendSetup) GetDecrypterByID(cn string) (crypto.Decrypter, error) {
	key, err := s.GetKeyByID(cn)
	if err != nil {
		return nil, err
	}
	if decrypter, ok := key.(crypto.Decrypter); ok {
		return decrypter, nil
	}
	return nil, ErrUnsupportedOperation
}

// Helper function to get public key by CN
func (s *testBackendSetup) GetPublicKeyByID(cn string) (crypto.PublicKey, error) {
	key, err := s.GetKeyByID(cn)
	if err != nil {
		return nil, err
	}
	if signer, ok := key.(crypto.Signer); ok {
		return signer.Public(), nil
	}
	return nil, ErrUnsupportedOperation
}

// Helper to create RSA key attributes
func createRSAAttrs(cn string, keySize int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      types.KeyType(backend.KEY_TYPE_TLS),
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: keySize,
		},
		Hash: crypto.SHA256,
	}
}

// Helper to create ECDSA key attributes
func createECDSAAttrs(cn string, curve elliptic.Curve) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      types.KeyType(backend.KEY_TYPE_TLS),
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: curve,
		},
		Hash: crypto.SHA256,
	}
}

// Helper to create Ed25519 key attributes
func createEd25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      types.KeyType(backend.KEY_TYPE_TLS),
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.Ed25519,
	}
}

// GenerateRSAKey generates an RSA key with the given CN and key size
func (s *testBackendSetup) GenerateRSAKey(cn string, keySize int) error {
	attrs := createRSAAttrs(cn, keySize)
	_, err := s.backend.GenerateKey(attrs)
	return err
}

// GenerateECDSAKey generates an ECDSA key with the given CN and curve
func (s *testBackendSetup) GenerateECDSAKey(cn string, curve elliptic.Curve) error {
	attrs := createECDSAAttrs(cn, curve)
	_, err := s.backend.GenerateKey(attrs)
	return err
}

// GenerateEd25519Key generates an Ed25519 key with the given CN
func (s *testBackendSetup) GenerateEd25519Key(cn string) error {
	attrs := createEd25519Attrs(cn)
	_, err := s.backend.GenerateKey(attrs)
	return err
}

// Helper to get curve from bit size
func getCurveFromBitSize(bitSize int) elliptic.Curve {
	switch bitSize {
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}
