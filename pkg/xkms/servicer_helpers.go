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

package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// resolveBackend returns the backend for the given name, or the default backend
// if the name is empty. This is the canonical backend resolution method shared
// across all servicer files.
func (s *XKMSService) resolveBackend(name string) (Backend, error) {
	if name == "" {
		return DefaultBackend()
	}
	return GetBackend(name)
}

// resolveBackendWithName returns the Backend and its resolved name.
// If backendName is empty, the default backend name is used.
func (s *XKMSService) resolveBackendWithName(backendName string) (Backend, string, error) {
	if backendName == "" {
		backendName = s.defaultBackendName()
	}
	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, "", err
	}
	return b, backendName, nil
}

// defaultBackendName returns the name of the default backend.
func (s *XKMSService) defaultBackendName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultBackend
}

// findKeyAttrs searches a backend's key list for a key matching the given ID.
func findKeyAttrs(b Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := b.ListKeys()
	if err != nil {
		return nil, err
	}
	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}
	return nil, ErrKeyNotFound
}

// algorithmString returns a human-readable algorithm string from key attributes.
func algorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}

// parseHash converts a hash algorithm name string to a crypto.Hash value.
// Returns crypto.SHA256 as the default if the input is empty or unrecognized.
func parseHash(hash string) crypto.Hash {
	if hash == "" {
		return crypto.SHA256
	}
	h := types.ParseHash(hash)
	if h == 0 {
		return crypto.SHA256
	}
	return h
}

// pubKeyPEM extracts the public key from a private key and encodes it as PEM.
func pubKeyPEM(privKey crypto.PrivateKey) (string, error) {
	if privKey == nil {
		return "", ErrNilPrivateKey
	}

	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		pubKey = k.Public()
	default:
		return "", &ErrUnsupportedPrivateKeyType{KeyType: fmt.Sprintf("%T", privKey)}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", &ErrKeyOperation{Operation: "marshal public key", Err: err}
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}
