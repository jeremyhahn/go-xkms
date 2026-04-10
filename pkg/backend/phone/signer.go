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

package phone

import (
	"context"
	"crypto"
	"io"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// phoneSigner implements crypto.Signer by proxying sign operations to the phone.
// The private key never leaves the phone's secure hardware (TEE/StrongBox).
type phoneSigner struct {
	backend   *Backend
	keyID     string
	algorithm string           // "ES256", "ES384", "ES512", "RS256", etc.
	pubKey    crypto.PublicKey // Cached public key from phone
}

// Compile-time interface assertion.
var _ crypto.Signer = (*phoneSigner)(nil)

// newPhoneSigner creates a new phoneSigner that proxies signing operations to
// the Android phone via the Backend's Noise-encrypted JSON-RPC channel.
func newPhoneSigner(backend *Backend, keyID, algorithm string, pubKey crypto.PublicKey) *phoneSigner {
	return &phoneSigner{
		backend:   backend,
		keyID:     keyID,
		algorithm: algorithm,
		pubKey:    pubKey,
	}
}

// Public returns the cached public key corresponding to the private key held
// on the phone's secure hardware.
func (s *phoneSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// Sign sends a local.sign JSON-RPC request to the phone and returns the
// resulting signature. The rand and opts parameters are unused because the
// phone's secure hardware controls the signing process. The digest is the
// pre-hashed data to sign.
func (s *phoneSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	params := phoneproto.LocalSignParams{
		KeyID:     s.keyID,
		Data:      digest,
		Algorithm: s.algorithm,
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.backend.config.RequestTimeout)
	defer cancel()

	resp, err := s.backend.sendLocalRequest(ctx, phoneproto.MethodLocalSign, params)
	if err != nil {
		return nil, ErrSigningFailed
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalSignResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result.Signature, nil
}
