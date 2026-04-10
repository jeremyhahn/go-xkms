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

// phoneDecrypter implements crypto.Decrypter by proxying decrypt operations
// to an Android phone via Noise-encrypted JSON-RPC.
type phoneDecrypter struct {
	backend   *Backend
	keyID     string
	algorithm string
	pubKey    crypto.PublicKey
}

// newPhoneDecrypter creates a new phoneDecrypter that proxies decryption
// operations to the phone backend for the given key.
func newPhoneDecrypter(backend *Backend, keyID, algorithm string, pubKey crypto.PublicKey) *phoneDecrypter {
	return &phoneDecrypter{
		backend:   backend,
		keyID:     keyID,
		algorithm: algorithm,
		pubKey:    pubKey,
	}
}

// Public returns the cached public key associated with this decrypter.
func (d *phoneDecrypter) Public() crypto.PublicKey {
	return d.pubKey
}

// Decrypt decrypts ciphertext by sending a local.decrypt JSON-RPC request
// to the phone. The rand parameter is unused as the phone handles all
// cryptographic randomness internally.
func (d *phoneDecrypter) Decrypt(_ io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	params := &phoneproto.LocalDecryptParams{
		KeyID:      d.keyID,
		Ciphertext: ciphertext,
		Algorithm:  d.algorithm,
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.backend.config.RequestTimeout)
	defer cancel()

	resp, err := d.backend.sendLocalRequest(ctx, phoneproto.MethodLocalDecrypt, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalDecryptResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result.Plaintext, nil
}

// Compile-time assertion that phoneDecrypter implements crypto.Decrypter.
var _ crypto.Decrypter = (*phoneDecrypter)(nil)
