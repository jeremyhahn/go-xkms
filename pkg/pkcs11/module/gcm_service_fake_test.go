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

package module

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errFakeServiceGCMAuth is returned when a ciphertext fails authentication,
// as distinct from a construction the process refuses to build.
var errFakeServiceGCMAuth = errors.New("fake key service: AES-GCM authentication failed")

// fakeServiceGCMSeal seals AES-GCM the way the key service does, for the test
// doubles that stand in for it.
//
// Outside fips140=only it uses the caller's nonce, or draws one, at any tag
// length NIST SP 800-38D section 5.2.1.2 approves. Under fips140=only the
// stdlib refuses arbitrary-IV GCM, so a caller nonce or a truncated tag is
// refused and everything else is sealed with cipher.NewGCMWithRandomNonce,
// the response naming that construction in GCMNonceMode.
func fakeServiceGCMSeal(key []byte, tagSize int, nonce, plaintext, aad []byte) (*transport.EncryptResponse, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, randomNonce, err := aead.NewGCMForFreshEncrypt(block, tagSize, len(nonce) > 0)
	if err != nil {
		return nil, err
	}
	if randomNonce {
		usedNonce, ciphertext, tag, err := aead.SplitGCMWithRandomNonce(gcm.Seal(nil, nil, plaintext, aad))
		if err != nil {
			return nil, err
		}
		return &transport.EncryptResponse{
			Ciphertext:   ciphertext,
			Nonce:        usedNonce,
			Tag:          tag,
			GCMNonceMode: string(types.GCMNonceModeRandom),
		}, nil
	}

	if len(nonce) == 0 {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	split := len(sealed) - gcm.Overhead()
	return &transport.EncryptResponse{
		Ciphertext: sealed[:split],
		Nonce:      nonce,
		Tag:        sealed[split:],
	}, nil
}

// callerIVSealRefusedUnderFIPS reports whether this process runs
// fips140=only, where the stdlib refuses arbitrary-IV AES-GCM and the key
// service with it, and in that case asserts that seal, which seals under a
// caller-supplied IV, was refused. Outside fips140=only it does not call seal.
func callerIVSealRefusedUnderFIPS(t *testing.T, seal func() error) bool {
	t.Helper()
	if aead.ArbitraryIVGCMUsable() {
		return false
	}
	if err := seal(); err == nil {
		t.Fatal("a fips140=only key service sealed AES-GCM under a caller-supplied IV")
	}
	return true
}

// callerIVOutsideFIPS returns iv outside fips140=only and nil under it, where
// the stdlib refuses a caller-supplied AES-GCM IV and the token generates one
// instead (SP 800-38D section 8.2.2). Tests whose subject is not the IV use
// it so they run in both modes.
func callerIVOutsideFIPS(iv []byte) []byte {
	if aead.ArbitraryIVGCMUsable() {
		return iv
	}
	return nil
}

// fakeServiceGCMOpen opens what fakeServiceGCMSeal, or the module on the
// service's behalf, produced, choosing the construction from the request's
// GCMNonceMode as the key service does.
func fakeServiceGCMOpen(key []byte, tagSize int, req *transport.DecryptRequest) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	randomNonce := req.GCMNonceMode == string(types.GCMNonceModeRandom)
	gcm, err := aead.NewGCMForDecrypt(block, tagSize, randomNonce)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	if randomNonce {
		plaintext, err = gcm.Open(nil, nil, aead.JoinGCMWithRandomNonce(req.Nonce, req.Ciphertext, req.Tag), req.AdditionalData)
	} else {
		plaintext, err = gcm.Open(nil, req.Nonce, append(slices.Clone(req.Ciphertext), req.Tag...), req.AdditionalData)
	}
	if err != nil {
		return nil, errFakeServiceGCMAuth
	}
	return plaintext, nil
}
