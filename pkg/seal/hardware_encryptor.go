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

package seal

import (
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface check.
var _ SymmetricEncrypter = (*hardwareEncryptorWrapper)(nil)

// hardwareEncryptorWrapper adapts a types.SymmetricEncrypter (which uses
// the rich EncryptedData struct) to the simple SymmetricEncrypter interface
// ([]byte in, []byte out). This is an internal implementation detail of
// hardware-backed sealing strategies (TPM2, PKCS#11, cloud KMS).
//
// The wire format is symmetric.Marshal(EncryptedData) (TLV encoding).
// The version byte prefix is added by go-qrdb's barrier layer, not here.
type hardwareEncryptorWrapper struct {
	inner types.SymmetricEncrypter
}

// Encrypt encrypts plaintext using the underlying hardware-backed
// types.SymmetricEncrypter and serializes the result using TLV wire format.
// The version byte prefix is added by go-qrdb's barrier layer, not here.
func (w *hardwareEncryptorWrapper) Encrypt(plaintext []byte) ([]byte, error) {
	ed, err := w.inner.Encrypt(plaintext, nil)
	if err != nil {
		return nil, err
	}

	return symmetric.Marshal(ed)
}

// Decrypt parses the TLV wire format and decrypts using the underlying
// hardware-backed types.SymmetricEncrypter. The version byte prefix has
// already been stripped by go-qrdb's barrier layer.
func (w *hardwareEncryptorWrapper) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 1 {
		return nil, ErrCorruptRootKey
	}

	ed, err := symmetric.Unmarshal(ciphertext)
	if err != nil {
		return nil, ErrCorruptRootKey
	}

	plaintext, err := w.inner.Decrypt(ed, nil)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if plaintext == nil {
		plaintext = []byte{}
	}
	return plaintext, nil
}
