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

//go:build pkcs11

package pkcs11

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"
)

// ckrAEADDecryptFailed is CKR_AEAD_DECRYPT_FAILED, the PKCS#11 v3.0 return
// value for an AEAD tag that does not verify. miekg/pkcs11 predates v3.0 and
// does not define it.
const ckrAEADDecryptFailed = 0x00000035

// ErrCiphertextRejected is joined with the token's error when C_Decrypt
// refuses an AES-GCM ciphertext with a return value that names the
// ciphertext itself (see ciphertextRejections): it was tampered with,
// truncated or extended, produced under another key, or sealed under
// different additional authenticated data.
var ErrCiphertextRejected = errors.New("pkcs11: token rejected the AES-GCM ciphertext")

// ErrDecryptInit is joined with the token's error when C_DecryptInit fails:
// the key, mechanism or session was refused before any ciphertext was read,
// so the failure never says anything about the ciphertext.
var ErrDecryptInit = errors.New("pkcs11: C_DecryptInit failed")

// ciphertextRejections are the C_Decrypt return values PKCS#11 defines for an
// AES-GCM ciphertext that does not authenticate: v2.40's
// CKR_ENCRYPTED_DATA_INVALID and CKR_ENCRYPTED_DATA_LEN_RANGE, and v3.0's
// CKR_AEAD_DECRYPT_FAILED. Each names the input, never the device.
//
// CKR_GENERAL_ERROR is deliberately absent. The specification reserves it
// for an unrecoverable token error, and a module that also uses it for a tag
// mismatch -- SoftHSM v2 does, for an OpenSSL EVP_DecryptFinal refusal and an
// EVP_DecryptUpdate engine fault alike -- gives no way to tell the two apart
// from the operation itself. An ambiguous code is never promoted to an
// authentication failure: on such a module a tampered ciphertext is reported
// with the token's own CKR_GENERAL_ERROR, without ErrCiphertextRejected.
var ciphertextRejections = map[pkcs11.Error]struct{}{
	pkcs11.CKR_ENCRYPTED_DATA_INVALID:   {},
	pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE: {},
	ckrAEADDecryptFailed:                {},
}

// rejectsCiphertext reports whether err, returned by C_Decrypt over an
// AES-GCM ciphertext whose nonce and tag lengths were already validated and
// whose C_DecryptInit succeeded, is one of ciphertextRejections. Every other
// return value -- device, session, memory, login and key-handle errors, and
// CKR_GENERAL_ERROR -- is not.
func rejectsCiphertext(err error) bool {
	var ckErr pkcs11.Error
	if !errors.As(err, &ckErr) {
		return false
	}
	_, ok := ciphertextRejections[ckErr]
	return ok
}

// gcmDecryptToken is the slice of the PKCS#11 API one AES-GCM decrypt
// drives; *pkcs11.Ctx satisfies it.
type gcmDecryptToken interface {
	DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
}

// decryptGCM runs one AES-GCM decrypt -- C_DecryptInit then C_Decrypt -- of
// ciphertext (tag appended) under key. A C_DecryptInit failure is
// ErrDecryptInit and never a rejection; a C_Decrypt failure is
// ErrCiphertextRejected exactly when rejectsCiphertext says the token named
// the ciphertext.
func decryptGCM(
	token gcmDecryptToken,
	session pkcs11.SessionHandle,
	mechanism []*pkcs11.Mechanism,
	key pkcs11.ObjectHandle,
	ciphertext []byte,
) ([]byte, error) {
	if err := token.DecryptInit(session, mechanism, key); err != nil {
		return nil, &errs.Joined{Lead: ErrDecryptInit, Detail: "failed to initialize decryption", Cause: err}
	}
	plaintext, err := token.Decrypt(session, ciphertext)
	if err != nil {
		wrapped := &errs.Wrapped{Msg: "decryption failed (authentication error)", Err: err}
		if rejectsCiphertext(err) {
			return nil, &errs.Joined{Lead: ErrCiphertextRejected, Cause: wrapped}
		}
		return nil, wrapped
	}
	return plaintext, nil
}
