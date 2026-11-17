// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package opteeblob is the go-xkms codec of the sealed blob that
// trusted-firmware's OP-TEE trusted application (TA) returns from its SEAL
// command and accepts in its UNSEAL command.
//
// The blob is a tagged COSE_Encrypt0 (RFC 9052 §5.2) under A256GCM
// (RFC 9053 §4.1), with the TA's identity as the external AAD (RFC 9052
// §5.3). The key is derived with HKDF-SHA-256 (RFC 5869 §2) from the TA
// unique key that OP-TEE's system PTA command PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY
// returns to the TA, never from the raw hardware unique key (README §1).
// docs/optee-sealed-blob/README.md is the
// normative description of every byte.
package opteeblob

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Sizes of the format, in bytes.
const (
	// Version is the blob version this package writes and reads.
	Version = 1

	// KeySize is the length of the sealing key: AES-256 (RFC 9053 §4.1).
	KeySize = 32

	// NonceSize is the length of the AES-GCM nonce (RFC 9053 §4.1).
	NonceSize = 12

	// TagSize is the length of the AES-GCM tag that ends the ciphertext
	// (RFC 9053 §4.1).
	TagSize = 16

	// TAUniqueKeySize is the length of the TA unique key DeriveKey accepts:
	// the key size the TA requests from PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY
	// (README §1).
	TAUniqueKeySize = 32

	// UUIDSize is the length of a TA UUID in its RFC 9562 §4 octet form.
	UUIDSize = 16
)

// COSE labels and values (RFC 9052 §3.1, §5.3; RFC 9053 §4.1).
const (
	labelAlgorithm = 1
	labelIV        = 5

	// labelVersion is the first private-use header label (RFC 9052 §3.1:
	// integer labels less than -65536 are private use).
	labelVersion = -65537

	algorithmA256GCM = 3

	tagEncrypt0     = 16
	contextEncrypt0 = "Encrypt0"
)

// kdfLabel starts the HKDF info; the TA UUID follows it after one zero byte.
const kdfLabel = "go-xkms optee-sealed-blob v1"

// protectedHeader is the only protected header a version 1 blob carries: the
// core deterministic encoding (RFC 8949 §4.2.1) of
// {1: 3, -65537: 1}, the algorithm A256GCM and the version.
var protectedHeader = []byte{0xa2, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01}

// TAUUID is the identity of the TA that seals: its UUID in the RFC 9562 §4
// octet order, as OP-TEE's tee_uuid_to_octets writes it.
type TAUUID [UUIDSize]byte

// encrypt0 is the COSE_Encrypt0 array (RFC 9052 §5.2).
type encrypt0 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Ciphertext  []byte
}

var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

// DeriveKey derives the TA's sealing key from its TA unique key, the
// TAUniqueKeySize-byte output of PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY requested
// with the extra_data kdfLabel (README §1): HKDF-SHA-256 (RFC 5869 §2) with
// no salt, the info kdfLabel, one zero byte and the TA UUID, and an output of
// KeySize bytes.
func DeriveKey(taKey []byte, ta TAUUID) ([]byte, error) {
	if len(taKey) != TAUniqueKeySize {
		return nil, ErrTAUniqueKeyLength
	}
	key, err := hkdf.Key(sha256.New, taKey, nil, kdfInfo(ta), KeySize)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrDeriveFailed, Cause: err}
	}
	return key, nil
}

// Seal encrypts plaintext under key for the TA ta and returns the blob. The
// nonce is drawn at random for every call (NIST SP 800-38D §8.2.2), so no
// nonce repeats under one key.
func Seal(key []byte, ta TAUUID, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	// The random-nonce AEAD returns the nonce followed by the ciphertext
	// and tag.
	sealed := aead.Seal(nil, nil, plaintext, enc0AAD(ta))
	blob, err := encode(sealed[:NonceSize], sealed[NonceSize:])
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSealFailed, Cause: err}
	}
	return blob, nil
}

// Unseal checks blob against the format, authenticates it under key and the
// TA ta, and returns its plaintext.
func Unseal(key []byte, ta TAUUID, blob []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext, err := decode(blob)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(append(sealed, nonce...), ciphertext...)
	plaintext, err := aead.Open(nil, nil, sealed, enc0AAD(ta))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAuthentication, Cause: err}
	}
	return plaintext, nil
}

// newAEAD returns AES-256-GCM under key with a random 96-bit nonce, the
// FIPS 140-3 approved GCM construction.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyLength, Cause: err}
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrKeyLength, Cause: err}
	}
	return aead, nil
}

// kdfInfo is the HKDF info: kdfLabel, a zero byte, and the TA UUID.
func kdfInfo(ta TAUUID) string {
	return kdfLabel + "\x00" + string(ta[:])
}

// enc0AAD is the AEAD's additional data: the Enc_structure
// ["Encrypt0", protected, external_aad] (RFC 9052 §5.3), with the TA UUID as
// external_aad.
func enc0AAD(ta TAUUID) []byte {
	aad := make([]byte, 0, 37)
	aad = append(aad, 0x83, 0x68)
	aad = append(aad, contextEncrypt0...)
	aad = append(aad, 0x40|byte(len(protectedHeader)))
	aad = append(aad, protectedHeader...)
	aad = append(aad, 0x40|UUIDSize)
	return append(aad, ta[:]...)
}

// encode writes the blob: COSE_Encrypt0 under CBOR tag 16, in core
// deterministic encoding.
func encode(nonce, ciphertext []byte) ([]byte, error) {
	unprotected, err := encMode.Marshal(map[int64][]byte{labelIV: nonce})
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(cbor.Tag{
		Number: tagEncrypt0,
		Content: encrypt0{
			Protected:   protectedHeader,
			Unprotected: unprotected,
			Ciphertext:  ciphertext,
		},
	})
}

// decode checks blob against every rule of the format but the tag, and
// returns its nonce and its ciphertext with the tag.
func decode(blob []byte) (nonce, ciphertext []byte, err error) {
	var tag cbor.RawTag
	if err := decMode.Unmarshal(blob, &tag); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, &errs.Joined{Lead: ErrTruncated, Cause: err}
		}
		return nil, nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	if tag.Number != tagEncrypt0 {
		return nil, nil, &errs.Detail{Err: ErrMalformed, Detail: "not CBOR tag 16"}
	}
	var msg encrypt0
	if err := decMode.Unmarshal(tag.Content, &msg); err != nil {
		return nil, nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	// A ciphertext shorter than the tag is refused before the headers:
	// README section 5 lists truncation first.
	if len(msg.Ciphertext) < TagSize {
		return nil, nil, &errs.Detail{Err: ErrTruncated, Detail: "ciphertext shorter than the GCM tag"}
	}
	if err := checkProtected(msg.Protected); err != nil {
		return nil, nil, err
	}
	nonce, err = parseUnprotected(msg.Unprotected)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := encode(nonce, msg.Ciphertext)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	if !bytes.Equal(canonical, blob) {
		return nil, nil, &errs.Detail{Err: ErrMalformed, Detail: "not core deterministic encoding"}
	}
	return nonce, msg.Ciphertext, nil
}

// checkProtected requires the protected header to be exactly
// protectedHeader, naming the version and the algorithm first when they are
// the reason it is not.
func checkProtected(protected []byte) error {
	var header map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(protected, &header); err != nil {
		return &errs.Joined{Lead: ErrHeader, Detail: "protected header", Cause: err}
	}
	version, ok := intParameter(header, labelVersion)
	if !ok {
		return &errs.Detail{Err: ErrHeader, Detail: "protected header has no integer version"}
	}
	if version != Version {
		return ErrVersion
	}
	algorithm, ok := intParameter(header, labelAlgorithm)
	if !ok {
		return &errs.Detail{Err: ErrHeader, Detail: "protected header has no integer algorithm"}
	}
	if algorithm != algorithmA256GCM {
		return ErrAlgorithm
	}
	if !bytes.Equal(protected, protectedHeader) {
		return &errs.Detail{Err: ErrHeader, Detail: "protected header carries another parameter or encoding"}
	}
	return nil
}

// parseUnprotected requires the unprotected header to hold the IV and
// nothing else, and returns the IV.
func parseUnprotected(unprotected cbor.RawMessage) ([]byte, error) {
	var header map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(unprotected, &header); err != nil {
		return nil, &errs.Joined{Lead: ErrHeader, Detail: "unprotected header", Cause: err}
	}
	raw, ok := header[labelIV]
	if !ok || len(header) != 1 {
		return nil, &errs.Detail{Err: ErrHeader, Detail: "unprotected header must hold the IV only"}
	}
	var nonce []byte
	if err := decMode.Unmarshal(raw, &nonce); err != nil {
		return nil, &errs.Joined{Lead: ErrHeader, Detail: "IV must be a 12-byte string", Cause: err}
	}
	if len(nonce) != NonceSize {
		return nil, &errs.Detail{Err: ErrHeader, Detail: "IV must be a 12-byte string"}
	}
	return nonce, nil
}

// intParameter returns the integer header parameter at label.
func intParameter(header map[int64]cbor.RawMessage, label int64) (int64, bool) {
	raw, ok := header[label]
	if !ok {
		return 0, false
	}
	var value int64
	if err := decMode.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}
