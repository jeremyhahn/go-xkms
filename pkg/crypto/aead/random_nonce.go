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

package aead

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// GCMRandomNonceSize is the nonce length cipher.NewGCMWithRandomNonce
// generates internally and prepends to its Seal output (96 bits, the
// standard AES-GCM nonce length). A nonce extracted from that output is
// therefore the same size EncryptedData.Nonce already carries for every
// other AES-GCM construction in this stack.
const GCMRandomNonceSize = 12

// ErrArbitraryIVGCMUnavailable is returned when an AES-GCM operation
// requires a caller-supplied nonce -- an interop wire format, or a nonce
// derived through a KDF -- and this process cannot construct the AEAD that
// would honour it.
//
// Under GODEBUG=fips140=only, Go's crypto/cipher refuses cipher.NewGCM and
// cipher.NewGCMWithTagSize outright, because FIPS 140-3 requires the module
// itself generate the nonce; see ArbitraryIVGCMUsable.
// cipher.NewGCMWithRandomNonce keeps working in that mode, but it generates
// its own nonce and cannot honour one the caller supplies, so there is no
// substitute construction for this case. The operation fails closed here
// rather than silently switching to a framing an interop peer, or a
// KDF-nonce scheme, cannot consume.
var ErrArbitraryIVGCMUnavailable = errors.New("aead: this FIPS 140-only process cannot construct an AES-GCM AEAD over a caller-supplied nonce")

// NewGCMForFreshEncrypt selects the AES-GCM construction for a new
// encryption. tagSize is the requested authentication tag length in bytes
// (zero selects the full 128-bit tag, exactly as NewGCM); callerNonce
// reports whether the caller is supplying its own nonce to Seal, rather
// than leaving this call to generate one.
//
// When this process can construct arbitrary-IV GCM (the default, and
// GODEBUG=fips140=on), the answer is always NewGCM and randomNonce is
// always false: the caller-nonce framing already in use across the stack
// keeps working, and nothing changes for it.
//
// When this process cannot (GODEBUG=fips140=only) and the caller left the
// nonce to be generated with the default full-length tag -- the only
// combination cipher.NewGCMWithRandomNonce supports -- this substitutes it
// and reports randomNonce true. cipher.NewGCMWithRandomNonce's NonceSize is
// zero, so the caller must call Seal with a nil/empty nonce argument; the
// 96-bit nonce Seal generates and prepends to its output must then be split
// back out with SplitGCMWithRandomNonce before it is stored.
//
// Every other combination under FIPS 140-only -- a caller-supplied nonce, or
// a truncated tag, which NewGCMWithRandomNonce cannot produce -- fails
// closed with ErrArbitraryIVGCMUnavailable: falling through to NewGCM here
// would only relay the runtime's own refusal from deep inside the seal,
// after the caller had already committed to a nonce or a tag length the
// process cannot honour.
func NewGCMForFreshEncrypt(block cipher.Block, tagSize int, callerNonce bool) (gcm cipher.AEAD, randomNonce bool, err error) {
	if ArbitraryIVGCMUsable() {
		gcm, err = NewGCM(block, tagSize)
		return gcm, false, err
	}

	resolved, err := ResolveGCMTagSize(tagSize)
	if err != nil {
		return nil, false, err
	}
	if callerNonce || resolved != GCMFullTagSize {
		return nil, false, &errs.Detail{
			Err: ErrArbitraryIVGCMUnavailable,
			Detail: fmt.Sprintf(
				"caller-supplied nonce=%t, requested tag size=%d bytes; only a %d-byte tag with a process-generated nonce is available",
				callerNonce, tagSize, GCMFullTagSize),
		}
	}

	gcm, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, false, err
	}
	return gcm, true, nil
}

// NewGCMForDecrypt selects the AES-GCM construction matching how a
// ciphertext was produced. randomNonce is normally the value
// NewGCMForFreshEncrypt returned when the ciphertext was written, carried
// forward through the stored envelope (types.GCMNonceMode), so a
// ciphertext written under one FIPS posture decrypts correctly under a
// different one later: a process running GODEBUG=fips140=on can still
// decrypt a ciphertext GODEBUG=fips140=only wrote with a random nonce, and
// a process that can construct arbitrary-IV GCM can still decrypt a legacy
// caller-nonce ciphertext GODEBUG=fips140=only itself could no longer open.
//
// tagSize is ignored when randomNonce is true beyond confirming it resolves
// to the full tag: cipher.NewGCMWithRandomNonce supports only the full
// 128-bit tag, so a ciphertext claiming both randomNonce and a truncated
// tag names a combination this process never produces and cannot open.
func NewGCMForDecrypt(block cipher.Block, tagSize int, randomNonce bool) (cipher.AEAD, error) {
	if randomNonce {
		resolved, err := ResolveGCMTagSize(tagSize)
		if err != nil {
			return nil, err
		}
		if resolved != GCMFullTagSize {
			return nil, &errs.Detail{
				Err: ErrInvalidGCMTagSize,
				Detail: fmt.Sprintf(
					"%d bytes; a random-nonce ciphertext carries only the %d-byte full tag", tagSize, GCMFullTagSize),
			}
		}
		return cipher.NewGCMWithRandomNonce(block)
	}

	if !ArbitraryIVGCMUsable() {
		return nil, &errs.Detail{
			Err:    ErrArbitraryIVGCMUnavailable,
			Detail: "ciphertext carries an explicit nonce, which this FIPS 140-only process cannot open",
		}
	}
	return NewGCM(block, tagSize)
}

// SplitGCMWithRandomNonce splits sealed -- the output of Seal on an AEAD
// built by cipher.NewGCMWithRandomNonce -- into the nonce it generated and
// prepended, the ciphertext, and the trailing authentication tag: the same
// three-way split every other AES-GCM construction in this stack produces,
// so the result stores into EncryptedData's Nonce, Ciphertext and Tag
// fields exactly as the caller-nonce path does.
func SplitGCMWithRandomNonce(sealed []byte) (nonce, ciphertext, tag []byte, err error) {
	const overhead = GCMRandomNonceSize + GCMFullTagSize
	if len(sealed) < overhead {
		return nil, nil, nil, &errs.Message{Msg: fmt.Sprintf(
			"aead: random-nonce GCM output is %d bytes, want at least %d (%d-byte nonce + %d-byte tag)",
			len(sealed), overhead, GCMRandomNonceSize, GCMFullTagSize)}
	}
	nonce = sealed[:GCMRandomNonceSize]
	tag = sealed[len(sealed)-GCMFullTagSize:]
	ciphertext = sealed[GCMRandomNonceSize : len(sealed)-GCMFullTagSize]
	return nonce, ciphertext, tag, nil
}

// JoinGCMWithRandomNonce reassembles nonce, ciphertext and tag -- the three
// fields EncryptedData carries -- into the single byte slice Open expects
// from an AEAD built by cipher.NewGCMWithRandomNonce, which reads its nonce
// from the front of the input rather than accepting one as a parameter.
func JoinGCMWithRandomNonce(nonce, ciphertext, tag []byte) []byte {
	joined := make([]byte, 0, len(nonce)+len(ciphertext)+len(tag))
	joined = append(joined, nonce...)
	joined = append(joined, ciphertext...)
	joined = append(joined, tag...)
	return joined
}
