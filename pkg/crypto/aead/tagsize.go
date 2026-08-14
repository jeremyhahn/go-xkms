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

package aead

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// GCMFullTagSize is the full 128-bit AES-GCM authentication tag length, in
// bytes. It is the default every caller gets when no tag length is requested,
// and the only length NIST SP 800-38D appendix C recommends without a
// supporting analysis of the application's forgery tolerance.
const GCMFullTagSize = 16

// ErrInvalidGCMTagSize is returned when a requested AES-GCM tag length is not
// one NIST SP 800-38D section 5.2.1.2 approves. The approved lengths are t of
// 128, 120, 112, 104 and 96 bits, which is 16, 15, 14, 13 and 12 bytes.
var ErrInvalidGCMTagSize = errors.New("aead: unsupported AES-GCM authentication tag size")

// ErrTagSizeNotConfigurable is returned by an implementation that does not
// choose its own authentication tag length -- a remote KMS that returns an
// opaque ciphertext blob, or a cipher such as ChaCha20-Poly1305 with no
// truncation construction. Accepting the request and returning the only tag
// length available would report success for something the caller did not get,
// and the substitution is invisible until a peer fails to authenticate.
var ErrTagSizeNotConfigurable = errors.New("aead: authentication tag length is not configurable for this provider")

// RequireDefaultTagSize returns nil when tagSize selects the provider's own
// tag length -- zero, meaning "whatever the provider produces" -- and
// ErrTagSizeNotConfigurable otherwise. The provider name appears in the error
// so an operator can tell which of several configured backends refused.
func RequireDefaultTagSize(tagSize int, provider string) error {
	if tagSize == 0 {
		return nil
	}
	return &errs.Detail{
		Err:    ErrTagSizeNotConfigurable,
		Detail: fmt.Sprintf("%s produces a fixed-length tag; %d bytes was requested", provider, tagSize),
	}
}

// gcmTagSizes is the approved set, as a map so membership is a constant-time
// lookup rather than a chain of comparisons.
var gcmTagSizes = map[int]struct{}{
	12: {}, 13: {}, 14: {}, 15: {}, 16: {},
}

// ValidGCMTagSize reports whether tagSize bytes is an AES-GCM authentication
// tag length NIST SP 800-38D section 5.2.1.2 approves.
func ValidGCMTagSize(tagSize int) bool {
	_, ok := gcmTagSizes[tagSize]
	return ok
}

// ResolveGCMTagSize maps a requested AES-GCM tag length in bytes onto the
// length to use, with zero selecting the full 128-bit tag.
//
// A length outside the approved set is an error rather than something to be
// rounded to the nearest permitted value. Both halves of a round trip have to
// agree on t: SP 800-38D section 5.2.2 verifies a t-bit tag by recomputing the
// tag at t bits and comparing, so a tag produced at one length and verified at
// another fails authentication in a way indistinguishable from ciphertext
// corruption.
func ResolveGCMTagSize(requested int) (int, error) {
	if requested == 0 {
		return GCMFullTagSize, nil
	}
	if !ValidGCMTagSize(requested) {
		return 0, &errs.Detail{
			Err:    ErrInvalidGCMTagSize,
			Detail: fmt.Sprintf("%d bytes; AES-GCM permits 12, 13, 14, 15 or 16", requested),
		}
	}
	return requested, nil
}

// NewGCM builds an AES-GCM AEAD over block that produces a tagSize-byte
// authentication tag, with zero selecting the full 128-bit tag.
//
// SP 800-38D section 5.2.1.2 defines the t-bit tag as the leading t bits of
// the full 128-bit tag, which is exactly the truncation crypto/cipher's
// NewGCMWithTagSize implements, so a shorter tag here is the standard's own
// construction and not an approximation of it.
func NewGCM(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	resolved, err := ResolveGCMTagSize(tagSize)
	if err != nil {
		return nil, err
	}
	if resolved == GCMFullTagSize {
		return cipher.NewGCM(block)
	}
	return cipher.NewGCMWithTagSize(block, resolved)
}
