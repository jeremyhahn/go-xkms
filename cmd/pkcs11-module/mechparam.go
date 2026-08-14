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

package main

// Mechanism-parameter admission policy for the cgo boundary.
//
// The rules here decide whether the bytes behind CK_MECHANISM.pParameter may
// be read as the structure the mechanism is defined with. They are kept in a
// file that does not import "C" so they can be exercised directly by unit
// tests; exports.go supplies the C structure sizes and the decoders that do
// the actual reading.

import (
	"unsafe"

	module "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// mechanismParameterDecoder describes the CK_MECHANISM parameter structure one
// mechanism is defined with, and how to read it.
//
// Keeping the size and the decoder in one value is deliberate: the size is the
// bound that makes the decoder's pointer cast safe, so the two must never be
// able to drift apart.
type mechanismParameterDecoder struct {
	// StructSize is the size, in bytes, of the C structure the specification
	// defines for the mechanism, as measured by the compiler that built this
	// module. PKCS#11 v3.2 section 5.2 makes CK_MECHANISM.ulParameterLen the
	// authoritative length of the buffer CK_MECHANISM.pParameter addresses,
	// so a shorter declaration means Decode would read past the end of memory
	// the caller owns.
	StructSize uintptr

	// Required reports whether the mechanism can be performed at all without
	// its parameter structure. When it is true an absent parameter is refused
	// rather than defaulted, because a default performs a different
	// cryptographic operation than the caller asked for and the substitution
	// is invisible to it.
	Required bool

	// Unsupported reports that this module cannot perform what the parameter
	// selects, so a caller supplying one is refused with
	// CKR_MECHANISM_PARAM_INVALID.
	//
	// The alternative is to accept the parameter and perform the mechanism's
	// default instead, which is the outcome that must never happen: it hands
	// the caller output from a different cryptographic scheme than the one it
	// asked for, under CKR_OK, with nothing anywhere to indicate the
	// substitution. A refusal is visible at the call that asked; a downgrade
	// is visible nowhere.
	//
	// The decoder is kept alongside the flag rather than deleted, so that the
	// capability landing upstream is a matter of clearing the flag.
	Unsupported bool

	// Decode reads the parameter structure at pParameter and returns the Go
	// value to attach to Mechanism.TypedParameter. It reports ok=false when a
	// length carried inside the structure is not addressable as a Go slice, in
	// which case the call is refused with CKR_MECHANISM_PARAM_INVALID rather
	// than proceeding with the field silently dropped.
	//
	// Decode is only ever called after checkMechanismParameter has returned
	// CKR_OK for the same mechanism, which is what bounds the cast it makes.
	Decode func(pParameter unsafe.Pointer) (typed any, ok bool)
}

// checkMechanismParameter reports the CK_RV a Cryptoki entry point must return
// for the parameter a caller supplied alongside a mechanism, or CKR_OK when
// the parameter may be read.
//
// decoder is nil for a mechanism that takes no fixed-layout parameter
// structure; hasPointer reports whether CK_MECHANISM.pParameter is non-NULL,
// and paramLen is CK_MECHANISM.ulParameterLen verbatim.
//
// PKCS#11 v3.2 section 5.2 defines the pair as a buffer and its length, which
// gives four shapes this refuses:
//
//   - A length with no buffer behind it, which no reader can honour.
//   - A length shorter than the mechanism's structure, which would make the
//     decoder's cast an out-of-bounds read across the C boundary. Section 5.2
//     names CKR_MECHANISM_PARAM_INVALID for a parameter the token cannot use.
//   - An absent parameter for a mechanism that has no meaning without one,
//     for example CKM_RSA_PKCS_OAEP (section 6.1.7), whose digest, mask
//     generation function and label all live in CK_RSA_PKCS_OAEP_PARAMS.
//     SoftHSM2 answers CKR_ARGUMENTS_BAD here and this module matches it.
//   - A well-formed parameter selecting something this module cannot do. See
//     mechanismParameterDecoder.Unsupported.
func checkMechanismParameter(decoder *mechanismParameterDecoder, hasPointer bool, paramLen uint64) module.CK_RV {
	if !hasPointer && paramLen > 0 {
		return module.CKR_ARGUMENTS_BAD
	}

	if decoder == nil {
		return module.CKR_OK
	}

	if !hasPointer || paramLen == 0 {
		if decoder.Required {
			return module.CKR_ARGUMENTS_BAD
		}
		return module.CKR_OK
	}

	if paramLen < uint64(decoder.StructSize) {
		return module.CKR_MECHANISM_PARAM_INVALID
	}

	if decoder.Unsupported {
		return module.CKR_MECHANISM_PARAM_INVALID
	}

	return module.CKR_OK
}
