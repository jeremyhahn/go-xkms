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

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrSealedObjectRejected is joined with the TPM's response code when
	// TPM2_Load refuses a sealed object's public or private area (or the
	// areas exceed any TPM-created size, ErrObjectAreaTooLarge), or when
	// TPM2_Unseal refuses the loaded object as not sealed data: the
	// private area's integrity HMAC does not verify (TPM_RC_INTEGRITY --
	// tampered, or created under a different parent or TPM), the areas are
	// not bound to each other (TPM_RC_BINDING), or either area does not
	// unmarshal (TPM_RC_SIZE, TPM_RC_INSUFFICIENT, and the other
	// parameter-scoped response codes; TPM_RC_SENSITIVE for a private area
	// that decrypts to garbage).
	ErrSealedObjectRejected = errors.New("tpm: TPM2_Load rejected the sealed object")

	// ErrSealedObjectIncomplete is returned when sealed data carries one of
	// TPMPublic and TPMPrivate but not the other: a sealed object is the
	// pair, and half of it was lost or stripped.
	ErrSealedObjectIncomplete = errors.New("tpm: sealed data carries only one of the public and private areas")

	// ErrObjectAreaTooLarge is returned, before anything is sent to the TPM,
	// when an object's public or private area is larger than maxLoadAreaSize,
	// or the two together larger than maxLoadAreasSize: no object a TPM
	// creates is that large, and a TPM2_Load carrying it would only be
	// refused as a whole command (TPM_RC_COMMAND_SIZE).
	ErrObjectAreaTooLarge = errors.New("tpm: object public or private area exceeds any TPM-created size")

	// ErrSealAADTooLarge is returned when a seal with additional
	// authenticated data would not fit the TPM's sealed-data capacity once
	// the AAD binding is added.
	ErrSealAADTooLarge = errors.New("tpm: data plus the AAD binding exceeds the sealed object's capacity")
)

// sealedAADMagic opens a sealed secret that carries an AAD binding. It is a
// fixed random value, so a secret sealed without one -- by this build or an
// earlier one -- starts with it only by a 2^-128 accident, and Seal wraps any
// such secret anyway, so the two forms never collide.
var sealedAADMagic = []byte{
	0x9b, 0x3e, 0x61, 0xd4, 0x0a, 0xc7, 0x52, 0xf8,
	0x2d, 0x86, 0xe1, 0x4f, 0xb0, 0x17, 0x7c, 0x35,
}

// sealedAADHeaderSize is the magic plus the SHA-256 digest of the AAD.
var sealedAADHeaderSize = len(sealedAADMagic) + sha256.Size

// maxLoadAreaSize bounds a TPM2B_PUBLIC or TPM2B_PRIVATE handed to
// TPM2_Load, and maxLoadAreasSize the two together. The largest object a TPM
// creates -- an RSA-4096 key with a SHA-512 authPolicy -- has a public area
// of roughly 600 bytes and a private area of roughly 900; a keyed-hash sealed
// object is a few hundred bytes in all. The bounds are far above every one of
// them, and a Load carrying maxLoadAreasSize bytes of areas plus its header,
// parent handle, authorization area (one session with a SHA-512 nonce and
// HMAC is under 160 bytes) and size fields stays well inside the 4096-byte
// MAX_COMMAND_SIZE PC Client TPMs implement, so an oversized object is
// reported here rather than as a whole-command TPM_RC_COMMAND_SIZE that does
// not name the object.
const (
	maxLoadAreaSize  = 2048
	maxLoadAreasSize = 3072
)

// checkLoadAreaSizes refuses public and private areas no TPM could have
// created, alone or together, before anything is sent to the TPM.
func checkLoadAreaSizes(public, private []byte) error {
	if len(public) > maxLoadAreaSize || len(private) > maxLoadAreaSize || len(public)+len(private) > maxLoadAreasSize {
		return &errs.Detail{Err: ErrObjectAreaTooLarge, Detail: fmt.Sprintf(
			"public %d bytes, private %d bytes; limits %d each, %d together",
			len(public), len(private), maxLoadAreaSize, maxLoadAreasSize)}
	}
	return nil
}

// maxSealedDataSize is MAX_SYM_DATA, the largest TPM2B_SENSITIVE_DATA a
// keyed-hash sealed object holds on every TPM (TCG TPM 2.0 Library Part 2,
// Table 2:2 and section 11.1.14).
const maxSealedDataSize = 128

// bindSealAAD returns the secret to seal for data under aad, and whether that
// secret is a buffer of its own the caller must wipe once it is copied.
//
// A TPM keyed-hash object has no additional-authenticated-data input, so the
// binding travels inside the sealed secret itself: magic || SHA-256(aad) ||
// data. The TPM integrity-protects the whole secret, so the digest cannot be
// altered without TPM2_Load refusing the object, and Unseal compares it with
// the AAD it is handed. A seal without AAD returns data unchanged -- the
// format every earlier build produced -- unless data itself begins with the
// magic, which is wrapped so Unseal never mistakes it for a binding.
//
// A nil data with AAD seals a fresh 32-byte random secret, the same secret
// the TPM path generates for a nil-data seal without AAD.
func bindSealAAD(random io.Reader, data, aad []byte) (secret []byte, owned bool, err error) {
	if len(aad) == 0 && !bytes.HasPrefix(data, sealedAADMagic) {
		return data, false, nil
	}
	if data == nil {
		data = make([]byte, 32)
		defer enclave.Wipe(data)
		if _, err := io.ReadFull(random, data); err != nil {
			return nil, false, err
		}
	}
	if sealedAADHeaderSize+len(data) > maxSealedDataSize {
		return nil, false, &errs.Detail{Err: ErrSealAADTooLarge, Detail: "at most 80 bytes of data can be sealed with AAD"}
	}
	digest := sha256.Sum256(aad)
	bound := make([]byte, 0, sealedAADHeaderSize+len(data))
	bound = append(bound, sealedAADMagic...)
	bound = append(bound, digest[:]...)
	return append(bound, data...), true, nil
}

// openSealAAD checks the AAD binding of an unsealed secret and returns the
// data it protects. A secret without a binding was sealed without AAD and
// opens only for an empty aad; one with a binding opens only for the aad
// whose digest it carries. Any mismatch is a sealed-data authentication
// failure. The returned data is a fresh copy; secret is wiped when it
// carried a binding.
func openSealAAD(secret, aad []byte) ([]byte, error) {
	if !bytes.HasPrefix(secret, sealedAADMagic) {
		if len(aad) != 0 {
			enclave.Wipe(secret)
			return nil, types.SealedDataAuthenticationError("sealed without additional authenticated data", nil)
		}
		return secret, nil
	}
	defer enclave.Wipe(secret)
	if len(secret) < sealedAADHeaderSize {
		return nil, types.SealedDataAuthenticationError("AAD binding is truncated", nil)
	}
	digest := sha256.Sum256(aad)
	if subtle.ConstantTimeCompare(secret[len(sealedAADMagic):sealedAADHeaderSize], digest[:]) != 1 {
		return nil, types.SealedDataAuthenticationError("additional authenticated data does not match", nil)
	}
	return bytes.Clone(secret[sealedAADHeaderSize:]), nil
}

// loadRejectsSealedObject reports whether err, returned while loading a
// sealed object, is TPM2_Load refusing the object's public or private area.
//
// TPM2_Load's only parameters are inPrivate and inPublic, so any
// parameter-scoped format-1 response code from it names the sealed object
// itself; TPM_RC_SENSITIVE is the one format-0 code Load returns for an input
// (a private area that decrypts to an unparseable sensitive area). Handle-
// and session-scoped codes (a missing parent, a parent policy that fails),
// format-0 resource and failure codes, and warnings (TPM_RC_RETRY,
// TPM_RC_OBJECT_MEMORY, ...) are the environment. Errors that are not TPM
// response codes -- transport, storage -- never match.
func loadRejectsSealedObject(err error) bool {
	if errors.Is(err, ErrObjectAreaTooLarge) {
		return true
	}
	var fmt1 tpm2.TPMFmt1Error
	if errors.As(err, &fmt1) {
		isParameter, _ := fmt1.Parameter()
		return isParameter
	}
	return errors.Is(err, tpm2.TPMRCSensitive)
}

// unsealObjectRejections are the response codes TPM2_Unseal returns, scoped
// to its itemHandle, when the loaded object is not a sealed data object at
// all: TPM_RC_TYPE (not a keyed-hash object) and TPM_RC_ATTRIBUTES (a
// keyed-hash object with sign or decrypt set -- an HMAC key). They are
// checked after authorization, so they are never a policy or UserAuth
// failure.
var unsealObjectRejections = map[tpm2.TPMRC]struct{}{
	tpm2.TPMRCType:       {},
	tpm2.TPMRCAttributes: {},
}

// unsealRejectsObject reports whether err, returned by TPM2_Unseal, says the
// loaded object is not sealed data: one of unsealObjectRejections scoped to
// handle 1, the item. Session-scoped codes (TPM_RC_POLICY_FAIL,
// TPM_RC_AUTH_FAIL, TPM_RC_BAD_AUTH), warnings and transport errors never
// match.
func unsealRejectsObject(err error) bool {
	var fmt1 tpm2.TPMFmt1Error
	if !errors.As(err, &fmt1) {
		return false
	}
	isHandle, index := fmt1.Handle()
	if !isHandle || index != 1 {
		return false
	}
	for code := range unsealObjectRejections {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}

// classifyUnsealError marks a TPM2_Unseal refusal of an object that is not
// sealed data as a sealed-data authentication failure, and returns every
// other error -- policy and authorization failures included -- as is.
func classifyUnsealError(err error) error {
	if unsealRejectsObject(err) {
		return types.SealedDataAuthenticationError("",
			&errs.Joined{Lead: ErrSealedObjectRejected, Cause: err})
	}
	return err
}

// classifyLoadError marks a TPM2_Load refusal of the sealed object as a
// sealed-data authentication failure, and returns every other error as is.
func classifyLoadError(err error) error {
	if loadRejectsSealedObject(err) {
		return types.SealedDataAuthenticationError("",
			&errs.Joined{Lead: ErrSealedObjectRejected, Cause: err})
	}
	return err
}
