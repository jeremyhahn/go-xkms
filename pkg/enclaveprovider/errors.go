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

package enclaveprovider

import (
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Construction errors.
var (
	// ErrNilSealer is returned by every constructor given a nil sealer.
	ErrNilSealer = errors.New("enclaveprovider: sealer is nil")

	// ErrNilKeyAttributes is returned by every constructor given nil
	// sealing-key attributes.
	ErrNilKeyAttributes = errors.New("enclaveprovider: sealing key attributes are nil")

	// ErrSealerUnavailable is returned by NewKeyProtector and ProvisionRoot
	// when the sealer reports that it cannot seal.
	ErrSealerUnavailable = errors.New("enclaveprovider: sealer cannot seal")
)

// Operation errors. Each wraps its cause, which stays reachable with
// errors.Is and errors.As: the backend's own error, or the context's.
var (
	// ErrProtectFailed is returned by KeyProtector.Protect when the key could
	// not be sealed.
	ErrProtectFailed = errors.New("enclaveprovider: could not protect key")

	// ErrUnprotectFailed is returned by KeyProtector.Unprotect for a failure
	// that says nothing about the blob: an ended context or a backend that
	// could not unseal.
	ErrUnprotectFailed = errors.New("enclaveprovider: could not unprotect key")

	// ErrUnsealRootFailed is RootUnsealer.UnsealRoot's ErrUnprotectFailed.
	ErrUnsealRootFailed = errors.New("enclaveprovider: could not unseal root key")

	// ErrProvisionRootFailed is returned by ProvisionRoot when the root key
	// could not be generated in locked memory or sealed.
	ErrProvisionRootFailed = errors.New("enclaveprovider: could not provision root key")

	// ErrInvalidKeyLength is returned by KeyProtector.Protect for a key that
	// is not enclave.RootKeyBytes long.
	ErrInvalidKeyLength = errors.New("enclaveprovider: key must be enclave.RootKeyBytes long")

	// ErrEnvelopeTooLarge is returned when the backend's sealed data does not
	// fit the envelope's size bound.
	ErrEnvelopeTooLarge = errors.New("enclaveprovider: sealed data exceeds the envelope size bound")
)

// Authentication causes. Every error carrying one also matches
// enclave.ErrSealedAuthentication.
var (
	// ErrMalformedEnvelope reports a blob that is not an envelope this
	// package writes: wrong magic or version, a truncated or overlong field,
	// unordered metadata, or trailing bytes.
	ErrMalformedEnvelope = errors.New("enclaveprovider: malformed envelope")

	// ErrWrongPurpose reports an envelope made for the other seam: a sealed
	// root handed to Unprotect, or a protected key handed to NewRootUnsealer.
	ErrWrongPurpose = errors.New("enclaveprovider: envelope was made for another purpose")

	// ErrKeyLengthMismatch reports a destination whose length is not the
	// length of the key the envelope holds.
	ErrKeyLengthMismatch = errors.New("enclaveprovider: destination length does not match the protected key")

	// ErrEnvelopeTag reports an envelope whose HMAC tag does not verify under
	// the key it unsealed to: a field the backend does not authenticate was
	// altered.
	ErrEnvelopeTag = errors.New("enclaveprovider: envelope tag does not verify")
)

// authenticationError reports a blob the provider did not produce. It matches
// enclave.ErrSealedAuthentication and cause.
func authenticationError(cause error, detail string) error {
	return &errs.Joined{Lead: enclave.ErrSealedAuthentication, Detail: detail, Cause: cause}
}
