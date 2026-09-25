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

package sealed

import "errors"

var (
	// ErrSealFailed indicates the seal operation failed.
	ErrSealFailed = errors.New("sealed: seal operation failed")

	// ErrUnsealFailed indicates the unseal operation failed.
	ErrUnsealFailed = errors.New("sealed: unseal operation failed")

	// ErrSealerNotAvailable indicates the sealer is not available for sealing.
	ErrSealerNotAvailable = errors.New("sealed: sealer not available")

	// ErrMarshalFailed indicates JSON marshaling of sealed data failed.
	ErrMarshalFailed = errors.New("sealed: marshal failed")

	// ErrUnmarshalFailed indicates JSON unmarshaling of sealed data failed.
	ErrUnmarshalFailed = errors.New("sealed: unmarshal failed")

	// ErrGuardEnclaveFailed indicates the unsealed guard value could not be
	// placed in locked memory, so the comparison was never performed. It is
	// distinct from ErrUnsealFailed: the decryption succeeded, and what failed
	// is the protection the comparison is required to happen under -- the
	// process allocator's budget refusing it (enclave.ErrBudgetExhausted) or
	// the kernel refusing to lock the pages (enclave.ErrLockedMemoryUnavailable).
	// The cause is wrapped alongside it.
	ErrGuardEnclaveFailed = errors.New("sealed: could not protect unsealed guard value")

	// ErrUnsealIntoUnsupported indicates the configured sealer cannot decrypt
	// into caller-supplied memory (types.UnsealerInto), so the guarded delete
	// cannot compare the unsealed value without first materializing it on the
	// heap. There is deliberately no heap fallback.
	ErrUnsealIntoUnsupported = errors.New("sealed: sealer cannot unseal into locked memory")

	// ErrGuardEscapedEnclave indicates the decryption did not land in the locked
	// region it was aimed at -- it reallocated onto the heap instead, which
	// looks like success and is exactly the exposure the locked region exists to
	// prevent.
	ErrGuardEscapedEnclave = errors.New("sealed: unsealed guard value escaped locked memory")
)
