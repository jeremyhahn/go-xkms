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

package pintpm2

import "errors"

// ErrFIDO2HashCacheFailed indicates the TPM accepted the user PIN but its
// CTAP2 PIN hash could not be placed in locked memory -- the process's
// locked-memory budget was exhausted (enclave.ErrBudgetExhausted), the kernel
// refused to lock the pages (enclave.ErrLockedMemoryUnavailable), or the
// budget could not be read (enclave.ErrLimitDiscoveryFailed). The cause is
// wrapped alongside it. No hash is cached afterwards, so VerifyFIDO2Hash
// reports false until a later PIN operation caches one.
var ErrFIDO2HashCacheFailed = errors.New("pintpm2: could not cache the FIDO2 PIN hash in locked memory")

// ErrFIDO2HashDestroyFailed is returned when the locked memory holding a
// cached FIDO2 PIN hash cannot be wiped and released.
var ErrFIDO2HashDestroyFailed = errors.New("pintpm2: could not wipe the cached FIDO2 PIN hash")
