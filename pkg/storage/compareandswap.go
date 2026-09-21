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

package storage

import "context"

// CompareAndSwapper is an OPTIONAL capability a Backend may implement: an atomic
// value compare-and-swap. It is a separate interface rather than a Backend
// method so a backend that cannot provide it is not forced to, mirroring how
// go-qrdb splits its optional AtomicKVStore / TransactionClient from the base
// KVStore. A caller that needs the guarantee type-asserts for it.
//
// It is the primitive a multi-client shared resource needs when PutIfAbsent is
// not enough — a value that is read, changed, and written back, where two
// clients must not both read the old value and both write. The PKCS#11 module's
// remote lockout counter is exactly this: two hosts sharing one token must not
// each increment from the same base and lose a failed-attempt.
type CompareAndSwapper interface {
	// CompareAndSwap atomically stores new at key only if the key's current
	// value equals expected, and reports the outcome.
	//
	// A swap can meaningfully edit; it cannot meaningfully create. So an absent
	// key REFUSES regardless of expected: expected is compared as raw bytes and
	// nil is NOT a wildcard for "require absent" — it is equivalent to an empty
	// slice, so it matches only a stored empty value, exactly the convention
	// CompareAndDeleter.CompareAndDelete already uses. A caller that wants to
	// create a key only when it is absent calls PutIfAbsent, the verb that
	// exists for exactly that precondition; a caller that needs "absent OR
	// equals X" in one guarded write has no primitive for that today and must
	// not approximate it here (#186).
	//
	// swapped is true when new was written. When swapped is false, current holds
	// the value that was actually present (nil when the key was absent), so a
	// caller doing a read-modify-write can recompute against it and retry. A
	// non-nil error means the outcome is unknown and the caller must not assume
	// either way.
	//
	// A replicated/clustered implementation MUST make this atomic across nodes
	// (a consensus compare-and-set); a single-process implementation satisfies
	// it with internal synchronization.
	CompareAndSwap(ctx context.Context, key string, expected, new []byte) (swapped bool, current []byte, err error)
}
