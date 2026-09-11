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

var _ GuardedWriteReporter = (*PrefixBackend)(nil)

// GuardedWritesAvailable reports whether the WRAPPED backend can actually
// serve a guarded write: PrefixBackend namespaces keys and adds no writer of
// its own, so it can neither create the capability nor remove it.
//
// It asks GuardedWritesUsable rather than GuardedWritesAvailable, and the
// difference is the whole point. PrefixBackend declares CompareAndSwap and
// CompareAndDelete UNCONDITIONALLY — it has to, because a decorator cannot add
// a method depending on what it wraps, and those methods return
// ErrCompareAndSwapUnsupported / ErrCompareAndDeleteUnsupported when the inner
// backend does not offer them. So PrefixBackend's own method set says nothing
// about whether a guarded write will work, and a caller that read only the
// method set plus an availability report would take a prefixed view of a
// backend with no guarded writes at all for an atomic store, and fail on the
// first one.
func (p *PrefixBackend) GuardedWritesAvailable() bool {
	return GuardedWritesUsable(p.inner)
}
