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

package file

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// lockPollInterval bounds how long withCrossProcessLock waits between
// attempts to acquire the advisory lock. The critical sections it protects
// are an engine open or a handful of small reads and writes, not a
// long-held section, so a short fixed poll keeps contention latency low
// without the complexity of a blocking lock call plus a second mechanism (a
// signal, or a watcher goroutine) to make it obey ctx.
const lockPollInterval = time.Millisecond

// withCrossProcessLock runs fn while holding an exclusive advisory lock on
// the store directory dir. It guards every write this package performs --
// Put, Delete, PutIfAbsent, PutIfAllAbsent, CompareAndSwap and
// CompareAndDelete -- and the engine open in New against the same operations
// racing from another process against the same directory (#1157).
//
// Any write this package performs must exclude every OTHER write -- guarded or not -- from another process, the
// same guarantee engineBackend's writeMu already gives this package's calls
// against goroutines in the same process (see pkg/storage/engine.go's
// writeMu doc). Without covering the unconditional Put and Delete too, a
// plain Put from a second process could still land between a first process's
// guarded read and write and defeat the guard, exactly as an unguarded Put
// would defeat writeMu in-process.
//
// A fresh lock handle is opened for every call rather than one held for the
// life of the FileStorage. Both platform locks (flock(2), LockFileEx) are
// scoped to the open handle, not the process: two handles opened by the SAME
// process still contend for the lock like any other pair of processes would.
// Opening fresh each time is what lets this single mechanism serialize this
// process's own goroutines calling concurrently AND every other process,
// with no separate in-process mutex to keep paired with the lock calls.
//
// The lock releases the moment the holding handle closes, including on
// process exit. openDirLock documents what each platform locks.
func withCrossProcessLock(ctx context.Context, dir string, fn func() error) error {
	lock, err := openDirLock(dir)
	if err != nil {
		return &errs.Wrapped{Msg: "file storage: failed to open store directory for locking", Err: err}
	}
	defer func() { _ = lock.close() }()

	for {
		acquired, lockErr := lock.tryLock()
		if lockErr != nil {
			return &errs.Wrapped{Msg: "file storage: failed to acquire cross-process lock", Err: lockErr}
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return &errs.Wrapped{Msg: "file storage: acquiring cross-process lock", Err: ctx.Err()}
		case <-time.After(lockPollInterval):
		}
	}
	// Unlocked explicitly, ahead of the deferred close above, so release is
	// deterministic the instant fn returns rather than left to close/GC
	// ordering.
	defer func() { _ = lock.unlock() }()

	return fn()
}
