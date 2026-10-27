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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

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
	if err := acquireLock(ctx, lock); err != nil {
		return err
	}
	defer func() { _ = lock.close() }()
	// Unlocked explicitly, ahead of the deferred close above, so release is
	// deterministic the instant fn returns rather than left to close/GC
	// ordering.
	defer func() { _ = lock.unlock() }()

	return fn()
}

// acquireLock takes the exclusive lock on lock's handle, waiting until it is
// free or ctx ends. On success the caller owns the held handle; on failure
// the handle is no longer the caller's to use or close.
//
// A contended lock is waited for in the kernel (flock(2) without LOCK_NB,
// LockFileEx without LOCKFILE_FAIL_IMMEDIATELY), which wakes the waiter the
// moment the holder releases. Polling a non-blocking attempt on a timer
// instead starves a waiter whenever writers keep the lock busy: a holder
// that releases and immediately re-acquires wins every time, because the
// poller only looks between its sleeps, so on a loaded host a waiter could
// miss every release until its deadline (DS-4012).
//
// The kernel wait cannot observe ctx, so it runs on its own goroutine. When
// ctx ends first, acquireLock returns and leaves the handle to that
// goroutine, which releases and closes it once the kernel grants the lock:
// an abandoned wait never keeps the lock from the next caller.
func acquireLock(ctx context.Context, lock *dirLock) error {
	acquired, err := lock.tryLock()
	if err != nil {
		_ = lock.close()
		return &errs.Wrapped{Msg: "file storage: failed to acquire cross-process lock", Err: err}
	}
	if acquired {
		return nil
	}

	granted := make(chan error)
	abandoned := make(chan struct{})
	go func() {
		lockErr := lock.lock()
		select {
		case granted <- lockErr:
		case <-abandoned:
			if lockErr == nil {
				_ = lock.unlock()
			}
			_ = lock.close()
		}
	}()

	select {
	case lockErr := <-granted:
		if lockErr != nil {
			_ = lock.close()
			return &errs.Wrapped{Msg: "file storage: failed to acquire cross-process lock", Err: lockErr}
		}
		return nil
	case <-ctx.Done():
		close(abandoned)
		return &errs.Wrapped{Msg: "file storage: acquiring cross-process lock", Err: ctx.Err()}
	}
}
