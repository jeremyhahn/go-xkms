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
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// lockPollInterval bounds how long withCrossProcessLock waits between
// attempts to acquire the advisory lock. The critical sections it protects
// are an engine open or a handful of small reads and writes, not a
// long-held section, so a short fixed poll keeps contention latency low
// without the complexity of a blocking flock(2) call plus a second
// mechanism (a signal, or a watcher goroutine) to make it obey ctx.
const lockPollInterval = time.Millisecond

// withCrossProcessLock runs fn while holding an exclusive advisory lock on
// the store directory dir. It guards every write this package performs --
// Put, Delete, PutIfAbsent, PutIfAllAbsent, CompareAndSwap and
// CompareAndDelete -- and the engine open in New against the same operations
// racing from another process against the same directory (#1157).
//
// The lock is taken on the directory itself, not on a lock file inside it:
// go-qrdb's file engine refuses to initialise a directory that already holds
// anything but its format marker, so a lock file created before the first
// open would make the store unopenable. Locking the directory also leaves
// nothing behind on disk.
//
// Any write this package performs must exclude every OTHER write -- guarded or not -- from another process, the
// same guarantee engineBackend's writeMu already gives this package's calls
// against goroutines in the same process (see pkg/storage/engine.go's
// writeMu doc). Without covering the unconditional Put and Delete too, a
// plain Put from a second process could still land between a first process's
// guarded read and write and defeat the guard, exactly as an unguarded Put
// would defeat writeMu in-process.
//
// A fresh file description is opened for every call rather than one held for
// the life of the FileStorage. flock(2) locks are scoped to the open file
// description, not the process or the file: two descriptions opened by the
// SAME process still contend for the lock like any other pair of processes
// would. Opening fresh each time is what lets this single mechanism serialize
// this process's own goroutines calling concurrently AND every other process,
// with no separate in-process mutex to keep paired with the flock calls.
//
// flock releases the moment the holding file description closes, including
// on process exit.
func withCrossProcessLock(ctx context.Context, dir string, fn func() error) error {
	dirFile, err := os.Open(dir) // #nosec G304 -- dir is the store root New resolved
	if err != nil {
		return &errs.Wrapped{Msg: "file storage: failed to open store directory for locking", Err: err}
	}
	defer func() { _ = dirFile.Close() }()

	fd := int(dirFile.Fd())
	for {
		flockErr := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if flockErr == nil {
			break
		}
		if flockErr != unix.EWOULDBLOCK {
			return &errs.Wrapped{Msg: "file storage: failed to acquire cross-process lock", Err: flockErr}
		}
		select {
		case <-ctx.Done():
			return &errs.Wrapped{Msg: "file storage: acquiring cross-process lock", Err: ctx.Err()}
		case <-time.After(lockPollInterval):
		}
	}
	// Unlocked explicitly, ahead of the deferred Close above, so release is
	// deterministic the instant fn returns rather than left to Close/GC
	// ordering.
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()

	return fn()
}
