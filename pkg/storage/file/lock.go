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
	"path/filepath"
	"sync"

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
// Callers in this process first take dir's turn (see dirGate), then open a
// fresh lock handle and take the platform lock on it. Both platform locks
// (flock(2), LockFileEx) are scoped to the open handle, not the process, so
// the handle is what excludes every other process; the turn is what bounds
// this process's share of the wait. A caller whose ctx ends while it waits
// for the turn leaves holding nothing -- no handle, no goroutine -- so
// however many callers time out behind a long-lived holder in another
// process, this process keeps at most one handle open and one thread blocked
// in the kernel for dir (DS-4012).
//
// The lock releases the moment the holding handle closes, including on
// process exit. openDirLock documents what each platform locks.
func withCrossProcessLock(ctx context.Context, dir string, fn func() error) error {
	turn, err := takeTurn(ctx, filepath.Clean(dir))
	if err != nil {
		return err
	}
	lock, err := openDirLock(dir)
	if err != nil {
		turn.release()
		return &errs.Wrapped{Msg: "file storage: failed to open store directory for locking", Err: err}
	}
	if err := acquireLock(ctx, lock, turn); err != nil {
		return err
	}
	defer turn.release()
	defer func() { _ = lock.close() }()
	// Unlocked explicitly, ahead of the deferred close above, so release is
	// deterministic the instant fn returns rather than left to close/GC
	// ordering.
	defer func() { _ = lock.unlock() }()

	return fn()
}

// acquireLock takes the exclusive lock on lock's handle, waiting until it is
// free or ctx ends. The caller must hold turn. On success the caller owns
// the held handle and turn; on failure neither is the caller's to use, close
// or release any more.
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
// ctx ends first, acquireLock returns and leaves the handle and turn to that
// goroutine, which unlocks and closes the handle and only then releases the
// turn once the kernel grants the lock. Holding the turn until then is what
// keeps abandoned waits from piling up: no other caller in this process can
// open a handle or start a kernel wait on dir until the abandoned one ends.
func acquireLock(ctx context.Context, lock *dirLock, turn *dirTurn) error {
	acquired, err := lock.tryLock()
	if err != nil {
		_ = lock.close()
		turn.release()
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
			turn.release()
		}
	}()

	select {
	case lockErr := <-granted:
		if lockErr != nil {
			_ = lock.close()
			turn.release()
			return &errs.Wrapped{Msg: "file storage: failed to acquire cross-process lock", Err: lockErr}
		}
		return nil
	case <-ctx.Done():
		close(abandoned)
		return &errs.Wrapped{Msg: "file storage: acquiring cross-process lock", Err: ctx.Err()}
	}
}

// dirGate admits one caller in this process at a time to a store
// directory's cross-process lock. Its turn channel has capacity one: a send
// takes the turn, a receive gives it back. Go queues blocked senders in
// arrival order, so callers in this process take turns first come, first
// served, and a sender gives up the moment its ctx ends.
type dirGate struct {
	turn chan struct{}
	refs int // guarded by gatesMu
}

// gates holds the gate of every directory some caller currently holds or
// waits for, keyed by the cleaned directory path. A gate is removed when its
// last caller leaves, so the map is bounded by the directories in use.
var (
	gatesMu sync.Mutex
	gates   = map[string]*dirGate{}
)

// dirTurn is a held turn on a directory's gate.
type dirTurn struct {
	dir  string
	gate *dirGate
}

// takeTurn waits for dir's turn until it is free or ctx ends.
func takeTurn(ctx context.Context, dir string) (*dirTurn, error) {
	gate := joinGate(dir)
	select {
	case gate.turn <- struct{}{}:
		return &dirTurn{dir: dir, gate: gate}, nil
	case <-ctx.Done():
		leaveGate(dir, gate)
		return nil, &errs.Wrapped{Msg: "file storage: acquiring cross-process lock", Err: ctx.Err()}
	}
}

// release gives the turn back. The holder must already have closed its lock
// handle. The gate is left before the turn is given back, so once the next
// caller holds the turn the previous holder's bookkeeping is complete.
func (t *dirTurn) release() {
	leaveGate(t.dir, t.gate)
	<-t.gate.turn
}

// joinGate returns dir's gate, creating it if no caller holds it, and
// counts the caller in.
func joinGate(dir string) *dirGate {
	gatesMu.Lock()
	defer gatesMu.Unlock()
	gate, ok := gates[dir]
	if !ok {
		gate = &dirGate{turn: make(chan struct{}, 1)}
		gates[dir] = gate
	}
	gate.refs++
	return gate
}

// leaveGate counts a caller out of gate, removing it from gates when no
// caller is left. A holder that leaves while still holding the turn has
// already closed its handle, so a caller that then creates a fresh gate for
// dir contends only through the platform lock, as it must.
func leaveGate(dir string, gate *dirGate) {
	gatesMu.Lock()
	defer gatesMu.Unlock()
	gate.refs--
	if gate.refs == 0 {
		delete(gates, dir)
	}
}
