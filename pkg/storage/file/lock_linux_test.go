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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// openHandleCount reports how many file descriptors this process has open.
func openHandleCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// kernelWaiterCount reports how many goroutines are parked in acquireLock's
// kernel wait.
func kernelWaiterCount() int {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "file.acquireLock.func1(")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestWithCrossProcessLock_TimedOutWaitsStayBounded times out many callers
// while another handle -- standing in for another process -- holds the
// lock. However many time out, this process keeps at most one extra handle
// open and one goroutine in the kernel wait, every caller gets the typed
// deadline error, and the lock is still acquired once the holder releases.
func TestWithCrossProcessLock_TimedOutWaitsStayBounded(t *testing.T) {
	const callers = 16
	dir := t.TempDir()
	holder, err := openDirLock(dir)
	if err != nil {
		t.Fatalf("openDirLock: %v", err)
	}
	defer func() { _ = holder.close() }()
	if err := holder.lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}
	baseHandles := openHandleCount(t)

	for i := 0; i < callers; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		ran := false
		err := withCrossProcessLock(ctx, dir, func() error {
			ran = true
			return nil
		})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("caller %d error = %v, want context.DeadlineExceeded", i, err)
		}
		var wrapped *errs.Wrapped
		if !errors.As(err, &wrapped) {
			t.Fatalf("caller %d error %T is not *errs.Wrapped", i, err)
		}
		if ran {
			t.Fatalf("caller %d ran fn while another handle held the lock", i)
		}
	}

	if waiters := kernelWaiterCount(); waiters != 1 {
		t.Fatalf("%d goroutines wait in the kernel after %d timed-out callers, want 1", waiters, callers)
	}
	if extra := openHandleCount(t) - baseHandles; extra > 1 {
		t.Fatalf("%d extra handles open after %d timed-out callers, want at most 1", extra, callers)
	}

	if err := holder.unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := withCrossProcessLock(bounded, dir, func() error { return nil }); err != nil {
		t.Fatalf("lock not acquired after the holder released: %v", err)
	}
	if extra := openHandleCount(t) - baseHandles; extra > 0 {
		t.Fatalf("%d handles left open after the abandoned wait ended", extra)
	}
	gatesMu.Lock()
	_, left := gates[filepath.Clean(dir)]
	gatesMu.Unlock()
	if left {
		t.Fatal("directory gate left behind after every caller finished")
	}
}
