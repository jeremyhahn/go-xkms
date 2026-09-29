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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// crossLockCounterKey is the shared counter key every accumulation test below
// increments. It lives under "keys/" so validateStorageKey and the 0600
// permission-widening path both run, matching how the PKCS#11 module's
// failed-attempt counter (#1144) is stored.
const crossLockCounterKey = "keys/shared-counter"

// crossLockCASRetryBudget bounds one increment's compare-and-swap retry loop.
// It mirrors pkg/pkcs11/module's attemptCASRetryBudget: a losing writer's
// retry count is not a function of contender count, since a winner that keeps
// getting rescheduled first can beat a loser an unbounded number of times in a
// row, so the budget has to stay generous rather than proportional to the
// worker count below.
const crossLockCASRetryBudget = 4096

// incrementSharedCounter performs ONE atomic increment of crossLockCounterKey
// against store: read, then retry a compare-and-swap (bootstrapping via
// PutIfAbsent when the counter is absent) until it wins or the retry budget is
// exhausted. This is the same shape as
// pkg/pkcs11/module/storage.go's updateViaCAS, reimplemented here rather than
// imported so pkg/storage/file's tests do not depend on the pkcs11 module --
// this package sits below it.
func incrementSharedCounter(t testing.TB, store storage.Backend) {
	t.Helper()
	ctx := context.Background()
	cas, ok := store.(storage.CompareAndSwapper)
	if !ok {
		t.Fatalf("backend does not implement CompareAndSwapper")
	}

	expected, err := store.Get(ctx, crossLockCounterKey)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}

	for attempt := 0; attempt < crossLockCASRetryBudget; attempt++ {
		if expected == nil {
			stored, err := store.PutIfAbsent(ctx, crossLockCounterKey, []byte("1"))
			if err != nil {
				t.Fatalf("PutIfAbsent: %v", err)
			}
			if stored {
				return
			}
			expected, err = store.Get(ctx, crossLockCounterKey)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					runtime.Gosched()
					continue
				}
				t.Fatalf("Get: %v", err)
			}
			continue
		}

		current, parseErr := strconv.ParseUint(string(expected), 10, 64)
		if parseErr != nil {
			t.Fatalf("corrupt counter %q: %v", expected, parseErr)
		}
		next := []byte(strconv.FormatUint(current+1, 10))

		swapped, observed, err := cas.CompareAndSwap(ctx, crossLockCounterKey, expected, next)
		if err != nil {
			t.Fatalf("CompareAndSwap: %v", err)
		}
		if swapped {
			return
		}
		expected = observed
		runtime.Gosched()
	}
	t.Fatalf("exhausted %d compare-and-swap retries incrementing %q", crossLockCASRetryBudget, crossLockCounterKey)
}

// readSharedCounter returns the shared counter's current value, or 0 if it
// was never created.
func readSharedCounter(t testing.TB, store storage.Backend) uint64 {
	t.Helper()
	data, err := store.Get(context.Background(), crossLockCounterKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return 0
		}
		t.Fatalf("Get: %v", err)
	}
	v, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil {
		t.Fatalf("corrupt counter %q: %v", data, err)
	}
	return v
}

// TestFileStorage_CompareAndSwap_ConcurrentAccumulates is the single-process
// baseline #1157's fix must not regress: many goroutines over one FileStorage
// instance, each racing incrementSharedCounter, must count every increment.
// withCrossProcessLock opens a fresh file description per call specifically
// so it keeps serializing this process's own goroutines the way
// engineBackend's writeMu always did (see lock.go) -- this test is the proof.
func TestFileStorage_CompareAndSwap_ConcurrentAccumulates(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const goroutines = 8
	const perGoroutine = 25

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				incrementSharedCounter(t, store)
			}
		}()
	}
	wg.Wait()

	want := uint64(goroutines * perGoroutine)
	if got := readSharedCounter(t, store); got != want {
		t.Fatalf("shared counter = %d, want %d: a concurrent increment within one process was lost", got, want)
	}
}

// crossProcessWorkerDirEnv and crossProcessWorkerCountEnv drive the re-exec'd
// worker below: the directory of the shared store, and how many increments
// this worker process performs against it.
const (
	crossProcessWorkerDirEnv   = "XKMS_CROSSLOCK_WORKER_DIR"
	crossProcessWorkerCountEnv = "XKMS_CROSSLOCK_WORKER_COUNT"
)

// TestFileStorage_CompareAndSwap_CrossProcessAccumulates is #1157's actual
// regression test: several OS processes -- not goroutines -- sharing one
// store directory, each racing incrementSharedCounter, must still count every
// increment. This is the property the PKCS#11 file-token PIN attempt counter
// (#1144) depends on when several module instances share one token
// directory: a lost update here is a lost failed-attempt charge there, which
// is a lockout that can be bypassed by running from two processes instead of
// one.
//
// It re-execs this test binary as worker processes, the same pattern
// pkg/crypto/fips uses to run code under a distinct process state
// (runOutsideFIPS): XKMS_CROSSLOCK_WORKER_DIR being set is what tells a
// worker process to run runCrossProcessWorker and exit, rather than the
// top-level orchestration below.
func TestFileStorage_CompareAndSwap_CrossProcessAccumulates(t *testing.T) {
	if dir := os.Getenv(crossProcessWorkerDirEnv); dir != "" {
		runCrossProcessWorker(t, dir)
		return
	}

	dir := t.TempDir()
	const workers = 4
	const perWorker = 40

	type outcome struct {
		out []byte
		err error
	}
	results := make([]outcome, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestFileStorage_CompareAndSwap_CrossProcessAccumulates$", "-test.v")
			cmd.Env = append(os.Environ(),
				crossProcessWorkerDirEnv+"="+dir,
				crossProcessWorkerCountEnv+"="+strconv.Itoa(perWorker),
			)
			out, err := cmd.CombinedOutput()
			results[i] = outcome{out: out, err: err}
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("worker %d failed: %v\n%s", i, r.err, r.out)
		}
		if !strings.Contains(string(r.out), "PASS") {
			t.Fatalf("worker %d did not pass:\n%s", i, r.out)
		}
	}

	store, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	want := uint64(workers * perWorker)
	if got := readSharedCounter(t, store); got != want {
		t.Fatalf("shared counter across %d processes = %d, want %d: "+
			"a cross-process compare-and-swap lost an update", workers, got, want)
	}
}

// runCrossProcessWorker is the child-process body for
// TestFileStorage_CompareAndSwap_CrossProcessAccumulates: it opens its own
// FileStorage over the shared directory -- a fresh backend, fresh engine, and
// fresh withCrossProcessLock, wholly independent of the parent's -- and
// performs its share of increments before exiting.
func runCrossProcessWorker(t *testing.T, dir string) {
	t.Helper()
	count, err := strconv.Atoi(os.Getenv(crossProcessWorkerCountEnv))
	if err != nil {
		t.Fatalf("%s: %v", crossProcessWorkerCountEnv, err)
	}

	store, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = store.Close() }()

	for i := 0; i < count; i++ {
		incrementSharedCounter(t, store)
	}
	fmt.Fprintln(os.Stdout, "worker done")
}
