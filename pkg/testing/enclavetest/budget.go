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

// Package enclavetest runs a test against a bounded go-enclave process
// allocator, so code that admits locked memory through
// enclave.ProcessAllocator can have its budget-exhaustion path exercised
// deterministically.
//
// The process allocator is one-shot: enclave.SetAllocator succeeds only
// before anything in the process has allocated. A test binary cannot
// guarantee that, and a budget installed there would leak into every other
// test, so the test is re-executed in a child process that installs the
// budget first. Nothing on the host changes: the budget is an in-process
// admission limit, not RLIMIT_MEMLOCK, and it holds regardless of the
// runner's privileges.
package enclavetest

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// childEnv marks a process as the budgeted child of RunWithBudget.
const childEnv = "XKMS_ENCLAVETEST_BUDGET_CHILD"

// RunWithBudget reports whether the caller is running inside a child
// process whose enclave.ProcessAllocator admits at most budget bytes.
//
// In the parent it re-executes the current test binary for t alone, fails t
// if the child fails, and returns false; the caller returns immediately. In
// the child it installs the budget and returns true; the caller then runs
// its assertions:
//
//	func TestRefusal(t *testing.T) {
//		if !enclavetest.RunWithBudget(t, int64(os.Getpagesize())) {
//			return
//		}
//		// ... every enclave.ProcessAllocator() call now sees the budget.
//	}
//
// Budgets are charged in whole pages, so a budget of one page admits
// exactly one small enclave at a time.
func RunWithBudget(t *testing.T, budget int64) bool {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		alloc, err := enclave.NewAllocator(budget)
		if err != nil {
			t.Fatalf("enclavetest: NewAllocator(%d): %v", budget, err)
		}
		if err := enclave.SetAllocator(alloc); err != nil {
			t.Fatalf("enclavetest: SetAllocator: %v", err)
		}
		return true
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("enclavetest: budgeted child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("enclavetest: budgeted child did not run %s:\n%s", t.Name(), out)
	}
	return false
}
