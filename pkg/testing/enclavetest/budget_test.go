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

package enclavetest

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// The child must see exactly the installed budget through ProcessAllocator,
// and must refuse an allocation past it with the typed budget error.
func TestRunWithBudget_InstallsTheBudgetInTheChild(t *testing.T) {
	page := int64(os.Getpagesize())
	if !RunWithBudget(t, page) {
		return
	}

	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	if got := alloc.Limit(); got != page {
		t.Fatalf("Limit() = %d, want %d", got, page)
	}

	held, err := alloc.NewSized(1)
	if err != nil {
		t.Fatalf("the first page must be admitted: %v", err)
	}
	defer held.Destroy()

	if _, err := alloc.NewSized(1); !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("second page: err = %v, want ErrBudgetExhausted", err)
	}
}

// fixtureEnv selects the invalid-budget fixture below; it is set only by
// TestRunWithBudget_FailsTheParentWhenTheChildFails.
const fixtureEnv = "XKMS_ENCLAVETEST_INVALID_BUDGET_FIXTURE"

// TestRunWithBudget_InvalidBudgetFixture is driven by the test below. Run on
// its own it passes trivially; run with fixtureEnv set it asks for a budget
// NewAllocator rejects, so its child fails and it must fail too.
func TestRunWithBudget_InvalidBudgetFixture(t *testing.T) {
	if os.Getenv(fixtureEnv) != "1" {
		return
	}
	RunWithBudget(t, 0)
}

// A child that cannot install its budget must fail the parent rather than
// letting the test body run against the unbounded default allocator.
func TestRunWithBudget_FailsTheParentWhenTheChildFails(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunWithBudget_InvalidBudgetFixture$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), fixtureEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fixture passed with an invalid budget:\n%s", out)
	}
	if !strings.Contains(string(out), "NewAllocator(0)") {
		t.Fatalf("fixture failed for the wrong reason:\n%s", out)
	}
	if !strings.Contains(string(out), "budgeted child failed") {
		t.Fatalf("the parent did not report the child's failure:\n%s", out)
	}
}
