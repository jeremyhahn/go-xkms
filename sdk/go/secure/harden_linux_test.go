// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package secure

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// prGetDumpable is PR_GET_DUMPABLE from <linux/prctl.h>. The syscall package
// does not name it, and this one test is not worth a module dependency.
const prGetDumpable = 3

// hardenChildEnv marks the re-executed test binary as the child that hardens
// itself. Hardening is irreversible, so it runs in a subprocess rather than in
// the test binary that has to keep running the rest of the suite.
const hardenChildEnv = "XKMS_TEST_HARDEN_CHILD"

// TestHardenProcessChild is the subprocess body. It hardens, then reports
// prctl(PR_GET_DUMPABLE) and the outcome on stdout. It does nothing unless
// re-executed by runHardenChild.
func TestHardenProcessChild(t *testing.T) {
	if os.Getenv(hardenChildEnv) != "1" {
		return
	}
	outcome, err := HardenProcess(nil)
	if err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}
	dumpable, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("prctl(PR_GET_DUMPABLE): %v", errno)
	}
	report := "dumpable=" + strconv.FormatUint(uint64(dumpable), 10) + " outcome=" + outcome.String() + "\n"
	if _, err := os.Stdout.WriteString(report); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

// runHardenChild re-executes this test binary as the hardening child with the
// given opt-out value ("" leaves it unset) and returns its report line.
func runHardenChild(t *testing.T, optOut string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProcessChild$", "-test.count=1")
	env := []string{hardenChildEnv + "=1"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, AllowProcessInspectionEnv+"=") {
			env = append(env, kv)
		}
	}
	if optOut != "" {
		env = append(env, AllowProcessInspectionEnv+"="+optOut)
	}
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("hardening child failed: %v\nstdout: %s\nstderr: %s", err, out, exitErr.Stderr)
		}
		t.Fatalf("hardening child: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "dumpable=") {
			return line
		}
	}
	t.Fatalf("hardening child printed no report: %s", out)
	return ""
}

// TestHardenProcess_MarksTheProcessNonDumpable verifies the re-export reaches
// go-qrdb's Linux mechanism: after hardening the process is non-dumpable, so
// ptrace attach and /proc/<pid>/mem need CAP_SYS_PTRACE.
func TestHardenProcess_MarksTheProcessNonDumpable(t *testing.T) {
	want := "dumpable=0 outcome=" + ProcessHardened.String()
	if got := runHardenChild(t, ""); got != want {
		t.Fatalf("child reported %q, want %q", got, want)
	}
}

// TestHardenProcess_OptOutLeavesTheProcessDumpable verifies the debugger
// opt-out: the process stays dumpable and the outcome says so, so a caller
// with an audit trail can record it.
func TestHardenProcess_OptOutLeavesTheProcessDumpable(t *testing.T) {
	want := "dumpable=1 outcome=" + ProcessInspectionAllowed.String()
	if got := runHardenChild(t, "true"); got != want {
		t.Fatalf("child reported %q, want %q", got, want)
	}
}

// TestHardenProcess_UnparseableOptOutIsRefused verifies a typo in the opt-out
// is an error rather than either answer, and that the error type survives
// the re-export.
func TestHardenProcess_UnparseableOptOutIsRefused(t *testing.T) {
	t.Setenv(AllowProcessInspectionEnv, "perhaps")
	_, err := HardenProcess(nil)
	var optOutErr *ProcessInspectionOptOutError
	if !errors.As(err, &optOutErr) {
		t.Fatalf("HardenProcess = %v, want *ProcessInspectionOptOutError", err)
	}
}
