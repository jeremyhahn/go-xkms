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

package password

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	// memlockChildEnv marks the re-executed test binary as the child that
	// lowers its own RLIMIT_MEMLOCK. The parent's limits are never touched.
	memlockChildEnv = "XKMS_PASSWORD_MEMLOCK_CHILD"

	// memlockCeiling is the RLIMIT_MEMLOCK the child holds itself to.
	memlockCeiling = 128 << 10

	// memlockReport is the line the child prints when every check held.
	memlockReport = "memlock=fail-closed"
)

// TestMemlockChild runs only inside the child process started by
// TestNewPassword_FailsClosedPastLockedMemoryCeiling.
func TestMemlockChild(t *testing.T) {
	if os.Getenv(memlockChildEnv) != "1" {
		return
	}
	// mlock and go-enclave's ceiling discovery both check the calling
	// thread's capabilities. Pin this goroutine to its thread and never
	// unlock it, so the thread that drops CAP_IPC_LOCK exits with the test
	// instead of returning to the scheduler.
	runtime.LockOSThread()
	dropIPCLock(t)
	lowerMemlock(t, memlockCeiling)

	small, err := NewPassword([]byte("1234"))
	if err != nil {
		t.Fatalf("allocation under the ceiling: %v", err)
	}
	small.Clear()

	large, err := NewPassword(make([]byte, 8*memlockCeiling))
	if !errors.Is(err, ErrEnclaveUnavailable) {
		t.Fatalf("allocation past the ceiling: err = %v, want %v", err, ErrEnclaveUnavailable)
	}
	if large != nil {
		t.Fatal("allocation past the ceiling returned a password; it must not fall back to unlocked memory")
	}
	if _, err := os.Stdout.WriteString(memlockReport + "\n"); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

// dropIPCLock removes CAP_IPC_LOCK from the calling thread, so the lowered
// RLIMIT_MEMLOCK binds even when the test runs as root.
func dropIPCLock(t *testing.T) {
	t.Helper()
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		t.Fatalf("capget: %v", err)
	}
	data[0].Effective &^= 1 << unix.CAP_IPC_LOCK
	data[0].Permitted &^= 1 << unix.CAP_IPC_LOCK
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		t.Fatalf("capset: %v", err)
	}
}

// lowerMemlock sets this process's soft RLIMIT_MEMLOCK to ceiling, or to the
// hard limit when that is lower.
func lowerMemlock(t *testing.T, ceiling uint64) {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	lim.Cur = min(ceiling, lim.Max)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}
}

// TestNewPassword_FailsClosedPastLockedMemoryCeiling proves a password
// allocation that does not fit under RLIMIT_MEMLOCK returns
// ErrEnclaveUnavailable rather than holding the secret in unlocked memory.
// The ceiling is lowered in a child process, so the host's limits and this
// process's budget are unchanged.
func TestNewPassword_FailsClosedPastLockedMemoryCeiling(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemlockChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), memlockChildEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("memlock child failed: %v\nstdout: %s\nstderr: %s", err, out, exitErr.Stderr)
		}
		t.Fatalf("memlock child: %v", err)
	}
	if !strings.Contains(string(out), memlockReport) {
		t.Fatalf("memlock child printed no report: %s", out)
	}
}
