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

package cdp

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"testing"
)

// strictFIPSChildEnv marks the re-executed test binary that runs under
// GODEBUG=fips140=only.
const strictFIPSChildEnv = "CDP_STRICT_FIPS_CHILD"

// TestMain runs the package's tests outside strict FIPS mode. Every test
// drives a WebSocket, whose RFC 6455 §4.2.2 handshake hashes with SHA-1, so
// under GODEBUG=fips140=only NewClient refuses with ErrCDPFIPSUnsupported.
// A strict-FIPS run re-executes this binary with GODEBUG=fips140=off and
// exits with its status; TestNewClient_RefusedWithoutPanicUnderStrictFIPS
// still proves the refusal in its own fips140=only child.
func TestMain(m *testing.M) {
	if fips140.Enforced() && os.Getenv(strictFIPSChildEnv) != "1" {
		os.Exit(runOutsideStrictFIPS())
	}
	os.Exit(m.Run())
}

// runOutsideStrictFIPS re-executes the test binary with the same flags under
// GODEBUG=fips140=off and returns its exit code.
func runOutsideStrictFIPS() int {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=off")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cdp: re-running tests under GODEBUG=fips140=off: %v\n", err)
		return 1
	}
	return 0
}

// TestNewClient_RefusedWithoutPanicUnderStrictFIPS re-runs itself under
// GODEBUG=fips140=only, where the SHA-1 WebSocket handshake panics:
// NewClient must refuse with ErrCDPFIPSUnsupported instead.
func TestNewClient_RefusedWithoutPanicUnderStrictFIPS(t *testing.T) {
	if os.Getenv(strictFIPSChildEnv) == "1" {
		strictFIPSChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestNewClient_RefusedWithoutPanicUnderStrictFIPS", "-test.v")
	cmd.Env = append(os.Environ(), strictFIPSChildEnv+"=1", "GODEBUG=fips140=only")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("NewClient did not survive GODEBUG=fips140=only: %v\n%s", err, out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("panic under GODEBUG=fips140=only:\n%s", out)
	}
}

func strictFIPSChild(t *testing.T) {
	t.Helper()

	if !fips140.Enforced() {
		t.Fatal("GODEBUG=fips140=only did not enforce FIPS in the child; the subprocess proves nothing")
	}

	// Port 1 has no listener: any error other than the FIPS refusal means
	// NewClient reached the network before the gate.
	if _, err := NewClient("127.0.0.1", 1, slog.Default()); !errors.Is(err, ErrCDPFIPSUnsupported) {
		t.Fatalf("NewClient: error = %v, want ErrCDPFIPSUnsupported", err)
	}
}
