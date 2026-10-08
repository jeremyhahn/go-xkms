// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

// Tests for runInit's own orchestration (init.go): the exit-code paths that,
// before go-xkms#1141, were reachable only by killing the test binary with
// os.Exit. runInit now reports its outcome as a return value -- exactly like
// run() and, since #1153, runProcess -- so these call it directly and assert
// on the returned code instead of forking a subprocess.
//
// These use the resolveInitNodeConfig / openDurableInitNode path (the same
// one init_ceremony_test.go's testNodeConfig exercises): no --config file, so
// the durable node config comes entirely from defaults and --data-dir/
// --barrier-strategy, storage rooted at a t.TempDir(), and no hardware
// backend anywhere in the plan (the default --admin-factor is mtls, backed
// by the certificate first-boot itself issues).

import (
	"path/filepath"
	"strings"
	"testing"
)

// runInitArgs returns the minimal flag set a compliant `xkmsd init` run
// needs: the SO PIN and a data directory rooted at a fresh temp dir so the
// durable node's storage never collides across tests or touches a shared
// path. Callers append case-specific flags.
func runInitArgs(t *testing.T) []string {
	t.Helper()
	return []string{
		// --config defaults to /etc/xkms/xkmsd.yaml, which does not exist on
		// this host (or in CI); an explicit empty value keeps runInit on its
		// no-config-file path (flags and defaults only) instead of failing
		// at config.Load before any of these tests reach their own case.
		"--config", "",
		"--so-pin", "test-so-pin",
		"--data-dir", t.TempDir(),
		"--hostname", "xkmsd-init-test.example.com",
	}
}

// TestRunInit_Success drives the full bootstrap end to end -- the default
// --barrier-strategy passphrase auto-unseals the durable node from the
// supplied --so-pin (init_node.go's unsealDurableInitNode), so the run
// completes unattended -- and proves runInit reports success as a return
// value of 0. printInitSummary's validated-configuration summary goes to
// stdout; printBootstrapOutcome's report of the finished bootstrap (SPKI pin,
// CA bundle location) goes to stderr, so only the former is asserted here.
func TestRunInit_Success(t *testing.T) {
	var code int
	out := captureStdout(t, func() {
		code = runInit(runInitArgs(t))
	})

	if code != 0 {
		t.Fatalf("runInit() = %d, want 0 for a successful bootstrap", code)
	}
	if !strings.Contains(out, "Validation Passed") {
		t.Errorf("runInit() success output missing the validation summary; got:\n%s", out)
	}
}

// TestRunInit_FlagParseFailure proves an unrecognized flag is reported as
// exit code 1 rather than terminating the process -- the failure runInit
// hits before any barrier credential exists, so no exitInit cleanup applies.
func TestRunInit_FlagParseFailure(t *testing.T) {
	if code := runInit([]string{"--this-flag-does-not-exist"}); code != 1 {
		t.Fatalf("runInit(bad flag) = %d, want 1", code)
	}
}

// TestRunInit_ValidationFailure proves a structurally valid flag set that
// fails validateInitFlags (here, a missing --so-pin) is also reported as
// exit code 1, before anything is built.
func TestRunInit_ValidationFailure(t *testing.T) {
	if code := runInit([]string{"--hostname", "only-a-hostname"}); code != 1 {
		t.Fatalf("runInit(missing --so-pin) = %d, want 1", code)
	}
}

// TestRunInit_ConfigLoadFailure proves an unreadable --config path fails
// before the bootstrap touches any state.
func TestRunInit_ConfigLoadFailure(t *testing.T) {
	args := append(runInitArgs(t), "--config", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if code := runInit(args); code != 1 {
		t.Fatalf("runInit(unreadable --config) = %d, want 1", code)
	}
}

// TestRunInit_PreflightFailure exercises exitInit: a --admin-factor piv plan
// fails preflightAdminFactors on a host with no PIV hardware configured (see
// TestPreflightAdminFactors_RefusesAPlanItCannotEnroll in
// init_ceremony_test.go), so runInit must route the failure through
// exitInit(env, 1) -- releasing the (here absent) FIDO2 handler.
func TestRunInit_PreflightFailure(t *testing.T) {
	args := append(runInitArgs(t), "--admin-factor", "piv")
	if code := runInit(args); code != 1 {
		t.Fatalf("runInit(--admin-factor piv, no PIV hardware) = %d, want 1", code)
	}
}
