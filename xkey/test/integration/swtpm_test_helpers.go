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

//go:build integration && linux && tpm_simulator

// Package xkey — ephemeral swtpm lifecycle for the TPM2 barrier CLI tests.
//
// The in-process go-tpm-tools simulator (used by the "xkey barrier ...
// --tpm-simulator" flag and its unit tests) cannot be shared across separate
// OS processes: each "xkey" CLI invocation is a brand-new process with its
// own blank virtual TPM, so a root key sealed by one invocation can never be
// unsealed by another. swtpm solves this the same way real hardware does: it
// is a persistent external TPM emulator exposed as a unix-socket device
// (opened via linuxudstpm exactly like real hardware, per the ".sock" suffix
// convention in pkg/tpm2/tpm.go), so every "xkey" CLI subprocess that
// connects to the same socket sees the same on-disk NVRAM state.
//
// This mirrors xkey/pkg/authenticator/keybackend/adapter_integration_swtpm_test.go
// (unix-socket device, provisioned exactly once, retry loop for the
// TPM_RC_RETRY/TPM_RC_INITIALIZE window right after swtpm start) and
// xkey/test/integration/fido2-hardware-entrypoint.sh (the swtpm_setup +
// "swtpm socket --server type=unixio" invocation).
package xkey

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// swtpm lifecycle errors.
var (
	// ErrSwtpmSetupFailed indicates "swtpm_setup" could not initialize the
	// ephemeral TPM state directory.
	ErrSwtpmSetupFailed = errors.New("swtpm: setup failed")

	// ErrSwtpmStartFailed indicates the "swtpm socket" process could not be
	// started or its unix-socket device never appeared.
	ErrSwtpmStartFailed = errors.New("swtpm: start failed")

	// ErrSwtpmProvisionFailed indicates the shared swtpm instance could not
	// be provisioned with an EK/SRK/IAK before the CLI tests ran.
	ErrSwtpmProvisionFailed = errors.New("swtpm: provisioning failed")
)

// swtpmMaxProvisionAttempts bounds the retry loop absorbing the brief
// TPM_RC_RETRY/TPM_RC_INITIALIZE window right after swtpm starts.
const swtpmMaxProvisionAttempts = 40

// Shared, provisioned swtpm state for the whole test binary. All TPM2
// barrier CLI tests in this package pass swtpmDevicePath(t) as --tpm-device
// so every "xkey" subprocess talks to this same persistent instance.
var (
	swtpmLifecycleOnce sync.Once
	swtpmLifecycleErr  error
	swtpmSocketPath    string
	swtpmStateDir      string
	swtpmProc          *exec.Cmd
)

// swtpmDevicePath returns the unix-socket device path of the shared,
// provisioned swtpm instance, starting and provisioning it exactly once per
// test binary run. Per repo policy this never skips: if swtpm cannot be
// started or provisioned, the test fails loudly with an actionable error
// instead of silently passing over the TPM2 coverage.
func swtpmDevicePath(t *testing.T) string {
	t.Helper()
	swtpmLifecycleOnce.Do(func() {
		swtpmLifecycleErr = startAndProvisionSwtpm()
	})
	if swtpmLifecycleErr != nil {
		t.Fatalf("swtpm not available for TPM2 barrier tests: %v", swtpmLifecycleErr)
	}
	return swtpmSocketPath
}

// stopSwtpmForTests terminates the shared swtpm process (if it was started)
// and removes its ephemeral state directory. Called unconditionally from
// TestMain (main_test.go) after all tests finish; it is a safe no-op when no
// test in the run ever called swtpmDevicePath (swtpm is started lazily, on
// first use, so suites that never touch TPM2 never pay its startup cost).
func stopSwtpmForTests() {
	if swtpmProc != nil && swtpmProc.Process != nil {
		_ = swtpmProc.Process.Kill()
		_, _ = swtpmProc.Process.Wait()
	}
	if swtpmStateDir != "" {
		_ = os.RemoveAll(swtpmStateDir)
	}
}

// startAndProvisionSwtpm creates an ephemeral swtpm TPM state directory,
// starts "swtpm socket" on a unix-socket device, waits for the socket to
// appear, and provisions it (EK/SRK/IAK) exactly once so every subsequent
// "xkey barrier ..." CLI subprocess in this test binary can seal/unseal
// against the same persistent TPM state.
func startAndProvisionSwtpm() error {
	stateDir, err := os.MkdirTemp("", "xkey-swtpm-*")
	if err != nil {
		return &DetailError{Err: ErrSwtpmSetupFailed, Detail: fmt.Sprintf(": state dir: %v", err)}
	}
	swtpmStateDir = stateDir

	// No --create-ek-cert/--create-platform-cert: those invoke swtpm_localca,
	// which needs write access to a system-owned CA state directory that is
	// not guaranteed to be writable on a bare dev host (only inside a
	// preconfigured container). The barrier TPM2 strategy only needs a live
	// TPM transport plus a persisted SRK (created by tpm.Provision below),
	// neither of which requires a manufacturer EK certificate.
	setupCmd := exec.Command("swtpm_setup",
		"--tpm2",
		"--tpmstate", stateDir,
		"--overwrite",
		"--pcr-banks", "sha256,sha384",
	)
	if out, err := setupCmd.CombinedOutput(); err != nil {
		return &DetailError{Err: ErrSwtpmSetupFailed, Detail: fmt.Sprintf(": swtpm_setup: %v: %s", err, string(out))}
	}

	sockPath := filepath.Join(stateDir, "swtpm.sock")
	ctrlPath := sockPath + ".ctrl"
	logPath := filepath.Join(stateDir, "swtpm.log")

	swtpmProc = exec.Command("swtpm", "socket",
		"--tpm2",
		"--tpmstate", "dir="+stateDir,
		"--server", "type=unixio,path="+sockPath,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--flags", "startup-clear,not-need-init",
		"--log", "level=1,file="+logPath,
	)
	if err := swtpmProc.Start(); err != nil {
		return &DetailError{Err: ErrSwtpmStartFailed, Detail: fmt.Sprintf(": swtpm socket: %v", err)}
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			logContents, _ := os.ReadFile(logPath)
			return &DetailError{Err: ErrSwtpmStartFailed, Detail: fmt.Sprintf(": socket %s never appeared: %s", sockPath, string(logContents))}
		}
		time.Sleep(100 * time.Millisecond)
	}
	swtpmSocketPath = sockPath

	if err := provisionSwtpm(sockPath); err != nil {
		return err
	}
	return nil
}

// provisionSwtpm opens the swtpm via its unix-socket device (exactly like
// real hardware) and provisions it with an EK/SRK/IAK, retrying the initial
// connection to absorb the brief TPM_RC_RETRY/TPM_RC_INITIALIZE window right
// after swtpm start. Provisioning happens over its own short-lived
// connection; the persisted TPM state remains on disk for every later
// connection (each "xkey" CLI subprocess) to see.
func provisionSwtpm(sockPath string) error {
	logger := slog.Default()

	keyDir, err := os.MkdirTemp("", "xkey-swtpm-keys-*")
	if err != nil {
		return &DetailError{Err: ErrSwtpmProvisionFailed, Detail: fmt.Sprintf(": key dir: %v", err)}
	}
	// keyDir only backs the one-shot provisioning connection below; every
	// later "xkey" CLI subprocess opens its own key directory under its own
	// --data-dir, so this one is safe to remove once provisioning completes.
	defer func() { _ = os.RemoveAll(keyDir) }()

	factory, err := xkms.NewTPMStorageFactory(logger, keyDir)
	if err != nil {
		return &DetailError{Err: ErrSwtpmProvisionFailed, Detail: fmt.Sprintf(": storage factory: %v", err)}
	}

	cfg := xkms.DefaultTPMConfig
	cfg.UseSimulator = false
	cfg.Device = sockPath

	var lastErr error
	for attempt := 1; attempt <= swtpmMaxProvisionAttempts; attempt++ {
		params := &xkms.TPMParams{
			Logger:    logger,
			Config:    &cfg,
			BlobStore: factory.BlobStore(),
			Backend:   factory.KeyBackend(),
		}
		tpm, err := xkms.NewTPM2(params)
		// NewTPM2 returns a usable TPM both when fully provisioned (err ==
		// nil) and when the EK exists but other keys are missing
		// (ErrTPMNotInitialized). swtpm_setup --create-ek-cert pre-creates
		// the EK, so NewTPM2 may succeed yet the SRK/IAK are absent --
		// Provision is idempotent (creates only what's missing), so it is
		// always safe to run here.
		if err == nil || errors.Is(err, xkms.ErrTPMNotInitialized) {
			provErr := tpm.Provision(nil)
			_ = tpm.Close()
			if provErr == nil {
				return nil
			}
			if isTransientSwtpmError(provErr) {
				lastErr = provErr
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return &SentinelCauseError{Sentinel: ErrSwtpmProvisionFailed, Cause: provErr}
		}
		if isTransientSwtpmError(err) {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return &SentinelCauseError{Sentinel: ErrSwtpmProvisionFailed, Cause: err}
	}
	return &DetailError{Err: ErrSwtpmProvisionFailed, Detail: fmt.Sprintf(": not ready after %d attempts: %v", swtpmMaxProvisionAttempts, lastErr)}
}

// isTransientSwtpmError reports whether err is a retryable swtpm-not-ready
// condition (TPM_RC_RETRY / TPM_RC_INITIALIZE during the startup window).
func isTransientSwtpmError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "TPM_RC_RETRY") || strings.Contains(msg, "TPM_RC_INITIALIZE")
}
