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

//go:build integration && initceremony

// Package initceremony -- this file starts a private, ephemeral swtpm
// (software TPM 2.0) instance for the tpm2 barrier strategy
// TestInitPersistsAdminFactor_SurvivesRestart needs: "none" cannot be used
// (xkmsd init refuses it -- see validBarrierStrategies in
// cmd/xkmsd/init.go), and of the strategies init accepts, tpm2 is the one
// that also auto-unseals unattended on every `xkmsd run`, init included (see
// cmd/xkmsd/init_node.go's unsealDurableInitNode and
// pkg/embeddednode/embedded_node.go's ResolveNodeSeal / OpenEmbeddedNode) --
// exactly what a restart-driven test with no operator step in between needs.
// pkcs11 also auto-unseals, but only with its user PIN sealed beforehand into
// the TPM-sealed pre-barrier store (`xkmsd seal-pin`), so it needs a TPM as
// well as a token; tpm2 alone is the simpler fixture.
//
// Why a PRIVATE swtpm rather than the devcontainer's shared instance
// (/tmp/swtpm/swtpm.sock, started once per container by
// build/docker/devcontainer/scripts/post-start.sh): this test's xkmsd subprocesses
// provision themselves on first use through pkg/backend/tpm2/backend.go's
// pkg/tpm2.ProvisionFresh, entered only when the backend config's
// UseSimulator is true, which does nothing but ADD an EK and SRK to a blank
// TPM -- safe against a scratch instance nobody else touches. Full TCG
// provisioning (pkg/tpm2.(*TPM2).Provision) is a different, heavier
// operation that opens by calling TPM2_Clear, wiping every hierarchy; this
// file never calls it, and must not be pointed at the devcontainer's shared
// TPM, which other suites running in the same container session depend on
// staying in the state post-start.sh left it.
//
// swtpm is reached over TCP (command/ctrl ports), not the shared instance's
// unix-socket device path, because pkg/backend/tpm2/backend.go's
// auto-provision branch is gated on config.TPM2Config.UseSimulator, and
// config.TPM2Config.SimulatorHost/SimulatorPort are how that path is wired
// to an external swtpm (see config.TPM2Config.ToTPMConfig, and
// pkg/tpm2/tpm.go's CommandAddress case, whose own comment names this exact
// "swtpm convention": command port, control port = command+1).
package initceremony

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

var (
	swtpmOnce     sync.Once
	swtpmCmdPort  int
	swtpmStartErr error
)

// startTPM2Simulator starts this test binary's private swtpm instance,
// exactly once, and returns the TCP command port xkmsd's tpm2 barrier config
// dials (config.TPM2Config.SimulatorPort; the control port is always that
// port+1 -- see this file's package doc comment). Per repo policy this never
// skips: if swtpm cannot be started, the test fails loudly with an
// actionable error instead of silently passing over tpm2 barrier coverage.
//
// The instance -- and its state directory -- lives for as long as the test
// that first calls this (t.Cleanup below), which is sufficient today because
// exactly one test in this package needs a TPM. A second such test would
// need this promoted to a TestMain-driven lifecycle (mirroring
// xkey/test/integration/swtpm_test_helpers.go) so neither test's cleanup
// tears down the shared instance out from under the other.
func startTPM2Simulator(t *testing.T) int {
	t.Helper()
	swtpmOnce.Do(func() {
		swtpmCmdPort, swtpmStartErr = launchSwtpm(t)
	})
	if swtpmStartErr != nil {
		t.Fatalf("swtpm not available for the tpm2 barrier strategy: %v", swtpmStartErr)
	}
	return swtpmCmdPort
}

// launchSwtpm creates a fresh swtpm TPM state directory, authors it with
// swtpm_setup, and starts "swtpm socket" listening on a TCP command/control
// port pair. It does not provision an EK/SRK itself -- see this file's
// package doc comment for why that is xkmsd's own job, not this helper's.
func launchSwtpm(t *testing.T) (int, error) {
	t.Helper()

	stateDir, err := os.MkdirTemp("", "xkmsd-initceremony-swtpm-*")
	if err != nil {
		return 0, fmt.Errorf("swtpm state dir: %w", err)
	}

	// No --create-ek-cert/--create-platform-cert: pkg/tpm2.ProvisionFresh
	// only ever calls CreateEK/CreateSRK, neither of which reads or
	// validates a manufacturer EK certificate.
	setup := exec.Command("swtpm_setup",
		"--tpm2",
		"--tpmstate", stateDir,
		"--overwrite",
		"--pcr-banks", "sha256",
	)
	if out, err := setup.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("swtpm_setup: %w: %s", err, out)
	}

	cmdPort := freePort(t)
	ctrlPort := cmdPort + 1
	logPath := filepath.Join(stateDir, "swtpm.log")

	proc := exec.Command("swtpm", "socket",
		"--tpm2",
		"--tpmstate", "dir="+stateDir,
		"--server", fmt.Sprintf("type=tcp,port=%d", cmdPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", ctrlPort),
		"--flags", "startup-clear,not-need-init",
		"--log", "level=1,file="+logPath,
	)
	if err := proc.Start(); err != nil {
		_ = os.RemoveAll(stateDir)
		return 0, fmt.Errorf("start swtpm socket: %w", err)
	}

	cmdAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cmdPort))
	if !waitUntil(10*time.Second, func() bool { return listenerAccepts("tcp", cmdAddr) }) {
		logContents, _ := os.ReadFile(logPath)
		_ = proc.Process.Kill()
		_, _ = proc.Process.Wait()
		_ = os.RemoveAll(stateDir)
		return 0, fmt.Errorf("swtpm command port %d never opened: %s", cmdPort, logContents)
	}

	t.Cleanup(func() {
		if proc.Process != nil {
			_ = proc.Process.Kill()
			_, _ = proc.Process.Wait()
		}
		_ = os.RemoveAll(stateDir)
	})

	return cmdPort, nil
}
