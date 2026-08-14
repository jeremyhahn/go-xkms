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

//go:build integration && linux

// Package xkey provides integration tests for the "xkey agent" command
// group (start / status / stop). The agent server is the master-side
// listener that accepts connections from enrolled remote agents; these
// tests exercise it as a real subprocess bound to an ephemeral loopback
// port, isolated to a per-test XKEY_HOME.
//
// The tests drive the real server lifecycle end to end: "agent start"
// records its PID and bound address in a run-state file under the xKey
// home, "agent status" reports whether that process is a live agent
// server, and "agent stop" signals it and waits for it to exit. Enrolling
// agents receive certificates signed by the xkmsd certificate authority,
// so the tests point the CLI at an in-test endpoint that speaks the
// documented xkmsd REST CA contract and returns real certificate
// material; the server half of that contract is covered by go-xkms's own
// handler tests.
package xkey

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// agentStateFileRelPath is the run-state file "agent start" writes under
// XKEY_HOME. It is asserted directly so the tests can prove the file is
// created on start, self-healed when stale, and removed on shutdown.
var agentStateFileRelPath = filepath.Join("data", "agent", "server.state.json")

// agentPIDPattern extracts the PID line printed by "agent start" and
// "agent status".
var agentPIDPattern = regexp.MustCompile(`PID:\s+(\d+)`)

// startFakeCAEndpoint starts an HTTP endpoint that speaks the xkmsd REST
// CA verbs used by agent enrollment, backed by a real in-memory CA. It
// returns the endpoint URL for XKMSD_URL.
func startFakeCAEndpoint(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate CA key")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkey agent integration CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create CA certificate")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeCAJSON(t, w, map[string]string{"status": "ok", "version": "integration"})
	})
	mux.HandleFunc("/api/v1/ca/certificate", func(w http.ResponseWriter, r *http.Request) {
		writeCAJSON(t, w, map[string]any{
			"certificate_pem": caPEM,
			"subject":         "CN=xkey agent integration CA",
			"issuer":          "CN=xkey agent integration CA",
			"serial_number":   "01",
			"is_ca":           true,
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

// writeCAJSON encodes a JSON response for the fake CA endpoint.
func writeCAJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode CA response: %v", err)
	}
}

// setupAgentEnv creates an isolated XKEY_HOME with a reachable CA
// endpoint and returns the home directory. $HOME is redirected alongside
// XKEY_HOME because parts of the CLI resolve storage through $HOME.
func setupAgentEnv(t *testing.T) string {
	t.Helper()

	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("HOME", xkeyHome)
	t.Setenv("XKMSD_URL", startFakeCAEndpoint(t))

	return xkeyHome
}

// agentServerProcess is a running "xkey agent start" subprocess.
type agentServerProcess struct {
	cmd         *exec.Cmd
	home        string
	pid         int
	listenAddr  string
	mu          sync.Mutex
	lines       []string
	doneReading chan struct{}
}

// startAgentServer launches "xkey agent start" bound to an ephemeral
// loopback port and blocks until it reports that it is listening.
func startAgentServer(t *testing.T, binary, home string) *agentServerProcess {
	t.Helper()

	cmd := exec.Command(binary, "agent", "start", "--listen", "127.0.0.1:0")
	cmd.Env = os.Environ()

	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout

	proc := &agentServerProcess{
		cmd:         cmd,
		home:        home,
		doneReading: make(chan struct{}),
	}

	require.NoError(t, cmd.Start(), "start agent server")
	proc.pid = cmd.Process.Pid

	listening := make(chan string, 1)
	go func() {
		defer close(proc.doneReading)

		scanner := bufio.NewScanner(stdoutPipe)
		announced := false
		for scanner.Scan() {
			line := scanner.Text()

			proc.mu.Lock()
			proc.lines = append(proc.lines, line)
			proc.mu.Unlock()

			if !announced && strings.Contains(line, "Listen:") {
				announced = true
				listening <- strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Listen:"))
			}
		}
	}()

	t.Cleanup(func() {
		// Never leave a stray server behind, whatever the test did.
		if proc.cmd.Process != nil {
			_ = proc.cmd.Process.Kill()
		}
		<-proc.doneReading
		_ = proc.cmd.Wait()
	})

	select {
	case addr := <-listening:
		proc.listenAddr = addr
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for the agent server to listen; output:\n%s", proc.output())
	}

	return proc
}

// output returns everything the server has written so far.
func (p *agentServerProcess) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.lines, "\n")
}

// waitExit waits for the server process to exit, returning its wait error.
func (p *agentServerProcess) waitExit(t *testing.T, timeout time.Duration) error {
	t.Helper()

	select {
	case <-p.doneReading:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for the agent server to exit; output:\n%s", p.output())
	}

	waitErr := p.cmd.Wait()
	p.cmd.Process = nil
	return waitErr
}

// agentStateFile returns the path of the run-state file for a home.
func agentStateFile(home string) string {
	return filepath.Join(home, agentStateFileRelPath)
}

// waitForAgentStatus polls "xkey agent status" until its output contains
// want, failing the test if that does not happen within the timeout.
func waitForAgentStatus(t *testing.T, binary, want string, timeout time.Duration) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last string
	for {
		stdout, stderr, exitCode := RunXKey(t, binary, "", "agent", "status")
		last = stdout + stderr
		if exitCode == 0 && strings.Contains(stdout, want) {
			return stdout
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent status never reported %q; last output (exit %d):\n%s", want, exitCode, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAgentCLI_Status_NoAgentsEnrolled verifies that "xkey agent status"
// succeeds against a freshly initialized home, reporting that no server is
// running and that no agents are enrolled.
func TestAgentCLI_Status_NoAgentsEnrolled(t *testing.T) {
	binary := getOrBuildBinary(t)
	setupAgentEnv(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "agent", "status")

	assert.Contains(t, stdout, "Agent server: not running")
	assert.Contains(t, stdout, "No enrolled agents")
}

// TestAgentCLI_Stop_WithoutRunningServer verifies that "xkey agent stop"
// fails with a clear error, and a non-zero exit status, when no agent
// server is running. It must never claim to have stopped anything.
func TestAgentCLI_Stop_WithoutRunningServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	setupAgentEnv(t)

	stdout, stderr, exitCode := RunXKey(t, binary, "", "agent", "stop")

	assert.NotEqual(t, 0, exitCode, "stop with nothing running must exit non-zero")
	assert.Contains(t, stderr, "agent: no agent server is running")
	assert.NotContains(t, stdout, "Agent server stopped")
}

// TestAgentCLI_Start_WithoutCertificateAuthority verifies that the agent
// server refuses to start when no xkmsd certificate authority is
// configured, rather than starting with a signer that cannot issue real
// agent certificates.
func TestAgentCLI_Start_WithoutCertificateAuthority(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("HOME", xkeyHome)
	t.Setenv("XKMSD_URL", "")

	errOutput := RunXKeyExpectFailure(t, binary, "", "agent", "start", "--listen", "127.0.0.1:0")

	assert.Contains(t, errOutput, "agent: enrollment requires a reachable xkmsd certificate authority")
	assert.NoFileExists(t, agentStateFile(xkeyHome),
		"a failed start must not leave a run-state file behind")
}

// TestAgentCLI_Start_UnreachableCertificateAuthority verifies that a
// configured but unreachable authority also fails the start closed.
func TestAgentCLI_Start_UnreachableCertificateAuthority(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("HOME", xkeyHome)
	// Port 9 (discard) refuses connections.
	t.Setenv("XKMSD_URL", "http://127.0.0.1:9")

	errOutput := RunXKeyExpectFailure(t, binary, "", "agent", "start", "--listen", "127.0.0.1:0")

	assert.Contains(t, errOutput, "agent: enrollment requires a reachable xkmsd certificate authority")
	assert.NoFileExists(t, agentStateFile(xkeyHome))
}

// TestAgentCLI_Start_InvalidTLSFiles verifies that "xkey agent start" fails
// with a clear error when the configured TLS certificate/key files do not
// exist, and that the run-state file it claimed is released again.
func TestAgentCLI_Start_InvalidTLSFiles(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := setupAgentEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"agent", "start",
		"--listen", "127.0.0.1:0",
		"--tls-cert", "/nonexistent/agent-cert.pem",
		"--tls-key", "/nonexistent/agent-key.pem",
	)

	assert.Contains(t, errOutput, "agent: failed to start server")
	assert.NoFileExists(t, agentStateFile(xkeyHome),
		"a failed start must release its run-state claim")
}

// TestAgentCLI_Lifecycle drives the full start / status / stop lifecycle:
// the server is started as a subprocess on an ephemeral loopback port,
// "agent status" is polled until it reports the server running with its
// PID and bound address, "agent stop" terminates it, and the process is
// verified to have actually exited with status reporting not running.
func TestAgentCLI_Lifecycle(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := setupAgentEnv(t)

	server := startAgentServer(t, binary, xkeyHome)

	require.FileExists(t, agentStateFile(xkeyHome),
		"agent start must record its run state")

	statusOut := waitForAgentStatus(t, binary, "Agent server: running", 30*time.Second)
	assert.Contains(t, statusOut, server.listenAddr, "status must report the bound listen address")
	assert.Contains(t, statusOut, "No enrolled agents", "status must still list enrolled agents")

	match := agentPIDPattern.FindStringSubmatch(statusOut)
	require.Len(t, match, 2, "status must report the server PID; output:\n%s", statusOut)
	reportedPID, err := strconv.Atoi(match[1])
	require.NoError(t, err)
	assert.Equal(t, server.pid, reportedPID, "status must report the real server PID")

	stopOut := RunXKeyExpectSuccess(t, binary, "", "agent", "stop")
	assert.Contains(t, stopOut, "Agent server stopped")
	assert.Contains(t, stopOut, strconv.Itoa(server.pid))
	assert.Contains(t, stopOut, "SIGTERM", "a healthy server must stop gracefully")

	waitErr := server.waitExit(t, 30*time.Second)
	assert.NoError(t, waitErr, "the server must exit cleanly after agent stop; output:\n%s", server.output())
	assert.Contains(t, server.output(), "Shutting down agent server")

	assert.NoFileExists(t, agentStateFile(xkeyHome), "agent stop must remove the run-state file")

	afterStop := RunXKeyExpectSuccess(t, binary, "", "agent", "status")
	assert.Contains(t, afterStop, "Agent server: not running")

	// A second stop has nothing to stop and must say so.
	_, stderr, exitCode := RunXKey(t, binary, "", "agent", "stop")
	assert.NotEqual(t, 0, exitCode)
	assert.Contains(t, stderr, "agent: no agent server is running")
}

// TestAgentCLI_Start_RejectsSecondInstance verifies that starting a second
// agent server against the same home fails with a clear already-running
// error instead of silently double-binding or clobbering the run state.
func TestAgentCLI_Start_RejectsSecondInstance(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := setupAgentEnv(t)

	server := startAgentServer(t, binary, xkeyHome)
	waitForAgentStatus(t, binary, "Agent server: running", 30*time.Second)

	errOutput := RunXKeyExpectFailure(t, binary, "", "agent", "start", "--listen", "127.0.0.1:0")
	assert.Contains(t, errOutput, "agent: agent server is already running")
	assert.Contains(t, errOutput, strconv.Itoa(server.pid))

	// The original server is untouched and still owns the run state.
	statusOut := RunXKeyExpectSuccess(t, binary, "", "agent", "status")
	assert.Contains(t, statusOut, "Agent server: running")
	assert.Contains(t, statusOut, strconv.Itoa(server.pid))

	RunXKeyExpectSuccess(t, binary, "", "agent", "stop")
	assert.NoError(t, server.waitExit(t, 30*time.Second))
}

// TestAgentCLI_StaleStateFileSelfHeals verifies that a run-state file left
// behind by a crashed server (SIGKILL, no chance to clean up) is reported
// as not running and removed, so a later start is not blocked and stop
// does not claim to have stopped a dead process.
func TestAgentCLI_StaleStateFileSelfHeals(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := setupAgentEnv(t)

	server := startAgentServer(t, binary, xkeyHome)
	waitForAgentStatus(t, binary, "Agent server: running", 30*time.Second)

	// Simulate a crash: SIGKILL leaves the run-state file behind.
	require.NoError(t, server.cmd.Process.Signal(syscall.SIGKILL))
	require.Error(t, server.waitExit(t, 30*time.Second), "SIGKILL must not look like a clean exit")
	require.FileExists(t, agentStateFile(xkeyHome), "a crashed server leaves its run state behind")

	statusOut := RunXKeyExpectSuccess(t, binary, "", "agent", "status")
	assert.Contains(t, statusOut, "Agent server: not running")
	assert.NoFileExists(t, agentStateFile(xkeyHome), "status must self-heal the stale run-state file")

	_, stderr, exitCode := RunXKey(t, binary, "", "agent", "stop")
	assert.NotEqual(t, 0, exitCode)
	assert.Contains(t, stderr, "agent: no agent server is running")

	// A fresh server can claim the home again.
	restarted := startAgentServer(t, binary, xkeyHome)
	waitForAgentStatus(t, binary, "Agent server: running", 30*time.Second)
	RunXKeyExpectSuccess(t, binary, "", "agent", "stop")
	assert.NoError(t, restarted.waitExit(t, 30*time.Second))
}

// TestAgentCLI_StartAndGracefulShutdown verifies that a foreground
// "agent start" still performs a clean shutdown on SIGINT (the signal a
// user's Ctrl-C delivers) and removes its run-state file on the way out,
// so the signal path and the "agent stop" path leave the same state.
func TestAgentCLI_StartAndGracefulShutdown(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := setupAgentEnv(t)

	server := startAgentServer(t, binary, xkeyHome)
	require.FileExists(t, agentStateFile(xkeyHome))

	require.NoError(t, server.cmd.Process.Signal(syscall.SIGINT), "failed to send SIGINT")

	waitErr := server.waitExit(t, 30*time.Second)
	require.NoError(t, waitErr, "expected clean exit after SIGINT; output:\n%s", server.output())

	assert.Contains(t, server.output(), "Agent server started")
	assert.Contains(t, server.output(), "Shutting down agent server")
	assert.NoFileExists(t, agentStateFile(xkeyHome),
		"graceful shutdown must remove the run-state file")

	statusOut := RunXKeyExpectSuccess(t, binary, "", "agent", "status")
	assert.Contains(t, statusOut, "Agent server: not running")
}
