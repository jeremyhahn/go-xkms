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

//go:build integration

// Package oidccredentials is the end-to-end suite of server-side OIDC
// credentials. TestMain builds and starts a real xkmsd serving every network
// transport (Unix gRPC, REST, gRPC, QUIC, MCP) over TLS, its barrier
// auto-unsealed (strategy none: credentials are sealed by the barrier, so the
// suite needs it open without an operator ceremony), and the tests drive the real xkey and xkmsctl binaries against it.
// The lease-contention test runs credential services over a real raft qrdb
// node. Run it in the devcontainer: make integration-test-oidc-credentials.
package oidccredentials

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// env is the running xkmsd and the binaries driven against it.
var env struct {
	xkey      string
	xkmsctl   string
	caFile    string
	socket    string
	urls      map[string]string
	adminCert string
	adminKey  string
	token     string
}

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "oidc credentials integration:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run sets the suite up, runs it, and tears the server down.
func run(m *testing.M) (int, error) {
	work, err := os.MkdirTemp("", "oidc-credentials-it-")
	if err != nil {
		return 0, err
	}
	defer func() {
		if rmErr := os.RemoveAll(work); rmErr != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", rmErr)
		}
	}()

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		return 0, err
	}
	bin := filepath.Join(work, "bin")
	xkmsd := filepath.Join(bin, "xkmsd")
	env.xkmsctl = filepath.Join(bin, "xkmsctl")
	env.xkey = filepath.Join(bin, "xkey")
	const tags = "codec_cbor codec_json codec_msgpack"
	for _, b := range []struct{ dir, out, pkg string }{
		{root, xkmsd, "./cmd/xkmsd"},
		{root, env.xkmsctl, "./cmd/xkmsctl"},
		{filepath.Join(root, "xkey"), env.xkey, "./cmd/xkey"},
	} {
		if err := goBuild(b.dir, tags, b.out, b.pkg); err != nil {
			return 0, err
		}
	}

	ports, err := freePorts()
	if err != nil {
		return 0, err
	}
	env.socket = filepath.Join(work, "run", "xkms.sock")
	env.urls = map[string]string{
		"unix": "unix://" + env.socket,
		"rest": fmt.Sprintf("https://localhost:%d", ports.rest),
		"grpc": fmt.Sprintf("grpcs://127.0.0.1:%d", ports.grpc),
		// QUIC is HTTP/3 on the REST port of the unified server.
		"quic": fmt.Sprintf("quic://localhost:%d", ports.rest),
		"mcp":  fmt.Sprintf("mcps://localhost:%d", ports.mcp),
	}
	config := filepath.Join(work, "xkmsd.yaml")
	if err := writeConfig(config, filepath.Join(work, "data"), ports); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(env.socket), 0o700); err != nil {
		return 0, err
	}

	logFile, err := os.Create(filepath.Join(work, "xkmsd.log"))
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := logFile.Close(); closeErr != nil {
			fmt.Fprintln(os.Stderr, "close log:", closeErr)
		}
	}()
	server := exec.Command(xkmsd, "-config", config)
	server.Stdout = logFile
	server.Stderr = logFile
	if err := server.Start(); err != nil {
		return 0, err
	}
	// exited closes when xkmsd exits; waitErr is then its exit status.
	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = server.Wait()
		close(exited)
	}()
	defer func() {
		select {
		case <-exited:
			return
		default:
		}
		if killErr := server.Process.Kill(); killErr != nil {
			fmt.Fprintln(os.Stderr, "stop xkmsd:", killErr)
		}
		<-exited
	}()

	if err := waitForServer(ports, exited, &waitErr, 60*time.Second); err != nil {
		return 0, newSetupError("xkmsd did not come up", err, logFile.Name())
	}

	if err := trustServer(env.urls["rest"], filepath.Join(work, "trust.pem")); err != nil {
		return 0, newSetupError("trust the server's CA", err, logFile.Name())
	}
	if err := authBootstrap(filepath.Join(work, "data"), env.urls["rest"]); err != nil {
		return 0, newSetupError("authenticate as the first-boot admin", err, logFile.Name())
	}

	code := m.Run()
	if code != 0 {
		if data, readErr := os.ReadFile(logFile.Name()); readErr == nil {
			lines := strings.Split(string(data), "\n")
			if len(lines) > 60 {
				lines = lines[len(lines)-60:]
			}
			fmt.Fprintln(os.Stderr, "xkmsd log tail:\n"+strings.Join(lines, "\n"))
		}
	}
	return code, nil
}

// setupError reports a failed setup step with the tail of the server log,
// read when the error is made: the work directory is gone by the time it
// is printed.
type setupError struct {
	step string
	err  error
	tail string
}

func newSetupError(step string, err error, log string) *setupError {
	e := &setupError{step: step, err: err}
	if data, readErr := os.ReadFile(log); readErr == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 40 {
			lines = lines[len(lines)-40:]
		}
		e.tail = strings.Join(lines, "\n")
	}
	return e
}

func (e *setupError) Error() string {
	if e.tail == "" {
		return e.step + ": " + e.err.Error()
	}
	return e.step + ": " + e.err.Error() + "\nxkmsd log tail:\n" + e.tail
}

func (e *setupError) Unwrap() error { return e.err }

// serverExitError reports xkmsd exiting before it served.
type serverExitError struct{ err error }

func (e *serverExitError) Error() string {
	if e.err == nil {
		return "xkmsd exited"
	}
	return "xkmsd exited: " + e.err.Error()
}

// goBuild builds pkg in dir to out.
func goBuild(dir, tags, out, pkg string) error {
	cmd := exec.Command("go", "build", "-buildvcs=false", "-tags", tags, "-o", out, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return &setupError{step: "go build " + pkg + ": " + stderr.String(), err: err}
	}
	return nil
}

// portSet are the listener ports of the test server.
type portSet struct{ rest, grpc, quic, mcp int }

// freePorts reserves loopback ports from the kernel: TCP for REST, gRPC and
// MCP, UDP for QUIC.
func freePorts() (portSet, error) {
	var p portSet
	for _, dst := range []*int{&p.rest, &p.grpc, &p.mcp} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return p, err
		}
		*dst = l.Addr().(*net.TCPAddr).Port
		if err := l.Close(); err != nil {
			return p, err
		}
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return p, err
	}
	p.quic = pc.LocalAddr().(*net.UDPAddr).Port
	return p, pc.Close()
}

// writeConfig writes an xkmsd configuration serving every transport.
func writeConfig(path, data string, p portSet) error {
	cfg := fmt.Sprintf(`server:
  host: "localhost"
  rest_port: %d
  grpc_port: %d
  quic_port: %d
  mcp_port: %d
protocols:
  unix: true
  rest: true
  grpc: true
  quic: true
  mcp: true
unix:
  socket_path: %s
  socket_mode: "0600"
  protocol: grpc
tls:
  enabled: true
  server_cn: localhost
  min_version: TLS1.3
  client_auth: verify
auth:
  enabled: true
  type: composite
  # The suite's xkey logs in with the first-boot admin's software mTLS
  # credential, which has no smartcard attestation chain.
  piv_login:
    enabled: true
    allow_unattested: true
ca:
  enabled: true
  identity:
    - subject:
        cn: "OIDC Credentials Integration Root CA"
        organization: "XKMS Tests"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc-curve: "P-256"
          key_type: "CA"
      keystore-type: "software"
      is-root: true
  selected-ca: 0
  default-validity-days: 365
logging:
  level: info
  format: json
datastore:
  engine: file
  path: %s
default_backend: software
backends:
  software:
    enabled: true
    path: %s/software
barrier:
  enabled: true
  strategy: none
`, p.rest, p.grpc, p.quic, p.mcp, env.socket, data, data)
	return os.WriteFile(path, []byte(cfg), 0o600)
}

// waitForServer waits until the Unix socket and every TCP listener accept.
func waitForServer(p portSet, exited <-chan struct{}, waitErr *error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		targets := []struct{ network, addr string }{
			{"unix", env.socket},
			{"tcp", fmt.Sprintf("127.0.0.1:%d", p.rest)},
			{"tcp", fmt.Sprintf("127.0.0.1:%d", p.grpc)},
			{"tcp", fmt.Sprintf("127.0.0.1:%d", p.mcp)},
		}
		for _, target := range targets {
			conn, err := net.DialTimeout(target.network, target.addr, 200*time.Millisecond)
			if err != nil {
				ready = false
				break
			}
			if err := conn.Close(); err != nil {
				return err
			}
		}
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-exited:
			return &serverExitError{err: *waitErr}
		case <-ticker.C:
		}
	}
}

// xkmsctl runs xkmsctl against transport and returns its combined output.
func xkmsctl(transport string, args ...string) (string, error) {
	full := append([]string{"--server", env.urls[transport], "--tls-ca", env.caFile,
		"--tls-cert", env.adminCert, "--tls-key", env.adminKey}, args...)
	cmd := exec.Command(env.xkmsctl, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// xkey runs xkey with XKMSD_URL set to transport's URL (empty transport: no
// xkmsd, xkey's local backend) and an isolated home.
func xkey(t *testing.T, transport, stdin string, args ...string) (string, error) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(env.xkey, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XKEY_HOME="+home,
		"XKEY_DATA_DIR="+filepath.Join(home, "data"),
		"XKMSD_TLS_CA="+env.caFile,
		"XKMSD_TOKEN="+env.token,
		"XKMSD_TLS_CERT="+env.adminCert,
		"XKMSD_TLS_KEY="+env.adminKey,
	)
	if transport != "" {
		cmd.Env = append(cmd.Env, "XKMSD_URL="+env.urls[transport])
	} else {
		cmd.Env = append(cmd.Env, "XKMSD_URL=")
	}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
