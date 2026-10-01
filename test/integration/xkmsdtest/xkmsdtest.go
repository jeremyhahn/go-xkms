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

// Package xkmsdtest runs a real xkmsd for an integration suite: it builds
// the binaries from this checkout, starts xkmsd over a throwaway data
// directory with a passphrase barrier, initializes that barrier through the
// pre-boot sealed-window listener as an operator does on a fresh
// deployment, trusts the server's CA the way a first-contact client does,
// and hands the suite the first-boot admin's mTLS credential.
//
// The server serves REST over TLS on a kernel-assigned loopback port, with
// client certificates verified against its own CA and the WebAuthn relying
// party "localhost", so passkeys and console origins work against it.
package xkmsdtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// RelyingParty is the WebAuthn relying party ID the server is configured
// with: its passkeys are scoped to it and the console runs on it.
const RelyingParty = "localhost"

// barrierPassphrase is the test server's barrier passphrase.
const barrierPassphrase = "xkmsdtest-barrier-passphrase"

// startTimeout bounds each start-up step.
const startTimeout = 90 * time.Second

// Errors.
var (
	// ErrExited reports xkmsd exiting before it served.
	ErrExited = errors.New("xkmsdtest: xkmsd exited")

	// ErrTimeout reports a start-up step that did not finish in time.
	ErrTimeout = errors.New("xkmsdtest: timed out")

	// ErrNoAdminCredential reports a first boot that left no admin
	// credential in the data directory.
	ErrNoAdminCredential = errors.New("xkmsdtest: no first-boot admin credential in the data directory")
)

// StepError reports a failed start-up step with the tail of the server log.
type StepError struct {
	Step string
	Err  error
	Log  string
}

// Error implements the error interface.
func (e *StepError) Error() string {
	msg := "xkmsdtest: " + e.Step + ": " + e.Err.Error()
	if e.Log != "" {
		msg += "\nxkmsd log tail:\n" + e.Log
	}
	return msg
}

// Unwrap returns the step's failure.
func (e *StepError) Unwrap() error { return e.Err }

// BuildError reports a binary that did not build.
type BuildError struct {
	Pkg    string
	Output string
	Err    error
}

// Error implements the error interface.
func (e *BuildError) Error() string {
	return "xkmsdtest: go build " + e.Pkg + ": " + e.Err.Error() + "\n" + e.Output
}

// Unwrap returns the build's failure.
func (e *BuildError) Unwrap() error { return e.Err }

// StatusError reports an unexpected HTTP status.
type StatusError struct {
	URL  string
	Code int
	Body string
}

// Error implements the error interface.
func (e *StatusError) Error() string {
	return fmt.Sprintf("xkmsdtest: %s: HTTP %d: %s", e.URL, e.Code, e.Body)
}

// Build builds Go package pkg of the module in dir, with tags, to out.
func Build(dir, tags, out, pkg string) error {
	cmd := exec.Command("go", "build", "-buildvcs=false", "-tags", tags, "-o", out, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return &BuildError{Pkg: pkg, Output: output.String(), Err: err}
	}
	return nil
}

// Server is a running xkmsd.
type Server struct {
	// URL is the REST base URL, https://localhost:<port>.
	URL string

	// CAFile is the server's CA bundle, PEM.
	CAFile string

	// AdminCert and AdminKey are the first-boot admin's mTLS credential.
	AdminCert string
	AdminKey  string

	// Dir is the server's work directory (config, data, log).
	Dir string

	cmd    *exec.Cmd
	exited chan struct{}
	err    error
	log    string
}

// Start starts the xkmsd binary at bin over a new data
// directory under dir and returns once the server serves, its barrier is
// initialized and its CA is trusted.
func Start(bin, dir string) (*Server, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	s := &Server{
		URL:    fmt.Sprintf("https://localhost:%d", port),
		CAFile: filepath.Join(dir, "ca.pem"),
		Dir:    dir,
		log:    filepath.Join(dir, "xkmsd.log"),
		exited: make(chan struct{}),
	}
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	config := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(config, []byte(serverConfig(port, data)), 0o600); err != nil {
		return nil, err
	}
	logFile, err := os.Create(s.log)
	if err != nil {
		return nil, err
	}
	s.cmd = exec.Command(bin, "-config", config)
	s.cmd.Dir = dir
	s.cmd.Stdout = logFile
	s.cmd.Stderr = logFile
	if err := s.cmd.Start(); err != nil {
		return nil, errors.Join(err, logFile.Close())
	}
	go func() {
		s.err = s.cmd.Wait()
		_ = logFile.Close()
		close(s.exited)
	}()

	steps := []struct {
		name string
		run  func() error
	}{
		{"initialize the barrier through the sealed window", func() error { return s.initializeBarrier(data) }},
		{"wait for the server", func() error { return s.waitServing(port) }},
		{"trust the server's CA", s.trustCA},
		{"find the first-boot admin credential", func() error { return s.findAdminCredential(data) }},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			stepErr := &StepError{Step: step.name, Err: err, Log: s.LogTail(40)}
			return nil, errors.Join(stepErr, s.Close())
		}
	}
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error {
	select {
	case <-s.exited:
		return nil
	default:
	}
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-s.exited:
		return nil
	case <-timer.C:
		if err := s.cmd.Process.Kill(); err != nil {
			return err
		}
		<-s.exited
		return nil
	}
}

// LogTail returns the last n lines of the server log.
func (s *Server) LogTail(n int) string {
	data, err := os.ReadFile(s.log)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// RootCAs returns a pool holding the server's CA.
func (s *Server) RootCAs() (*x509.CertPool, error) {
	pem, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, &StatusError{URL: s.CAFile, Body: "no certificate in the CA bundle"}
	}
	return pool, nil
}

// HTTPClient returns a client that trusts the server and presents the mTLS
// credential certFile/keyFile.
func (s *Server) HTTPClient(certFile, keyFile string) (*http.Client, error) {
	roots, err := s.RootCAs()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}},
	}, nil
}

// wait waits a moment before the next attempt; it fails once deadline has
// passed or xkmsd has exited.
func (s *Server) wait(deadline time.Time) error {
	if time.Now().After(deadline) {
		return ErrTimeout
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.exited:
		return errors.Join(ErrExited, s.err)
	case <-timer.C:
		return nil
	}
}

// initializeBarrier initializes the passphrase barrier through the pre-boot
// sealed-window listener, which serves the TLS certificate xkmsd persisted
// in its data directory before any CA exists.
func (s *Server) initializeBarrier(data string) error {
	deadline := time.Now().Add(startTimeout)
	certPath := filepath.Join(data, "unified-tls", "cert.pem")
	var client *http.Client
	for client == nil {
		if pem, err := os.ReadFile(certPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				client = &http.Client{
					Timeout:   15 * time.Second,
					Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
				}
				break
			}
		}
		if err := s.wait(deadline); err != nil {
			return err
		}
	}
	body, err := json.Marshal(map[string][]byte{"secret": []byte(barrierPassphrase)})
	if err != nil {
		return err
	}
	for {
		resp, err := client.Post(s.URL+"/v1/barrier/initialize", "application/json", bytes.NewReader(body))
		if err == nil {
			return drain(resp, http.StatusNoContent)
		}
		if err := s.wait(deadline); err != nil {
			return err
		}
	}
}

// waitServing waits until the unsealed server accepts connections.
func (s *Server) waitServing(port int) error {
	deadline := time.Now().Add(startTimeout)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			return conn.Close()
		}
		if err := s.wait(deadline); err != nil {
			return err
		}
	}
}

// trustCA fetches the server's CA bundle trust-on-first-use over the public
// GET /v1/ca/bootstrap, retrying until the embedded CA has composed.
func (s *Server) trustCA() error {
	deadline := time.Now().Add(startTimeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
			Mode:      bootstrap.ModeTOFU,
			ServerURL: s.URL,
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			TOFU: &bootstrap.TOFUConfig{
				PinStore:    truststrap.NewMemoryPinStore(),
				ConfirmFunc: func(context.Context, *truststrap.Pin) error { return nil },
			},
		})
		cancel()
		if err == nil {
			return os.WriteFile(s.CAFile, bundle.PEM, 0o600)
		}
		if waitErr := s.wait(deadline); waitErr != nil {
			return errors.Join(waitErr, err)
		}
	}
}

// findAdminCredential locates the first-boot admin credential first boot
// wrote into the data directory.
func (s *Server) findAdminCredential(data string) error {
	cert, key := filepath.Join(data, "admin-cert.pem"), filepath.Join(data, "admin-key.pem")
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); err != nil {
			return errors.Join(ErrNoAdminCredential, err)
		}
	}
	s.AdminCert, s.AdminKey = cert, key
	return nil
}

// drain consumes and closes resp, refusing any status but want.
func drain(resp *http.Response, want int) error {
	body, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		return &StatusError{URL: resp.Request.URL.String(), Code: resp.StatusCode, Body: string(body)}
	}
	return nil
}

// freePort reserves a loopback TCP port from the kernel.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close()
}

// serverConfig is the xkmsd configuration of the test server.
func serverConfig(port int, data string) string {
	return fmt.Sprintf(`server:
  host: "localhost"
  rest_port: %[1]d
protocols:
  unix: false
  rest: true
  grpc: false
  quic: false
  mcp: false
tls:
  enabled: true
  server_cn: localhost
  min_version: TLS1.3
  client_auth: verify
auth:
  enabled: true
  type: composite
  piv_login:
    enabled: true
    allow_unattested: true
  # A suite onboards many users from one address in seconds; the login
  # limiter's production default (10/min) would throttle the invitations.
  session:
    login_rate_per_min: 6000
webauthn:
  enabled: true
  rp_id: %[3]q
  rp_origins:
    - "https://%[3]s:%[1]d"
  rp_display_name: "xkmsdtest"
  attestation_preference: "none"
  resident_key: "preferred"
  user_verification: "preferred"
ca:
  enabled: true
  identity:
    - subject:
        cn: "xkmsdtest Root CA"
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
  path: %[2]s
default_backend: software
backends:
  software:
    enabled: true
    path: %[2]s/software
barrier:
  enabled: true
  strategy: passphrase
`, port, data, RelyingParty)
}
