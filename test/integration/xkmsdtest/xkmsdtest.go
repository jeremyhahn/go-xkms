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
// the binaries from this checkout, runs `xkmsd init` over a throwaway data
// directory with a passphrase barrier as an operator does on a fresh
// deployment, starts xkmsd and unseals that barrier through the pre-boot
// sealed-window listener, trusts the CA bundle the server publishes, fetched
// from the server the TLS anchors it persisted verify, and hands the suite the
// admin mTLS credential init issued.
//
// The server serves REST over TLS on a kernel-assigned loopback port, with
// client certificates verified against its own CA and init's, and the
// WebAuthn relying party "localhost", so passkeys and console origins work
// against it.
package xkmsdtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// RelyingParty is the WebAuthn relying party ID the server is configured
// with: its passkeys are scoped to it and the console runs on it.
const RelyingParty = "localhost"

// barrierPassphrase is the test server's SO PIN, which `xkmsd init` makes
// its barrier passphrase.
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

	// URLs maps each transport the server serves to the URL a client dials
	// it at: "rest" always; "unix", "grpc", "quic" and "mcp" with
	// WithAllTransports.
	URLs map[string]string

	// Data is the server's data directory.
	Data string

	cmd    *exec.Cmd
	exited chan struct{}
	err    error
	log    string
}

// Option configures the server Start runs.
type Option func(*options)

// options are the Start settings.
type options struct {
	allTransports bool
}

// WithAllTransports serves every transport, not only REST: gRPC, MCP and
// HTTP/3 (QUIC, on the REST port) over TLS on kernel-assigned loopback
// ports, and gRPC on a Unix socket in the work directory. Server.URLs names
// each.
func WithAllTransports() Option {
	return func(o *options) { o.allTransports = true }
}

// listeners are the server's listen addresses.
type listeners struct {
	rest, grpc, quic, mcp int
	socket                string
}

// Start starts the xkmsd binary at bin over a new data
// directory under dir and returns once the server serves, its barrier is
// initialized and its CA is trusted.
func Start(bin, dir string, opts ...Option) (*Server, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	var l listeners
	var err error
	if l.rest, err = freePort(); err != nil {
		return nil, err
	}
	data := filepath.Join(dir, "data")
	s := &Server{
		URL:    fmt.Sprintf("https://localhost:%d", l.rest),
		CAFile: filepath.Join(dir, "ca.pem"),
		Dir:    dir,
		Data:   data,
		log:    filepath.Join(dir, "xkmsd.log"),
		exited: make(chan struct{}),
	}
	s.URLs = map[string]string{"rest": s.URL}
	if o.allTransports {
		if l.grpc, err = freePort(); err != nil {
			return nil, err
		}
		if l.mcp, err = freePort(); err != nil {
			return nil, err
		}
		// xkmsd's own QUIC listener; clients reach HTTP/3 on the unified
		// server's REST port.
		if l.quic, err = freePort(); err != nil {
			return nil, err
		}
		l.socket = filepath.Join(dir, "run", "xkms.sock")
		s.URLs["unix"] = "unix://" + l.socket
		s.URLs["grpc"] = fmt.Sprintf("grpcs://127.0.0.1:%d", l.grpc)
		s.URLs["quic"] = fmt.Sprintf("quic://localhost:%d", l.rest)
		s.URLs["mcp"] = fmt.Sprintf("mcps://localhost:%d", l.mcp)
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	config := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(config, []byte(serverConfig(l, data)), 0o600); err != nil {
		return nil, err
	}
	logFile, err := os.Create(s.log)
	if err != nil {
		return nil, err
	}
	if err := initialize(bin, config, data, logFile); err != nil {
		stepErr := &StepError{Step: "initialize the server with xkmsd init", Err: err, Log: s.LogTail(40)}
		return nil, errors.Join(stepErr, logFile.Close())
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
		{"unseal the barrier through the sealed window", func() error { return s.unsealBarrier(data) }},
		{"wait for the server", func() error { return s.waitServing(l) }},
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

// initialize runs `xkmsd init` with the config at config over data, as an
// operator does before a deployment's first start: it initializes the
// barrier with the SO PIN as its passphrase and issues the admin mTLS
// credential into data. The PIN travels in the environment, never argv.
func initialize(bin, config, data string, out io.Writer) error {
	cmd := exec.Command(bin, "init", "--config", config, "--data-dir", data,
		"--hostname", "localhost", "--admin-factor", "mtls")
	cmd.Dir = filepath.Dir(config)
	cmd.Env = append(os.Environ(), "XKMS_SO_PIN="+barrierPassphrase)
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// unsealBarrier unseals the barrier `xkmsd init` initialized through the
// pre-boot sealed-window listener (OpenBarrier), giving up when xkmsd exits or
// startTimeout passes.
func (s *Server) unsealBarrier(data string) error {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	go func() {
		select {
		case <-s.exited:
			cancel()
		case <-ctx.Done():
		}
	}()
	client, err := SealedWindowClient(ctx, bootstrapCertPath(data))
	if err == nil {
		err = OpenBarrier(ctx, client, s.URL, []byte(barrierPassphrase))
	}
	select {
	case <-s.exited:
		return errors.Join(ErrExited, s.err, err)
	default:
		return err
	}
}

// waitServing waits until the unsealed server accepts connections on every
// listener it serves.
func (s *Server) waitServing(l listeners) error {
	targets := [][2]string{{"tcp", fmt.Sprintf("127.0.0.1:%d", l.rest)}}
	if l.socket != "" {
		targets = append(targets,
			[2]string{"unix", l.socket},
			[2]string{"tcp", fmt.Sprintf("127.0.0.1:%d", l.grpc)},
			[2]string{"tcp", fmt.Sprintf("127.0.0.1:%d", l.mcp)})
	}
	deadline := time.Now().Add(startTimeout)
	for _, target := range targets {
		for {
			conn, err := net.DialTimeout(target[0], target[1], time.Second)
			if err == nil {
				if err := conn.Close(); err != nil {
					return err
				}
				break
			}
			if err := s.wait(deadline); err != nil {
				return err
			}
		}
	}
	return nil
}

// trustCA fetches the server's CA bundle over the public GET
// /v1/ca/bootstrap from the server the anchors it persisted verify, retrying
// until the embedded CA has composed.
func (s *Server) trustCA() error {
	deadline := time.Now().Add(startTimeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	client, err := SealedWindowClient(ctx, bootstrapCertPath(s.Data))
	if err != nil {
		return err
	}
	for {
		bundle, err := fetchCABundle(ctx, client, s.URL)
		if err == nil {
			return os.WriteFile(s.CAFile, bundle, 0o600)
		}
		if waitErr := s.wait(deadline); waitErr != nil {
			return errors.Join(waitErr, err)
		}
	}
}

// fetchCABundle makes one fetch of the CA bundle the server at url publishes
// on GET /v1/ca/bootstrap, through client, which verifies the server against
// the anchors it persisted (SealedWindowClient), and returns the bundle's PEM.
// A request no verified server answers fails with an *UnansweredError.
func fetchCABundle(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	route := url + "/v1/ca/bootstrap"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &UnansweredError{URL: route, Err: err}
	}
	bundle, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{URL: route, Code: resp.StatusCode, Body: string(bundle)}
	}
	if !x509.NewCertPool().AppendCertsFromPEM(bundle) {
		return nil, &StatusError{URL: route, Code: resp.StatusCode, Body: "no certificate in the CA bundle"}
	}
	return bundle, nil
}

// findAdminCredential locates the admin credential `xkmsd init` wrote into
// the data directory.
func (s *Server) findAdminCredential(data string) error {
	cert, key, err := adminCredential(data)
	if err != nil {
		return err
	}
	s.AdminCert, s.AdminKey = cert, key
	return nil
}

// adminCredential returns the paths of the first-boot admin's certificate
// and key under data, or ErrNoAdminCredential while either is missing.
func adminCredential(data string) (cert, key string, err error) {
	cert, key = filepath.Join(data, "admin-cert.pem"), filepath.Join(data, "admin-key.pem")
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); err != nil {
			return "", "", errors.Join(ErrNoAdminCredential, err)
		}
	}
	return cert, key, nil
}

// AdminClient returns the client an unsealed xkmsd at url answers: it
// presents the first-boot admin credential xkmsd writes under data, and
// trusts the CA bundle the server publishes, fetched only from a server the
// anchors it persisted under data verify. Once the barrier is unsealed every
// route, barrier status included, requires an authenticated caller, and the
// server presents its CA-issued certificate instead of the configured one.
// AdminClient waits, until ctx ends, for first boot to write the credential
// and for a verified server to serve the bundle.
func AdminClient(ctx context.Context, url, data string) (*http.Client, error) {
	cert, key, err := adminCredential(data)
	for err != nil {
		if waitErr := pause(ctx); waitErr != nil {
			return nil, errors.Join(waitErr, err)
		}
		cert, key, err = adminCredential(data)
	}
	anchored, err := SealedWindowClient(ctx, bootstrapCertPath(data))
	if err != nil {
		return nil, err
	}
	bundle, err := fetchCABundle(ctx, anchored, url)
	for err != nil {
		if waitErr := pause(ctx); waitErr != nil {
			return nil, errors.Join(waitErr, err)
		}
		bundle, err = fetchCABundle(ctx, anchored, url)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, &StatusError{URL: url, Body: "no certificate in the CA bundle"}
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS13,
		}},
	}, nil
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
func serverConfig(l listeners, data string) string {
	return fmt.Sprintf(`server:
  host: "localhost"
  rest_port: %[1]d
%[4]stls:
  enabled: true
  server_cn: localhost
  min_version: TLS1.3
  client_auth: verify
  client_cas:
    - %[2]s/ca-bundle.pem
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
`, l.rest, data, RelyingParty, transportConfig(l))
}

// transportConfig is the server configuration's transport section: REST
// alone, or every transport when l names the others.
func transportConfig(l listeners) string {
	if l.socket == "" {
		return `protocols:
  unix: false
  rest: true
  grpc: false
  quic: false
  mcp: false
`
	}
	return fmt.Sprintf(`  grpc_port: %d
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
`, l.grpc, l.quic, l.mcp, l.socket)
}
