// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package session

import (
	"bytes"
	"context"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Session is the MITM-safe SSH session surface. Every concrete session
// owns its underlying *keys.Key (and any short-lived signer state);
// Close() destroys those enclaves deterministically and closes the
// underlying *ssh.Client.
//
// Session methods are safe for concurrent use only across distinct
// sessions — a single Session MUST NOT have Run / Shell / Close called
// concurrently with each other. This mirrors the x/crypto/ssh.Client
// contract.
type Session interface {
	// Run executes cmd on the remote host, returning stdout, stderr,
	// and a *CommandError on non-zero exit.
	Run(ctx context.Context, cmd string) (stdout, stderr []byte, err error)

	// Shell opens an interactive shell wired to the process's stdio.
	// Blocks until the remote shell exits. Primarily used by CLI tools.
	Shell(ctx context.Context) error

	// Close terminates the SSH connection, destroys every owned
	// enclave (in LIFO order), and frees goroutines. Subsequent calls
	// return nil.
	Close() error
}

// session is the concrete Session. It owns the transport (*ssh.Client)
// and the list of closers produced during Dial (enclave Destroy,
// deadline cancel, etc). Closers run in LIFO order on Close.
type session struct {
	host    string
	user    string
	client  *ssh.Client
	closers []func()

	// mu guards client / closed so Close is safe against concurrent
	// Run calls.
	mu     sync.Mutex
	closed bool
}

// Run implements Session.Run.
func (s *session) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	s.mu.Lock()
	if s.closed || s.client == nil {
		s.mu.Unlock()
		return nil, nil, &ClosedError{}
	}
	client := s.client
	s.mu.Unlock()

	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, &SessionError{Host: s.host, Err: err}
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	// Wire context cancellation: if the caller cancels, close the
	// session channel to unblock Run.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Closing the ssh.Session on cancellation is the supported
			// cancellation path in x/crypto/ssh.
			_ = sess.Close()
		case <-done:
		}
	}()
	defer close(done)

	if runErr := sess.Run(cmd); runErr != nil {
		if ctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), &TimeoutError{
				Host:     s.host,
				Duration: 0,
				Err:      ctx.Err(),
			}
		}
		exit := -1
		if ee, ok := runErr.(*ssh.ExitError); ok {
			exit = ee.ExitStatus()
		}
		return stdout.Bytes(), stderr.Bytes(), &CommandError{
			Command:  cmd,
			ExitCode: exit,
			Stderr:   stderr.String(),
			Err:      runErr,
		}
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// Shell implements Session.Shell. Wires Stdin/Stdout/Stderr of the
// caller process through to the remote shell. Blocks until the shell
// exits.
func (s *session) Shell(ctx context.Context) error {
	s.mu.Lock()
	if s.closed || s.client == nil {
		s.mu.Unlock()
		return &ClosedError{}
	}
	client := s.client
	s.mu.Unlock()

	sess, err := client.NewSession()
	if err != nil {
		return &SessionError{Host: s.host, Err: err}
	}
	defer func() { _ = sess.Close() }()

	sess.Stdin = stdin
	sess.Stdout = stdout
	sess.Stderr = stderr

	if err := sess.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		return &SessionError{Host: s.host, Err: err}
	}
	if err := sess.Shell(); err != nil {
		return &SessionError{Host: s.host, Err: err}
	}

	// Wire cancellation.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	defer close(done)

	waitErr := sess.Wait()
	if ctx.Err() != nil {
		return &TimeoutError{Host: s.host, Err: ctx.Err()}
	}
	if waitErr != nil {
		return &CommandError{Command: "shell", ExitCode: -1, Err: waitErr}
	}
	return nil
}

// Close terminates the transport, runs every registered closer (LIFO),
// and marks the session closed.
func (s *session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var closeErr error
	if s.client != nil {
		closeErr = s.client.Close()
		s.client = nil
	}
	// Invoke closers in LIFO order so enclaves installed last are
	// destroyed first (matches defer semantics and the Phase 1a
	// handoff note).
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
	return closeErr
}

// stdio aliases the process stdio streams. Kept in variables so tests
// can substitute them without reaching into os directly. Defaults are
// set in init() to avoid importing os at the package top level in a
// way that would fire during test-only builds where the caller supplies
// its own streams via Dial.
var (
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
)

func init() {
	stdin = osStdin
	stdout = osStdout
	stderr = osStderr
}
