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
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// uploadPartialSuffix is appended to the remote path while an Upload is in
// flight. The fully-streamed payload is atomically renamed off this path
// onto the final path so a truncated transfer never appears at the target.
const uploadPartialSuffix = ".partial"

// Session is the MITM-safe SSH session surface. Every concrete session
// owns its underlying *keys.Key (and any short-lived signer state);
// Close() destroys those enclaves deterministically and closes the
// underlying *ssh.Client.
//
// Session methods are safe for concurrent use only across distinct
// sessions — a single Session MUST NOT have Run / Shell / Upload / Close
// called concurrently with each other. This mirrors the x/crypto/ssh.Client
// contract.
type Session interface {
	// Run executes cmd on the remote host, returning stdout, stderr,
	// and a *CommandError on non-zero exit.
	Run(ctx context.Context, cmd string) (stdout, stderr []byte, err error)

	// Shell opens an interactive shell wired to the process's stdio.
	// Blocks until the remote shell exits. Primarily used by CLI tools.
	Shell(ctx context.Context) error

	// Upload streams src to remotePath over the existing host-key-verified
	// connection WITHOUT buffering the whole payload in memory, so it is
	// safe for multi-gigabyte transfers (ISO images, container tars). The
	// payload is written to "<remotePath>.partial" and atomically renamed
	// onto remotePath once the stream completes, so a partial transfer
	// never leaves a truncated file at the final path.
	//
	// When mode has non-zero permission bits the staged file is chmod'd to
	// mode.Perm() before the rename; a zero mode preserves the remote
	// umask default. remotePath must not contain a single-quote character
	// (it is rejected with an *UnsafePathError). The context bounds the
	// transfer: on cancellation the in-flight command is aborted and a
	// *TimeoutError is returned.
	Upload(ctx context.Context, src io.Reader, remotePath string, mode fs.FileMode) error

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

// Upload implements Session.Upload. It opens a fresh ssh.Session on the
// already host-key-verified client, wires src into that session's stdin,
// and runs a remote shell command that writes stdin to a temporary
// "<remotePath>.partial" file, optionally chmods it, then atomically
// renames it onto remotePath. The payload is streamed (never buffered in
// memory), so multi-gigabyte transfers run in constant memory.
func (s *session) Upload(ctx context.Context, src io.Reader, remotePath string, mode fs.FileMode) error {
	if src == nil {
		return &NilInputError{Field: "src"}
	}
	if remotePath == "" {
		return &NilInputError{Field: "remotePath"}
	}
	if err := validateRemotePath(remotePath); err != nil {
		return err
	}

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

	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		return &SessionError{Host: s.host, Err: err}
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr

	cmd := uploadCommand(remotePath, mode)
	if err := sess.Start(cmd); err != nil {
		return &CommandError{Command: cmd, ExitCode: -1, Stderr: stderr.String(), Err: err}
	}

	// Wire context cancellation: closing the session on cancel aborts the
	// remote command, which unblocks both the stdin copy below (writes on
	// the closed channel return) and the Wait that follows.
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-cancelDone:
		}
	}()
	defer close(cancelDone)

	// Stream the payload to the remote stdin, then close it to deliver EOF
	// so the remote `cat` terminates and the command can complete.
	_, copyErr := io.Copy(stdinPipe, src)
	closeErr := stdinPipe.Close()

	waitErr := sess.Wait()

	if ctx.Err() != nil {
		return &TimeoutError{Host: s.host, Err: ctx.Err()}
	}
	if copyErr != nil {
		return &UploadError{Path: remotePath, Err: copyErr}
	}
	if closeErr != nil {
		return &UploadError{Path: remotePath, Err: closeErr}
	}
	if waitErr != nil {
		exit := -1
		if ee, ok := waitErr.(*ssh.ExitError); ok {
			exit = ee.ExitStatus()
		}
		return &CommandError{Command: cmd, ExitCode: exit, Stderr: stderr.String(), Err: waitErr}
	}
	return nil
}

// validateRemotePath rejects remote paths that cannot be safely embedded
// in a single-quoted remote shell argument. We single-quote every path in
// uploadCommand, so a path containing a single quote could break out of
// the quoting; rather than attempt fragile escaping we fail closed.
func validateRemotePath(path string) error {
	if strings.ContainsRune(path, '\'') {
		return &UnsafePathError{Path: path, Reason: "remote path must not contain a single-quote character"}
	}
	return nil
}

// uploadCommand builds the remote shell command that consumes stdin into a
// staged partial file, optionally chmods it, then atomically renames it
// onto the final path. The path is single-quoted; validateRemotePath has
// already rejected any path that would break out of the quoting.
func uploadCommand(path string, mode fs.FileMode) string {
	partial := path + uploadPartialSuffix
	var b strings.Builder
	b.WriteString("cat > '")
	b.WriteString(partial)
	b.WriteString("'")
	if perm := mode.Perm(); perm != 0 {
		b.WriteString(" && chmod ")
		b.WriteString(fmt.Sprintf("%#o", uint32(perm)))
		b.WriteString(" '")
		b.WriteString(partial)
		b.WriteString("'")
	}
	b.WriteString(" && mv -f '")
	b.WriteString(partial)
	b.WriteString("' '")
	b.WriteString(path)
	b.WriteString("'")
	return b.String()
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
