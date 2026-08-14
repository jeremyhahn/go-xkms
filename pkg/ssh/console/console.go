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

// Package console provides an interactive SSH PTY session suitable for an
// embedded terminal (xterm.js in a browser, bridged over a WebSocket or a
// gRPC stream). It is a first-class xkms capability: the same Console powers
// the xkey desktop loopback path and any server-mounted web path, and it
// reuses the existing key signer (software OR hardware-backed) and host-key
// verification — the private key never leaves a hardware device.
package console

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/session"
)

const (
	defaultTerm = "xterm-256color"
	defaultRows = 24
	defaultCols = 80
)

// Console is an interactive PTY-backed SSH session. Read drains the remote
// terminal output; Write feeds keystrokes to the remote shell; Resize informs
// the remote of a new window size.
//
// The two shutdown operations are deliberately separate, the way net.TCPConn
// separates CloseWrite from Close:
//
//   - CloseWrite performs a HALF close. It sends an SSH channel EOF so the
//     remote command's stdin reports EOF (what feeding a script into a shell
//     needs) and leaves the session readable.
//   - Close performs a FULL teardown. It closes the session — which tears the
//     channel down and releases any Read or Write still in flight — and, for a
//     Console created by Dial, the underlying connection as well.
//
// Concurrency contract:
//
//   - Read, Write, Resize and Close may all be called concurrently from
//     different goroutines. That is the terminal-pump pattern every consumer
//     uses: an output pump reading, an input pump writing, a control path
//     resizing, and a UI "disconnect" closing. Close never blocks on a Write.
//   - CloseWrite must be sequenced after the caller's final Write (it is the
//     "no more input" signal, so by definition no write is outstanding). Calls
//     to Write after CloseWrite return *WriteClosedError rather than racing the
//     channel's EOF flag.
//   - After Close, every operation returns *ClosedError. Close itself is
//     idempotent.
type Console interface {
	io.ReadWriteCloser

	// Resize sets the remote PTY window to rows x cols characters.
	Resize(rows, cols int) error

	// CloseWrite half-closes the session: it signals EOF to the remote
	// command's stdin and leaves the read side open. It is idempotent.
	CloseWrite() error
}

// Config tunes the PTY. Zero values select sensible defaults
// (xterm-256color, 24x80).
type Config struct {
	Term string
	Rows int
	Cols int
	// Env are additional environment variables to set on the remote shell.
	// Servers may ignore variables not in their AcceptEnv allow-list.
	Env map[string]string
}

func (c Config) term() string {
	if c.Term != "" {
		return c.Term
	}
	return defaultTerm
}

func (c Config) rows() int {
	if c.Rows > 0 {
		return c.Rows
	}
	return defaultRows
}

func (c Config) cols() int {
	if c.Cols > 0 {
		return c.Cols
	}
	return defaultCols
}

// DialRequest opens an interactive console against a host using a pre-resolved
// signer. Unlike pkg/ssh/session.DialRequest it carries a signer (not a
// *keys.Key), so it works with hardware-backed keys (the SDK resolves the
// signer via Client.Keys().Signer).
type DialRequest struct {
	Host   string
	Port   int
	User   string
	Signer ssh.Signer

	// Signers are additional candidate signers offered alongside Signer
	// during public-key authentication, in order — the way the OpenSSH
	// client offers every agent/identity key until the server accepts
	// one. At least one of Signer/Signers must be set.
	Signers []ssh.Signer

	KnownHosts   known_hosts.Store
	HostKeyScope scope.Scope
	HostKeyOwner string

	// HostKeyConfirm, when set, is consulted for a host with no existing
	// pin (trust-on-first-use). nil reproduces the current strict
	// behavior: an unpinned host fails the handshake. See
	// known_hosts.CallbackWithConfirm for the exact semantics — a
	// conflicting pin always hard-fails without ever reaching
	// HostKeyConfirm.
	HostKeyConfirm known_hosts.Confirmer

	// KnownHostsExtraFiles are additional OpenSSH known_hosts files (e.g.
	// ~/.ssh/known_hosts) consulted when the host has no store pin, before
	// HostKeyConfirm is invoked. A matching key found in one of these
	// files is treated as known; a different key for the same host is a
	// hard mismatch failure. On a fresh HostKeyConfirm acceptance the
	// accepted key is mirrored (best-effort) into every entry here.
	KnownHostsExtraFiles []string

	// KnownHostsSkipStore selects the "system"-only known-hosts policy:
	// KnownHosts is neither consulted nor written. KnownHosts must still
	// be non-nil (Dial's input guard is unconditional), but with this set
	// host trust is managed entirely via KnownHostsExtraFiles /
	// HostKeyConfirm.
	KnownHostsSkipStore bool
}

// Dial establishes the SSH connection (host-key verified against KnownHosts,
// any KnownHostsExtraFiles, and an optional HostKeyConfirm TOFU policy) and
// opens an interactive PTY shell. The returned Console owns the underlying
// connection — Close terminates it.
func Dial(ctx context.Context, req DialRequest, cfg Config) (Console, error) {
	if req.Signer == nil && len(req.Signers) == 0 {
		return nil, &InputError{Field: "Signer"}
	}
	if req.KnownHosts == nil {
		return nil, &InputError{Field: "KnownHosts"}
	}
	hostCallback := buildHostKeyCallback(ctx, req)
	client, err := session.DialClient(ctx, session.ClientParams{
		Host:            req.Host,
		Port:            req.Port,
		User:            req.User,
		Signer:          req.Signer,
		Signers:         req.Signers,
		HostKeyCallback: hostCallback,
	})
	if err != nil {
		return nil, err
	}
	c, err := open(client, cfg, true)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return c, nil
}

// buildHostKeyCallback composes the ssh.HostKeyCallback Dial installs on the
// client, layering (in order) the pin store, any external known_hosts
// files, and an optional TOFU confirmer:
//
//  1. The store is consulted first (known_hosts.Callback's normal path) —
//     entirely skipped (never read or written) when KnownHostsSkipStore is
//     set.
//  2. On a store *NotFoundError (including the always-not-found result of a
//     skipped store), each entry in KnownHostsExtraFiles is checked via
//     known_hosts.LookupFile. A matching key there is treated as known (the
//     connection proceeds, and — unless the store is skipped — the pin is
//     self-healed into the store); a DIFFERENT key for the same host is a
//     hard mismatch failure. TOFU never overrides a conflicting pin,
//     whether the conflict comes from the store or an external file.
//  3. If the host is still unknown, HostKeyConfirm (when set) is consulted.
//     On acceptance the new pin is persisted to the store (unless skipped)
//     and mirrored (best-effort) into every KnownHostsExtraFiles entry.
//
// The layering above is implemented as a single known_hosts.Confirmer
// composed with known_hosts.CallbackWithConfirm: Dial does not reimplement
// Verify or the store-persistence CallbackWithConfirm already provides.
// When KnownHostsExtraFiles is empty and HostKeyConfirm is nil, the
// composed confirmer is left nil so CallbackWithConfirm falls back to plain
// Callback — reproducing today's strict behavior byte for byte.
func buildHostKeyCallback(ctx context.Context, req DialRequest) ssh.HostKeyCallback {
	var confirm known_hosts.Confirmer
	if len(req.KnownHostsExtraFiles) > 0 || req.HostKeyConfirm != nil {
		confirm = func(cctx context.Context, host string, key ssh.PublicKey) (bool, error) {
			for _, f := range req.KnownHostsExtraFiles {
				pub, found, lerr := known_hosts.LookupFile(f, host)
				if lerr != nil {
					return false, lerr
				}
				if !found {
					continue
				}
				if keys.Fingerprint(pub) != keys.Fingerprint(key) {
					return false, &known_hosts.MismatchError{
						Host:     host,
						Expected: keys.Fingerprint(pub),
						Received: keys.Fingerprint(key),
					}
				}
				return true, nil // known via an external known_hosts file
			}

			if req.HostKeyConfirm == nil {
				return false, nil
			}
			accept, cerr := req.HostKeyConfirm(cctx, host, key)
			if cerr != nil || !accept {
				return accept, cerr
			}

			// Fresh first contact: mirror into every external file.
			// Best-effort — a write failure on an external file must not
			// fail the session, matching pkg/ssh/connect's Sync()/
			// mirrorKnownHosts treatment of the same class of failure.
			pin := known_hosts.PinFromPublicKey(host, req.HostKeyScope, req.HostKeyOwner, key, known_hosts.SourceFirstContact)
			if line, eerr := known_hosts.Emit(pin); eerr == nil {
				for _, f := range req.KnownHostsExtraFiles {
					_ = known_hosts.AppendMissing([]byte(line+"\n"), f)
				}
			}
			return true, nil
		}
	}

	store := req.KnownHosts
	if req.KnownHostsSkipStore {
		store = noopHostKeyStore{}
	}
	return known_hosts.CallbackWithConfirm(ctx, store, req.HostKeyScope, req.HostKeyOwner, confirm)
}

// noopHostKeyStore discards all writes and reports every lookup as absent.
// It backs the "system"-only known-hosts policy (DialRequest.
// KnownHostsSkipStore), letting Dial reuse known_hosts.CallbackWithConfirm's
// Verify/persist plumbing without ever touching the real pin store.
type noopHostKeyStore struct{}

var _ known_hosts.Store = noopHostKeyStore{}

func (noopHostKeyStore) Add(context.Context, *known_hosts.Pin) error { return nil }

func (noopHostKeyStore) Get(_ context.Context, sc scope.Scope, owner, host string) (*known_hosts.Pin, error) {
	return nil, &known_hosts.NotFoundError{Scope: string(sc), Owner: owner, Host: host}
}

func (noopHostKeyStore) List(context.Context, scope.Scope, string) ([]*known_hosts.Pin, error) {
	return nil, nil
}

func (noopHostKeyStore) Remove(_ context.Context, sc scope.Scope, owner, host string) error {
	return &known_hosts.NotFoundError{Scope: string(sc), Owner: owner, Host: host}
}

// Open starts an interactive PTY shell on an already-established *ssh.Client.
// The caller retains ownership of the client (Console.Close closes only the
// SSH session, not the client). Use Dial when you want the console to own the
// whole connection.
func Open(client *ssh.Client, cfg Config) (Console, error) {
	if client == nil {
		return nil, &InputError{Field: "client"}
	}
	return open(client, cfg, false)
}

// open is the shared implementation. ownClient controls whether Close also
// closes the *ssh.Client.
func open(client *ssh.Client, cfg Config, ownClient bool) (Console, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, &SessionError{Err: err}
	}

	for k, v := range cfg.Env {
		_ = sess.Setenv(k, v)
	}

	// For a terminal we want stderr merged into the single output stream the
	// PTY presents, so wire stdin/stdout pipes and merge stderr to stdout.
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, &SessionError{Err: err}
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, &SessionError{Err: err}
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, &SessionError{Err: err}
	}

	if err := sess.RequestPty(cfg.term(), cfg.rows(), cfg.cols(), ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		_ = sess.Close()
		return nil, &SessionError{Err: err}
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, &SessionError{Err: err}
	}

	c := &sshConsole{
		client:    client,
		ownClient: ownClient,
		sess:      sess,
		stdin:     stdin,
		out:       io.MultiReader(stdout, stderr),
	}
	return c, nil
}

var _ Console = (*sshConsole)(nil)

// sshConsole is the concrete Console.
//
// client, sess, stdin and out are written once during construction and only
// read afterwards, so no lock is needed to reach them. All mutable state is
// held in atomics and a sync.Once, which is what lets Close run concurrently
// with an in-flight Read or Write without either side blocking the other.
type sshConsole struct {
	client    *ssh.Client
	ownClient bool
	sess      *ssh.Session
	stdin     io.WriteCloser
	out       io.Reader

	// closed is set before teardown begins so a concurrent Read/Write/Resize
	// reports the typed closed error instead of touching a dying channel.
	closed atomic.Bool

	// writeClosed is set by CloseWrite (and by Close) and gates every later
	// Write. It is what keeps a post-half-close Write away from the
	// channel's EOF flag inside x/crypto/ssh.
	writeClosed atomic.Bool

	closeOnce sync.Once
	closeErr  error

	writeCloseOnce sync.Once
	writeCloseErr  error
}

// Read drains remote terminal output. Once the console is closed it reports
// *ClosedError rather than whatever transport-level error the teardown
// happened to produce.
func (c *sshConsole) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, &ClosedError{}
	}
	n, err := c.out.Read(p)
	if err != nil && c.closed.Load() {
		return n, &ClosedError{}
	}
	return n, err
}

// Write feeds keystrokes to the remote shell.
func (c *sshConsole) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, &ClosedError{}
	}
	if c.writeClosed.Load() {
		return 0, &WriteClosedError{}
	}
	n, err := c.stdin.Write(p)
	if err != nil && c.closed.Load() {
		// A concurrent Close released this write; report the teardown
		// rather than the transport's incidental error.
		return n, &ClosedError{}
	}
	return n, err
}

// Resize informs the remote PTY of a new window size.
func (c *sshConsole) Resize(rows, cols int) error {
	if c.closed.Load() {
		return &ClosedError{}
	}
	if rows <= 0 {
		rows = defaultRows
	}
	if cols <= 0 {
		cols = defaultCols
	}
	return c.sess.WindowChange(rows, cols)
}

// CloseWrite half-closes the console: it closes the session's stdin, which
// sends an SSH channel EOF so the remote command sees end-of-input, and leaves
// the read side open so trailing output can still be drained. Callers that
// want the whole session gone call Close instead (Close does NOT send EOF —
// it tears the channel down).
//
// It must be sequenced after the caller's last Write; subsequent writes are
// rejected with *WriteClosedError.
func (c *sshConsole) CloseWrite() error {
	if c.closed.Load() {
		return &ClosedError{}
	}
	c.writeCloseOnce.Do(func() {
		c.writeClosed.Store(true)
		if err := c.stdin.Close(); err != nil && !errors.Is(err, io.EOF) {
			// io.EOF means the remote already closed the channel, which
			// is the state CloseWrite is trying to reach.
			c.writeCloseErr = err
		}
	})
	return c.writeCloseErr
}

// Close terminates the session (and the connection when this Console owns it).
//
// It closes the SESSION, never the stdin pipe: closing stdin sends an SSH
// channel EOF, and x/crypto/ssh mutates the channel's EOF flag without
// synchronizing it against an in-flight write, so a "disconnect" racing the
// keystroke pump was a genuine data race. Closing the session tears the
// channel down instead, which releases any pending Read/Write with an error
// and can never block on the remote.
//
// Close is idempotent and safe to call from any goroutine at any time.
func (c *sshConsole) Close() error {
	c.closeOnce.Do(func() {
		// Publish the closed state first so a concurrent Read/Write/Resize
		// takes the fast path instead of entering a channel being torn down.
		c.closed.Store(true)
		c.writeClosed.Store(true)

		if c.sess != nil {
			// The remote may already have closed the channel (the shell
			// exited, or the peer hung up); x/crypto/ssh reports that as
			// io.EOF. The session is terminated either way, so it is a
			// clean close, not an error.
			if err := c.sess.Close(); err != nil && !errors.Is(err, io.EOF) {
				c.closeErr = err
			}
		}
		if c.ownClient && c.client != nil {
			// Closing the connection is what releases a write blocked in
			// SSH flow control against a remote that stopped reading.
			if err := c.client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				c.closeErr = errors.Join(c.closeErr, err)
			}
		}
	})
	return c.closeErr
}
