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

package agent

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// Request describes an agent-only session to start.
type Request struct {
	// Signers are the identities the agent serves. At least one is required
	// and none may be nil. Only the ssh.Signer is held: a signer backed by a
	// KMS, TPM, PKCS#11 token or a remote xkms leaves its private half exactly
	// where it lives — signature requests cross the socket, key material never
	// does.
	Signers []ssh.Signer

	// WorkDir is the directory the agent socket is created in. When empty a
	// temporary directory is created and removed when the session ends — that
	// is the only form the SDK offers, and the only one with a security
	// guarantee behind it.
	//
	// A caller-supplied directory is used as-is and left in place. It exists
	// for pkg/ssh/connect, which passes a directory it created itself and
	// keeps its known_hosts in alongside the socket. **Supplying one means
	// vouching for it.** checkWorkDir below rejects the obviously unsafe
	// shapes, but that is a sanity check and not a guarantee: it inspects a
	// pathname, and a pathname can be redirected between the check and the
	// bind by anyone controlling an ancestor. Off Unix it cannot even inspect
	// ownership. Pass only a directory this process created, or one whose
	// whole ancestry is under this user's control.
	WorkDir string
}

// Session is a running agent-only session: a socket serving the requested
// signers over the SSH agent protocol, with no connection target. It is the
// primitive behind tools that speak ssh-agent without dialing a host — git
// commit signing under gpg.format=ssh, ssh-keygen -Y sign, age — and is what
// pkg/ssh/connect layers host semantics on top of.
//
// The session ends at the first of Stop or cancellation of the context passed
// to StartSession. Either way the socket file is removed, along with the work
// directory when the session created it; Done reports when that has happened.
type Session struct {
	// SockPath is the filesystem path of the agent socket — the value a child
	// process needs in SSH_AUTH_SOCK.
	SockPath string

	// Env is {"SSH_AUTH_SOCK=<SockPath>"}, ready to append to a child
	// process's environment.
	Env []string

	cancel  context.CancelFunc
	stopped chan struct{}
}

// socketName is the file name the agent socket is given inside its work
// directory. Shared so pkg/ssh/connect names the same file.
const socketName = "agent.sock"

// SocketPath returns the agent socket path inside workDir.
func SocketPath(workDir string) string { return filepath.Join(workDir, socketName) }

// StartSession binds an ephemeral agent socket, serves req.Signers on it, and
// returns the live session. The socket exists by the time StartSession returns
// — it is bound synchronously, so a caller may hand SockPath to a child process
// immediately and a bind failure arrives as an error rather than as a socket
// that never appears.
//
// No connection target is involved and no host-key state is touched: this
// serves a key, nothing more.
func StartSession(ctx context.Context, req Request) (*Session, error) {
	// A session under a dead context is born dead: the reaper can remove the
	// socket before StartSession even returns, handing the caller a nil error
	// and an SSH_AUTH_SOCK that answers nothing. Say so instead.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Signers) == 0 {
		return nil, &InputError{Field: "Signers"}
	}
	for _, s := range req.Signers {
		if s == nil || !usableSigner(s) {
			return nil, &InputError{Field: "Signers"}
		}
	}
	// Freeze the identity set. Validation above is worth nothing if the caller
	// can reach into its own slice afterwards and change which key a live
	// signing oracle serves -- or write a nil into it and panic the agent.
	signers := make([]ssh.Signer, len(req.Signers))
	copy(signers, req.Signers)

	workDir := req.WorkDir
	ownsWorkDir := false
	if workDir == "" {
		dir, err := os.MkdirTemp("", "xkms-ssh-agent-")
		if err != nil {
			return nil, &WorkDirError{Err: err}
		}
		workDir = dir
		ownsWorkDir = true
	} else if err := checkWorkDir(workDir); err != nil {
		// Only a caller-supplied directory is checked. The temp directory the
		// branch above creates is already private by construction on Unix, and
		// off Unix it inherits the platform's per-user temp isolation -- which
		// is the OS's guarantee, not one this package would be inventing.
		return nil, err
	}

	// SockPath leaves this process: it becomes SSH_AUTH_SOCK for a child that
	// is usually started with its own Cmd.Dir (git commit runs in the repo).
	// A relative path would resolve against the child's directory instead of
	// ours -- and against whatever this process chdir'd to by shutdown, so
	// cleanup could miss the socket it bound.
	abs, err := filepath.Abs(workDir)
	if err != nil {
		if ownsWorkDir {
			_ = os.RemoveAll(workDir)
		}
		return nil, &WorkDirError{Err: err}
	}
	workDir = abs

	sock := SocketPath(workDir)
	ln, err := listen(sock)
	if err != nil {
		if ownsWorkDir {
			_ = os.RemoveAll(workDir)
		}
		return nil, err
	}

	agentCtx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = serveListener(agentCtx, ln, New(signers...))
	}()

	sess := &Session{
		SockPath: sock,
		Env:      []string{"SSH_AUTH_SOCK=" + sock},
		cancel:   cancel,
		stopped:  make(chan struct{}),
	}
	// One reaper for both exit paths (Stop and ctx cancellation): it waits for
	// ServeListener to remove the socket, then removes an owned work directory
	// and marks the session stopped.
	go func() {
		<-served
		if ownsWorkDir {
			_ = os.RemoveAll(workDir)
		}
		close(sess.stopped)
	}()
	return sess, nil
}

// Done is closed once the agent has stopped, the socket has been removed, and
// an owned work directory has been cleaned up. Wait on it to observe the end of
// a session cancelled through its context.
func (s *Session) Done() <-chan struct{} { return s.stopped }

// Stop ends the session and blocks until the socket is gone. Idempotent, and
// safe to call on a session whose context was already cancelled.
func (s *Session) Stop() {
	s.cancel()
	<-s.stopped
}

// usableSigner reports whether a signer can actually be served. A typed nil
// (a nil *T boxed in an ssh.Signer) is not caught by an interface nil check,
// and the first PublicKey call would panic -- inside the serving goroutine,
// where there is nobody to return an error to and a panic takes the process
// down. Failing the caller's own StartSession call is the right place.
func usableSigner(s ssh.Signer) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return s.PublicKey() != nil
}

// checkWorkDir rejects the unsafe shapes of a supplied work directory.
//
// This is defence in depth, **not a guarantee**, and the difference matters:
// it inspects a pathname, then the socket is bound through that pathname
// again, so anyone controlling an ancestor can redirect it in between.
// Checking every component only moves the same race one level up; closing it
// properly needs a bind anchored to an open directory descriptor, which
// net.Listen cannot express. That is precisely why the SDK exposes no
// caller-chosen directory at all — see sdk/go/client/ssh/agent.go.
//
// A unix socket's own 0600 mode does not protect it: whether the *pathname*
// can be replaced is governed by the containing directory. In a shared
// writable directory another user can unlink agent.sock and bind their own
// agent at the same path, and the child process reading SSH_AUTH_SOCK would
// then be talking to them. So the directory must be private to this user: not
// a symlink (which could be redirected after the check), owned by us, and not
// writable by group or other.
//
// That also closes the window between bind and chmod in Listen, during which
// the socket's mode is whatever the process umask left it: in a 0700
// directory nobody else can traverse in to reach it.
func checkWorkDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return &InputError{Field: "WorkDir"}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A symlink can be re-pointed between this check and the bind.
		return &InsecureWorkDirError{Path: dir, Reason: "is a symlink"}
	}
	if !info.IsDir() {
		return &InputError{Field: "WorkDir"}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return &InsecureWorkDirError{Path: dir, Reason: "is writable by group or other"}
	}
	return checkOwner(dir, info)
}
