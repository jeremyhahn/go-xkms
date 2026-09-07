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
	"errors"
	"io/fs"
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

	// SocketDir names the directory the session CREATES for its socket, giving
	// a caller the location without giving it the directory. The session makes
	// it with mode 0700, binds agent.sock inside it, and removes it — the
	// directory included — when the session ends. The resulting socket path is
	// SocketPath(SocketDir), known before the call, so a caller that has to
	// name the socket somewhere else (a container mount specification) can do
	// so without waiting for the session to start.
	//
	// It must not already exist: the session owns what it binds in, and a
	// directory somebody else made is one whose entries somebody else may be
	// able to replace. An existing path is refused with a *SocketDirExistsError
	// rather than adopted or cleared.
	//
	// This is what a caller wants when the socket has to live somewhere
	// specific — mounted into a sandbox, or under a tenant's own root — rather
	// than in the OS temporary directory. The parent directory must already
	// exist and pass checkWorkDir: creating the socket's own directory closes
	// the substitution window inside it, but nothing this package does closes
	// one in a parent that another user can write to.
	//
	// Mutually exclusive with WorkDir, which is the opposite bargain: an
	// existing directory the caller owns and keeps.
	SocketDir string
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
	served  chan struct{}
	stopped chan struct{}
	track   *tracker
	agent   *Agent
}

// ShutdownReport is what Stop returns. Abandoned counts the signature
// operations still executing when the caller's bound elapsed -- not connected
// clients, and not parked handlers.
//
// A non-zero count is not an error and not a leak: those handlers hold no
// connection any more, because Stop disconnects every attached client before it
// waits. They are goroutines finishing an uninterruptible Signer.Sign -- a TPM
// awaiting touch, a stalled KMS -- and the signature each eventually produces
// has nowhere to go.
//
// The one residual, stated so a caller can decide rather than discover: a
// handler abandoned this way may still deliver a signature to the client that
// asked for it, if that client attached BEFORE Stop began. No new authorization
// happens -- that client was already being served by an authorized session --
// but the operation completes after the owner considered the session closed. A
// caller that cannot accept this tears down its process; a caller that can
// (because the abandoned work is its own) carries on.
type ShutdownReport struct {
	// Abandoned counts signature operations still executing.
	Abandoned int

	// Joined reports whether every connection handler finished. It is separate
	// from Abandoned because the two can disagree: a handler parked with no
	// signature in flight -- an idle client holding the socket -- is zero
	// abandoned signatures AND an unfinished join. Collapsing them let that
	// case report a clean shutdown while the work directory was still on disk.
	Joined bool
}

// Clean reports whether shutdown finished completely: every handler joined and
// no signature left executing.
func (r ShutdownReport) Clean() bool { return r.Joined && r.Abandoned == 0 }

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
// The socket lives in the OS temporary directory by default. A caller that
// needs it somewhere specific -- under a tenant's own root, or in a directory
// it will mount into a sandbox -- names that location with req.SocketDir,
// which the session creates, owns, and removes with the socket inside it.
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

	if req.WorkDir != "" && req.SocketDir != "" {
		// The two say incompatible things about who owns the directory, and
		// silently preferring one would leave a caller convinced of the other.
		return nil, &InputError{Field: "SocketDir (WorkDir is also set)"}
	}

	workDir, ownsWorkDir, err := sessionDir(req)
	if err != nil {
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
	track := &tracker{}
	srv := New(signers...)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = serveListener(agentCtx, ln, srv, track)
	}()

	sess := &Session{
		SockPath: sock,
		Env:      []string{"SSH_AUTH_SOCK=" + sock},
		cancel:   cancel,
		served:   served,
		stopped:  make(chan struct{}),
		track:    track,
		agent:    srv,
	}
	// One reaper for both exit paths (Stop and ctx cancellation). It waits for
	// the listener to close and the clients to be disconnected, then joins the
	// handlers within the default bound and removes an owned work directory.
	// The bound is what guarantees the directory is reaped even when nobody
	// calls Stop and a signer is wedged.
	go func() {
		<-served
		_ = track.joinWithin(after(defaultJoinBound()))
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

// Stop ends the session and reports what it had to abandon.
//
// Two phases, and only the first is unconditional. The listener is closed and
// every attached client disconnected before Stop waits for anything: no new
// client can attach and no new signing operation can start, whatever ctx says.
// That is the security boundary, and it is not subject to a deadline.
//
// Stop then joins the connection handlers within ctx. A handler stuck inside an
// uninterruptible Signer.Sign cannot be woken by closing its connection, so
// waiting on one without a bound would hand control of the caller's shutdown to
// a wedged device. When ctx elapses first, the returned ShutdownReport says how
// many handlers were still running -- see its documentation for exactly what
// that does and does not mean. The count is never silently swallowed, because a
// bounded stop that reported nothing would be the same surprise as no bound at
// all.
//
// Pass a context with a deadline to choose the bound; pass context.Background()
// to wait for a clean join however long it takes. Idempotent, and safe on a
// session whose own context was already cancelled.
func (s *Session) Stop(ctx context.Context) ShutdownReport {
	s.cancel()
	<-s.served // listener closed, clients disconnected, socket unlinked

	// Join the handlers against the CALLER's bound, not the reaper's. Keying
	// this off s.stopped would silently truncate any bound longer than
	// defaultJoinBound -- and report the handler the reaper gave up on as a
	// clean shutdown, which is the exact failure this signature exists to
	// prevent.
	if !s.track.joinWithin(ctx.Done()) {
		// Two separate facts. Abandoned counts signature operations still
		// executing -- not handlers still parked, because an idle client
		// holding a socket is not a signing operation and calling it one raises
		// a security warning about work that never happened. Joined is false
		// regardless, because the handlers did NOT finish and the work
		// directory is therefore still on disk.
		return ShutdownReport{Abandoned: s.agent.InFlightSignatures()}
	}
	// Every handler finished, so the reaper's own join returns at once; waiting
	// for it here is what makes the work directory gone by the time a clean
	// Stop returns.
	<-s.stopped
	return ShutdownReport{Joined: true}
}

// sessionDir resolves the directory the agent socket is bound in and reports
// whether the session owns it. An owned directory is removed when the session
// ends; a caller's is left exactly as it was found.
//
// The three forms differ only in who made the directory, which is the whole of
// the security argument: the socket's own 0600 mode does not protect its
// pathname -- the containing directory decides who may unlink and re-bind it --
// so the directory has to be one nobody else can write to. A directory this
// process just created is that by construction. A caller's is that only if the
// caller says so, which is why Request.WorkDir is documented as a warranty.
func sessionDir(req Request) (string, bool, error) {
	switch {
	case req.SocketDir != "":
		// Absolute first: the path is checked, created and then handed out as
		// SSH_AUTH_SOCK, and a relative one would mean a different directory
		// to a child process with its own working directory.
		abs, err := filepath.Abs(req.SocketDir)
		if err != nil {
			return "", false, &WorkDirError{Err: err}
		}
		// The parent is checked, never created. Creating a caller's tree would
		// mean inventing directories with permissions nobody chose, in a place
		// nobody vouched for -- and the parent is exactly where a substitution
		// this package cannot prevent would come from: creating the socket's
		// own directory closes the window inside it, nothing closes one in a
		// parent another user can write to.
		if err := checkWorkDir(filepath.Dir(abs), "SocketDir"); err != nil {
			return "", false, err
		}
		// Mkdir, not MkdirAll: it fails when anything already occupies the
		// path, so a success means THIS call created the directory, with this
		// mode, and there was never a moment in which somebody else was inside
		// it. MkdirAll would instead accept an existing directory silently and
		// invent any missing parents.
		//
		// The mode is not restated afterwards. The process umask can only
		// CLEAR bits, so what lands is never more permissive than 0700 -- and
		// "no group or other access" is the whole of what the socket's safety
		// rests on, since the mode of the socket itself does not govern who can
		// reach its pathname. An owner-narrowing umask is the caller's own
		// setting and would fail the bind below with an error naming the path.
		// This is also exactly what os.MkdirTemp gives the default branch.
		if err := os.Mkdir(abs, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return "", false, &SocketDirExistsError{Path: abs}
			}
			return "", false, &WorkDirError{Err: err}
		}
		return abs, true, nil

	case req.WorkDir != "":
		// Only a caller-supplied directory is checked. The temp directory the
		// default branch creates is already private by construction on Unix,
		// and off Unix it inherits the platform's per-user temp isolation --
		// which is the OS's guarantee, not one this package would be inventing.
		if err := checkWorkDir(req.WorkDir, "WorkDir"); err != nil {
			return "", false, err
		}
		return req.WorkDir, false, nil

	default:
		dir, err := os.MkdirTemp("", "xkms-ssh-agent-")
		if err != nil {
			return "", false, &WorkDirError{Err: err}
		}
		return dir, true, nil
	}
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
func checkWorkDir(dir, field string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return &InputError{Field: field}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A symlink can be re-pointed between this check and the bind.
		return &InsecureWorkDirError{Path: dir, Reason: "is a symlink"}
	}
	if !info.IsDir() {
		return &InputError{Field: field}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return &InsecureWorkDirError{Path: dir, Reason: "is writable by group or other"}
	}
	return checkOwner(dir, info)
}
