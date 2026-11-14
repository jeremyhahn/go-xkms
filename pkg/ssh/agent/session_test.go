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
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// waitDone fails the test if the session does not finish cleaning up promptly.
func waitDone(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session never signalled Done")
	}
}

// stopClean stops a session and requires nothing was abandoned. Most tests have
// no wedged signer, so a non-zero count would mean a handler leaked rather than
// finished -- worth failing on rather than discarding.
func stopClean(t *testing.T, s *Session) {
	t.Helper()
	if r := s.Stop(context.Background()); !r.Clean() {
		t.Errorf("clean shutdown expected, %d handler(s) abandoned", r.Abandoned)
	}
}

// stopBounded calls Stop with a deadline. Stop is deliberately unbounded in
// production -- shutdown waits for connection handlers to finish -- so a test
// that called it directly would hang the whole suite rather than report which
// assertion broke.
func stopBounded(t *testing.T, s *Session) {
	t.Helper()
	stopped := make(chan struct{})
	go func() { defer close(stopped); s.Stop(context.Background()) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not complete; shutdown is blocked on a live connection handler")
	}
}

// privateDir returns a temp directory private to this user. t.TempDir gives
// 0775, which StartSession rightly refuses: an agent socket's own mode does not
// protect its pathname -- the containing directory decides who can replace it.
// A real caller supplying a WorkDir has to do exactly this.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}

// TestStartSession_SocketIsBoundBeforeReturn is the property the whole design
// rests on: a caller may hand SockPath to a child process the instant
// StartSession returns. It asserts a *connectable* socket, not merely a path
// that exists, because a bound-but-unserved socket would still fail a child.
func TestStartSession_SocketIsBoundBeforeReturn(t *testing.T) {
	signer := newEd25519Signer(t)
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{signer}})
	require.NoError(t, err)
	defer stopClean(t, sess)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err, "socket must be connectable on return, with no polling")
	defer func() { _ = conn.Close() }()

	keys, err := sshagent.NewClient(conn).List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, signer.PublicKey().Marshal(), keys[0].Blob,
		"the agent must advertise the signer it was given")
}

// TestStartSession_SignsOverTheSocket proves the session serves signatures, and
// that they verify under the served public key -- the reason a caller wants a
// socket at all.
func TestStartSession_SignsOverTheSocket(t *testing.T) {
	signer := newEd25519Signer(t)
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{signer}})
	require.NoError(t, err)
	defer stopClean(t, sess)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	payload := []byte("agent-only session signing payload")
	sig, err := sshagent.NewClient(conn).Sign(signer.PublicKey(), payload)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(payload, sig),
		"the signature must verify under the served key")
}

// TestStartSession_EnvCarriesTheSocket covers the child-process handoff: Env is
// exactly what goes into a spawned process's environment.
func TestStartSession_EnvCarriesTheSocket(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)
	defer stopClean(t, sess)

	require.Equal(t, []string{"SSH_AUTH_SOCK=" + sess.SockPath}, sess.Env)
}

// TestStartSession_SocketPermissions asserts the socket is not reachable by
// other users: an agent socket is a signing oracle for whoever can connect.
func TestStartSession_SocketPermissions(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)
	defer stopClean(t, sess)

	info, err := os.Stat(sess.SockPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"agent socket must be owner-only")
}

// TestStartSession_StopRemovesSocketAndOwnedWorkDir covers the Stop lifetime
// path: Stop blocks until the socket is gone, and the temp work dir the session
// created goes with it.
func TestStartSession_StopRemovesSocketAndOwnedWorkDir(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)
	workDir := filepath.Dir(sess.SockPath)

	stopClean(t, sess)

	_, err = os.Stat(sess.SockPath)
	assert.True(t, errors.Is(err, os.ErrNotExist), "socket must be gone once Stop returns, got %v", err)
	_, err = os.Stat(workDir)
	assert.True(t, errors.Is(err, os.ErrNotExist), "session-owned work dir must be removed, got %v", err)
}

// TestStartSession_StopDisconnectsLiveClients is the security half of the
// lifetime contract: closing the listener is not enough, because a client that
// connected first would keep signing through a session its owner believes is
// over. Stop must leave no usable signing path.
func TestStartSession_StopDisconnectsLiveClients(t *testing.T) {
	signer := newEd25519Signer(t)
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{signer}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := sshagent.NewClient(conn)

	payload := []byte("before stop")
	_, err = client.Sign(signer.PublicKey(), payload)
	require.NoError(t, err, "the held connection must work while the session is live")

	stopBounded(t, sess)

	_, err = client.Sign(signer.PublicKey(), []byte("after stop"))
	assert.Error(t, err, "a connection held across Stop must no longer sign")
}

// TestStartSession_ContextCancelDisconnectsLiveClients is the same property on
// the other exit path, observed through Done rather than Stop.
func TestStartSession_ContextCancelDisconnectsLiveClients(t *testing.T) {
	signer := newEd25519Signer(t)
	ctx, cancel := context.WithCancel(context.Background())
	sess, err := StartSession(ctx, Request{Signers: []ssh.Signer{signer}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := sshagent.NewClient(conn)

	_, err = client.Sign(signer.PublicKey(), []byte("before cancel"))
	require.NoError(t, err)

	cancel()
	waitDone(t, sess)

	_, err = client.Sign(signer.PublicKey(), []byte("after cancel"))
	assert.Error(t, err, "a connection held across cancellation must no longer sign")
}

// TestStartSession_StopIsIdempotent covers a second Stop (defer plus explicit
// stop is the ordinary caller shape) not panicking or blocking.
func TestStartSession_StopIsIdempotent(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)

	stopClean(t, sess)
	stopClean(t, sess)
}

// TestStartSession_ContextCancelEndsSession is the lifetime contract stated on
// the SDK entry point: the socket dies with ctx, without anyone calling Stop.
func TestStartSession_ContextCancelEndsSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sess, err := StartSession(ctx, Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)
	workDir := filepath.Dir(sess.SockPath)

	cancel()
	waitDone(t, sess)

	_, err = os.Stat(sess.SockPath)
	assert.True(t, errors.Is(err, os.ErrNotExist), "socket must be gone after ctx cancel, got %v", err)
	_, err = os.Stat(workDir)
	assert.True(t, errors.Is(err, os.ErrNotExist), "session-owned work dir must be removed after ctx cancel, got %v", err)
	_, err = net.Dial("unix", sess.SockPath)
	assert.Error(t, err, "a cancelled session must not still answer connections")
}

// TestStartSession_StopAfterContextCancel covers the overlap of both exit
// paths: Stop on an already-cancelled session returns rather than deadlocking.
func TestStartSession_StopAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sess, err := StartSession(ctx, Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)

	cancel()
	waitDone(t, sess)

	done := make(chan struct{})
	go func() { defer close(done); sess.Stop(context.Background()) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked on an already-cancelled session")
	}
}

// TestStartSession_CallerWorkDirIsLeftInPlace covers the borrowed-directory
// branch: the socket goes, the caller's directory stays (pkg/ssh/connect keeps
// its known_hosts alongside).
func TestStartSession_CallerWorkDirIsLeftInPlace(t *testing.T) {
	workDir := privateDir(t)
	sess, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: workDir,
	})
	require.NoError(t, err)
	require.Equal(t, SocketPath(workDir), sess.SockPath)

	stopClean(t, sess)

	_, err = os.Stat(sess.SockPath)
	assert.True(t, errors.Is(err, os.ErrNotExist), "socket must be gone, got %v", err)
	_, err = os.Stat(workDir)
	assert.NoError(t, err, "a caller-supplied work dir must be left in place")
}

// TestStartSession_CallerFileAtSocketPathIsNotDeleted covers a data-loss edge
// the public WorkDir option opens up: a caller's own file sitting at the socket
// path must fail the bind, not be silently unlinked. Only a real stale socket
// is ours to remove.
func TestStartSession_CallerFileAtSocketPathIsNotDeleted(t *testing.T) {
	workDir := privateDir(t)
	occupied := SocketPath(workDir)
	const precious = "a file the caller put here"
	require.NoError(t, os.WriteFile(occupied, []byte(precious), 0o600))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: workDir,
	})
	var le *ListenError
	require.ErrorAs(t, err, &le)
	require.ErrorIs(t, err, ErrPathOccupied)

	body, rerr := os.ReadFile(occupied)
	require.NoError(t, rerr, "the caller's file must still be there")
	assert.Equal(t, precious, string(body), "the caller's file must be untouched")
}

// TestStartSession_LiveSocketIsNotClobbered covers key isolation between two
// sessions sharing a WorkDir. The first session's children hold its socket path
// in SSH_AUTH_SOCK; binding over it would redirect them onto a different key
// set without anyone noticing.
func TestStartSession_LiveSocketIsNotClobbered(t *testing.T) {
	workDir := privateDir(t)
	first := newEd25519Signer(t)

	held, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{first},
		WorkDir: workDir,
	})
	require.NoError(t, err)
	defer stopClean(t, held)

	_, err = StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: workDir,
	})
	require.ErrorIs(t, err, ErrSocketInUse)
	var le *ListenError
	require.ErrorAs(t, err, &le)

	// The first session is untouched and still serves its own key.
	conn, err := net.Dial("unix", held.SockPath)
	require.NoError(t, err, "the live session's socket must survive the refused bind")
	defer func() { _ = conn.Close() }()
	keys, err := sshagent.NewClient(conn).List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, first.PublicKey().Marshal(), keys[0].Blob,
		"the live session must still serve its own key, not the second one's")
}

// TestStartSession_LeftoverSocketIsRefusedNotCleared pins the ownership rule:
// a socket left by a crashed run is NOT ours to clear. Clearing it needs
// inspect-unlink-bind, and between those steps another process can bind its own
// live agent at that path -- which the unlink would then destroy, redirecting
// its children onto a different key set. Refusing costs an error the caller can
// act on; the leftover belongs to whoever owns the directory.
func TestStartSession_LeftoverSocketIsRefusedNotCleared(t *testing.T) {
	workDir := privateDir(t)
	leftover := SocketPath(workDir)

	// Bind and abandon a socket without unlinking it, as a crash would.
	ln, err := net.Listen("unix", leftover)
	require.NoError(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	info, err := os.Lstat(leftover)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSocket, "precondition: a socket is left behind")

	_, err = StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: workDir,
	})
	require.ErrorIs(t, err, ErrPathOccupied)
	var le *ListenError
	require.ErrorAs(t, err, &le)

	_, serr := os.Lstat(leftover)
	assert.NoError(t, serr, "the leftover must still be there -- it is not ours to remove")
}

// TestStartSession_RelativeWorkDirIsAbsolutised is the consumer's real shape:
// SockPath becomes SSH_AUTH_SOCK for a child started with its own Cmd.Dir (git
// commit runs in the repo), so a relative path would resolve against the
// child's directory, not ours. The test moves this process elsewhere after
// starting the session and requires the socket to still be reachable.
func TestStartSession_RelativeWorkDirIsAbsolutised(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(base, "sock"), 0o700))
	t.Chdir(base)

	sess, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: "sock",
	})
	require.NoError(t, err)
	defer stopClean(t, sess)

	assert.True(t, filepath.IsAbs(sess.SockPath), "SockPath must be absolute, got %q", sess.SockPath)
	assert.Equal(t, "SSH_AUTH_SOCK="+sess.SockPath, sess.Env[0])

	// Whoever reads SSH_AUTH_SOCK does so from their own directory.
	t.Chdir(t.TempDir())
	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err, "the socket must be reachable from another working directory")
	require.NoError(t, conn.Close())
}

// TestStartSession_MissingCallerWorkDir refuses a supplied path that is not an
// existing directory. Listen would MkdirAll it, and the session does not own
// what it did not create -- so a typo would silently leave a directory behind
// on every run instead of reporting the mistake.
func TestStartSession_MissingCallerWorkDir(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(base, "not-created")

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: missing,
	})
	var ie *InputError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "WorkDir", ie.Field)

	_, serr := os.Stat(missing)
	assert.True(t, errors.Is(serr, os.ErrNotExist),
		"a rejected WorkDir must not have been created, got %v", serr)
}

// TestStartSession_CallerWorkDirIsNotADirectory covers the same guard for a
// path that exists but is a regular file.
func TestStartSession_CallerWorkDirIsNotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: file,
	})
	var ie *InputError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "WorkDir", ie.Field)
}

// TestStartSession_AlreadyCancelledContext refuses a dead context rather than
// returning a session whose socket the reaper is already removing -- which
// would hand a caller a nil error and an SSH_AUTH_SOCK that answers nothing.
func TestStartSession_AlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess, err := StartSession(ctx, Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, sess)
}

// TestStartSession_ExpiredDeadline covers the same guard for a deadline that
// has already passed.
func TestStartSession_ExpiredDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err := StartSession(ctx, Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestStartSession_NoSigners rejects an empty identity set rather than serving
// a socket that can sign nothing.
func TestStartSession_NoSigners(t *testing.T) {
	_, err := StartSession(context.Background(), Request{})
	var ie *InputError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "Signers", ie.Field)
}

// TestStartSession_NilSigner rejects a nil entry: it would panic on the first
// List rather than at the call that supplied it.
func TestStartSession_NilSigner(t *testing.T) {
	_, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t), nil}})
	var ie *InputError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "Signers", ie.Field)
}

// TestStartSession_ListenFailureIsReturnedNotAwaited covers the bind-failure
// branch. Binding synchronously is the point: an unusable work dir must come
// back as a typed error, not as a socket that never appears.
func TestStartSession_ListenFailureIsReturnedNotAwaited(t *testing.T) {
	workDir := privateDir(t)
	// Occupy the socket path with a non-empty directory: the stale-socket
	// unlink cannot clear it, so the bind cannot succeed.
	require.NoError(t, os.Mkdir(SocketPath(workDir), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(SocketPath(workDir), "occupied"), []byte("x"), 0o600))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: workDir,
	})
	var le *ListenError
	require.ErrorAs(t, err, &le)
}

// TestStartSession_ListenFailureCleansOwnedWorkDir asserts a failed start
// leaves no temp directory behind. A work dir nested deep enough pushes the
// socket path past the ~108-byte sockaddr_un limit: MkdirTemp still succeeds,
// so the cleanup path is exercised, and the failure does not depend on file
// permissions (which root ignores) or on the effective user at all.
func TestStartSession_ListenFailureCleansOwnedWorkDir(t *testing.T) {
	base := t.TempDir()
	deep := filepath.Join(base, strings.Repeat("d/", 60))
	require.NoError(t, os.MkdirAll(deep, 0o700))
	t.Setenv("TMPDIR", deep)

	_, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	var le *ListenError
	require.ErrorAs(t, err, &le, "an over-long socket path must fail the bind")

	entries, rerr := os.ReadDir(deep)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "a failed start must not leave a work dir behind")
}

// TestStartSession_WorkDirCreationFailure covers the other pre-bind failure:
// no usable temp root at all.
func TestStartSession_WorkDirCreationFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	var we *WorkDirError
	require.ErrorAs(t, err, &we)
}

// TestStartSession_SignersAreFrozen covers the identity set being copied: a
// caller that mutates its own slice afterwards must not be able to change what
// a live agent serves, which would make the nil/empty validation meaningless.
func TestStartSession_SignersAreFrozen(t *testing.T) {
	served, other := newEd25519Signer(t), newEd25519Signer(t)
	signers := []ssh.Signer{served}

	sess, err := StartSession(context.Background(), Request{Signers: signers})
	require.NoError(t, err)
	defer stopClean(t, sess)

	signers[0] = other // the caller reuses its slice

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	keys, err := sshagent.NewClient(conn).List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, served.PublicKey().Marshal(), keys[0].Blob,
		"the agent must keep serving the key it was started with")
}

// TestSocketPath names the socket file the whole stack agrees on.
func TestSocketPath(t *testing.T) {
	assert.Equal(t, filepath.Join("/work", "agent.sock"), SocketPath("/work"))
}

// TestSessionErrorTypes covers the Error/Unwrap methods of the session errors.
func TestSessionErrorTypes(t *testing.T) {
	ie := &InputError{Field: "Signers"}
	assert.Contains(t, ie.Error(), "Signers")

	inner := errors.New("boom")
	we := &WorkDirError{Err: inner}
	assert.Contains(t, we.Error(), "boom")
	assert.ErrorIs(t, we, inner)

	unknown := &UnknownKeyError{Format: "ssh-ed25519"}
	assert.Contains(t, unknown.Error(), "ssh-ed25519")

	le := &ListenError{Err: inner}
	assert.Contains(t, le.Error(), "listen")
	assert.ErrorIs(t, le, inner)

	ae := &AcceptError{Err: inner}
	assert.Contains(t, ae.Error(), "accept")
	assert.ErrorIs(t, ae, inner)
}

// TestStartSession_ShutdownUnderConcurrentDials drives shutdown against
// connections arriving continuously, so Stop lands in the middle of the accept
// loop rather than after it has quiesced. Under -race this guards the whole
// shutdown path -- the live-connection map, the drain, the handler join --
// against use-after-close and data races.
//
// It does NOT prove the Add/Wait ordering in the accept loop. That window is a
// few instructions wide and moving `handlers.Add` back outside the mutex does
// not fail this test, even at 300 iterations. The ordering is argued from the
// code (drain takes the same lock, so a counted handler is always visible to
// the drain that precedes Wait) rather than observed from a failure, and that
// is stated here so the next reader does not mistake a green run for evidence
// of it.
func TestStartSession_ShutdownUnderConcurrentDials(t *testing.T) {
	for i := 0; i < 100; i++ {
		sess, err := StartSession(context.Background(), Request{
			Signers: []ssh.Signer{newEd25519Signer(t)},
		})
		require.NoError(t, err)

		// Dial in a loop until the socket dies, so connections are still
		// arriving at the instant Stop begins draining.
		stopDialing := make(chan struct{})
		var dialers sync.WaitGroup
		for j := 0; j < 6; j++ {
			dialers.Add(1)
			go func() {
				defer dialers.Done()
				for {
					select {
					case <-stopDialing:
						return
					default:
					}
					c, derr := net.Dial("unix", sess.SockPath)
					if derr != nil {
						return
					}
					_ = c.Close()
				}
			}()
		}
		// Let the dialers get into their loop before shutdown starts.
		runtime.Gosched()

		stopBounded(t, sess)
		close(stopDialing)
		dialers.Wait()
	}
}

// nilSigner is a typed nil: a nil *nilSigner boxed in an ssh.Signer is not the
// nil interface, so an interface nil check waves it through.
type nilSigner struct{}

func (n *nilSigner) PublicKey() ssh.PublicKey                       { panic("typed nil") }
func (n *nilSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) { panic("typed nil") }

// TestStartSession_TypedNilSigner rejects a signer whose concrete value is nil.
// `s == nil` does not catch it, and the first PublicKey call would panic inside
// the serving goroutine -- where there is nobody to return an error to and the
// panic takes the process down. It has to fail the caller's own call instead.
func TestStartSession_TypedNilSigner(t *testing.T) {
	var typedNil *nilSigner
	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t), typedNil},
	})
	var ie *InputError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "Signers", ie.Field)
}

// TestStartSession_GroupWritableWorkDirIsRefused covers the local-substitution
// hazard: a unix socket's 0600 mode does not protect its pathname, the
// containing directory does. In a shared writable directory another user can
// unlink agent.sock and bind their own agent there, and the child reading
// SSH_AUTH_SOCK would be talking to them.
func TestStartSession_GroupWritableWorkDirIsRefused(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o775))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: dir,
	})
	var iw *InsecureWorkDirError
	require.ErrorAs(t, err, &iw)
	assert.Contains(t, iw.Error(), "group or other")
}

// TestStartSession_WorldWritableWorkDirIsRefused is the same hazard through the
// other-writable bit, which is the /tmp shape.
func TestStartSession_WorldWritableWorkDirIsRefused(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o707))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: dir,
	})
	var iw *InsecureWorkDirError
	require.ErrorAs(t, err, &iw)
}

// TestStartSession_SymlinkWorkDirIsRefused covers the check-then-use gap: a
// symlink pointing at a private directory today can be re-pointed at a shared
// one between the check and the bind, so the link itself is refused.
func TestStartSession_SymlinkWorkDirIsRefused(t *testing.T) {
	base := privateDir(t)
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))

	_, err := StartSession(context.Background(), Request{
		Signers: []ssh.Signer{newEd25519Signer(t)},
		WorkDir: link,
	})
	var iw *InsecureWorkDirError
	require.ErrorAs(t, err, &iw)
	assert.Contains(t, iw.Error(), "symlink")
}

// TestAgent_RSANeverSignsWithSHA1 pins the algorithm floor. x/crypto's default
// for an RSA signer is the legacy ssh-rsa (SHA-1), and an unflagged request is
// an ssh-agent client's default rather than a deliberate choice -- so with this
// agent reachable by any such client, falling through would hand out a
// non-approved primitive on request.
func TestAgent_RSANeverSignsWithSHA1(t *testing.T) {
	signer := newRSASigner(t)
	a := New(signer)
	data := []byte("payload")

	for _, tc := range []struct {
		name  string
		flags sshagent.SignatureFlags
		want  string
	}{
		{"no flags", 0, ssh.KeyAlgoRSASHA256},
		{"sha256", sshagent.SignatureFlagRsaSha256, ssh.KeyAlgoRSASHA256},
		{"sha512", sshagent.SignatureFlagRsaSha512, ssh.KeyAlgoRSASHA512},
		{"both, 512 wins", sshagent.SignatureFlagRsaSha256 | sshagent.SignatureFlagRsaSha512, ssh.KeyAlgoRSASHA512},
		{"unknown flag", sshagent.SignatureFlags(1 << 20), ssh.KeyAlgoRSASHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := a.SignWithFlags(signer.PublicKey(), data, tc.flags)
			require.NoError(t, err)
			assert.Equal(t, tc.want, sig.Format, "must never be %q", ssh.KeyAlgoRSA)
			require.NoError(t, signer.PublicKey().Verify(data, sig))
		})
	}
}

// TestAgent_Ed25519IgnoresRSAFlags covers the non-RSA path: the rsa-sha2 flags
// are meaningless for a key whose algorithm is its type.
func TestAgent_Ed25519IgnoresRSAFlags(t *testing.T) {
	signer := newEd25519Signer(t)
	a := New(signer)
	data := []byte("payload")

	sig, err := a.SignWithFlags(signer.PublicKey(), data, sshagent.SignatureFlagRsaSha512)
	require.NoError(t, err)
	assert.Equal(t, ssh.KeyAlgoED25519, sig.Format)
	require.NoError(t, signer.PublicKey().Verify(data, sig))
}

// blockingSigner stalls inside Sign until released, standing in for a TPM
// awaiting touch or a KMS that has stopped answering.
type blockingSigner struct {
	ssh.Signer
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

// Release unblocks the stalled Sign. Idempotent, so a test can free the signer
// at the point it wants and still register a cleanup for the failure paths.
func (b *blockingSigner) Release() { b.releaseOnce.Do(func() { close(b.release) }) }

func (b *blockingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.Signer.Sign(rand, data)
}

// TestStartSession_StopReportsAbandonedSigner is the ruled shutdown contract. A
// signer blocked inside Sign cannot be interrupted by closing its connection, so
// an unbounded Stop would hand control of the caller's shutdown to a wedged
// device. Stop honours the caller's bound -- and, crucially, SAYS what it
// abandoned. A bounded stop that reported nothing would be the same surprise as
// no bound at all.
func TestStartSession_StopReportsAbandonedSigner(t *testing.T) {
	blocked := &blockingSigner{
		Signer:  newEd25519Signer(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release) // never leave the goroutine parked

	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{blocked}})
	require.NoError(t, err)
	workDir := filepath.Dir(sess.SockPath)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Fire a signature request and wait until the signer is actually stuck.
	go func() { _, _ = sshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	type outcome struct{ report ShutdownReport }
	done := make(chan outcome, 1)
	go func() { done <- outcome{sess.Stop(ctx)} }()

	var got ShutdownReport
	select {
	case o := <-done:
		got = o.report
	case <-time.After(10 * time.Second):
		t.Fatal("Stop never returned with a signer stuck inside Sign")
	}

	// The report names the residual rather than hiding it.
	assert.False(t, got.Clean(), "a stuck signer must not be reported as a clean shutdown")
	assert.False(t, got.Joined, "the handler cannot have finished; its signer is still inside Sign")
	assert.Equal(t, 1, got.Abandoned, "the abandoned signing operation must be counted")

	// The security boundary held regardless of the bound: socket gone, client
	// disconnected. Only the work dir waits on the reaper.
	_, serr := os.Stat(sess.SockPath)
	assert.True(t, errors.Is(serr, os.ErrNotExist), "socket must be gone, got %v", serr)
	_, werr := conn.Write([]byte{0, 0, 0, 1, 11})
	if werr == nil {
		_, rerr := conn.Read(make([]byte, 1))
		assert.Error(t, rerr, "a client held across shutdown must not still be served")
	}

	// Once the signer is released the reaper finishes and the dir goes.
	blocked.Release()
	waitDone(t, sess)
	_, derr := os.Stat(workDir)
	assert.True(t, errors.Is(derr, os.ErrNotExist), "work dir must be reaped, got %v", derr)
}

// TestStartSession_StopReportsCleanShutdown is the other half of the contract:
// with nothing wedged, the report says so. Without this, a Stop that always
// claimed an abandonment would pass the test above.
func TestStartSession_StopReportsCleanShutdown(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	_, err = sshagent.NewClient(conn).List()
	require.NoError(t, err)
	_ = conn.Close()

	report := sess.Stop(context.Background())
	assert.True(t, report.Clean(), "expected a clean shutdown, got %d abandoned", report.Abandoned)
	assert.True(t, report.Joined, "every handler should have finished")
	assert.Zero(t, report.Abandoned)

	// A clean protocol exchange followed by an ordinary close must not leave
	// anything on Err (#701): the agent-protocol client's Close (io.EOF on
	// the server side) is exactly the shape recordErr treats as meaningless.
	waitDone(t, sess)
	assert.NoError(t, sess.Err())
}

// TestStartSession_ErrSurfacesHandlerProtocolError verifies that a genuine
// per-connection protocol error -- neither an ordinary disconnect (io.EOF)
// nor this package's own shutdown Close (net.ErrClosed) -- reaches Session.Err
// rather than being silently discarded (#701).
func TestStartSession_ErrSurfacesHandlerProtocolError(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)

	// A length-prefixed agent-protocol frame claiming a 10-byte body,
	// followed by only 1 of those bytes and then a close: the server's
	// io.ReadFull of the body reads a partial amount before EOF and reports
	// io.ErrUnexpectedEOF, not io.EOF -- a real error, not an ordinary
	// disconnect.
	_, err = conn.Write([]byte{0, 0, 0, 10, 0xff})
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// The malformed connection's handler runs concurrently with this test
	// goroutine. A second, well-behaved round trip only completes once the
	// accept loop -- a strictly sequential for-loop -- has moved past
	// accepting the connection above, which exercises the agent continuing
	// to serve other clients after one connection errors.
	confirm, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	_, err = sshagent.NewClient(confirm).List()
	require.NoError(t, err)
	require.NoError(t, confirm.Close())

	// That ordering is only a head start, not a guarantee: it says handler 1
	// was launched before handler 2's round trip, not that handler 1 has
	// finished reading and recording its error by the time it completes.
	// Poll the tracker directly -- deterministic, and available here since
	// this test lives in the same package -- rather than firing Stop's
	// unconditional listener-close and client-drain (which would turn a
	// still-unread partial frame into net.ErrClosed instead of
	// io.ErrUnexpectedEOF) on a race.
	require.Eventually(t, func() bool {
		return errors.Is(sess.track.err(), io.ErrUnexpectedEOF)
	}, 10*time.Second, 10*time.Millisecond, "handler did not record the protocol error")

	stopClean(t, sess)
	waitDone(t, sess)

	gotErr := sess.Err()
	require.Error(t, gotErr, "a genuine protocol error on a served connection must not vanish")
	assert.ErrorIs(t, gotErr, io.ErrUnexpectedEOF)
}

// TestStartSession_StopHonoursABoundLongerThanTheReapers closes the hole a
// caller-supplied bound is easy to fake: keying Stop off the session's reaper
// works for any bound SHORTER than the reaper's own, and silently truncates
// every longer one — reporting the handler the reaper gave up on as a clean
// shutdown. That is the silent bounded stop wearing the new signature.
//
// The bound here has to exceed defaultJoinBound, which is the only region where
// the two differ, so the test shortens that bound rather than spending the
// production five seconds to reach it.
func TestStartSession_StopHonoursABoundLongerThanTheReapers(t *testing.T) {
	joinBoundOverride.Store(int64(150 * time.Millisecond))
	t.Cleanup(func() { joinBoundOverride.Store(0) })

	blocked := &blockingSigner{
		Signer:  newEd25519Signer(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release)

	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{blocked}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	go func() { _, _ = sshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	bound := defaultJoinBound() + 200*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()

	start := time.Now()
	report := sess.Stop(ctx)
	elapsed := time.Since(start)

	assert.Equal(t, 1, report.Abandoned,
		"the abandoned handler must be reported even past the reaper's own bound")
	assert.GreaterOrEqual(t, elapsed, defaultJoinBound(),
		"Stop returned at the reaper's bound (%s), so it ignored the caller's (%s)", elapsed, bound)
}

// TestStartSession_RepeatedBoundedStopDoesNotLeakWaiters covers the cost of
// making Stop both idempotent and bounded: each call used to spawn its own
// goroutine to wait on the handler WaitGroup, and against a signer that never
// returns none of them ever exited. Repeated teardown — which the GUI does on
// Disconnect after a TTL expiry, and which the documented idempotency invites —
// therefore grew goroutines without limit against a single wedged KMS.
func TestStartSession_RepeatedBoundedStopDoesNotLeakWaiters(t *testing.T) {
	blocked := &blockingSigner{
		Signer:  newEd25519Signer(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release)

	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{blocked}})
	require.NoError(t, err)

	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	go func() { _, _ = sshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		require.False(t, sess.Stop(ctx).Clean(), "precondition: the signer is still wedged")
	}

	stop() // first call starts the one waiter that is allowed to exist
	runtime.Gosched()
	before := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		stop()
	}
	runtime.Gosched()
	growth := runtime.NumGoroutine() - before

	// Some slack for the scheduler and the still-parked signing handler, but
	// nothing like the fifty a per-call waiter would have added.
	assert.LessOrEqual(t, growth, 5,
		"50 bounded stops grew the goroutine count by %d; each is spawning its own waiter", growth)
}

// TestStartSession_IdleClientIsNotAnAbandonedSignature separates the two things
// the report used to conflate. Counting accepted connections meant a client
// that merely held the socket open — never asking for anything — was reported
// as an abandoned signing operation, and the CLI and GUI turn that number into
// a security warning. A warning about work that never happened is worse than
// no warning: it teaches people to ignore the real one.
func TestStartSession_IdleClientIsNotAnAbandonedSignature(t *testing.T) {
	sess, err := StartSession(context.Background(), Request{Signers: []ssh.Signer{newEd25519Signer(t)}})
	require.NoError(t, err)

	// Connect and sit there. The handler is live; no signature is executing.
	conn, err := net.Dial("unix", sess.SockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = sshagent.NewClient(conn).List()
	require.NoError(t, err, "the connection is established and idle")

	// An already-expired bound: the join cannot succeed, so this exercises the
	// reporting branch rather than the clean one.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Abandoned is the deterministic property here, and the one the finding was
	// about: whatever happens to the join, an idle client must never be counted
	// as a signature.
	//
	// Joined is deliberately NOT asserted. An idle handler finishes as soon as
	// the drain closes its connection, so it may or may not have joined by the
	// time Stop looks -- asserting either way would be asserting a race. The
	// Joined=false path is covered where it is actually deterministic, by
	// TestStartSession_StopReportsAbandonedSigner, whose signer genuinely
	// cannot finish.
	report := sess.Stop(ctx)
	assert.Zero(t, report.Abandoned,
		"an idle connected client is not a signing operation")
}
