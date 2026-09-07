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
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// signThrough proves a socket is a working agent rather than merely a file
// that exists: it lists the identity and verifies a signature under it.
func signThrough(t *testing.T, sockPath string, signer ssh.Signer) {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	client := sshagent.NewClient(conn)
	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, signer.PublicKey().Marshal(), keys[0].Blob)

	payload := []byte("signed through a caller-located socket")
	sig, err := client.Sign(signer.PublicKey(), payload)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(payload, sig))
}

// TestStartSession_SocketDirIsHonoured is the whole point of the option: the
// socket lands at a path the caller knew before the call, in a directory the
// session made, with the modes the security argument depends on -- 0700 on the
// directory, because that is what stops another user reaching the socket at
// all, and 0600 on the socket.
func TestStartSession_SocketDirIsHonoured(t *testing.T) {
	signer := newEd25519Signer(t)
	dir := filepath.Join(privateDir(t), "agent")

	sess, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{signer},
		SocketDir: dir,
	})
	require.NoError(t, err)
	defer stopClean(t, sess)

	assert.Equal(t, SocketPath(dir), sess.SockPath,
		"the socket path must be the one the caller could compute in advance")
	assert.Equal(t, "SSH_AUTH_SOCK="+sess.SockPath, sess.Env[0])

	di, err := os.Stat(dir)
	require.NoError(t, err)
	// No group or other access is the invariant, not the exact mode: os.Mkdir
	// is filtered by the process umask, which can only clear bits. The
	// directory is what keeps other users away from the socket, since the
	// socket's own mode does not govern who can reach its pathname.
	assert.Zero(t, di.Mode().Perm()&0o077,
		"the session's directory must grant nothing to group or other, got %#o", di.Mode().Perm())

	si, err := os.Lstat(sess.SockPath)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), si.Mode().Perm())
	assert.NotZero(t, si.Mode()&os.ModeSocket, "a socket, not a regular file")

	signThrough(t, sess.SockPath, signer)
}

// TestStartSession_SocketDirIsRemovedOnStop covers the other half of ownership.
// A caller that names a location inside its own tree gets the directory back
// empty; a leftover socket there would be an unattended signing oracle in a
// place the caller keeps.
func TestStartSession_SocketDirIsRemovedOnStop(t *testing.T) {
	parent := privateDir(t)
	dir := filepath.Join(parent, "agent")

	sess, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	require.NoError(t, err)
	stopClean(t, sess)

	_, err = os.Stat(dir)
	assert.ErrorIs(t, err, fs.ErrNotExist, "the session removes the directory it created")
	_, err = os.Stat(parent)
	assert.NoError(t, err, "the parent belongs to the caller and is never touched")
}

// TestStartSession_SocketDirIsRemovedOnContextCancel is the same guarantee on
// the exit path a caller takes when it cancels rather than stops.
func TestStartSession_SocketDirIsRemovedOnContextCancel(t *testing.T) {
	dir := filepath.Join(privateDir(t), "agent")

	ctx, cancel := context.WithCancel(context.Background())
	sess, err := StartSession(ctx, Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	require.NoError(t, err)

	cancel()
	waitDone(t, sess)

	_, err = os.Stat(dir)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestStartSession_ExistingSocketDirIsRefused is the refusal the option is
// built around. Adopting an existing directory would put the socket somewhere
// this package cannot vouch for, and removing it at shutdown would destroy
// whatever else it held -- so the call fails and the directory is untouched.
func TestStartSession_ExistingSocketDirIsRefused(t *testing.T) {
	dir := filepath.Join(privateDir(t), "agent")
	require.NoError(t, os.Mkdir(dir, 0o700))
	keeper := filepath.Join(dir, "keep-me")
	require.NoError(t, os.WriteFile(keeper, []byte("caller's file"), 0o600))

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	var exists *SocketDirExistsError
	require.ErrorAs(t, err, &exists)
	assert.Equal(t, dir, exists.Path)
	assert.Contains(t, exists.Error(), dir, "the message must name the path a caller has to fix")
	assert.ErrorIs(t, err, fs.ErrExist, "callers match the standard sentinel too")

	_, serr := os.Stat(keeper)
	assert.NoError(t, serr, "a refused path is never cleared")
}

// TestStartSession_FileAtSocketDirIsRefused is the same refusal through the
// other shape of occupancy: something that is not a directory at all.
func TestStartSession_FileAtSocketDirIsRefused(t *testing.T) {
	dir := filepath.Join(privateDir(t), "agent")
	require.NoError(t, os.WriteFile(dir, []byte("not a directory"), 0o600))

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	var exists *SocketDirExistsError
	require.ErrorAs(t, err, &exists)

	body, rerr := os.ReadFile(dir)
	require.NoError(t, rerr)
	assert.Equal(t, "not a directory", string(body))
}

// TestStartSession_SocketDirAndWorkDirAreMutuallyExclusive refuses a request
// that says two incompatible things about who owns the directory. Preferring
// one silently would leave the caller believing the other -- and the two differ
// in whether the directory is removed at shutdown.
func TestStartSession_SocketDirAndWorkDirAreMutuallyExclusive(t *testing.T) {
	work := privateDir(t)
	socketDir := filepath.Join(privateDir(t), "agent")

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		WorkDir:   work,
		SocketDir: socketDir,
	})
	var input *InputError
	require.ErrorAs(t, err, &input)
	assert.Contains(t, input.Error(), "WorkDir")

	_, serr := os.Stat(socketDir)
	assert.ErrorIs(t, serr, fs.ErrNotExist, "a refused request creates nothing")
}

// TestStartSession_MissingSocketDirParentIsRefused keeps the session out of the
// business of inventing a caller's tree: directories created on the way to the
// socket would carry permissions nobody chose, in a place nobody vouched for.
func TestStartSession_MissingSocketDirParentIsRefused(t *testing.T) {
	dir := filepath.Join(privateDir(t), "missing", "agent")

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	var input *InputError
	require.ErrorAs(t, err, &input)
	assert.Contains(t, input.Error(), "SocketDir")
}

// TestStartSession_WorldWritableSocketDirParentIsRefused is the hazard the
// parent check exists for. Creating the socket's own directory closes the
// substitution window inside it, but in a parent another user can write to,
// that directory can be renamed away and replaced wholesale -- and the child
// process reading SSH_AUTH_SOCK would then be talking to somebody else's agent.
func TestStartSession_WorldWritableSocketDirParentIsRefused(t *testing.T) {
	parent := privateDir(t)
	require.NoError(t, os.Chmod(parent, 0o707))

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: filepath.Join(parent, "agent"),
	})
	var insecure *InsecureWorkDirError
	require.ErrorAs(t, err, &insecure)
	assert.Contains(t, insecure.Error(), "group or other")
}

// TestStartSession_SymlinkSocketDirParentIsRefused closes the check-then-use
// gap one level up: a link pointing at a private directory now can be
// re-pointed at a shared one before the bind.
func TestStartSession_SymlinkSocketDirParentIsRefused(t *testing.T) {
	base := privateDir(t)
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: filepath.Join(link, "agent"),
	})
	var insecure *InsecureWorkDirError
	require.ErrorAs(t, err, &insecure)
	assert.Contains(t, insecure.Error(), "symlink")
}

// TestStartSession_SocketDirServesAnotherWorkingDirectory is the consumer
// scenario the option exists for: the socket is handed to a process that runs
// somewhere else entirely -- a container with its own working directory and PID
// namespace -- so SockPath must be absolute and must not encode anything about
// this process. A relative SocketDir is resolved against OUR directory at the
// call, not the reader's later.
func TestStartSession_SocketDirServesAnotherWorkingDirectory(t *testing.T) {
	signer := newEd25519Signer(t)
	base := privateDir(t)
	t.Chdir(base)

	sess, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{signer},
		SocketDir: "agent",
	})
	require.NoError(t, err)
	defer stopClean(t, sess)

	require.True(t, filepath.IsAbs(sess.SockPath), "SockPath must be absolute, got %q", sess.SockPath)
	resolved, err := filepath.EvalSymlinks(base)
	require.NoError(t, err)
	assert.Equal(t, SocketPath(filepath.Join(resolved, "agent")), sess.SockPath,
		"a relative SocketDir resolves against this process's directory at the call, once")

	// Whoever reads SSH_AUTH_SOCK does so from its own directory.
	t.Chdir(privateDir(t))
	signThrough(t, sess.SockPath, signer)
}

// TestStartSession_UncreatableSocketDirIsReported covers the creation failure
// that is not occupancy: the name itself is impossible. It uses an over-long
// component rather than a permission the effective user lacks, because root
// ignores permissions and this branch has to be reachable in a container that
// runs the suite as root.
func TestStartSession_UncreatableSocketDirIsReported(t *testing.T) {
	dir := filepath.Join(privateDir(t), strings.Repeat("n", 300))

	_, err := StartSession(context.Background(), Request{
		Signers:   []ssh.Signer{newEd25519Signer(t)},
		SocketDir: dir,
	})
	var wd *WorkDirError
	require.ErrorAs(t, err, &wd)
	assert.NotErrorIs(t, err, fs.ErrExist, "an impossible name is not an occupied path")
}
