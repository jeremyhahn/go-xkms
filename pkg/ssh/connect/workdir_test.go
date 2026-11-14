package connect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sshagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// sunPathLen is AF_UNIX's sun_path buffer on Linux, trailing NUL included.
const sunPathLen = 108

// longTempDir returns an existing directory whose path is long enough that
// <dir>/xkey-ssh-<rand>/agent.sock overflows AF_UNIX's sun_path.
func longTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 60), strings.Repeat("e", 60))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir long dir: %v", err)
	}
	if n := len(sshagent.SocketPath(filepath.Join(dir, "xkey-ssh-0123456789"))); n < sunPathLen {
		t.Fatalf("long dir is not long enough: socket path is %d bytes", n)
	}
	return dir
}

func TestStart_DefaultWorkDirFitsSunPathUnderALongTMPDIR(t *testing.T) {
	t.Setenv("TMPDIR", longTempDir(t))
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true,
	})
	if err != nil {
		t.Fatalf("Start under a long TMPDIR: %v", err)
	}
	workDir := sess.workDir
	sock := sshagent.SocketPath(workDir)
	if len(sock) >= sunPathLen {
		t.Errorf("agent socket path is %d bytes, want < %d: %s", len(sock), sunPathLen, sock)
	}
	info, serr := os.Stat(workDir)
	if serr != nil {
		t.Fatalf("work dir: %v", serr)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("work dir mode = %o, want 700", perm)
	}
	if _, serr := os.Stat(sock); serr != nil {
		t.Fatalf("agent socket should exist: %v", serr)
	}

	sess.Stop(context.Background())
	if _, serr := os.Stat(workDir); !os.IsNotExist(serr) {
		t.Errorf("owned work dir should be removed on Stop, stat err = %v", serr)
	}
}

func TestDefaultWorkDirBase_PrefersAPrivateXDGRuntimeDir(t *testing.T) {
	shortTmp := shortTempDir(t)
	xdg := shortTempDir(t)
	t.Setenv("TMPDIR", longTempDir(t))
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	if got := defaultWorkDirBase(); got != xdg {
		t.Errorf("defaultWorkDirBase() = %q, want the private XDG_RUNTIME_DIR %q", got, xdg)
	}

	if err := os.Chmod(xdg, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if got := defaultWorkDirBase(); got != shortWorkDirBase {
		t.Errorf("defaultWorkDirBase() with a 0755 XDG_RUNTIME_DIR = %q, want %q", got, shortWorkDirBase)
	}

	t.Setenv("TMPDIR", shortTmp)
	if got := defaultWorkDirBase(); got != "" {
		t.Errorf("defaultWorkDirBase() with a short TMPDIR = %q, want the default temp dir", got)
	}
}

func TestDefaultWorkDirBase_RefusesAnXDGRuntimeDirOwnedByAnotherUser(t *testing.T) {
	xdg := shortTempDir(t)
	t.Setenv("TMPDIR", longTempDir(t))
	t.Setenv("XDG_RUNTIME_DIR", xdg)

	// Run as a different effective user from the directory's owner: root
	// that inherited an unprivileged user's XDG_RUNTIME_DIR can write the
	// 0700 directory, but its owner could still swap the session's files.
	otherUID := os.Geteuid() + 1
	orig := geteuid
	geteuid = func() int { return otherUID }
	t.Cleanup(func() { geteuid = orig })

	if got := defaultWorkDirBase(); got != shortWorkDirBase {
		t.Errorf("defaultWorkDirBase() with an XDG_RUNTIME_DIR owned by another user = %q, want %q", got, shortWorkDirBase)
	}
}

// shortTempDir returns a 0700 directory straight under /tmp, removed in
// t.Cleanup: t.TempDir() under these test names is too long to fit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(shortWorkDirBase, "xk-")
	if err != nil {
		t.Fatalf("mkdir short dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// On macOS /tmp is a symlink to /private/tmp; isPrivateDir refuses a
	// path through a symlink, so hand back the resolved path.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve short dir: %v", err)
	}
	return resolved
}

func TestDefaultWorkDirBase_RefusesASymlinkedXDGRuntimeDir(t *testing.T) {
	root := shortTempDir(t)
	target := filepath.Join(root, "d")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("TMPDIR", longTempDir(t))

	// The target alone is acceptable, so only the symlink can refuse it.
	t.Setenv("XDG_RUNTIME_DIR", target)
	if got := defaultWorkDirBase(); got != target {
		t.Fatalf("defaultWorkDirBase() with the real dir = %q, want %q", got, target)
	}

	// Whoever owns a symlink can repoint it after the check and swap the
	// session's known_hosts, so neither a symlinked leaf nor a symlinked
	// ancestor is trusted.
	leaf := filepath.Join(root, "l")
	if err := os.Symlink(target, leaf); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", leaf)
	if got := defaultWorkDirBase(); got != shortWorkDirBase {
		t.Errorf("defaultWorkDirBase() with a symlinked XDG_RUNTIME_DIR = %q, want %q", got, shortWorkDirBase)
	}

	inner := filepath.Join(target, "x")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(leaf, "x"))
	if got := defaultWorkDirBase(); got != shortWorkDirBase {
		t.Errorf("defaultWorkDirBase() with a symlinked ancestor = %q, want %q", got, shortWorkDirBase)
	}
}

func TestDefaultWorkDirBase_RefusesAnXDGRuntimeDirUnderAWritableParent(t *testing.T) {
	parent := shortTempDir(t)
	xdg := filepath.Join(parent, "d")
	if err := os.Mkdir(xdg, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("TMPDIR", longTempDir(t))
	t.Setenv("XDG_RUNTIME_DIR", xdg)

	// Anyone who can write the parent can rename the leaf away and put
	// their own directory in its place.
	for _, mode := range []os.FileMode{0o777, 0o770, 0o702} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if got := defaultWorkDirBase(); got != shortWorkDirBase {
			t.Errorf("defaultWorkDirBase() under a %o parent = %q, want %q", mode, got, shortWorkDirBase)
		}
	}

	// The sticky bit stops others from renaming the leaf, as on /tmp.
	if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if got := defaultWorkDirBase(); got != xdg {
		t.Errorf("defaultWorkDirBase() under a sticky parent = %q, want %q", got, xdg)
	}
}
