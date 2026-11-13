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
	// t.TempDir() under this test's name is itself too long to fit, so the
	// short directories come straight from /tmp.
	shortDir := func() string {
		dir, err := os.MkdirTemp(shortWorkDirBase, "xk-")
		if err != nil {
			t.Fatalf("mkdir short dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	shortTmp := shortDir()
	xdg := shortDir()
	if err := os.Chmod(xdg, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
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
