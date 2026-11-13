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

// longTempDir returns an existing directory whose path is long enough that
// <dir>/xkey-ssh-<rand>/agent.sock overflows AF_UNIX's sun_path.
func longTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 60), strings.Repeat("e", 60))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir long dir: %v", err)
	}
	if n := len(sshagent.SocketPath(filepath.Join(dir, "xkey-ssh-0123456789"))); n <= 108 {
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
	if len(sock) >= maxUnixSocketPathLen {
		t.Errorf("agent socket path is %d bytes, want < %d: %s", len(sock), maxUnixSocketPathLen, sock)
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

	if err := sess.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, serr := os.Stat(workDir); !os.IsNotExist(serr) {
		t.Errorf("owned work dir should be removed on Stop, stat err = %v", serr)
	}
}
