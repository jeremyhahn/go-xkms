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

package connect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	sshagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func testHostPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return sshPub
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestStart_ArgsEnvAndSeed(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())
	// Pre-pin the target so it is seeded into the known_hosts file.
	if err := store.Add(ctx, known_hosts.PinFromPublicKey("server.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceManual)); err != nil {
		t.Fatalf("Add pin: %v", err)
	}

	sess, err := Start(ctx, Request{
		Host:            "server.example.com",
		Port:            2222,
		User:            "deploy",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.SyncAndStop()

	if !contains(sess.Args, "deploy@server.example.com") {
		t.Fatalf("args missing target: %v", sess.Args)
	}
	if !contains(sess.Args, "IdentitiesOnly=yes") {
		t.Fatalf("args missing IdentitiesOnly: %v", sess.Args)
	}
	if !contains(sess.Args, "-p") || !contains(sess.Args, "2222") {
		t.Fatalf("args missing port: %v", sess.Args)
	}
	var hasKH bool
	for _, a := range sess.Args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			hasKH = true
		}
	}
	if !hasKH {
		t.Fatalf("args missing UserKnownHostsFile: %v", sess.Args)
	}
	if len(sess.Env) != 1 || !strings.HasPrefix(sess.Env[0], "SSH_AUTH_SOCK=") {
		t.Fatalf("unexpected env: %v", sess.Env)
	}

	// The agent socket exists and the seeded known_hosts holds the pin.
	sock := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")
	if _, statErr := os.Stat(sock); statErr != nil {
		t.Fatalf("agent socket not present: %v", statErr)
	}
	body, _ := os.ReadFile(sess.knownHostsFile)
	if !strings.Contains(string(body), "server.example.com ssh-ed25519 ") {
		t.Fatalf("known_hosts not seeded: %q", body)
	}
}

func TestStart_SyncBackImportsNewHost(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())

	sess, err := Start(ctx, Request{
		Host:            "fresh.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Simulate the native ssh client accepting a new host and appending it.
	line, _ := known_hosts.Emit(known_hosts.PinFromPublicKey("fresh.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, _ := os.OpenFile(sess.knownHostsFile, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(line + "\n")
	_ = f.Close()

	added, err := sess.SyncAndStop()
	if err != nil {
		t.Fatalf("SyncAndStop: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected 1 host pinned back, got %d", added)
	}
	if _, gerr := store.Get(ctx, scope.User, "alice", "fresh.example.com"); gerr != nil {
		t.Fatalf("host not pinned after sync: %v", gerr)
	}
}

func TestStart_Validation(t *testing.T) {
	ctx := context.Background()
	store, _ := known_hosts.NewBackendStore(storage.New())
	if _, err := Start(ctx, Request{Signer: testSigner(t), KnownHostsStore: store}); err == nil {
		t.Fatal("expected error for missing host")
	}
	if _, err := Start(ctx, Request{Host: "h", KnownHostsStore: store}); err == nil {
		t.Fatal("expected error for missing signer")
	}
	if _, err := Start(ctx, Request{Host: "h", Signer: testSigner(t)}); err == nil {
		t.Fatal("expected error for missing known_hosts store")
	}
}

// TestStart_AgentSessionFailureIsALaunchError pins this package's error
// contract across the agent extraction: every setup failure surfaces as
// *LaunchError, and the underlying cause stays reachable. A caller matching
// *LaunchError must not start missing agent failures just because the agent
// now lives in its own package.
func TestStart_AgentSessionFailureIsALaunchError(t *testing.T) {
	workDir := privateDir(t)
	// Occupy the agent socket path with a file the session must not delete.
	occupied := sshagent.SocketPath(workDir)
	if err := os.WriteFile(occupied, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	store, _ := known_hosts.NewBackendStore(storage.New())

	_, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true,
		WorkDir:         workDir,
	})

	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LaunchError, got %T: %v", err, err)
	}
	if le.Op != "agent session" {
		t.Fatalf("expected the agent session op, got %q", le.Op)
	}
	if !errors.Is(err, sshagent.ErrPathOccupied) {
		t.Fatalf("the cause must stay reachable, got %v", err)
	}
}

// TestStart_CreatesASuppliedWorkDir pins this package's WorkDir contract, which
// differs from the agent session's on purpose. Request.WorkDir names where the
// session's scratch area GOES, so connect creates it; agent.StartSession
// requires an existing directory because it would not own, and so would not
// clean up, one it created.
func TestStart_CreatesASuppliedWorkDir(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "not-created-yet")
	store, _ := known_hosts.NewBackendStore(storage.New())

	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true,
		WorkDir:         fresh,
	})
	if err != nil {
		t.Fatalf("Start with a fresh WorkDir: %v", err)
	}
	defer sess.Stop()

	info, serr := os.Stat(fresh)
	if serr != nil || !info.IsDir() {
		t.Fatalf("WorkDir should have been created: %v", serr)
	}
	if _, serr := os.Stat(sshagent.SocketPath(fresh)); serr != nil {
		t.Fatalf("agent socket should live in the supplied WorkDir: %v", serr)
	}
}

// TestStart_RelativeWorkDirYieldsAbsoluteArtifactPaths covers the paths that
// leave this process. The spawned ssh client runs with its own working
// directory, so a relative -o UserKnownHostsFile would send it looking
// somewhere else — and a known_hosts the client cannot find is not a missing
// file to it, it is a host it has never seen. That silently turns pinned
// verification into first contact, which is the failure this whole package
// exists to prevent.
func TestStart_RelativeWorkDirYieldsAbsoluteArtifactPaths(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	store, _ := known_hosts.NewBackendStore(storage.New())

	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true,
		WorkDir:         "scratch",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Stop()

	var khArg string
	for _, a := range sess.Args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			khArg = strings.TrimPrefix(a, "UserKnownHostsFile=")
		}
	}
	if khArg == "" {
		t.Fatalf("no UserKnownHostsFile in args: %v", sess.Args)
	}
	if !filepath.IsAbs(khArg) {
		t.Fatalf("UserKnownHostsFile must be absolute, got %q", khArg)
	}
	if !filepath.IsAbs(strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")) {
		t.Fatalf("SSH_AUTH_SOCK must be absolute, got %q", sess.Env[0])
	}

	// Resolve both from a different working directory, as the child does.
	t.Chdir(t.TempDir())
	if _, serr := os.Stat(khArg); serr != nil {
		t.Fatalf("known_hosts must resolve from another working directory: %v", serr)
	}
	if _, serr := os.Stat(strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")); serr != nil {
		t.Fatalf("agent socket must resolve from another working directory: %v", serr)
	}
}

// TestSession_SyncRacesStop covers the documented GUI workflow: Sync is polled
// on one goroutine while the session can be stopped from another (the spawned
// ssh exiting, or the window closing). Without synchronisation this reads
// knownHostsFile and the agent handle while Stop is clearing them and removing
// the work directory — a data race, and one that can delete the known_hosts
// out from under an import that is reading it.
func TestSession_SyncRacesStop(t *testing.T) {
	for i := 0; i < 40; i++ {
		store, _ := known_hosts.NewBackendStore(storage.New())
		sess, err := Start(context.Background(), Request{
			Host:            "host.example.com",
			User:            "root",
			Signer:          testSigner(t),
			KnownHostsStore: store,
			Scope:           scope.User,
			Owner:           "alice",
		})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}

		var pollers sync.WaitGroup
		for j := 0; j < 4; j++ {
			pollers.Add(1)
			go func() {
				defer pollers.Done()
				for k := 0; k < 20; k++ {
					_, _ = sess.Sync()
					_ = sess.KnownHostsFile()
				}
			}()
		}
		sess.Stop()
		pollers.Wait()
	}
}

// blockingStore stalls inside the lookup ImportKnownHostsFile drives per host,
// standing in for a barrier-backed store that has stopped answering. It is
// inert until armed, so Start's own seeding is unaffected.
type blockingStore struct {
	storage.Backend
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStore) Get(ctx context.Context, key string) ([]byte, error) {
	if b.armed.Load() {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.Backend.Get(ctx, key)
}

// TestSession_StopIsNotHeldHostageByAStalledSync is the shutdown-liveness
// guarantee. Sync imports against a caller-supplied store over a context this
// session does not control, so holding the lifecycle lock across that import
// would let a stalled backend block Stop forever — keeping a signing agent
// alive because a host-key store stopped answering. Stopping the agent has
// nothing to do with known_hosts and must not wait on it.
func TestSession_StopIsNotHeldHostageByAStalledSync(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := known_hosts.NewBackendStore(blocked)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sockPath := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")

	// Give the import something to do: a host the native client "accepted".
	line, _ := known_hosts.Emit(known_hosts.PinFromPublicKey(
		"accepted.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, oerr := os.OpenFile(sess.KnownHostsFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	if oerr != nil {
		t.Fatalf("open known_hosts: %v", oerr)
	}
	if _, werr := f.WriteString(line + "\n"); werr != nil {
		t.Fatalf("write known_hosts: %v", werr)
	}
	_ = f.Close()

	blocked.armed.Store(true)
	go func() { _, _ = sess.Sync() }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the store never entered Get")
	}

	stopped := make(chan struct{})
	go func() { defer close(stopped); sess.Stop() }()
	select {
	case <-stopped:
	case <-time.After(syncDrainTimeout + 5*time.Second):
		t.Fatal("Stop never returned with a Sync stalled inside the store")
	}

	// The agent is gone despite the stalled import.
	if _, serr := os.Stat(sockPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the agent socket must be gone once Stop returns: %v", serr)
	}
}
