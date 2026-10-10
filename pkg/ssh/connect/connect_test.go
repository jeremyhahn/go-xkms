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
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	gosshagent "golang.org/x/crypto/ssh/agent"

	sshagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
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
	defer sess.SyncAndStop(context.Background())

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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

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

	added, _, err := sess.SyncAndStop(context.Background())
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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

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
	defer sess.Stop(context.Background())

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
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

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
	defer sess.Stop(context.Background())

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
		store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
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
					_, _ = sess.Sync(context.Background())
					_ = sess.KnownHostsFile()
				}
			}()
		}
		sess.Stop(context.Background())
		pollers.Wait()
	}
}

// blockingStore stalls inside the lookup ImportKnownHostsFile drives per host,
// standing in for a barrier-backed store that has stopped answering. It is
// inert until armed, so Start's own seeding is unaffected.
type blockingStore struct {
	storage.Backend
	armed   atomic.Bool
	entries atomic.Int64 // how many imports actually reached the store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStore) Get(ctx context.Context, key string) ([]byte, error) {
	if b.armed.Load() {
		b.entries.Add(1)
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.Backend.Get(ctx, key)
}

func (b *blockingStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, next)
}

func (b *blockingStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return b.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
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

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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
	go func() { _, _ = sess.Sync(context.Background()) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the store never entered Get")
	}

	stopped := make(chan struct{})
	// A bounded context, because that is the honest call for a store that has
	// stopped answering: context.Background() means "wait as long as it takes",
	// and Stop is entitled to take it at its word. What must NOT depend on the
	// bound is the agent, and the assertion below is that it died anyway.
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelStop()
	go func() { defer close(stopped); sess.Stop(stopCtx) }()
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

// TestSession_SyncAndStopHonoursItsBound covers the teardown path xkey actually
// takes — the CLI after ssh exits, the GUI on disconnect. An unbounded
// convenience here would put the wedged-signer hang on the one path everyone
// uses, which is worse than not offering the bound at all.
func TestSession_SyncAndStopHonoursItsBound(t *testing.T) {
	blocked := &blockingConnectSigner{
		Signer:  testSigner(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release)

	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          blocked,
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sockPath := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")

	conn, derr := net.Dial("unix", sockPath)
	if derr != nil {
		t.Fatalf("dial: %v", derr)
	}
	defer func() { _ = conn.Close() }()
	go func() { _, _ = gosshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	type result struct {
		report sshagent.ShutdownReport
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, report, serr := sess.SyncAndStop(ctx)
		done <- result{report, serr}
	}()

	select {
	case r := <-done:
		if r.report.Clean() {
			t.Fatal("a wedged signer must be reported, not hidden behind a clean teardown")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SyncAndStop never returned with a signer stuck inside Sign")
	}
}

// blockingConnectSigner stalls inside Sign until released.
type blockingConnectSigner struct {
	ssh.Signer
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (b *blockingConnectSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.Signer.Sign(rand, data)
}

func (b *blockingConnectSigner) Release() { b.releaseOnce.Do(func() { close(b.release) }) }

// TestSession_SyncAndStopStopsTheAgentDespiteAStalledStore covers the ordering
// trap in SyncAndStop: it imports before it stops, so an unbounded import means
// the agent is still serving signatures long after the caller asked for
// teardown. The store is the caller's and may be barrier-backed — stopping the
// agent must not be gated on it answering.
func TestSession_SyncAndStopStopsTheAgentDespiteAStalledStore(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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

	// Give the import a host to look up, then wedge the store.
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

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = sess.SyncAndStop(ctx) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SyncAndStop never returned with the store wedged inside the import")
	}

	if _, serr := os.Stat(sockPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the agent must be stopped even though the store stalled: %v", serr)
	}
}

// TestSession_SyncAndStopKillsTheAgentBeforeWaiting is the ordering assertion,
// and it is stronger than "SyncAndStop returns in time". A stalled store used
// to leave the SSH_AUTH_SOCK live for the whole shutdown bound — bounded, but
// still signing for anyone already holding the path. The socket's lifetime has
// to be independent of the import, not merely capped alongside it.
func TestSession_SyncAndStopKillsTheAgentBeforeWaiting(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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

	// A long bound: if the agent's death were gated on the import, the socket
	// would still be answering for all of it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _, _, _ = sess.SyncAndStop(ctx) }()

	// The store is wedged, so the import is definitely still running.
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the store never entered the import")
	}

	// The agent must already be gone, well inside the shutdown bound.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, serr := os.Stat(sockPath); errors.Is(serr, os.ErrNotExist) {
			return // agent died without waiting for the import
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent socket was still live while the import stalled; the stop is gated on the import")
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("shutdown context elapsed before the agent died")
		}
	}
}

// TestSession_SyncAndStopReturnsNearTheDeadline is the arithmetic assertion the
// other bound tests miss. Each phase of teardown was individually bounded, and
// the cleanup phase quietly used its own five-second constant instead of the
// caller's remaining budget — so a 250ms shutdown took five seconds and every
// test that only asserted "returned eventually" passed.
//
// A bounded shutdown that silently costs twenty times its bound is not bounded.
func TestSession_SyncAndStopReturnsNearTheDeadline(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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
	blocked.armed.Store(true) // and it ignores the context it is handed

	const bound = 250 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()

	start := time.Now()
	_, _, _ = sess.SyncAndStop(ctx)
	elapsed := time.Since(start)

	// Generous headroom for a loaded CI box, but far below the background
	// reaper's own five seconds — which is the number that used to leak in.
	if elapsed > 2*time.Second {
		t.Fatalf("SyncAndStop took %s against a %s bound; a cleanup phase is using its own timeout", elapsed, bound)
	}
}

// TestSession_SyncAndStopPinsHostsDespiteAWedgedSigner is the data-loss case
// the ShutdownReport assertions could not see. Sequencing the import after the
// agent shutdown meant a signer wedged for the whole budget left Sync starting
// on an already-expired context — so the first-contact host keys ssh had just
// accepted were dropped, silently, while the report looked exactly as expected.
// A signing hazard traded for a host-verification one.
func TestSession_SyncAndStopPinsHostsDespiteAWedgedSigner(t *testing.T) {
	blocked := &blockingConnectSigner{
		Signer:  testSigner(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release)

	store, err := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          blocked,
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sockPath := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")

	// ssh "accepts" a host on first contact.
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

	// ...and a signing request is wedged when ssh dies.
	conn, derr := net.Dial("unix", sockPath)
	if derr != nil {
		t.Fatalf("dial: %v", derr)
	}
	defer func() { _ = conn.Close() }()
	go func() { _, _ = gosshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	// The whole budget will be spent waiting on that signer.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	added, report, _ := sess.SyncAndStop(ctx)

	if report.Clean() {
		t.Fatal("precondition: the wedged signer should have been reported abandoned")
	}
	if added != 1 {
		t.Fatalf("the accepted host key must be pinned despite the wedged signer, added=%d", added)
	}
	if _, gerr := store.Get(context.Background(), scope.User, "alice", "accepted.example.com"); gerr != nil {
		t.Fatalf("the accepted host key was lost: %v", gerr)
	}
}

// TestSession_RepeatedStopKeepsReportingTheAbandonment covers the sequential
// half of the idempotency contract. Releasing the agent handle after the first
// bounded stop made every later Stop take the nil branch and report clean —
// so a GUI disconnect following a TTL expiry would be told the session was
// tidy while a signing operation was still running inside it.
func TestSession_RepeatedStopKeepsReportingTheAbandonment(t *testing.T) {
	blocked := &blockingConnectSigner{
		Signer:  testSigner(t),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(blocked.Release)

	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())
	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          blocked,
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sockPath := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")

	conn, derr := net.Dial("unix", sockPath)
	if derr != nil {
		t.Fatalf("dial: %v", derr)
	}
	defer func() { _ = conn.Close() }()
	go func() { _, _ = gosshagent.NewClient(conn).Sign(blocked.PublicKey(), []byte("stalls")) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer never entered Sign")
	}

	bounded := func() sshagent.ShutdownReport {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		return sess.Stop(ctx)
	}

	if first := bounded(); first.Clean() {
		t.Fatal("precondition: the wedged signer should be reported abandoned")
	}
	if second := bounded(); second.Clean() {
		t.Fatal("a repeated stop reported clean while the signer was still wedged")
	}

	// Once the signer returns, a further stop is honestly clean.
	blocked.Release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if bounded().Clean() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("stop never reported clean after the signer was released")
		}
	}
}

// TestSession_SyncFailsWhenTheSystemMirrorFails covers the system-only policy,
// where the mirror is the ONLY persistence path. Discarding its error meant an
// unwritable destination returned a successful Sync — and reap then deleted the
// temp known_hosts, so the accepted key was gone and the next connection was
// first contact again with nobody told.
func TestSession_SyncFailsWhenTheSystemMirrorFails(t *testing.T) {
	store, _ := known_hosts.NewDAOStore(testutil.NewMemoryDAOFactory())

	// A mirror destination that cannot be written: a directory where a file
	// must go.
	extDir := privateDir(t)
	unwritable := filepath.Join(extDir, "known_hosts")
	if err := os.Mkdir(unwritable, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	sess, err := Start(context.Background(), Request{
		Host:            "host.example.com",
		User:            "root",
		Signer:          testSigner(t),
		KnownHostsStore: store,
		Scope:           scope.User,
		Owner:           "alice",
		SkipStore:       true, // system-only: the mirror is all there is
		ExtraKnownHosts: []string{unwritable},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Stop(context.Background())

	// ssh accepts a host on first contact.
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

	added, serr := sess.Sync(context.Background())
	if serr == nil {
		t.Fatal("an unwritable system mirror must fail Sync, not report success")
	}
	if added != 0 {
		t.Fatalf("nothing was persisted, got added=%d", added)
	}
	var le *LaunchError
	if !errors.As(serr, &le) {
		t.Fatalf("expected *LaunchError, got %T: %v", serr, serr)
	}
}

// TestSession_RepeatedReapDoesNotLeakWaiters is the connect-side twin of the
// agent's waiter leak: each teardown used to start its own drain waiter, and a
// store that ignores cancellation meant none of them ever exited.
func TestSession_RepeatedReapDoesNotLeakWaiters(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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

	line, _ := known_hosts.Emit(known_hosts.PinFromPublicKey(
		"accepted.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, _ := os.OpenFile(sess.KnownHostsFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(line + "\n")
	_ = f.Close()

	// Wedge a Sync so the drain can never complete.
	blocked.armed.Store(true)
	go func() { _, _ = sess.Sync(context.Background()) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the store never entered the import")
	}

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		sess.Stop(ctx)
	}

	stop()
	runtime.Gosched()
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		stop()
	}
	runtime.Gosched()
	growth := runtime.NumGoroutine() - before

	if growth > 5 {
		t.Fatalf("50 bounded stops grew the goroutine count by %d; each is starting its own drain waiter", growth)
	}
}

// TestSession_SyncIsSingleFlight covers what happens when teardown arrives
// during a poll that is already wedged. Without single-flight, SyncAndStop
// starts a SECOND import against the same store — and with a backend that
// ignores cancellation both block forever, so each session leaks a pair of
// permanently-parked backend calls. Some stores also assume serialized access.
func TestSession_SyncIsSingleFlight(t *testing.T) {
	blocked := &blockingStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocked.release)

	store, err := pinStoreOver(blocked)
	if err != nil {
		t.Fatalf("pinStoreOver: %v", err)
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

	line, _ := known_hosts.Emit(known_hosts.PinFromPublicKey(
		"accepted.example.com", scope.User, "alice", testHostPub(t), known_hosts.SourceFirstContact))
	f, oerr := os.OpenFile(sess.KnownHostsFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	if oerr != nil {
		t.Fatalf("open known_hosts: %v", oerr)
	}
	if _, werr := f.WriteString(line + "\n"); werr != nil {
		t.Fatalf("write known_hosts: %v", werr)
	}
	if cerr := f.Close(); cerr != nil {
		t.Fatalf("close known_hosts: %v", cerr)
	}
	blocked.armed.Store(true)

	// A poll wedges inside the store.
	go func() { _, _ = sess.Sync(context.Background()) }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the poll never reached the store")
	}

	// Teardown arrives while it is still stuck. It must join that import, not
	// launch another.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, _, _ = sess.SyncAndStop(ctx)

	if n := blocked.entries.Load(); n != 1 {
		t.Fatalf("the store was entered %d times; a second import was stacked on the wedged one", n)
	}
}
