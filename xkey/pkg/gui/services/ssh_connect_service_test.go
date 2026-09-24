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

package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// setupConnect builds a connect service backed by a real embedded SSH client
// with a software key, plus injected lookPath/execCommand so no real terminal
// is spawned. It returns the service and a pointer to the captured exec call.
func setupConnect(t *testing.T) (*SSHConnectService, *capturedExec) {
	t.Helper()
	ctx := context.Background()
	backend := storage.New()

	client, err := sshclient.NewEmbedded(sshclient.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if _, err := client.Keys().Generate(ctx, sshclient.GenerateRequest{
		Scope: "user", Owner: "local", Name: "laptop", Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hostKeys, err := sshclient.NewHostKeyStore(backend)
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}

	svc := NewSSHConnectService()
	svc.SetContext(ctx)
	svc.SetSSHClient(client)
	svc.SetHostKeyStore(hostKeys)

	cap := &capturedExec{}
	svc.lookPath = func(name string) (string, error) {
		if name == "x-terminal-emulator" {
			return "/usr/bin/x-terminal-emulator", nil
		}
		return "", exec.ErrNotFound
	}
	svc.execCommand = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		cap.name = name
		cap.args = arg
		// Return a harmless command so Start() succeeds without a terminal.
		return exec.CommandContext(ctx, "true")
	}
	return svc, cap
}

type capturedExec struct {
	name string
	args []string
}

func (c *capturedExec) argsContain(want string) bool {
	for _, a := range c.args {
		if a == want {
			return true
		}
	}
	return false
}

func TestSSHConnect_OneTimeLaunch(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !strings.HasSuffix(cap.name, "x-terminal-emulator") {
		t.Fatalf("unexpected terminal: %s", cap.name)
	}
	if !cap.argsContain("-e") || !cap.argsContain("ssh") {
		t.Fatalf("missing terminal/ssh args: %v", cap.args)
	}
	if !cap.argsContain("deploy@server.example.com") {
		t.Fatalf("missing target: %v", cap.args)
	}
	if !cap.argsContain("-p") || !cap.argsContain("2222") {
		t.Fatalf("missing port: %v", cap.args)
	}
	var hasKH bool
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			hasKH = true
		}
	}
	if !hasKH {
		t.Fatalf("missing UserKnownHostsFile option: %v", cap.args)
	}
}

func TestSSHConnect_TerminalOverride(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()
	svc.SetTerminalCommand("kitty -e")

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "h", User: "u", KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if cap.name != "kitty" || cap.args[0] != "-e" || cap.args[1] != "ssh" {
		t.Fatalf("override not applied: name=%s args=%v", cap.name, cap.args)
	}
}

func TestSSHConnect_LocalPassthrough_HostPort(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
		KeySource: "local",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !cap.argsContain("-p") || !cap.argsContain("2222") {
		t.Fatalf("missing port: %v", cap.args)
	}
	if !cap.argsContain("deploy@server.example.com") {
		t.Fatalf("missing target: %v", cap.args)
	}
	// No agent/known_hosts option injection for a passthrough connection.
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") || strings.HasPrefix(a, "IdentitiesOnly") {
			t.Fatalf("unexpected managed-connection option in passthrough args: %v", cap.args)
		}
	}
}

func TestSSHConnect_LocalPassthrough_ConfigAlias(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		KeySource: "local", SSHConfigAlias: "bastion",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if len(cap.args) < 2 || cap.args[len(cap.args)-1] != "bastion" {
		t.Fatalf("expected plain alias invocation, got %v", cap.args)
	}
}

func TestSSHConnect_ConnectConfigHost(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectConfigHost("prod-bastion"); err != nil {
		t.Fatalf("ConnectConfigHost: %v", err)
	}
	if cap.args[len(cap.args)-1] != "prod-bastion" {
		t.Fatalf("expected alias in argv, got %v", cap.args)
	}
}

func TestSSHConnect_ConnectConfigHost_MissingAlias(t *testing.T) {
	svc := NewSSHConnectService()
	if err := svc.ConnectConfigHost("  "); !errors.Is(err, ErrSSHConnectMissingTarget) {
		t.Fatalf("expected ErrSSHConnectMissingTarget, got %v", err)
	}
}

func TestSSHConnect_LocalPassthrough_MissingTarget(t *testing.T) {
	svc := NewSSHConnectService()
	// KeySource == "local" bypasses the "not configured" check entirely
	// (no sshClient/hostKeys are required for a passthrough connection), so
	// an empty target must fail with ErrSSHConnectMissingTarget specifically.
	if err := svc.ConnectOneTime(SSHConnectParams{KeySource: "local"}); !errors.Is(err, ErrSSHConnectMissingTarget) {
		t.Fatalf("expected ErrSSHConnectMissingTarget, got %v", err)
	}
}

func TestSSHConnect_NotConfigured(t *testing.T) {
	svc := NewSSHConnectService()
	if err := svc.ConnectOneTime(SSHConnectParams{Host: "h", KeyName: "k"}); err == nil {
		t.Fatal("expected error when not configured")
	}
}

// TestSSHConnect_NoKeyPassthrough verifies that a connection with no key
// selected launches a plain passthrough `ssh` (agent/password auth handled by
// the system client) instead of failing to resolve a nameless managed key.
func TestSSHConnect_NoKeyPassthrough(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", Port: 2222, User: "deploy",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	if !cap.argsContain("deploy@server.example.com") || !cap.argsContain("2222") {
		t.Fatalf("missing target/port: %v", cap.args)
	}
	for _, a := range cap.args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") || a == "-i" {
			t.Fatalf("unexpected managed/identity option in no-key passthrough: %v", cap.args)
		}
	}
}

// TestSSHConnect_LocalPassthrough_IdentityFile verifies that a file-backed
// LocalIdentity is forwarded to ssh as -i <path>.
func TestSSHConnect_LocalPassthrough_IdentityFile(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", User: "deploy",
		KeySource: "local", LocalIdentity: "/home/op/.ssh/id_ed25519",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}

	iAt := -1
	for i, a := range cap.args {
		if a == "-i" {
			iAt = i
		}
	}
	if iAt == -1 || iAt+1 >= len(cap.args) || cap.args[iAt+1] != "/home/op/.ssh/id_ed25519" {
		t.Fatalf("missing -i <path>: %v", cap.args)
	}
	if cap.args[len(cap.args)-1] != "deploy@server.example.com" {
		t.Fatalf("target must come last: %v", cap.args)
	}
}

// TestSSHConnect_LocalPassthrough_AgentIdentityNoFlag verifies that an
// agent-held LocalIdentity ("agent:<fp>") adds no -i flag — the system agent
// offers the key itself.
func TestSSHConnect_LocalPassthrough_AgentIdentityNoFlag(t *testing.T) {
	svc, cap := setupConnect(t)
	defer svc.StopAll()

	if err := svc.ConnectOneTime(SSHConnectParams{
		Host: "server.example.com", User: "deploy",
		KeySource: "local", LocalIdentity: "agent:SHA256:abcdef",
	}); err != nil {
		t.Fatalf("ConnectOneTime: %v", err)
	}
	if cap.argsContain("-i") {
		t.Fatalf("agent identity must not add -i: %v", cap.args)
	}
	if cap.args[len(cap.args)-1] != "deploy@server.example.com" {
		t.Fatalf("missing target: %v", cap.args)
	}
}

// testConnectSigner builds an ed25519 signer for a connect session.
func testConnectSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return sg
}

// testKnownHostsLine renders a known_hosts entry the poll will try to import.
func testKnownHostsLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	hostPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return "accepted.example.com " + string(ssh.MarshalAuthorizedKey(hostPub))
}

// wedgedStore ignores the context it is handed and blocks until released,
// standing in for a barrier-backed store that has stopped answering.
type wedgedStore struct {
	storage.Backend
	entered chan struct{}
	once    sync.Once
	release chan struct{}
}

func (w *wedgedStore) Get(ctx context.Context, key string) ([]byte, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.Backend.Get(ctx, key)
}

// TestSSHConnect_WatcherShutdownIsNotBlockedByAWedgedStore covers the failure
// StopAll cannot recover from on its own. The watcher polls Sync; if that call
// is synchronous, a store that ignores its context parks the loop inside it and
// the ctx.Done branch is never reached — so cancelling has no effect and the
// signing socket stays alive for as long as the backend stays wedged, through
// application shutdown included.
//
// The poll interval is shortened rather than waited out, so the test is
// deterministic and fast and needs no skip guard: every step either happens or
// fails.
func TestSSHConnect_WatcherShutdownIsNotBlockedByAWedgedStore(t *testing.T) {
	sshSyncIntervalOverride.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { sshSyncIntervalOverride.Store(0) })

	wedged := &wedgedStore{
		Backend: storage.New(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(wedged.release)

	hostKeys, err := sshclient.NewHostKeyStore(wedged)
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	sess, err := sshclient.StartConnect(context.Background(), sshclient.ConnectOptions{
		Host:     "host.example.com",
		User:     "root",
		Signer:   testConnectSigner(t),
		HostKeys: hostKeys,
		Scope:    "user",
		Owner:    "alice",
	})
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	sockPath := strings.TrimPrefix(sess.Env[0], "SSH_AUTH_SOCK=")

	// A host the poll will try to import, so the wedged Get is actually
	// reached. Every step is checked: a silent setup failure here would leave
	// the store never entered and the behaviour under test never exercised.
	f, oerr := os.OpenFile(sess.KnownHostsFile(), os.O_APPEND|os.O_WRONLY, 0o600)
	if oerr != nil {
		t.Fatalf("open known_hosts: %v", oerr)
	}
	if _, werr := f.WriteString(testKnownHostsLine(t)); werr != nil {
		t.Fatalf("write known_hosts: %v", werr)
	}
	if cerr := f.Close(); cerr != nil {
		t.Fatalf("close known_hosts: %v", cerr)
	}

	svc := &SSHConnectService{sessions: map[string]*liveSession{"s1": {sess: sess}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.watch(ctx, "s1", sess) }()

	// Wait until the poll is genuinely stuck inside the store.
	select {
	case <-wedged.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the poll never reached the store; the behaviour under test was not exercised")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the watcher never shut down; its poll is blocking the ctx.Done branch")
	}

	if _, serr := os.Stat(sockPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the agent socket outlived shutdown: %v", serr)
	}
}

// --- SetKnownHostsPolicy / SetStrictHostKeyChecking ---

// TestSSHConnectService_SetKnownHostsPolicy_ValidatesInput pins the
// validating switch: only "system" and "both" are accepted verbatim.
func TestSSHConnectService_SetKnownHostsPolicy_ValidatesInput(t *testing.T) {
	svc := NewSSHConnectService()

	svc.SetKnownHostsPolicy("both")
	if svc.knownHostsPolicy != "both" {
		t.Fatalf("knownHostsPolicy = %q, want %q", svc.knownHostsPolicy, "both")
	}

	svc.SetKnownHostsPolicy("system")
	if svc.knownHostsPolicy != "system" {
		t.Fatalf("knownHostsPolicy = %q, want %q", svc.knownHostsPolicy, "system")
	}
}

// TestSSHConnectService_SetKnownHostsPolicy_UnknownValueFailsClosed pins the
// default branch: a value that isn't one of the recognized policies resets
// to "barrier" (the strictest option) rather than silently accepting
// garbage or leaving a stale value in place.
func TestSSHConnectService_SetKnownHostsPolicy_UnknownValueFailsClosed(t *testing.T) {
	svc := NewSSHConnectService()
	svc.SetKnownHostsPolicy("system")

	svc.SetKnownHostsPolicy("not-a-real-policy")

	if svc.knownHostsPolicy != "barrier" {
		t.Fatalf("knownHostsPolicy = %q, want %q (an unrecognized policy must fail closed)", svc.knownHostsPolicy, "barrier")
	}
}

// TestSSHConnectService_SetStrictHostKeyChecking_EmptyResetsToAsk pins the
// normalization: an empty policy is not stored as-is, it resets to the
// documented default "ask".
func TestSSHConnectService_SetStrictHostKeyChecking_EmptyResetsToAsk(t *testing.T) {
	svc := NewSSHConnectService()
	svc.SetStrictHostKeyChecking("yes")

	svc.SetStrictHostKeyChecking("")

	if svc.strictPolicy != "ask" {
		t.Fatalf("strictPolicy = %q, want %q", svc.strictPolicy, "ask")
	}
}

// --- envPrefix / shellJoin ---

func TestEnvPrefix(t *testing.T) {
	if got := envPrefix(nil); got != "" {
		t.Fatalf("envPrefix(nil) = %q, want empty", got)
	}
	if got := envPrefix([]string{}); got != "" {
		t.Fatalf("envPrefix([]) = %q, want empty", got)
	}
	if got := envPrefix([]string{"FOO=bar"}); got != "FOO=bar " {
		t.Fatalf("envPrefix single = %q, want %q", got, "FOO=bar ")
	}
	if got := envPrefix([]string{"FOO=bar", "BAZ=qux"}); got != "FOO=bar BAZ=qux " {
		t.Fatalf("envPrefix multiple = %q, want %q", got, "FOO=bar BAZ=qux ")
	}
}

func TestShellJoin(t *testing.T) {
	if got := shellJoin([]string{"ssh", "-p", "22", "host"}); got != "ssh -p 22 host" {
		t.Fatalf("shellJoin plain = %q", got)
	}
	if got := shellJoin([]string{"echo", "hello world"}); got != `echo 'hello world'` {
		t.Fatalf("shellJoin with space = %q, want %q", got, `echo 'hello world'`)
	}
	if got := shellJoin([]string{"echo", "it's a test"}); got != `echo 'it'\''s a test'` {
		t.Fatalf("shellJoin with embedded quote = %q, want %q", got, `echo 'it'\''s a test'`)
	}
	if got := shellJoin(nil); got != "" {
		t.Fatalf("shellJoin(nil) = %q, want empty", got)
	}
}
