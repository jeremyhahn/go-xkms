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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func setupConsole(t *testing.T) *SSHConsoleService {
	t.Helper()
	ctx := context.Background()
	daos := sshDAOs(t, storage.New())
	client, err := sshclient.NewEmbedded(sshclient.EmbeddedOptions{Stores: sshStores(t, daos)})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if _, err := client.Keys().Generate(ctx, sshclient.GenerateRequest{
		Scope: "user", Owner: "local", Name: "laptop", Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hostKeys, err := sshclient.NewHostKeyStore(daos)
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	svc := NewSSHConsoleService()
	svc.SetContext(ctx)
	svc.SetSSHClient(client)
	svc.SetHostKeyStore(hostKeys)
	return svc
}

func TestSSHConsole_OpenEndpoint(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	ep, err := svc.OpenConsole(SSHConnectParams{
		Host: "server.example.com", Port: 22, User: "deploy",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}
	if !strings.HasPrefix(ep.URL, "ws://127.0.0.1:") {
		t.Fatalf("unexpected loopback URL: %s", ep.URL)
	}
	if !strings.Contains(ep.URL, "/console?token=") || ep.Token == "" {
		t.Fatalf("endpoint missing token: %+v", ep)
	}

	// A second request reuses the same loopback server (same host:port) with a
	// distinct one-time token.
	ep2, err := svc.OpenConsole(SSHConnectParams{Host: "h2", User: "u", KeyName: "laptop"})
	if err != nil {
		t.Fatalf("OpenConsole 2: %v", err)
	}
	base := func(u string) string { return u[:strings.Index(u, "?")] }
	if base(ep.URL) != base(ep2.URL) {
		t.Fatalf("loopback server not reused: %s vs %s", ep.URL, ep2.URL)
	}
	if ep.Token == ep2.Token {
		t.Fatal("tokens must be unique per request")
	}
}

func TestSSHConsole_Bg_FallsBackToBackground(t *testing.T) {
	svc := NewSSHConsoleService()
	if svc.bg() == nil {
		t.Fatal("expected a non-nil background context")
	}
}

func TestSSHConsole_SetProfileServiceAndSetLogger(t *testing.T) {
	svc := NewSSHConsoleService()
	if svc.profiles != nil {
		t.Fatal("expected nil profiles by default")
	}
	if svc.logger != nil {
		t.Fatal("expected nil logger by default")
	}

	profiles := NewSSHProfileService(nil)
	svc.SetProfileService(profiles)
	if svc.profiles != profiles {
		t.Fatal("SetProfileService did not store the profile service")
	}

	logger := slog.Default()
	svc.SetLogger(logger)
	if svc.logger != logger {
		t.Fatal("SetLogger did not store the logger")
	}
}

func TestSSHConsole_OpenProfileConsole_NotConfigured(t *testing.T) {
	svc := NewSSHConsoleService()
	if _, err := svc.OpenProfileConsole("any"); !errors.Is(err, ErrSSHConsoleNotConfigured) {
		t.Fatalf("expected ErrSSHConsoleNotConfigured, got %v", err)
	}
}

func TestSSHConsole_OpenProfileConsole_NotFound(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	store, err := sshclient.NewProfileStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	svc.SetProfileService(NewSSHProfileService(store))

	if _, err := svc.OpenProfileConsole("missing"); !errors.Is(err, ErrSSHConsoleProfileNotFound) {
		t.Fatalf("expected ErrSSHConsoleProfileNotFound, got %v", err)
	}
}

func TestSSHConsole_OpenProfileConsole_ManagedKey(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	store, err := sshclient.NewProfileStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	profileSvc := NewSSHProfileService(store)
	svc.SetProfileService(profileSvc)

	entry, err := profileSvc.AddProfile(SSHProfileParams{
		Name: "prod", Host: "prod.example.com", User: "deploy",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	ep, err := svc.OpenProfileConsole(entry.ID)
	if err != nil {
		t.Fatalf("OpenProfileConsole: %v", err)
	}
	if ep.Token == "" {
		t.Fatal("expected a non-empty token")
	}
}

func TestSSHConsole_OpenProfileConsole_LocalAliasDelegatesToConfigHost(t *testing.T) {
	pub, priv := newTestEd25519Key(t)
	writeConfigHostAndIdentity(t, "bastion", pub)

	// The identity file is a placeholder, so the signer must come from an
	// agent. Serve one in-process instead of inheriting the host's
	// SSH_AUTH_SOCK, which CI does not have.
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, keyring))

	svc := setupConsole(t)
	defer svc.Shutdown()

	store, err := sshclient.NewProfileStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	profileSvc := NewSSHProfileService(store)
	svc.SetProfileService(profileSvc)

	entry, err := profileSvc.AddProfile(SSHProfileParams{
		Name: "bastion-profile", Host: "bastion.example.com",
		KeySource: sshKeySourceLocal, SSHConfigAlias: "bastion",
	})
	if err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	ep, err := svc.OpenProfileConsole(entry.ID)
	if err != nil {
		t.Fatalf("OpenProfileConsole: %v", err)
	}
	if ep.Token == "" {
		t.Fatal("expected a non-empty token")
	}
}

func TestCurrentOSUser(t *testing.T) {
	// currentOSUser wraps os/user.Current(); it must return exactly what
	// that call reports (empty string only if the lookup itself fails).
	want := ""
	if u, err := osuser.Current(); err == nil {
		want = u.Username
	}
	if got := currentOSUser(); got != want {
		t.Fatalf("currentOSUser() = %q, want %q", got, want)
	}
}

func TestSSHConsole_NotConfigured(t *testing.T) {
	svc := NewSSHConsoleService()
	if _, err := svc.OpenConsole(SSHConnectParams{Host: "h", KeyName: "k"}); err == nil {
		t.Fatal("expected error when not configured")
	}
}

// newTestEd25519Key generates a fresh ed25519 key pair for local-identity /
// ssh-agent tests.
func newTestEd25519Key(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub, priv
}

// serveTestAgent serves keyring on a fresh unix socket under t.TempDir()
// until the test ends.
func serveTestAgent(t *testing.T, keyring sshagent.Agent) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()
	return sock
}

// writeConfigHostAndIdentity sets HOME to a fresh temp dir carrying an
// ssh_config Host block for alias plus a paired (dummy private / real
// public) identity file for pub, and returns HOME.
func writeConfigHostAndIdentity(t *testing.T, alias string, pub ssh.PublicKey) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	cfg := "Host " + alias + "\n  HostName real.example.com\n  User carol\n  Port 2200\n  IdentityFile ~/.ssh/id_test\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_test"), []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write dummy private key: %v", err)
	}
	line := string(ssh.MarshalAuthorizedKey(pub))
	if err := os.WriteFile(filepath.Join(sshDir, "id_test.pub"), []byte(line), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return home
}

func TestSSHConsole_OpenConfigHostConsole_Success(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	pub, priv := newTestEd25519Key(t)
	writeConfigHostAndIdentity(t, "cfg-alias", pub)

	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, keyring))

	svc.SetHostKeyPolicy("accept-new")
	svc.SetKnownHostsPolicy("both")

	ep, err := svc.OpenConfigHostConsole("cfg-alias")
	if err != nil {
		t.Fatalf("OpenConfigHostConsole: %v", err)
	}
	if !strings.Contains(ep.URL, "token=") || ep.Token == "" {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	svc.mu.Lock()
	ticket := svc.tickets[ep.Token]
	svc.mu.Unlock()
	if ticket == nil {
		t.Fatal("expected ticket to be recorded")
	}
	if ticket.host != "real.example.com" || ticket.user != "carol" || ticket.port != 2200 {
		t.Fatalf("unexpected ticket target: %+v", ticket)
	}

	req := httptest.NewRequest(http.MethodGet, ep.URL, nil)
	target, err := svc.resolve(req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.Host != "real.example.com" || target.User != "carol" || target.Port != 2200 {
		t.Fatalf("unexpected target: %+v", target)
	}
	if target.HostKeyPolicy != "accept-new" {
		t.Fatalf("HostKeyPolicy = %q, want accept-new", target.HostKeyPolicy)
	}
	if len(target.KnownHostsExtraFiles) != 1 || target.KnownHostsSkipStore {
		t.Fatalf("unexpected known-hosts plumbing: %+v", target)
	}
	// Local tickets carry their resolved signers as the ordered candidate
	// list (agent keys first), not the single managed-key Signer.
	if target.Signer != nil {
		t.Fatalf("expected no managed signer, got %+v", target.Signer)
	}
	if len(target.Signers) == 0 || target.Signers[0].PublicKey().Type() != pub.Type() {
		t.Fatalf("unexpected signers: %+v", target.Signers)
	}

	// The token is one-time: a second resolve must fail.
	if _, err := svc.resolve(req); !errors.Is(err, ErrSSHConsoleInvalidToken) {
		t.Fatalf("expected ErrSSHConsoleInvalidToken on reuse, got %v", err)
	}
}

// TestSSHConsole_Resolve_ExpiredTicketRefused verifies resolve refuses (and
// deletes) a ticket older than consoleTicketTTL, so a WebSocket upgrade that
// arrives long after OpenConsole -- a browser tab left open after the
// dialog it belonged to was abandoned -- cannot redeem a ticket whose
// signer(s) and host-key policy were captured under stale conditions
// (go-xkms#1299). The service's clock seam (now) makes this hermetic: no
// real consoleTicketTTL-length sleep.
func TestSSHConsole_Resolve_ExpiredTicketRefused(t *testing.T) {
	svc := NewSSHConsoleService()
	defer svc.Shutdown()

	fixed := time.Now()
	svc.now = func() time.Time { return fixed }

	const token = "expired-ticket-token"
	svc.mu.Lock()
	svc.tickets[token] = &consoleTicket{
		host:    "example.com",
		port:    22,
		user:    "carol",
		created: fixed.Add(-consoleTicketTTL - time.Second),
	}
	svc.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/console?token="+token, nil)
	if _, err := svc.resolve(req); !errors.Is(err, ErrSSHConsoleInvalidToken) {
		t.Fatalf("expected ErrSSHConsoleInvalidToken for expired ticket, got %v", err)
	}

	svc.mu.Lock()
	_, exists := svc.tickets[token]
	svc.mu.Unlock()
	if exists {
		t.Fatal("expected expired ticket to be deleted from the ticket table")
	}
}

// TestSSHConsole_Resolve_UnexpiredTicketAccepted verifies resolve still
// redeems a ticket within consoleTicketTTL, the companion case to
// TestSSHConsole_Resolve_ExpiredTicketRefused: the TTL check must not
// reject a ticket that simply has not aged out yet.
func TestSSHConsole_Resolve_UnexpiredTicketAccepted(t *testing.T) {
	svc := NewSSHConsoleService()
	defer svc.Shutdown()

	fixed := time.Now()
	svc.now = func() time.Time { return fixed }

	const token = "fresh-ticket-token"
	svc.mu.Lock()
	svc.tickets[token] = &consoleTicket{
		host:    "example.com",
		port:    22,
		user:    "carol",
		created: fixed.Add(-consoleTicketTTL + time.Second),
	}
	svc.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/console?token="+token, nil)
	target, err := svc.resolve(req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if target.Host != "example.com" || target.User != "carol" || target.Port != 22 {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestSSHConsole_OpenConfigHostConsole_MissingAlias(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()
	if _, err := svc.OpenConfigHostConsole("  "); !errors.Is(err, ErrSSHConsoleMissingAlias) {
		t.Fatalf("expected ErrSSHConsoleMissingAlias, got %v", err)
	}
}

func TestSSHConsole_OpenConfigHostConsole_NoIdentities(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "") // no agent — nothing to fall back on
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	cfg := "Host bare-alias\n  HostName bare.example.com\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := svc.OpenConfigHostConsole("bare-alias")
	var noUsable *NoUsableLocalIdentityError
	if !errors.As(err, &noUsable) {
		t.Fatalf("expected *NoUsableLocalIdentityError, got %T: %v", err, err)
	}
	if noUsable.Alias != "bare-alias" {
		t.Fatalf("unexpected alias: %+v", noUsable)
	}
}

func TestSSHConsole_ResolveLocalSigners_AllFail(t *testing.T) {
	pub, _ := newTestEd25519Key(t)
	writeConfigHostAndIdentity(t, "fail-alias", pub)
	t.Setenv("SSH_AUTH_SOCK", "") // no agent — file parse of "dummy" bytes will fail

	_, resolveErr := sshclient.ResolveLocalSigners(context.Background(), sshclient.LocalKeySelector{Alias: "fail-alias"}, "")
	var noUsable *NoUsableLocalIdentityError
	if !errors.As(resolveErr, &noUsable) {
		t.Fatalf("expected *NoUsableLocalIdentityError, got %T: %v", resolveErr, resolveErr)
	}
	if noUsable.Alias != "fail-alias" {
		t.Fatalf("unexpected alias: %+v", noUsable)
	}
	var attempt *LocalIdentityAttemptError
	if !errors.As(resolveErr, &attempt) {
		t.Fatalf("expected a joined *LocalIdentityAttemptError, got %v", resolveErr)
	}
}

func TestSSHConsole_HostKeyPolicy_DefaultsAndInvalid(t *testing.T) {
	svc := NewSSHConsoleService()
	// "ask" is the default so a fresh install's first-contact connection
	// raises the in-console fingerprint prompt instead of hard-failing
	// against an empty pin store.
	if svc.hostKeyPolicy != "ask" || svc.knownHostsPolicy != "barrier" {
		t.Fatalf("unexpected defaults: %+v", svc)
	}
	svc.SetHostKeyPolicy("yes")
	if svc.hostKeyPolicy != "yes" {
		t.Fatalf("strict policy not applied, got %q", svc.hostKeyPolicy)
	}
	svc.SetHostKeyPolicy("bogus")
	if svc.hostKeyPolicy != "ask" {
		t.Fatalf("invalid policy should reset to ask, got %q", svc.hostKeyPolicy)
	}
	svc.SetKnownHostsPolicy("bogus")
	if svc.knownHostsPolicy != "barrier" {
		t.Fatalf("invalid policy should reset to barrier, got %q", svc.knownHostsPolicy)
	}
}

// TestSSHConsole_OpenConsole_NoKey_UsesLocalAgent verifies that a one-time
// embedded connect with no key selected authenticates with the operator's
// local identities — here, a key held only by the system agent.
func TestSSHConsole_OpenConsole_NoKey_UsesLocalAgent(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	home := t.TempDir()
	t.Setenv("HOME", home) // no ~/.ssh at all — the agent is the only source

	pub, priv := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, keyring))

	ep, err := svc.OpenConsole(SSHConnectParams{Host: "server.example.com", User: "deploy"})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}

	svc.mu.Lock()
	ticket := svc.tickets[ep.Token]
	svc.mu.Unlock()
	if ticket == nil {
		t.Fatal("expected ticket")
	}
	if ticket.signer != nil {
		t.Fatalf("no-key ticket must not carry a managed signer: %+v", ticket.signer)
	}
	if len(ticket.signers) != 1 || ticket.signers[0].PublicKey().Type() != pub.Type() {
		t.Fatalf("expected the agent key as candidate signer, got %+v", ticket.signers)
	}
}

// TestSSHConsole_OpenConsole_NoKey_NoIdentities verifies that with no agent
// and no local identities the failure surfaces from OpenConsole itself (so
// the GUI can show it) as *NoUsableLocalIdentityError.
func TestSSHConsole_OpenConsole_NoKey_NoIdentities(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")

	_, err := svc.OpenConsole(SSHConnectParams{Host: "server.example.com", User: "deploy"})
	var noUsable *NoUsableLocalIdentityError
	if !errors.As(err, &noUsable) {
		t.Fatalf("expected *NoUsableLocalIdentityError, got %T: %v", err, err)
	}
	if noUsable.Alias != "server.example.com" {
		t.Fatalf("error should be labeled with the host: %+v", noUsable)
	}
}

// TestSSHConsole_OpenConsole_AgentFingerprintPinned verifies that
// LocalIdentity "agent:<fp>" pins the connection to exactly that agent key,
// and that an unknown fingerprint fails eagerly at OpenConsole.
func TestSSHConsole_OpenConsole_AgentFingerprintPinned(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	t.Setenv("HOME", t.TempDir())

	pubA, privA := newTestEd25519Key(t)
	_, privB := newTestEd25519Key(t)
	keyring := sshagent.NewKeyring()
	for _, priv := range []interface{}{privA, privB} {
		if err := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); err != nil {
			t.Fatalf("keyring.Add: %v", err)
		}
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, keyring))

	ep, err := svc.OpenConsole(SSHConnectParams{
		Host: "h", User: "u",
		KeySource: "local", LocalIdentity: "agent:" + ssh.FingerprintSHA256(pubA),
	})
	if err != nil {
		t.Fatalf("OpenConsole: %v", err)
	}
	svc.mu.Lock()
	ticket := svc.tickets[ep.Token]
	svc.mu.Unlock()
	if len(ticket.signers) != 1 || ssh.FingerprintSHA256(ticket.signers[0].PublicKey()) != ssh.FingerprintSHA256(pubA) {
		t.Fatalf("expected exactly the pinned agent key, got %+v", ticket.signers)
	}

	if _, err := svc.OpenConsole(SSHConnectParams{
		Host: "h", User: "u",
		KeySource: "local", LocalIdentity: "agent:SHA256:doesnotexist",
	}); err == nil {
		t.Fatal("expected error for unknown agent fingerprint")
	} else {
		var notFound *sshclient.LocalAgentKeyNotFoundError
		if !errors.As(err, &notFound) {
			t.Fatalf("expected *LocalAgentKeyNotFoundError, got %T: %v", err, err)
		}
	}
}

// TestSSHConsole_OpenConsole_ManagedKeyNotFound verifies that a bad managed
// key name fails eagerly at OpenConsole instead of surfacing as an opaque
// WebSocket handshake failure.
func TestSSHConsole_OpenConsole_ManagedKeyNotFound(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()

	if _, err := svc.OpenConsole(SSHConnectParams{
		Host: "h", User: "u", KeyName: "no-such-key",
	}); err == nil {
		t.Fatal("expected error for missing managed key")
	}
}

// TestSSHConsole_SessionCRUD verifies the persisted-session surface the GUI
// tabs drive: save (ID assigned), list (most recent first), delete.
func TestSSHConsole_SessionCRUD(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()
	store, err := sshclient.NewConsoleSessionStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewConsoleSessionStore: %v", err)
	}
	svc.SetSessionStore(store)

	saved, err := svc.SaveSession(sshclient.ConsoleSessionRecord{
		Title: "deploy@web1", Host: "web1", Port: 22, User: "deploy", KeyName: "laptop",
	})
	if err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if saved.ID == "" || saved.LastConnectedAt.IsZero() {
		t.Fatalf("record not stamped: %+v", saved)
	}

	second, err := svc.SaveSession(sshclient.ConsoleSessionRecord{Title: "omega", ProfileID: "omega-id"})
	if err != nil {
		t.Fatalf("SaveSession (profile origin): %v", err)
	}

	all, err := svc.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(all))
	}
	if all[0].ID != second.ID {
		t.Fatalf("expected most-recent-first order, got %+v", all)
	}

	// Re-saving with the same ID updates in place (reconnect touch).
	saved.Title = "deploy@web1 (renamed)"
	if _, err := svc.SaveSession(*saved); err != nil {
		t.Fatalf("SaveSession (update): %v", err)
	}
	if all, _ = svc.ListSessions(); len(all) != 2 {
		t.Fatalf("update must not duplicate, got %d", len(all))
	}

	if err := svc.DeleteSession(saved.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	all, _ = svc.ListSessions()
	if len(all) != 1 || all[0].ID != second.ID {
		t.Fatalf("expected only the profile session to remain, got %+v", all)
	}
}

// TestSSHConsole_Session_StoreNotSet verifies every session operation fails
// with a typed error before the store is wired.
func TestSSHConsole_Session_StoreNotSet(t *testing.T) {
	svc := NewSSHConsoleService()
	if _, err := svc.SaveSession(sshclient.ConsoleSessionRecord{Title: "t", Host: "h"}); !errors.Is(err, ErrSSHConsoleSessionStoreNotSet) {
		t.Fatalf("SaveSession: expected ErrSSHConsoleSessionStoreNotSet, got %v", err)
	}
	if _, err := svc.ListSessions(); !errors.Is(err, ErrSSHConsoleSessionStoreNotSet) {
		t.Fatalf("ListSessions: expected ErrSSHConsoleSessionStoreNotSet, got %v", err)
	}
	if err := svc.DeleteSession("x"); !errors.Is(err, ErrSSHConsoleSessionStoreNotSet) {
		t.Fatalf("DeleteSession: expected ErrSSHConsoleSessionStoreNotSet, got %v", err)
	}
}

// TestSSHConsole_Session_InvalidRecord verifies validation errors surface
// through the service.
func TestSSHConsole_Session_InvalidRecord(t *testing.T) {
	svc := setupConsole(t)
	defer svc.Shutdown()
	store, err := sshclient.NewConsoleSessionStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewConsoleSessionStore: %v", err)
	}
	svc.SetSessionStore(store)

	if _, err := svc.SaveSession(sshclient.ConsoleSessionRecord{Host: "h"}); !errors.Is(err, sshclient.ErrConsoleSessionInvalidTitle) {
		t.Fatalf("expected invalid-title error, got %v", err)
	}
	if _, err := svc.SaveSession(sshclient.ConsoleSessionRecord{Title: "t"}); !errors.Is(err, sshclient.ErrConsoleSessionInvalidOrigin) {
		t.Fatalf("expected invalid-origin error, got %v", err)
	}
	if err := svc.DeleteSession("missing"); !errors.Is(err, sshclient.ErrConsoleSessionNotFound) {
		t.Fatalf("expected not-found error, got %v", err)
	}
}
