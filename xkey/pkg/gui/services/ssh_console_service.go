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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

var (
	// ErrSSHConsoleNotConfigured indicates the console service lacks its SSH
	// client or host-key store.
	ErrSSHConsoleNotConfigured = errors.New("ssh_console_service: not configured")

	// ErrSSHConsoleProfileNotFound indicates the requested profile is missing.
	ErrSSHConsoleProfileNotFound = errors.New("ssh_console_service: profile not found")

	// ErrSSHConsoleMissingAlias indicates OpenConfigHostConsole was called
	// with an empty alias.
	ErrSSHConsoleMissingAlias = errors.New("ssh_console_service: ssh_config alias is required")

	// ErrSSHConsoleInvalidToken indicates the WebSocket upgrade's token is
	// missing, unknown, or already consumed.
	ErrSSHConsoleInvalidToken = errors.New("ssh_console_service: invalid or expired console token")

	// ErrSSHConsoleSessionStoreNotSet indicates a persisted-session
	// operation was requested before the session store was wired.
	ErrSSHConsoleSessionStoreNotSet = errors.New("ssh_console_service: session store not configured")
)

// LocalIdentityAttemptError is the SDK's per-identity resolution failure,
// aliased for the frontend-facing error surface.
type LocalIdentityAttemptError = sshclient.LocalIdentityAttemptError

// NoUsableLocalIdentityError is the SDK's "no candidate local key resolved"
// failure, aliased for the frontend-facing error surface.
type NoUsableLocalIdentityError = sshclient.NoUsableLocalIdentityError

// SSHConsoleEndpoint is returned to the frontend to open an embedded terminal:
// the xterm.js client connects to URL (which carries the one-time Token).
type SSHConsoleEndpoint struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// consoleTicket is the per-connection state a WebSocket upgrade resolves.
// The signer(s) are resolved eagerly at open() time so a bad key reference
// fails the GUI call (where the dialog can show the error) instead of the
// later WebSocket handshake (where it surfaces as an opaque HTTP 403).
type consoleTicket struct {
	host    string
	port    int
	user    string
	created time.Time

	// hostKeyPolicy / knownHostsPolicy are captured from the service's
	// current settings at open() time, so a change to the global setting
	// mid-flight never affects an already-issued ticket.
	hostKeyPolicy    string
	knownHostsPolicy string

	// signer / signers carry the pre-resolved authentication key(s):
	// signer for an xkey-managed key, signers for local identities
	// (agent + ~/.ssh files, offered in order like the OpenSSH client).
	signer  gossh.Signer
	signers []gossh.Signer
}

// SSHConsoleService runs a loopback WebSocket server that bridges xterm.js in
// the xkey UI to an interactive SSH console. It mounts the reusable SDK console
// handler (sshclient.NewConsoleWSHandler) — the same handler the xkms REST
// transport and other apps mount — and resolves the connection's signer through
// the SDK ssh client, so hardware-backed keys never export private material.
type SSHConsoleService struct {
	ctx       context.Context
	sshClient sshclient.Client
	hostKeys  sshclient.HostKeyStore
	profiles  *SSHProfileService
	sessions  sshclient.ConsoleSessionStore
	logger    *slog.Logger

	mu               sync.Mutex
	server           *http.Server
	baseURL          string
	tickets          map[string]*consoleTicket
	hostKeyPolicy    string // "yes" (default) | "ask" | "accept-new"
	knownHostsPolicy string // "barrier" (default) | "system" | "both"
}

// NewSSHConsoleService constructs the service. The loopback server starts
// lazily on the first console request.
//
// The default host-key policy is "ask" — matching SSHConnectService's
// default and the Settings UI — so a first-contact host raises the
// in-console Accept/Reject fingerprint prompt instead of hard-failing
// against an empty pin store (a fresh install has no pins at all).
func NewSSHConsoleService() *SSHConsoleService {
	return &SSHConsoleService{
		tickets:          make(map[string]*consoleTicket),
		hostKeyPolicy:    "ask",
		knownHostsPolicy: "barrier",
	}
}

// SetContext is invoked by the Wails startup lifecycle hook.
func (s *SSHConsoleService) SetContext(ctx context.Context) { s.ctx = ctx }

// SetSSHClient wires the SSH SDK client used to resolve key signers.
func (s *SSHConsoleService) SetSSHClient(c sshclient.Client) { s.sshClient = c }

// SetHostKeyStore wires the host-key pin store the console verifies against.
func (s *SSHConsoleService) SetHostKeyStore(store sshclient.HostKeyStore) { s.hostKeys = store }

// SetProfileService wires the profile service for ConnectProfile.
func (s *SSHConsoleService) SetProfileService(p *SSHProfileService) { s.profiles = p }

// SetSessionStore wires the persisted-session store (barrier-routed).
// Sessions started without persistence never touch it.
func (s *SSHConsoleService) SetSessionStore(store sshclient.ConsoleSessionStore) { s.sessions = store }

// SaveSession persists (or updates) a record for a session explicitly
// started with persistence enabled, returning it with its assigned ID.
func (s *SSHConsoleService) SaveSession(rec sshclient.ConsoleSessionRecord) (*sshclient.ConsoleSessionRecord, error) {
	if s.sessions == nil {
		return nil, ErrSSHConsoleSessionStoreNotSet
	}
	rec.LastConnectedAt = time.Now().UTC()
	if err := s.sessions.Save(&rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListSessions returns every persisted session, most recently connected
// first — the set the GUI restores as disconnected tabs at startup.
func (s *SSHConsoleService) ListSessions() ([]*sshclient.ConsoleSessionRecord, error) {
	if s.sessions == nil {
		return nil, ErrSSHConsoleSessionStoreNotSet
	}
	return s.sessions.List()
}

// DeleteSession removes a persisted session record (tab closed for good).
func (s *SSHConsoleService) DeleteSession(id string) error {
	if s.sessions == nil {
		return ErrSSHConsoleSessionStoreNotSet
	}
	return s.sessions.Delete(id)
}

// SetLogger wires the structured logger.
func (s *SSHConsoleService) SetLogger(l *slog.Logger) { s.logger = l }

// SetHostKeyPolicy chooses how an unpinned host key is handled during the
// interactive WebSocket handshake: "ask" (default — pause for an interactive
// hostkey/hostkey-response round trip), "yes" (strict: unpinned hosts fail),
// or "accept-new" (auto-accept first contact). Any other value resets to
// "ask".
func (s *SSHConsoleService) SetHostKeyPolicy(policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch policy {
	case "yes", "accept-new":
		s.hostKeyPolicy = policy
	default:
		s.hostKeyPolicy = "ask"
	}
}

// SetKnownHostsPolicy chooses where host-key pins live: "barrier" (xkey's
// encrypted store, default), "system" (~/.ssh/known_hosts), or "both".
func (s *SSHConsoleService) SetKnownHostsPolicy(policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch policy {
	case "system", "both":
		s.knownHostsPolicy = policy
	default:
		s.knownHostsPolicy = "barrier"
	}
}

// OpenProfileConsole prepares an embedded console for a saved profile and
// returns the WebSocket endpoint the frontend connects to.
func (s *SSHConsoleService) OpenProfileConsole(profileID string) (*SSHConsoleEndpoint, error) {
	if s.profiles == nil {
		return nil, ErrSSHConsoleNotConfigured
	}
	p, err := s.profiles.GetProfile(profileID)
	if err != nil {
		return nil, ErrSSHConsoleProfileNotFound
	}
	if p.KeySource == sshKeySourceLocal && p.SSHConfigAlias != "" && p.LocalIdentity == "" {
		return s.OpenConfigHostConsole(p.SSHConfigAlias)
	}
	return s.open(SSHConnectParams{
		Host: p.Host, Port: p.Port, User: p.User,
		KeyScope: p.KeyScope, KeyOwner: p.KeyOwner, KeyName: p.KeyName,
		KeySource: p.KeySource, LocalIdentity: p.LocalIdentity,
	})
}

// OpenConsole prepares an embedded console for a one-time connection.
func (s *SSHConsoleService) OpenConsole(params SSHConnectParams) (*SSHConsoleEndpoint, error) {
	return s.open(params)
}

// OpenConfigHostConsole prepares an embedded console for a ssh_config(5)
// Host alias, authenticating with the operator's local ssh-agent / ~/.ssh
// identity files instead of an xkey-managed key. It resolves the host
// (HostName/User/Port) and the candidate identity files at call time;
// resolve() later tries each identity, in order, the first time the
// WebSocket handshake actually needs a signer.
func (s *SSHConsoleService) OpenConfigHostConsole(alias string) (*SSHConsoleEndpoint, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return nil, ErrSSHConsoleMissingAlias
	}
	if s.hostKeys == nil {
		return nil, ErrSSHConsoleNotConfigured
	}

	cfg, err := sshclient.LoadLocalSSHConfig(sshclient.DefaultLocalSSHConfigPaths()...)
	if err != nil {
		return nil, err
	}
	hc := cfg.Lookup(alias)

	signers, err := sshclient.ResolveLocalSigners(s.bg(), sshclient.LocalKeySelector{Alias: alias}, os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}

	user := hc.User
	if user == "" {
		user = currentOSUser()
	}
	port := hc.Port
	if port == 0 {
		port = 22
	}

	return s.issueTicket(&consoleTicket{
		host: hc.HostName, port: port, user: user,
		signers: signers,
	})
}

func (s *SSHConsoleService) open(params SSHConnectParams) (*SSHConsoleEndpoint, error) {
	if s.hostKeys == nil {
		return nil, ErrSSHConsoleNotConfigured
	}

	ticket := &consoleTicket{host: params.Host, port: params.Port, user: params.User}

	// "local" key source — or no key at all — authenticates with the
	// operator's own agent/~/.ssh identities, the way the system ssh
	// client would.
	if params.KeySource == sshKeySourceLocal || params.KeyName == "" {
		signers, err := s.resolveLocalParams(params)
		if err != nil {
			return nil, err
		}
		ticket.signers = signers
		return s.issueTicket(ticket)
	}

	if s.sshClient == nil {
		return nil, ErrSSHConsoleNotConfigured
	}
	if params.KeyScope == "" {
		params.KeyScope = "user"
	}
	if params.KeyOwner == "" {
		params.KeyOwner = "local"
	}
	signer, err := s.sshClient.Keys().Signer(s.bg(), sshclient.GetKeyRequest{
		Scope: params.KeyScope, Owner: params.KeyOwner, Name: params.KeyName,
	})
	if err != nil {
		return nil, err
	}
	ticket.signer = signer
	return s.issueTicket(ticket)
}

// resolveLocalParams maps a "local"-source connect request to its signers
// via the SDK resolver: a pinned agent key ("agent:<fp>"), a pinned identity
// file path, or — when LocalIdentity is empty — every discovered local
// identity plus every agent key, OpenSSH-style.
func (s *SSHConsoleService) resolveLocalParams(params SSHConnectParams) ([]gossh.Signer, error) {
	return sshclient.ResolveLocalSigners(s.bg(), sshclient.LocalKeySelector{
		Identity: params.LocalIdentity,
		Host:     params.Host,
	}, os.Getenv("SSH_AUTH_SOCK"))
}

// consoleTicketTTL bounds how long an issued-but-never-connected ticket
// survives. The frontend opens its WebSocket immediately after OpenConsole,
// so anything this old is abandoned (e.g. a dialog dismissed mid-connect)
// and would otherwise accumulate for the daemon's lifetime.
const consoleTicketTTL = 2 * time.Minute

// issueTicket registers a resolved ticket under a fresh one-time token,
// stamping the service's current policies, and returns the WS endpoint.
// Stale abandoned tickets are purged on every issue.
func (s *SSHConsoleService) issueTicket(ticket *consoleTicket) (*SSHConsoleEndpoint, error) {
	base, err := s.ensureServer()
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	ticket.created = time.Now()
	s.mu.Lock()
	for tok, t := range s.tickets {
		if time.Since(t.created) > consoleTicketTTL {
			delete(s.tickets, tok)
		}
	}
	ticket.hostKeyPolicy = s.hostKeyPolicy
	ticket.knownHostsPolicy = s.knownHostsPolicy
	s.tickets[token] = ticket
	s.mu.Unlock()
	return &SSHConsoleEndpoint{URL: base + "?token=" + token, Token: token}, nil
}

// ensureServer lazily starts the loopback WebSocket server and returns the base
// ws:// URL.
func (s *SSHConsoleService) ensureServer() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return s.baseURL, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", &WrappedError{Msg: "ssh_console_service: listen", Err: err}
	}

	handler := sshclient.NewConsoleWSHandler(
		sshclient.ConsoleResolverFunc(s.resolve),
		// Loopback only; the one-time token in the query is the gate.
		sshclient.WithConsoleCheckOrigin(func(*http.Request) bool { return true }),
	)
	mux := http.NewServeMux()
	mux.Handle("/console", handler)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	s.server = srv
	s.baseURL = "ws://" + ln.Addr().String() + "/console"
	logger := s.logger
	go func() {
		if serr := srv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) && logger != nil {
			logger.Error("ssh console server stopped", "error", serr)
		}
	}()
	if s.logger != nil {
		s.logger.Info("SSH embedded console server started", "addr", ln.Addr().String())
	}
	return s.baseURL, nil
}

// resolve maps an authenticated WebSocket upgrade (carrying a one-time token)
// to a console Target, resolving the signer via the SDK ssh client (or, for a
// local-identity ticket, via the operator's ssh-agent/~/.ssh files).
func (s *SSHConsoleService) resolve(r *http.Request) (*sshclient.ConsoleTarget, error) {
	token := r.URL.Query().Get("token")
	s.mu.Lock()
	ticket := s.tickets[token]
	if ticket != nil {
		delete(s.tickets, token) // one-time use
	}
	s.mu.Unlock()
	if ticket == nil {
		return nil, ErrSSHConsoleInvalidToken
	}

	var extraKnownHosts []string
	skipStore := false
	if ticket.knownHostsPolicy == "system" || ticket.knownHostsPolicy == "both" {
		if home, herr := os.UserHomeDir(); herr == nil {
			extraKnownHosts = []string{filepath.Join(home, ".ssh", "known_hosts")}
		}
		skipStore = ticket.knownHostsPolicy == "system"
	}

	return &sshclient.ConsoleTarget{
		Host:                 ticket.host,
		Port:                 ticket.port,
		User:                 ticket.user,
		Signer:               ticket.signer,
		Signers:              ticket.signers,
		HostKeys:             s.hostKeys,
		Scope:                sshConnectScope,
		Owner:                sshConnectOwner,
		HostKeyPolicy:        ticket.hostKeyPolicy,
		KnownHostsExtraFiles: extraKnownHosts,
		KnownHostsSkipStore:  skipStore,
	}, nil
}

// bg returns the service context, falling back to background before startup.
func (s *SSHConsoleService) bg() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Shutdown stops the loopback server (called on app shutdown).
func (s *SSHConsoleService) Shutdown() {
	s.mu.Lock()
	srv := s.server
	s.server = nil
	s.tickets = make(map[string]*consoleTicket)
	s.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Warn("failed to shut down SSH console loopback server", "error", err)
		}
	}
}

// randomToken returns a 32-hex-char one-time token.
func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// currentOSUser returns the current OS user's login name, or "" if it
// cannot be determined.
func currentOSUser() string {
	u, err := osuser.Current()
	if err != nil {
		return ""
	}
	return u.Username
}
