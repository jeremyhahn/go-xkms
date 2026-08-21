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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// SSH connection identity defaults — the GUI operates a single local custodian,
// matching SSHService's key scope/owner.
const (
	sshConnectScope = "user"
	sshConnectOwner = "local"

	// sshSyncInterval is how often a live session re-imports first-contact host
	// keys the native client accepted.
	sshSyncIntervalDefault = 3 * time.Second

	// sshSyncBound caps one polled host-key import. The store may be
	// barrier-backed, and a poll that outlives its own interval is a poll that
	// stacks up behind itself.
	sshSyncBound = 2 * time.Second

	// sshShutdownBound caps teardown. A spawned ssh can have a request parked
	// in Signer.Sign on a hardware key awaiting touch, which closing its
	// connection cannot interrupt; past this the session is torn down anyway
	// and the abandoned count is logged.
	sshShutdownBound = 5 * time.Second

	// sshSessionTTL bounds how long a launched agent stays alive (safety net;
	// also torn down on app shutdown / Disconnect).
	sshSessionTTL = 12 * time.Hour

	// sshKeySourceLocal selects the operator's local ssh-agent/~/.ssh identity
	// files instead of an xkey-managed key. Empty (the zero value) means
	// "managed" — the historical, still-default behavior.
	sshKeySourceLocal = "local"
)

// sshSyncIntervalOverride lets a test drive the poll without waiting seconds
// for a real tick. Atomic because watchers from other tests may be reading it
// concurrently. Zero means the default.
var sshSyncIntervalOverride atomic.Int64

// sshSyncInterval is the poll interval in effect.
func sshSyncInterval() time.Duration {
	if n := sshSyncIntervalOverride.Load(); n > 0 {
		return time.Duration(n)
	}
	return sshSyncIntervalDefault
}

var (
	// ErrSSHConnectNotConfigured indicates the connect service is missing its
	// SSH client or host-key store.
	ErrSSHConnectNotConfigured = errors.New("ssh_connect_service: not configured")

	// ErrSSHConnectNoTerminal indicates no system terminal emulator was found.
	ErrSSHConnectNoTerminal = errors.New("ssh_connect_service: no system terminal found")

	// ErrSSHConnectUnsupportedPlatform indicates an unsupported GOOS.
	ErrSSHConnectUnsupportedPlatform = errors.New("ssh_connect_service: unsupported platform")

	// ErrSSHConnectProfileNotFound indicates the requested profile is missing.
	ErrSSHConnectProfileNotFound = errors.New("ssh_connect_service: profile not found")

	// ErrSSHConnectMissingTarget indicates a KeySource == "local" connection
	// was requested with neither an SSHConfigAlias nor a Host.
	ErrSSHConnectMissingTarget = errors.New("ssh_connect_service: host or ssh_config_alias is required")
)

// SSHConnectParams is a one-time (unsaved) connection request from the GUI.
type SSHConnectParams struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	KeyScope string `json:"key_scope"`
	KeyOwner string `json:"key_owner"`
	KeyName  string `json:"key_name"`

	// KeySource selects where the authentication key comes from: "" (the
	// default) uses the xkey-managed key named by KeyScope/KeyOwner/KeyName;
	// "local" launches a plain passthrough `ssh` in the system terminal
	// using the operator's own ssh-agent/~/.ssh identities instead — no
	// in-process agent, no temporary known_hosts, no env injection.
	KeySource string `json:"key_source"`

	// SSHConfigAlias names the ssh_config(5) Host alias to connect through
	// when KeySource is "local". When set, the terminal runs plain
	// `ssh <alias>` and Host/Port/User below are ignored (the system ssh
	// client resolves them from ssh_config itself).
	SSHConfigAlias string `json:"ssh_config_alias"`

	// LocalIdentity pins the connection to one specific local key when
	// KeySource is "local": either an identity file path (passed to ssh
	// as -i) or "agent:<SHA256-fingerprint>" for a key held only by the
	// system agent (the agent offers it; no -i is added). Empty lets the
	// system ssh client pick from its default identities/agent.
	LocalIdentity string `json:"local_identity"`
}

// localIdentityAgentPrefix marks a LocalIdentity value that names a system
// ssh-agent key by fingerprint instead of an identity file path.
const localIdentityAgentPrefix = "agent:"

// SSHConnectService launches `ssh` in the system terminal using an xkey-managed
// key served over an in-process agent. Host-key first-contact is handled by the
// native client; accepted keys are synced back into the pin store.
type SSHConnectService struct {
	ctx       context.Context
	sshClient sshclient.Client
	hostKeys  sshclient.HostKeyStore
	profiles  *SSHProfileService
	logger    *slog.Logger

	// execCommand / lookPath are injected for testability.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
	lookPath    func(string) (string, error)

	mu               sync.Mutex
	terminalOverride string
	strictPolicy     string
	knownHostsPolicy string // "barrier" (default) | "system" | "both"
	sessions         map[string]*liveSession
	seq              int
}

type liveSession struct {
	sess   *sshclient.ConnectSession
	cancel context.CancelFunc
}

// NewSSHConnectService constructs the connect service with production defaults.
func NewSSHConnectService() *SSHConnectService {
	return &SSHConnectService{
		execCommand:      exec.CommandContext,
		lookPath:         exec.LookPath,
		strictPolicy:     "ask",
		knownHostsPolicy: "barrier",
		sessions:         make(map[string]*liveSession),
	}
}

// SetKnownHostsPolicy chooses where host-key pins live: "barrier" (xkey's
// encrypted store, default), "system" (~/.ssh/known_hosts), or "both".
func (s *SSHConnectService) SetKnownHostsPolicy(policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch policy {
	case "system", "both":
		s.knownHostsPolicy = policy
	default:
		s.knownHostsPolicy = "barrier"
	}
}

// SetContext is invoked by the Wails startup lifecycle hook.
func (s *SSHConnectService) SetContext(ctx context.Context) { s.ctx = ctx }

// SetSSHClient wires the SSH SDK client used to resolve the key's signer.
func (s *SSHConnectService) SetSSHClient(c sshclient.Client) { s.sshClient = c }

// SetHostKeyStore wires the host-key pin store seeded into / synced from the
// native client's known_hosts.
func (s *SSHConnectService) SetHostKeyStore(store sshclient.HostKeyStore) { s.hostKeys = store }

// SetProfileService wires the profile service used to resolve saved profiles.
func (s *SSHConnectService) SetProfileService(p *SSHProfileService) { s.profiles = p }

// SetLogger wires the structured logger.
func (s *SSHConnectService) SetLogger(l *slog.Logger) { s.logger = l }

// SetTerminalCommand sets a terminal-launcher override (e.g. "kitty -e"). The
// `ssh` command is appended after the override tokens. Empty restores the
// per-platform default.
func (s *SSHConnectService) SetTerminalCommand(cmd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalOverride = strings.TrimSpace(cmd)
}

// SetStrictHostKeyChecking sets the OpenSSH StrictHostKeyChecking policy
// ("ask", "yes", "accept-new"). Empty restores "ask".
func (s *SSHConnectService) SetStrictHostKeyChecking(policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy == "" {
		policy = "ask"
	}
	s.strictPolicy = policy
}

// ConnectProfile launches a connection from a saved profile.
func (s *SSHConnectService) ConnectProfile(profileID string) error {
	if s.profiles == nil {
		return ErrSSHConnectNotConfigured
	}
	p, err := s.profiles.GetProfile(profileID)
	if err != nil {
		return ErrSSHConnectProfileNotFound
	}
	return s.launch(SSHConnectParams{
		Host:     p.Host,
		Port:     p.Port,
		User:     p.User,
		KeyScope: p.KeyScope,
		KeyOwner: p.KeyOwner,
		KeyName:  p.KeyName,

		KeySource:      p.KeySource,
		SSHConfigAlias: p.SSHConfigAlias,
		LocalIdentity:  p.LocalIdentity,
	})
}

// ConnectOneTime launches a one-time (unsaved) connection.
func (s *SSHConnectService) ConnectOneTime(params SSHConnectParams) error {
	return s.launch(params)
}

// ConnectConfigHost launches a plain passthrough `ssh <alias>` in the system
// terminal, authenticating however the operator's own ssh_config/ssh-agent
// resolves it. This never touches xkey's managed keys, in-process agent, or
// known_hosts store — it is functionally identical to running `ssh <alias>`
// directly in a terminal.
func (s *SSHConnectService) ConnectConfigHost(alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return ErrSSHConnectMissingTarget
	}
	return s.launchPassthrough(SSHConnectParams{KeySource: sshKeySourceLocal, SSHConfigAlias: alias})
}

// launch resolves the signer, starts the agent + known_hosts seed, spawns the
// system terminal, and registers a live session that syncs first-contact pins.
// A KeySource of "local" bypasses all of that in favor of a plain passthrough
// `ssh` invocation (see launchPassthrough) — as does an empty KeyName with no
// KeySource, so "no key" connections authenticate via the operator's own
// agent/identities or an interactive password prompt instead of failing to
// resolve a nameless managed key.
func (s *SSHConnectService) launch(params SSHConnectParams) error {
	if params.KeySource == sshKeySourceLocal || params.KeyName == "" {
		return s.launchPassthrough(params)
	}

	if s.sshClient == nil || s.hostKeys == nil {
		return ErrSSHConnectNotConfigured
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
		return err
	}

	s.mu.Lock()
	strict := s.strictPolicy
	policy := s.knownHostsPolicy
	s.mu.Unlock()

	var extraKnownHosts []string
	skipStore := false
	if policy == "system" || policy == "both" {
		if home, herr := os.UserHomeDir(); herr == nil {
			extraKnownHosts = []string{filepath.Join(home, ".ssh", "known_hosts")}
		}
		skipStore = policy == "system"
	}

	sess, err := sshclient.StartConnect(context.Background(), sshclient.ConnectOptions{
		Host:                  params.Host,
		Port:                  params.Port,
		User:                  params.User,
		Signer:                signer,
		HostKeys:              s.hostKeys,
		Scope:                 sshConnectScope,
		Owner:                 sshConnectOwner,
		StrictHostKeyChecking: strict,
		ExtraKnownHosts:       extraKnownHosts,
		SkipStore:             skipStore,
	})
	if err != nil {
		return err
	}

	name, args, err := s.buildTerminal(sess.Args, sess.Env)
	if err != nil {
		sess.Stop(context.Background())
		return err
	}
	cmd := s.execCommand(context.Background(), name, args...)
	cmd.Env = append(os.Environ(), sess.Env...)
	if startErr := cmd.Start(); startErr != nil {
		sess.Stop(context.Background())
		return &WrappedError{Msg: "ssh_connect_service: launch terminal", Err: startErr}
	}

	s.register(sess)
	return nil
}

// launchPassthrough spawns a plain `ssh` invocation in the system terminal:
// no in-process agent, no temporary known_hosts, no env injection beyond the
// inherited process environment. When SSHConfigAlias is set the terminal
// runs `ssh <alias>` verbatim (letting the system ssh_config resolve
// everything); otherwise it runs `ssh [-p port] [user@]host`.
func (s *SSHConnectService) launchPassthrough(params SSHConnectParams) error {
	var sshArgs []string
	switch {
	case params.SSHConfigAlias != "":
		sshArgs = []string{params.SSHConfigAlias}
	case params.Host != "":
		if params.Port != 0 {
			sshArgs = append(sshArgs, "-p", strconv.Itoa(params.Port))
		}
		// A file-backed LocalIdentity is passed as -i; an agent-held key
		// ("agent:<fp>") needs no flag — the system agent offers it.
		if id := params.LocalIdentity; id != "" && !strings.HasPrefix(id, localIdentityAgentPrefix) {
			sshArgs = append(sshArgs, "-i", id)
		}
		target := params.Host
		if params.User != "" {
			target = params.User + "@" + target
		}
		sshArgs = append(sshArgs, target)
	default:
		return ErrSSHConnectMissingTarget
	}

	name, args, err := s.buildTerminal(sshArgs, nil)
	if err != nil {
		return err
	}
	cmd := s.execCommand(context.Background(), name, args...)
	cmd.Env = os.Environ()
	if startErr := cmd.Start(); startErr != nil {
		return &WrappedError{Msg: "ssh_connect_service: launch terminal", Err: startErr}
	}
	return nil
}

// register stores a live session and starts its sync watcher.
func (s *SSHConnectService) register(sess *sshclient.ConnectSession) {
	watchCtx, cancel := context.WithTimeout(context.Background(), sshSessionTTL)
	s.mu.Lock()
	s.seq++
	id := strconv.Itoa(s.seq)
	s.sessions[id] = &liveSession{sess: sess, cancel: cancel}
	s.mu.Unlock()

	go s.watch(watchCtx, id, sess)
}

// watch periodically imports first-contact host keys until the TTL/ctx ends,
// then performs a final sync, stops the agent, and deregisters the session.
func (s *SSHConnectService) watch(ctx context.Context, id string, sess *sshclient.ConnectSession) {
	ticker := time.NewTicker(sshSyncInterval())
	defer ticker.Stop()

	// polling is non-nil while a poll is in flight; its result arrives on the
	// channel. The poll runs on its own goroutine because a store that ignores
	// the context it was handed -- the failure mode this whole teardown design
	// exists for -- would otherwise block this loop inside Sync, so shutdown
	// could never reach the ctx.Done branch and the signing socket would stay
	// alive for as long as the backend stayed wedged. StopAll only cancels
	// ctx; it cannot interrupt a synchronous call.
	var polling chan error

	shutdown := func() {
		// ctx is already cancelled here, so the teardown gets its own bound.
		stopCtx, cancelStop := context.WithTimeout(context.Background(), sshShutdownBound)
		_, report, err := sess.SyncAndStop(stopCtx)
		cancelStop()
		if err != nil && s.logger != nil {
			s.logger.Warn("ssh connect: final host-key sync failed", "error", err)
		}
		if !report.Clean() && s.logger != nil {
			s.logger.Warn("ssh connect: shutdown abandoned in-flight signing operations",
				"session", id, "abandoned", report.Abandoned)
		}
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
	}

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return

		case err := <-polling:
			polling = nil
			if err != nil && s.logger != nil {
				s.logger.Debug("ssh connect: host-key sync", "error", err)
			}

		case <-ticker.C:
			if polling != nil {
				continue // a poll is still running; do not stack another on it
			}
			polling = make(chan error, 1)
			go func(done chan<- error) {
				syncCtx, cancelSync := context.WithTimeout(context.Background(), sshSyncBound)
				_, err := sess.Sync(syncCtx)
				cancelSync()
				done <- err
			}(polling)
		}
	}
}

// StopAll tears down every live session (called on app shutdown).
func (s *SSHConnectService) StopAll() {
	s.mu.Lock()
	live := make([]*liveSession, 0, len(s.sessions))
	for _, ls := range s.sessions {
		live = append(live, ls)
	}
	s.mu.Unlock()
	for _, ls := range live {
		ls.cancel() // watcher performs SyncAndStop + deregister
	}
}

// buildTerminal resolves the system terminal launcher for `ssh sshArgs...`.
// env carries SSH_AUTH_SOCK; on platforms whose terminal spawns a fresh shell
// that does not inherit the parent environment (macOS/Windows), it is embedded
// into the command. A nil/empty env (see launchPassthrough) embeds nothing.
func (s *SSHConnectService) buildTerminal(sshArgs, env []string) (string, []string, error) {
	sshCmd := append([]string{"ssh"}, sshArgs...)

	s.mu.Lock()
	override := s.terminalOverride
	s.mu.Unlock()
	if override != "" {
		parts := strings.Fields(override)
		return parts[0], append(parts[1:], sshCmd...), nil
	}

	switch runtime.GOOS {
	case "linux":
		for _, term := range []struct{ name, flag string }{
			{"x-terminal-emulator", "-e"},
			{"gnome-terminal", "--"},
			{"konsole", "-e"},
			{"xfce4-terminal", "-x"},
			{"xterm", "-e"},
		} {
			if path, err := s.lookPath(term.name); err == nil {
				return path, append([]string{term.flag}, sshCmd...), nil
			}
		}
		return "", nil, ErrSSHConnectNoTerminal
	case "darwin":
		// Terminal.app spawns a fresh shell — embed the env into the script.
		script := fmt.Sprintf("tell application \"Terminal\" to do script %q", envPrefix(env)+shellJoin(sshCmd))
		return "osascript", []string{"-e", script}, nil
	case "windows":
		// "cmd /c start ssh ..." — env is inherited from cmd.Env.
		return "cmd", append([]string{"/c", "start", "ssh"}, sshArgs...), nil
	default:
		return "", nil, ErrSSHConnectUnsupportedPlatform
	}
}

// bg returns the service context, falling back to background before startup.
func (s *SSHConnectService) bg() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// envPrefix renders env assignments as a shell prefix ("K=V K2=V2 ").
func envPrefix(env []string) string {
	if len(env) == 0 {
		return ""
	}
	return strings.Join(env, " ") + " "
}

// shellJoin joins argv into a single space-delimited command, quoting tokens
// that contain spaces.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}
