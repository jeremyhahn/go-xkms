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

// Package connect orchestrates launching the system `ssh` client against a host
// using an xkey-managed key. It serves the key's signer over an in-process SSH
// agent (so hardware-backed keys never export private material), seeds a
// known_hosts file from xkey's pins (matched hosts verify silently; unknown
// hosts get the native console first-contact prompt), and on completion syncs
// newly-accepted host keys back into the store. It returns the `ssh` argv + env
// so the caller (the xkey GUI or CLI) only has to spawn it — in a system
// terminal window for the GUI, or inheriting the current terminal for the CLI.
package connect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	sshagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Request describes a connection to launch.
type Request struct {
	// Host / Port / User identify the target. Port defaults to 22; User may be
	// empty (the ssh client falls back to the local user).
	Host string
	Port int
	User string

	// Signer authenticates the connection. It comes from the SSH SDK
	// Client.Signer and may be backed by a hardware device.
	Signer ssh.Signer

	// KnownHostsStore holds xkey's host-key pins. Required: the seeded
	// known_hosts file is built from it and accepted keys are synced back.
	KnownHostsStore known_hosts.Store

	// Scope / Owner select the pin namespace.
	Scope scope.Scope
	Owner string

	// ExtraOptions are additional OpenSSH `-o KEY=VALUE` options appended after
	// the managed options.
	ExtraOptions []string

	// StrictHostKeyChecking overrides the default ("ask"), e.g. "yes" for a
	// strict policy or "accept-new" to auto-pin first contact.
	StrictHostKeyChecking string

	// ExtraKnownHosts are additional OpenSSH known_hosts files (e.g.
	// ~/.ssh/known_hosts) merged into the seed the native client verifies
	// against, and mirrored to (newly-accepted host keys are appended) on sync.
	// Used by the "system" / "both" known-hosts policies.
	ExtraKnownHosts []string

	// SkipStore disables seeding from / syncing to KnownHostsStore. With it set
	// and ExtraKnownHosts populated, host trust is managed entirely in the
	// external file(s) (the "system" policy). KnownHostsStore is still required
	// (the pin store type) but is not read or written.
	SkipStore bool

	// WorkDir is where the agent socket + temp known_hosts are created. A temp
	// dir is used when empty.
	WorkDir string
}

// Session is a launched connection's runtime handle. The caller spawns `ssh`
// with Args/Env, then calls SyncAndStop once it exits.
type Session struct {
	// Args is the `ssh` argument list (excluding the "ssh" binary itself).
	Args []string

	// Env is the additional environment (SSH_AUTH_SOCK=...) to merge into the
	// spawned process environment.
	Env []string

	store       known_hosts.Store
	sc          scope.Scope
	owner       string
	extraFiles  []string
	skipStore   bool
	workDir     string
	ownsWorkDir bool

	// mu guards the teardown state below. The GUI polls Sync on one goroutine
	// while the session can be stopped from another (the spawned ssh exiting,
	// or the window closing), so the live/stopped transition is genuinely
	// concurrent and must not be read while it is being made.
	//
	// mu is never held across the import inside Sync. That import runs against
	// a caller-supplied store over a context this session does not control, so
	// holding the lock through it would let a stalled backend block Stop --
	// and Stop's real job, killing the signing agent, has nothing to do with
	// known_hosts. inFlight tracks running imports instead, so Stop can stop
	// the agent at once and merely bound how long it waits before removing the
	// file underneath one.
	mu             sync.Mutex
	knownHostsFile string
	agent          *sshagent.Session
	inFlight       sync.WaitGroup
}

// syncDrainTimeout bounds how long Stop waits for a running Sync before
// removing the work directory anyway. Generous for a healthy store, finite for
// one that has stopped answering.
const syncDrainTimeout = 5 * time.Second

// Start launches the agent, seeds the known_hosts file, and returns the ssh
// argv/env. The agent runs until SyncAndStop (or ctx) cancels it.
func Start(ctx context.Context, req Request) (*Session, error) {
	if req.Host == "" {
		return nil, &InputError{Field: "Host"}
	}
	if req.Signer == nil {
		return nil, &InputError{Field: "Signer"}
	}
	if req.KnownHostsStore == nil {
		return nil, &InputError{Field: "KnownHostsStore"}
	}

	workDir := req.WorkDir
	ownsWorkDir := false
	if workDir == "" {
		dir, err := os.MkdirTemp("", "xkey-ssh-")
		if err != nil {
			return nil, &LaunchError{Op: "tempdir", Err: err}
		}
		workDir = dir
		ownsWorkDir = true
	} else if err := os.MkdirAll(workDir, 0o700); err != nil {
		// Request.WorkDir names where this session's scratch area goes, so
		// creating it is this package's job. The agent deliberately will not:
		// it refuses to conjure a directory it would not own and therefore
		// would leave behind. Here the connection owns the layout -- the
		// socket and the temp known_hosts live side by side in it.
		return nil, &LaunchError{Op: "workdir", Err: err}
	}

	// Every path derived from workDir leaves this process: the socket becomes
	// the child's SSH_AUTH_SOCK and known_hosts becomes its
	// -o UserKnownHostsFile. The child is spawned with its own working
	// directory (a terminal window for the GUI), so a relative spelling would
	// resolve somewhere else -- and a known_hosts the client cannot find is not
	// a missing file to it, it is a host it has never seen, which turns pinned
	// verification into first contact.
	abs, err := filepath.Abs(workDir)
	if err != nil {
		cleanupDir(ownsWorkDir, workDir)
		return nil, &LaunchError{Op: "workdir", Err: err}
	}
	workDir = abs

	// The agent half of a connection is exactly an agent-only session: serve
	// the signer, hand SSH_AUTH_SOCK to the child. Everything below this line
	// is the host semantics an agent-only session deliberately has none of.
	agentSess, err := sshagent.StartSession(ctx, sshagent.Request{
		Signers: []ssh.Signer{req.Signer},
		WorkDir: workDir,
	})
	if err != nil {
		cleanupDir(ownsWorkDir, workDir)
		// Every setup failure in this package is a *LaunchError; a caller
		// matching that type must not start missing agent failures just
		// because the agent moved into its own package. The cause stays
		// reachable through Unwrap.
		return nil, &LaunchError{Op: "agent session", Err: err}
	}

	// Seed the known_hosts the native client will verify against: pins from the
	// barrier store (unless SkipStore) plus any external files (~/.ssh).
	khFile := filepath.Join(workDir, "known_hosts")
	var seed []byte
	if !req.SkipStore {
		body, err := known_hosts.EmitAll(ctx, req.KnownHostsStore, req.Scope, req.Owner)
		if err != nil {
			agentSess.Stop()
			cleanupDir(ownsWorkDir, workDir)
			return nil, &LaunchError{Op: "emit known_hosts", Err: err}
		}
		seed = append(seed, body...)
	}
	for _, f := range req.ExtraKnownHosts {
		// ExtraKnownHosts is local operator config (CLI flags / GUI settings,
		// e.g. ~/.ssh/known_hosts), never remote/request-derived input.
		if data, rerr := os.ReadFile(f); rerr == nil { // #nosec G304 G703 -- operator-supplied local known_hosts path
			seed = append(seed, data...)
			if len(data) > 0 && data[len(data)-1] != '\n' {
				seed = append(seed, '\n')
			}
		}
	}
	// khFile is under workDir (req.WorkDir), which -- like ExtraKnownHosts
	// above -- is local operator/library-caller config, not remote input.
	if werr := os.WriteFile(khFile, seed, 0o600); werr != nil { // #nosec G304 G703 -- operator-supplied WorkDir, not attacker-controlled
		agentSess.Stop()
		cleanupDir(ownsWorkDir, workDir)
		return nil, &LaunchError{Op: "write known_hosts", Err: werr}
	}

	strict := req.StrictHostKeyChecking
	if strict == "" {
		strict = "ask"
	}
	args := []string{
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + khFile,
		"-o", "StrictHostKeyChecking=" + strict,
	}
	for _, opt := range req.ExtraOptions {
		args = append(args, "-o", opt)
	}
	if req.Port > 0 && req.Port != 22 {
		args = append(args, "-p", strconv.Itoa(req.Port))
	}
	args = append(args, target(req.User, req.Host))

	return &Session{
		Args:           args,
		Env:            agentSess.Env,
		store:          req.KnownHostsStore,
		sc:             req.Scope,
		owner:          req.Owner,
		knownHostsFile: khFile,
		extraFiles:     req.ExtraKnownHosts,
		skipStore:      req.SkipStore,
		workDir:        workDir,
		ownsWorkDir:    ownsWorkDir,
		agent:          agentSess,
	}, nil
}

// Sync imports any host keys the native client accepted into the store without
// stopping the agent. It is idempotent and safe to call repeatedly while the
// session is live (the GUI polls it so first-contact hosts pin promptly).
// Returns the number of newly-pinned hosts.
func (s *Session) Sync() (int, error) {
	// Take a consistent snapshot and register as in-flight under the lock, then
	// release it before doing any I/O. Stop waits on inFlight rather than on
	// the mutex, so a store that has stopped answering delays the work-dir
	// removal by at most syncDrainTimeout instead of wedging shutdown.
	s.mu.Lock()
	khFile := s.knownHostsFile
	if khFile == "" {
		s.mu.Unlock()
		return 0, nil
	}
	s.inFlight.Add(1)
	s.mu.Unlock()
	defer s.inFlight.Done()
	// Mirror newly-accepted host keys into external files (~/.ssh/known_hosts)
	// for the "system" / "both" policies.
	for _, f := range s.extraFiles {
		_ = mirrorKnownHosts(khFile, f)
	}
	if s.skipStore || s.store == nil {
		return 0, nil
	}
	return known_hosts.ImportKnownHostsFile(context.Background(), s.store, s.sc, s.owner, khFile, known_hosts.SourceFirstContact)
}

// Stop cancels the agent and removes temp artifacts. Idempotent. After Stop the
// session can no longer Sync (the temp known_hosts is gone).
//
// Stopping the agent is unconditional and immediate -- it is the part that
// matters, and it does not depend on known_hosts. Removing the work directory
// then waits, briefly, for an in-flight Sync: tearing the file out from under a
// running import would lose exactly the first-contact pins Sync exists to
// capture. The wait is bounded, because the import runs against a caller's
// store and a store that has stopped answering must not be able to keep a
// signing agent alive.
func (s *Session) Stop() {
	s.mu.Lock()
	agent := s.agent
	s.agent = nil
	s.knownHostsFile = "" // no Sync started from here on
	s.mu.Unlock()

	if agent != nil {
		agent.Stop()
	}
	drainWithin(&s.inFlight, syncDrainTimeout)
	cleanupDir(s.ownsWorkDir, s.workDir)
}

// drainWithin waits for wg, giving up after d. The watcher goroutine ends when
// the last worker finishes, however long that takes.
func drainWithin(wg *sync.WaitGroup, d time.Duration) {
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(d):
	}
}

// SyncAndStop imports accepted host keys, then stops the agent and removes temp
// artifacts. Returns the number of newly-pinned hosts.
func (s *Session) SyncAndStop() (int, error) {
	added, err := s.Sync()
	s.Stop()
	return added, err
}

// KnownHostsFile returns the path to the session's temp known_hosts file (empty
// after Stop). Exposed so a caller can watch it for changes.
func (s *Session) KnownHostsFile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.knownHostsFile
}

// target renders the "user@host" (or bare "host") connection argument.
func target(user, host string) string {
	if user == "" {
		return host
	}
	return user + "@" + host
}

// cleanupDir removes the work dir only when this package created it.
func cleanupDir(owns bool, dir string) {
	if owns && dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// mirrorKnownHosts appends host-key lines present in src but not in dst,
// deduplicating by host + fingerprint. Used to write first-contact host keys
// the native client accepted into an external file (e.g. ~/.ssh/known_hosts).
// The line-parsing/dedup logic lives in known_hosts.AppendMissing — this is a
// thin call-through that reads src and delegates.
func mirrorKnownHosts(src, dst string) error {
	// src is this session's own temp known_hosts, built above from operator
	// config -- never a remote or request-derived path.
	srcData, err := os.ReadFile(src) // #nosec G304 G703 -- session-owned temp path
	if err != nil {
		return err
	}
	return known_hosts.AppendMissing(srcData, dst)
}
