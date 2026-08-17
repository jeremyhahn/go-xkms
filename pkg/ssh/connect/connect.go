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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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

	store          known_hosts.Store
	sc             scope.Scope
	owner          string
	knownHostsFile string
	extraFiles     []string
	skipStore      bool
	workDir        string
	ownsWorkDir    bool
	cancel         context.CancelFunc
}

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
	}

	agentCtx, cancel := context.WithCancel(ctx)
	sock := filepath.Join(workDir, "agent.sock")
	go func() { _ = sshagent.Serve(agentCtx, sock, sshagent.New(req.Signer)) }()
	if err := waitForSocket(sock, 3*time.Second); err != nil {
		cancel()
		cleanupDir(ownsWorkDir, workDir)
		return nil, err
	}

	// Seed the known_hosts the native client will verify against: pins from the
	// barrier store (unless SkipStore) plus any external files (~/.ssh).
	khFile := filepath.Join(workDir, "known_hosts")
	var seed []byte
	if !req.SkipStore {
		body, err := known_hosts.EmitAll(ctx, req.KnownHostsStore, req.Scope, req.Owner)
		if err != nil {
			cancel()
			cleanupDir(ownsWorkDir, workDir)
			return nil, &LaunchError{Op: "emit known_hosts", Err: err}
		}
		seed = append(seed, body...)
	}
	for _, f := range req.ExtraKnownHosts {
		// ExtraKnownHosts is local operator config (CLI flags / GUI settings,
		// e.g. ~/.ssh/known_hosts), never remote/request-derived input.
		if data, rerr := os.ReadFile(f); rerr == nil { // #nosec G703 -- operator-supplied local known_hosts path
			seed = append(seed, data...)
			if len(data) > 0 && data[len(data)-1] != '\n' {
				seed = append(seed, '\n')
			}
		}
	}
	// khFile is under workDir (req.WorkDir), which -- like ExtraKnownHosts
	// above -- is local operator/library-caller config, not remote input.
	if werr := os.WriteFile(khFile, seed, 0o600); werr != nil { // #nosec G703 -- operator-supplied WorkDir, not attacker-controlled
		cancel()
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
		Env:            []string{"SSH_AUTH_SOCK=" + sock},
		store:          req.KnownHostsStore,
		sc:             req.Scope,
		owner:          req.Owner,
		knownHostsFile: khFile,
		extraFiles:     req.ExtraKnownHosts,
		skipStore:      req.SkipStore,
		workDir:        workDir,
		ownsWorkDir:    ownsWorkDir,
		cancel:         cancel,
	}, nil
}

// Sync imports any host keys the native client accepted into the store without
// stopping the agent. It is idempotent and safe to call repeatedly while the
// session is live (the GUI polls it so first-contact hosts pin promptly).
// Returns the number of newly-pinned hosts.
func (s *Session) Sync() (int, error) {
	if s.knownHostsFile == "" {
		return 0, nil
	}
	// Mirror newly-accepted host keys into external files (~/.ssh/known_hosts)
	// for the "system" / "both" policies.
	for _, f := range s.extraFiles {
		_ = mirrorKnownHosts(s.knownHostsFile, f)
	}
	if s.skipStore || s.store == nil {
		return 0, nil
	}
	return known_hosts.ImportKnownHostsFile(context.Background(), s.store, s.sc, s.owner, s.knownHostsFile, known_hosts.SourceFirstContact)
}

// Stop cancels the agent and removes temp artifacts. Idempotent. After Stop the
// session can no longer Sync (the temp known_hosts is gone).
func (s *Session) Stop() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	cleanupDir(s.ownsWorkDir, s.workDir)
	s.knownHostsFile = ""
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
func (s *Session) KnownHostsFile() string { return s.knownHostsFile }

// target renders the "user@host" (or bare "host") connection argument.
func target(user, host string) string {
	if user == "" {
		return host
	}
	return user + "@" + host
}

// waitForSocket polls until the agent unix socket exists or the deadline lapses.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &LaunchError{Op: "agent socket", Err: &errs.Message{Msg: fmt.Sprintf("socket %s did not appear within %s", path, timeout)}}
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
	srcData, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return known_hosts.AppendMissing(srcData, dst)
}
