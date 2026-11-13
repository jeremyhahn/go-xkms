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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	sshagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
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

	// cleanupErr holds a work-directory removal failure from reap, including
	// one that happens on the background reaper goroutine well after Stop /
	// SyncAndStop returned. Guarded by mu since the background reaper writes
	// it from its own goroutine. See Err.
	cleanupErr error

	// drained is closed once every running Sync has finished, by exactly ONE
	// waiter however many teardown calls ask for it. A waiter per call leaked
	// one permanently for each bounded stop whose store never answered, and
	// Stop is idempotent and called repeatedly.
	drainOnce sync.Once
	drained   chan struct{}

	// reapOnce keeps repeated bounded teardowns from each starting their own
	// background reaper.
	reapOnce sync.Once

	// reaperDone is closed once the background reaper has finished; nil until
	// reap starts one. Guarded by mu. See backgroundReap.
	reaperDone chan struct{}

	// syncing is non-nil while an import is running; a second caller joins it
	// rather than starting another. Two concurrent imports against the same
	// store are not merely wasteful -- with a backend that ignores
	// cancellation, each one blocks forever, and shutdown arriving during a
	// wedged poll would stack a second permanently-blocked call on top of the
	// first. Some stores also assume serialized access.
	syncing *syncFlight
}

// syncFlight is one in-progress import, shared by every caller that arrives
// while it runs.
type syncFlight struct {
	done  chan struct{}
	added int
	err   error
}

// drainCompletion returns the shared channel, starting its single waiter on
// first use. Only safe once knownHostsFile is cleared and no further Sync can
// register -- a WaitGroup.Wait racing an Add is a misuse panic. reap clears it
// before calling this.
func (s *Session) drainCompletion() <-chan struct{} {
	s.drainOnce.Do(func() {
		s.drained = make(chan struct{})
		go func() {
			s.inFlight.Wait()
			close(s.drained)
		}()
	})
	return s.drained
}

// syncDrainTimeout bounds the BACKGROUND reaper -- the one that takes over when
// a caller's own budget runs out with an import still going. No synchronous
// shutdown path waits on it; it exists so the work directory is eventually
// removed rather than leaked.
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
		dir, err := os.MkdirTemp(defaultWorkDirBase(), workDirPattern)
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
		return nil, errors.Join(&LaunchError{Op: "workdir", Err: err}, cleanupDir(removeAll, ownsWorkDir, workDir))
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
		// Every setup failure in this package is a *LaunchError; a caller
		// matching that type must not start missing agent failures just
		// because the agent moved into its own package. The cause stays
		// reachable through Unwrap.
		return nil, errors.Join(&LaunchError{Op: "agent session", Err: err}, cleanupDir(removeAll, ownsWorkDir, workDir))
	}

	// Seed the known_hosts the native client will verify against: pins from the
	// barrier store (unless SkipStore) plus any external files (~/.ssh).
	khFile := filepath.Join(workDir, "known_hosts")
	var seed []byte
	if !req.SkipStore {
		body, err := known_hosts.EmitAll(ctx, req.KnownHostsStore, req.Scope, req.Owner)
		if err != nil {
			// Nothing has attached yet, so this join is immediate. Stop
			// returns a ShutdownReport, not an error -- there is nothing to
			// join from it -- but the directory removal below can fail and
			// must not vanish.
			_ = agentSess.Stop(context.Background())
			return nil, errors.Join(&LaunchError{Op: "emit known_hosts", Err: err}, cleanupDir(removeAll, ownsWorkDir, workDir))
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
	if werr := fsutil.WriteFileAtomic(khFile, seed, 0o600); werr != nil { // #nosec G304 G703 -- operator-supplied WorkDir, not attacker-controlled
		// Nothing has attached yet, so this join is immediate.
		_ = agentSess.Stop(context.Background())
		return nil, errors.Join(&LaunchError{Op: "write known_hosts", Err: werr}, cleanupDir(removeAll, ownsWorkDir, workDir))
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
//
// ctx bounds the import. The store is the caller's and may be barrier-backed,
// so an unbounded import is an unbounded call in whatever is polling this --
// and in SyncAndStop it would delay stopping the agent, which is the one thing
// teardown must not wait on.
func (s *Session) Sync(ctx context.Context) (int, error) {
	if flight, mine := s.beginSync(); flight != nil {
		if !mine {
			// Someone else's import is already running; wait for it rather
			// than starting a second against the same store.
			select {
			case <-flight.done:
				return flight.added, flight.err
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		defer s.endSync(flight)
		flight.added, flight.err = s.syncOnce(ctx)
		return flight.added, flight.err
	}
	return 0, nil
}

// beginSync claims the single-flight slot. It returns the in-progress flight
// and whether this caller owns it; a nil flight means the session is closed to
// further imports.
func (s *Session) beginSync() (*syncFlight, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.knownHostsFile == "" {
		return nil, false
	}
	if s.syncing != nil {
		return s.syncing, false
	}
	s.syncing = &syncFlight{done: make(chan struct{})}
	s.inFlight.Add(1)
	return s.syncing, true
}

// endSync releases the slot and wakes everyone waiting on it.
func (s *Session) endSync(flight *syncFlight) {
	s.mu.Lock()
	s.syncing = nil
	s.mu.Unlock()
	close(flight.done)
	s.inFlight.Done()
}

// syncOnce is the actual import, run by whoever owns the flight.
func (s *Session) syncOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	khFile := s.knownHostsFile
	s.mu.Unlock()
	if khFile == "" {
		return 0, nil
	}
	// Mirror newly-accepted host keys into external files (~/.ssh/known_hosts)
	// for the "system" / "both" policies.
	//
	// A mirror failure is a REAL failure, not a nicety: under the system-only
	// policy (SkipStore) this is the sole persistence path, so an unwritable
	// destination or a full disk loses the accepted key outright -- and reap
	// then deletes the temp known_hosts, so the next connection is first
	// contact again with nobody told.
	for _, f := range s.extraFiles {
		if merr := mirrorKnownHosts(khFile, f); merr != nil {
			return 0, &LaunchError{Op: "mirror known_hosts", Err: merr}
		}
	}
	if s.skipStore || s.store == nil {
		return 0, nil
	}
	return known_hosts.ImportKnownHostsFile(ctx, s.store, s.sc, s.owner, khFile, known_hosts.SourceFirstContact)
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
// ctx bounds the wait for the agent session's connection handlers, and the
// returned report names any signing operation still running when it elapsed.
// The bound is the caller's for the same reason it is on the agent session: a
// handler stuck inside an uninterruptible Sign cannot be woken, and a layer
// that picks the number on the caller's behalf is choosing when to give up on
// their behalf too.
func (s *Session) Stop(ctx context.Context) sshagent.ShutdownReport {
	report := s.stopAgent(ctx)
	s.reap(ctx)
	return report
}

// stopAgent kills the signing agent and nothing else. It is separate from reap
// because it is the part that must never wait on anything: the known_hosts
// import, the store behind it and the work directory are all irrelevant to
// whether a socket is still handing out signatures.
func (s *Session) stopAgent(ctx context.Context) sshagent.ShutdownReport {
	s.mu.Lock()
	agent := s.agent
	s.mu.Unlock()

	if agent == nil {
		return sshagent.ShutdownReport{}
	}

	// The handle is NOT cleared before the stop completes. Clearing it first
	// meant a second caller -- a GUI Disconnect racing the TTL watcher -- saw
	// nil and was handed a clean report while the first was still waiting on an
	// uninterruptible signature. agent.Stop is safe to call concurrently and
	// bounds each caller by its own context, so both observe the truth.
	report := agent.Stop(ctx)

	// The handle is released only on a CLEAN join. Clearing it while a signer
	// is still wedged made the NEXT shutdown -- a GUI disconnect after a TTL
	// expiry, say -- take the nil branch and report clean, hiding a signing
	// operation that was still running. agent.Stop is idempotent and cheap on
	// an already-stopped session, so keeping the handle costs nothing and every
	// later caller gets the truth until the signer actually returns.
	if report.Clean() {
		s.mu.Lock()
		s.agent = nil
		s.mu.Unlock()
	}
	return report
}

// reap closes the session to further Syncs, waits briefly for one already
// running, and removes the work directory. Tearing the known_hosts out from
// under a live import would lose exactly the first-contact pins Sync exists to
// capture, so the wait is real -- but bounded, because the store is the
// caller's.
func (s *Session) reap(ctx context.Context) {
	s.mu.Lock()
	s.knownHostsFile = "" // no Sync started from here on
	s.mu.Unlock()

	// Read the removal seam once, now: the background reaper below can run
	// long after the caller returned.
	remove := removeAll

	select {
	case <-s.drainCompletion():
		s.setCleanupErr(cleanupDir(remove, s.ownsWorkDir, s.workDir))
		return
	case <-ctx.Done():
	}

	// The caller's budget is spent and an import is still running. Removing the
	// work directory now would tear the known_hosts out from under it, and
	// waiting here would spend a second bound the caller never agreed to -- the
	// exact way a "bounded" shutdown quietly becomes twice as long. Hand it to a
	// background reaper instead; the caller returns now.
	s.reapOnce.Do(func() {
		done := make(chan struct{})
		s.mu.Lock()
		s.reaperDone = done
		s.mu.Unlock()
		go func() {
			defer close(done)
			select {
			case <-s.drainCompletion():
			case <-after(syncDrainTimeout):
			}
			s.setCleanupErr(cleanupDir(remove, s.ownsWorkDir, s.workDir))
		}()
	})
}

// setCleanupErr records a work-directory removal failure from reap so it is
// reachable via Err rather than dropped (#701). Safe to call from the
// background reaper goroutine.
func (s *Session) setCleanupErr(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.cleanupErr = errors.Join(s.cleanupErr, err)
	s.mu.Unlock()
}

// backgroundReap returns a channel closed once the background reaper reap
// handed teardown to has finished, or nil when reap never started one. It
// makes the reaper's lifetime observable, so a caller that triggered it can
// wait for the work directory's removal to settle.
func (s *Session) backgroundReap() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reaperDone
}

// Err returns the first work-directory cleanup failure recorded by Stop,
// SyncAndStop, or the background reaper they may have handed teardown to.
// It is nil until teardown has actually removed (or failed to remove) the
// directory, and safe to call at any time, including before Stop.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupErr
}

// after returns a channel closed once d has elapsed, for the background reaper,
// which has a duration rather than a caller's context.
func after(d time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		<-time.After(d)
		close(done)
	}()
	return done
}

// SyncAndStop imports accepted host keys, then stops the agent and removes temp
// artifacts. It returns the number of newly-pinned hosts and the shutdown
// report.
//
// ctx bounds the shutdown exactly as it does on Stop, and for the same reason:
// this is the teardown path the xkey CLI takes when ssh exits and the GUI takes
// on disconnect, so a signer wedged inside Sign would otherwise hang the very
// callers the bound exists for. Offering an unbounded convenience here and
// telling callers to compose Sync and Stop themselves when they want a bound
// would put the trap on the path everyone actually uses.
func (s *Session) SyncAndStop(ctx context.Context) (int, sshagent.ShutdownReport, error) {
	// The agent goes FIRST, before anything is waited on. Passing ctx into Sync
	// is necessary but not sufficient -- the store belongs to the caller, and a
	// backend that ignores the context it was handed is most of the ways a
	// store goes wrong. Ordering the stop ahead of the import is what makes the
	// socket's lifetime independent of it rather than merely bounded by it.
	// The import starts FIRST and runs concurrently with the agent shutdown,
	// against the known_hosts reap has not removed yet. Sequencing it after
	// stopAgent meant a signer wedged for the whole budget left the import
	// starting on an already-expired context -- so the first-contact host keys
	// ssh had just accepted were silently dropped, trading a signing hazard for
	// a host-verification one. Both phases now get the same budget rather than
	// dividing it.
	type syncResult struct {
		added int
		err   error
	}
	done := make(chan syncResult, 1)
	go func() {
		added, err := s.Sync(ctx)
		done <- syncResult{added, err}
	}()

	report := s.stopAgent(ctx)

	var added int
	var err error
	// A finished import always wins. By the time the agent shutdown returns the
	// context is usually spent, so both cases are ready at once and select
	// chooses at random -- which would throw away a completed import, and its
	// pinned host keys, on a coin flip.
	select {
	case r := <-done:
		added, err = r.added, r.err
	default:
		select {
		case r := <-done:
			added, err = r.added, r.err
		case <-ctx.Done():
			err = ctx.Err()
		}
	}

	s.reap(ctx)
	// reap either removed the work directory synchronously (in which case
	// Err already reflects the outcome) or hand it to the background
	// reaper on an exhausted budget, which finishes later -- the caller can
	// still consult Err once Stop's own context work is done, if it cares.
	return added, report, errors.Join(err, s.Err())
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

// removeAll deletes a session-owned work directory. Tests replace it to
// force a cleanup failure, which file permissions cannot do under root.
var removeAll = os.RemoveAll

// cleanupDir removes the work dir with remove, only when this package created
// it. The caller passes the seam it read, so a background reaper uses the one
// in force when it started.
// maxSocketPathLen is the longest agent socket path a default work dir may
// produce. AF_UNIX's sun_path buffer is 108 bytes on Linux and 104 on macOS,
// each including the trailing NUL; staying under 104 is safe on both, so a
// long TMPDIR fails over to a short base instead of failing bind(2) with
// EINVAL (the same limit xkey/pkg/ipc applies to its own sockets).
const maxSocketPathLen = 103

// workDirPattern is the os.MkdirTemp pattern of a default work dir.
const workDirPattern = "xkey-ssh-"

// shortWorkDirBase is the last-resort base for a default work dir: short
// enough that the agent socket under it always fits sun_path.
const shortWorkDirBase = "/tmp"

// defaultWorkDirBase picks the base directory of a default work dir: the
// usual temp dir when the agent socket under it fits sun_path, else
// $XDG_RUNTIME_DIR when it is a usable private directory that fits, else
// /tmp. MkdirTemp still makes the work dir itself 0700 and owned by this
// process, so the choice of base never weakens the socket's protection.
// geteuid is os.Geteuid, a seam so tests can stand in for another user.
var geteuid = os.Geteuid

func defaultWorkDirBase() string {
	if fitsSunPath(os.TempDir()) {
		return ""
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && filepath.IsAbs(xdg) && fitsSunPath(xdg) && isPrivateDir(xdg) {
		return xdg
	}
	return shortWorkDirBase
}

// fitsSunPath reports whether an agent socket in a default work dir under
// base stays within maxSocketPathLen. The placeholder stands in for the
// random suffix MkdirTemp appends (at most 20 decimal digits).
func fitsSunPath(base string) bool {
	probe := filepath.Join(base, workDirPattern+"00000000000000000000")
	return len(sshagent.SocketPath(probe)) <= maxSocketPathLen
}

// isPrivateDir reports whether dir is a 0700 directory owned by the
// effective user. Writability is not enough: root may write any 0700
// directory, and if it inherited an unprivileged user's XDG_RUNTIME_DIR that
// user could rename the session dir and redirect UserKnownHostsFile and
// SSH_AUTH_SOCK. Root therefore gets no exception.
func isPrivateDir(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	uid, ok := dirOwner(info)
	return ok && uid == geteuid()
}

func cleanupDir(remove func(string) error, owns bool, dir string) error {
	if owns && dir != "" {
		return remove(dir)
	}
	return nil
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
