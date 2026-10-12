// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package vtpm runs a per-tenant virtual TPM (swtpm) as a child process of
// the node, for tenants whose tpm.mode is "vtpm".
//
// Each vTPM is a `swtpm socket --tpm2` process with its own state directory
// and command socket. Its state is always encrypted: the AES-256 state key is
// obtained from a StateKeyProvider at every start -- xkms seals it under the
// system scope's "vtpm-state" TPM policy on the physical TPM -- and reaches
// swtpm through an inherited pipe, never a file. The Manager restarts a vTPM
// that exits unexpectedly, and the Transport it hands out reconnects to the
// restarted process. See docs/tpm-policies/architecture.md.
package vtpm

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// StateKeySize is the size of a vTPM state-encryption key (AES-256).
const StateKeySize = 32

const (
	// defaultBinary is the swtpm executable resolved from PATH.
	defaultBinary = "swtpm"

	// readyTimeout bounds how long Start waits for a new vTPM's socket.
	readyTimeout = 10 * time.Second

	// readyPoll is how often Start probes the socket while waiting.
	readyPoll = 20 * time.Millisecond

	// readyProbeTimeout bounds one readiness probe's connect and round trip,
	// so a probe never holds Start past a process exit or cancellation for
	// longer than this.
	readyProbeTimeout = time.Second

	// stopTimeout is how long Stop waits after SIGTERM before SIGKILL.
	stopTimeout = 5 * time.Second

	// minBackoff and maxBackoff bound the delay before restarting a vTPM
	// that exited on its own.
	minBackoff = 100 * time.Millisecond
	maxBackoff = 30 * time.Second
)

// StateKeyProvider supplies a tenant's vTPM state-encryption key. The key
// must be StateKeySize bytes and the same on every start, or swtpm cannot
// read the state it wrote before.
type StateKeyProvider interface {
	StateKey(tenant string) ([]byte, error)
}

// Config configures a Manager.
type Config struct {
	// Binary is the swtpm executable. Empty resolves "swtpm" from PATH.
	Binary string

	// StateDir holds one state directory per tenant (<StateDir>/<tenant>).
	StateDir string

	// RunDir holds the vTPM sockets. It is created with mode 0700.
	RunDir string

	// Logger receives lifecycle events. Nil uses slog.Default().
	Logger *slog.Logger
}

// Status describes one tenant's vTPM.
type Status struct {
	Tenant   string
	Running  bool
	PID      int
	Socket   string
	Restarts int64
}

// Manager starts, stops and supervises per-tenant vTPMs.
type Manager struct {
	cfg    Config
	keys   StateKeyProvider
	logger *slog.Logger

	mu        sync.Mutex
	instances map[string]*instance
	closed    atomic.Bool
}

// instance is one tenant's supervised swtpm process.
type instance struct {
	tenant   string
	stateDir string
	socket   string

	stop     chan struct{} // closed to end supervision
	stopped  chan struct{} // closed when the supervisor has returned
	pid      atomic.Int64
	running  atomic.Bool
	restarts atomic.Int64

	procMu sync.Mutex
	proc   *os.Process
}

// NewManager returns a Manager. Every vTPM it starts encrypts its state with
// a key from keys.
func NewManager(cfg Config, keys StateKeyProvider) (*Manager, error) {
	if cfg.StateDir == "" {
		return nil, ErrStateDirRequired
	}
	if cfg.RunDir == "" {
		return nil, ErrRunDirRequired
	}
	if keys == nil {
		return nil, ErrKeyProviderRequired
	}
	if cfg.Binary == "" {
		cfg.Binary = defaultBinary
	}
	resolved, err := resolveBinary(cfg.Binary)
	if err != nil {
		return nil, err
	}
	cfg.Binary = resolved
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		cfg:       cfg,
		keys:      keys,
		logger:    logger,
		instances: make(map[string]*instance),
	}, nil
}

// resolveBinary validates Config.Binary once, at construction (gosec G204:
// the value comes from node configuration, so Start must never run an
// exec.Command built from a name or path nobody has checked). A bare name
// (no path separator) is resolved through exec.LookPath, which on this
// platform already confirms an executable regular file; a path is checked
// directly with os.Stat. Either way the result is an absolute or
// already-verified path, resolved once rather than re-searched on PATH at
// every Start.
func resolveBinary(binary string) (string, error) {
	if !strings.Contains(binary, string(os.PathSeparator)) {
		resolved, err := exec.LookPath(binary)
		if err != nil {
			return "", &BinaryError{Binary: binary, Err: err}
		}
		return resolved, nil
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", &BinaryError{Binary: binary, Err: err}
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", &BinaryError{Binary: binary, Err: errBinaryNotExecutable}
	}
	return binary, nil
}

// Start starts the tenant's vTPM and returns once it answers a command, which
// it does only after its state has decrypted and loaded. Starting a running
// vTPM is a no-op.
func (m *Manager) Start(ctx context.Context, tenant string) error {
	if m.closed.Load() {
		return ErrManagerClosed
	}
	if err := validateTenant(tenant); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[tenant]; ok {
		return nil
	}

	inst := &instance{
		tenant:   tenant,
		stateDir: filepath.Join(m.cfg.StateDir, tenant),
		socket:   filepath.Join(m.cfg.RunDir, "vtpm-"+tenant+".sock"),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	if err := os.MkdirAll(inst.stateDir, 0o700); err != nil {
		return &StartError{Tenant: tenant, Err: err}
	}
	if err := os.MkdirAll(m.cfg.RunDir, 0o700); err != nil {
		return &StartError{Tenant: tenant, Err: err}
	}

	proc, err := m.spawn(inst)
	if err != nil {
		return err
	}
	if err := m.awaitReady(ctx, inst, proc); err != nil {
		return errors.Join(err, m.kill(inst, proc))
	}
	inst.running.Store(true)

	m.instances[tenant] = inst
	go m.supervise(inst, proc)
	m.logger.Info("vTPM started", slog.String("tenant", tenant), slog.Int64("pid", inst.pid.Load()))
	return nil
}

// Stop stops the tenant's vTPM and ends its supervision. swtpm saves its
// state on SIGTERM; a process that has not exited after stopTimeout is
// killed.
func (m *Manager) Stop(tenant string) error {
	if err := validateTenant(tenant); err != nil {
		return err
	}
	m.mu.Lock()
	inst, ok := m.instances[tenant]
	if ok {
		delete(m.instances, tenant)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotRunning
	}

	close(inst.stop)
	if err := inst.signal(syscall.SIGTERM); err != nil {
		return &StopError{Tenant: tenant, Err: err}
	}

	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()
	select {
	case <-inst.stopped:
	case <-timer.C:
		if err := inst.signal(syscall.SIGKILL); err != nil {
			return &StopError{Tenant: tenant, Err: err}
		}
		<-inst.stopped
	}
	m.logger.Info("vTPM stopped", slog.String("tenant", tenant))
	return nil
}

// Status reports the tenant's vTPM. A tenant with no vTPM reports
// Running false.
func (m *Manager) Status(tenant string) Status {
	m.mu.Lock()
	inst, ok := m.instances[tenant]
	m.mu.Unlock()
	if !ok {
		return Status{Tenant: tenant}
	}
	return Status{
		Tenant:   tenant,
		Running:  inst.running.Load(),
		PID:      int(inst.pid.Load()),
		Socket:   inst.socket,
		Restarts: inst.restarts.Load(),
	}
}

// Transport returns a connection to the tenant's vTPM command channel. It
// follows the vTPM across restarts: after the process is replaced, the next
// command reconnects. The caller closes it.
func (m *Manager) Transport(tenant string) (transport.TPMCloser, error) {
	if m.closed.Load() {
		return nil, ErrManagerClosed
	}
	m.mu.Lock()
	inst, ok := m.instances[tenant]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotRunning
	}
	socket := inst.socket
	return &socketTransport{dial: func() (net.Conn, error) {
		return net.Dial("unix", socket)
	}}, nil
}

// Close stops every vTPM. The Manager cannot be used afterwards.
func (m *Manager) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	m.mu.Lock()
	tenants := make([]string, 0, len(m.instances))
	for tenant := range m.instances {
		tenants = append(tenants, tenant)
	}
	m.mu.Unlock()

	var errs []error
	for _, tenant := range tenants {
		if err := m.Stop(tenant); err != nil && !errors.Is(err, ErrNotRunning) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// process is one run of a swtpm process. done is closed when it exits, after
// err holds its exit status, so any number of waiters can observe the exit.
type process struct {
	done chan struct{}
	err  error
}

// spawn starts one swtpm process for inst. It does not wait for the
// process's command socket to accept connections and does not mark inst
// running: the swtpm binary takes some time after the process starts to
// create and bind the socket, so a caller that needs inst.running (and so
// Status and Transport) to mean "ready for a command", not just "the
// process exists", must call awaitReady on the result and set inst.running
// itself once that succeeds -- as Start and supervise's restart both do.
func (m *Manager) spawn(inst *instance) (*process, error) {
	key, err := m.keys.StateKey(inst.tenant)
	if err != nil {
		return nil, &StateKeyError{Tenant: inst.tenant, Err: err}
	}
	if len(key) != StateKeySize {
		return nil, &StateKeySizeError{Tenant: inst.tenant, Size: len(key)}
	}

	// A stale socket from a process that died without cleaning up would make
	// swtpm fail to bind.
	if err := os.Remove(inst.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &StartError{Tenant: inst.tenant, Err: err}
	}

	keyRead, keyWrite, err := os.Pipe()
	if err != nil {
		return nil, &StartError{Tenant: inst.tenant, Err: err}
	}

	// #nosec G204 -- m.cfg.Binary is resolved and verified once, by
	// resolveBinary in NewManager, to a regular, executable file; this is
	// not a re-search of a tainted PATH value at every Start.
	cmd := exec.Command(m.cfg.Binary, "socket", "--tpm2",
		"--tpmstate", "dir="+inst.stateDir+",mode=0600",
		"--server", "type=unixio,path="+inst.socket+",mode=0600",
		"--key", "fd=3,mode=aes-256-cbc,format=binary",
		"--flags", "not-need-init,startup-clear",
		"--log", "level=0")
	cmd.ExtraFiles = []*os.File{keyRead}

	if err := cmd.Start(); err != nil {
		return nil, &StartError{Tenant: inst.tenant, Err: errors.Join(err, keyRead.Close(), keyWrite.Close())}
	}
	// The child holds its own copy of the read end; the key is written and
	// the write end closed so swtpm reads exactly the key and then EOF.
	_, writeErr := keyWrite.Write(key)
	if err := errors.Join(writeErr, keyWrite.Close(), keyRead.Close()); err != nil {
		return nil, &StartError{Tenant: inst.tenant, Err: errors.Join(err, cmd.Process.Kill(), waitIgnoringKill(cmd))}
	}

	inst.procMu.Lock()
	inst.proc = cmd.Process
	inst.procMu.Unlock()
	inst.pid.Store(int64(cmd.Process.Pid))

	proc := &process{done: make(chan struct{})}
	go func() {
		proc.err = cmd.Wait()
		inst.running.Store(false)
		close(proc.done)
	}()
	return proc, nil
}

// awaitReady waits until inst's vTPM answers a command (see probeReady), the
// process exits, the context ends, or readyTimeout passes.
func (m *Manager) awaitReady(ctx context.Context, inst *instance, proc *process) error {
	deadline := time.NewTimer(readyTimeout)
	defer deadline.Stop()
	poll := time.NewTicker(readyPoll)
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			return &StartError{Tenant: inst.tenant, Err: ctx.Err()}
		case <-proc.done:
			return &StartError{Tenant: inst.tenant, Err: errors.Join(ErrNotRunning, proc.err)}
		case <-deadline.C:
			return &StartError{Tenant: inst.tenant, Err: context.DeadlineExceeded}
		case <-poll.C:
			if probeReady(inst.socket) == nil {
				return nil
			}
		}
	}
}

// readyProbe is TPM2_GetRandom for one byte: the cheapest command a started
// TPM answers.
var readyProbe = []byte{
	0x80, 0x01, // TPM_ST_NO_SESSIONS
	0x00, 0x00, 0x00, 0x0c, // commandSize
	0x00, 0x00, 0x01, 0x7b, // TPM_CC_GetRandom
	0x00, 0x01, // bytesRequested
}

// probeReady reports whether the vTPM at socket answers a command. swtpm
// binds its socket before it decrypts and loads its state, so a successful
// connect alone does not mean the state loaded: under load, a vTPM started
// over state encrypted under another key accepted the connect and only then
// exited. Any response, success or TPM error code, is answered by a TPM whose
// state loaded.
func probeReady(socket string) error {
	conn, err := net.DialTimeout("unix", socket, readyProbeTimeout)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(readyProbeTimeout)); err != nil {
		return errors.Join(err, conn.Close())
	}
	if _, err := conn.Write(readyProbe); err != nil {
		return errors.Join(err, conn.Close())
	}
	if _, err := readResponse(conn); err != nil {
		return errors.Join(err, conn.Close())
	}
	return conn.Close()
}

// kill terminates a process that failed to become ready and waits for it.
func (m *Manager) kill(inst *instance, proc *process) error {
	if err := inst.signal(syscall.SIGKILL); err != nil {
		return err
	}
	<-proc.done
	return nil
}

// supervise waits for inst's process to exit and restarts it with backoff
// until Stop closes inst.stop. A restart is not visible as Running until the
// replacement's command socket is ready, exactly as Start requires for the
// first process.
func (m *Manager) supervise(inst *instance, proc *process) {
	defer close(inst.stopped)
	backoff := minBackoff
	for {
		select {
		case <-inst.stop:
			if proc != nil {
				<-proc.done
			}
			return
		case <-exitOf(proc):
			m.logger.Warn("vTPM exited; restarting",
				slog.String("tenant", inst.tenant), slog.Any("error", exitErr(proc)), slog.Duration("backoff", backoff))
		}

		timer := time.NewTimer(backoff)
		select {
		case <-inst.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, maxBackoff)

		next, err := m.spawn(inst)
		if err != nil {
			// No process is running; the next loop iteration waits out the
			// backoff (exitOf(nil) is already closed) and tries again.
			m.logger.Error("vTPM restart failed", slog.String("tenant", inst.tenant), slog.Any("error", err))
			proc = nil
			continue
		}

		// A client must never observe this restart as Running before the new
		// process's command socket actually accepts connections: Status and
		// Transport are both keyed off inst.running, and a client that acted
		// on "running" the instant the process merely started would dial a
		// socket swtpm has not created yet. readyCtx ends awaitReady early if
		// Stop is called while this wait is outstanding, so stopping never
		// waits out the full readyTimeout.
		readyCtx, cancelReady := stopContext(inst.stop)
		readyErr := m.awaitReady(readyCtx, inst, next)
		cancelReady()
		if readyErr != nil {
			m.logger.Error("vTPM restart failed to become ready",
				slog.String("tenant", inst.tenant), slog.Any("error", readyErr))
			if killErr := m.kill(inst, next); killErr != nil {
				m.logger.Error("vTPM restart cleanup failed", slog.String("tenant", inst.tenant), slog.Any("error", killErr))
			}
			select {
			case <-inst.stop:
				return
			default:
			}
			proc = nil
			continue
		}

		inst.running.Store(true)
		inst.restarts.Add(1)
		backoff = minBackoff
		proc = next
	}
}

// stopContext returns a context canceled as soon as stop closes, so a
// restart awaiting its new process's readiness does not outlive Stop. The
// returned cancel must be called once the caller no longer needs the
// context, win or lose, to release the watcher goroutine.
func stopContext(stop <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// closedDone is an already-closed channel: the exit of "no process".
var closedDone = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// exitOf returns the channel that closes when proc exits; for no process it
// is already closed.
func exitOf(proc *process) <-chan struct{} {
	if proc == nil {
		return closedDone
	}
	return proc.done
}

// exitErr returns proc's exit status, or ErrNotRunning when there was no
// process.
func exitErr(proc *process) error {
	if proc == nil {
		return ErrNotRunning
	}
	return proc.err
}

// signal delivers sig to inst's current process. A process that has already
// exited is not an error.
func (i *instance) signal(sig os.Signal) error {
	i.procMu.Lock()
	proc := i.proc
	i.procMu.Unlock()
	if proc == nil {
		return nil
	}
	if err := proc.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// waitIgnoringKill reaps a process the caller just killed; the "signal:
// killed" exit status is the expected outcome, not an error.
func waitIgnoringKill(cmd *exec.Cmd) error {
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	return err
}

// validateTenant refuses a tenant ID that cannot safely name a directory
// and socket.
func validateTenant(tenant string) error {
	if tenant == "" || tenant == "." || tenant == ".." || strings.ContainsAny(tenant, `/\`) {
		return ErrInvalidTenant
	}
	return nil
}
