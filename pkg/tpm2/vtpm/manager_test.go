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

package vtpm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the real swtpm binary, a declared test dependency of
// `make test` (installed on developer hosts and in the CI and devcontainer
// images). The in-process TPM simulator cannot stand in here: it is a
// process-wide singleton, and a vTPM is by definition a second TPM.

// fixedKeys is a StateKeyProvider with one key per tenant.
type fixedKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
	err  error
}

func (f *fixedKeys) StateKey(tenant string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.keys[tenant], nil
}

func (f *fixedKeys) set(tenant string, key []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[tenant] = key
}

func newTestManager(t *testing.T, keys *fixedKeys) *Manager {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes, which t.TempDir() under a
	// long test name can exceed, so the run directory is kept short.
	runDir, err := os.MkdirTemp("", "vtpm")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(runDir)) })

	m, err := NewManager(Config{StateDir: t.TempDir(), RunDir: runDir}, keys)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, StateKeySize) }

// getRandom proves the vTPM answers a real TPM command.
func getRandom(t *testing.T, tpm transport.TPM) {
	t.Helper()
	rsp, err := tpm2.GetRandom{BytesRequested: 16}.Execute(tpm)
	require.NoError(t, err)
	assert.Len(t, rsp.RandomBytes.Buffer, 16)
}

// testNVIndex is an owner-range NV index the tests use to prove state
// persists across restarts.
const testNVIndex = tpm2.TPMHandle(0x01500042)

func defineNV(t *testing.T, tpm transport.TPM, data []byte) {
	t.Helper()
	pub := tpm2.TPMSNVPublic{
		NVIndex:    testNVIndex,
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true},
		DataSize:   uint16(len(data)),
	}
	_, err := tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(pub)}.Execute(tpm)
	require.NoError(t, err)
	pub.Attributes.Written = false
	name, err := tpm2.NVName(&pub)
	require.NoError(t, err)
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: testNVIndex, Name: *name},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}.Execute(tpm)
	require.NoError(t, err)
}

func readNV(t *testing.T, tpm transport.TPM, size uint16) []byte {
	t.Helper()
	pubRsp, err := tpm2.NVReadPublic{NVIndex: testNVIndex}.Execute(tpm)
	require.NoError(t, err)
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: testNVIndex, Name: pubRsp.NVName},
		Size:       size,
	}.Execute(tpm)
	require.NoError(t, err)
	return rsp.Data.Buffer
}

// TestManager_StartServesAVTPMAndStopEndsIt proves a started vTPM answers TPM
// commands and a stopped one is gone.
func TestManager_StartServesAVTPMAndStopEndsIt(t *testing.T) {
	m := newTestManager(t, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	ctx := context.Background()

	require.NoError(t, m.Start(ctx, "acme"))
	require.NoError(t, m.Start(ctx, "acme"), "starting a running vTPM is a no-op")
	status := m.Status("acme")
	assert.True(t, status.Running)
	assert.NotZero(t, status.PID)

	tpm, err := m.Transport("acme")
	require.NoError(t, err)
	getRandom(t, tpm)
	require.NoError(t, tpm.Close())

	require.NoError(t, m.Stop("acme"))
	assert.False(t, m.Status("acme").Running)
	_, err = m.Transport("acme")
	assert.ErrorIs(t, err, ErrNotRunning)
	assert.ErrorIs(t, m.Stop("acme"), ErrNotRunning)
}

// TestManager_StatePersistsAcrossRestartUnderItsKey proves the vTPM keeps
// its state across a stop and start, and that state written under one key
// cannot be opened under another: the key really encrypts it.
func TestManager_StatePersistsAcrossRestartUnderItsKey(t *testing.T) {
	keys := &fixedKeys{keys: map[string][]byte{"acme": key(1)}}
	m := newTestManager(t, keys)
	ctx := context.Background()

	require.NoError(t, m.Start(ctx, "acme"))
	tpm, err := m.Transport("acme")
	require.NoError(t, err)
	defineNV(t, tpm, []byte("tenant-state"))
	require.NoError(t, tpm.Close())
	require.NoError(t, m.Stop("acme"))

	require.NoError(t, m.Start(ctx, "acme"))
	tpm, err = m.Transport("acme")
	require.NoError(t, err)
	assert.Equal(t, []byte("tenant-state"), readNV(t, tpm, 12))
	require.NoError(t, tpm.Close())
	require.NoError(t, m.Stop("acme"))

	keys.set("acme", key(2))
	err = m.Start(ctx, "acme")
	var startErr *StartError
	require.True(t, errors.As(err, &startErr), "a vTPM must not start over state encrypted under another key, got %v", err)
}

// listenOnce serves one connection on a fresh unix socket with serve and
// returns the socket path and a channel carrying serve's result.
func listenOnce(t *testing.T, serve func(conn net.Conn) error) (string, <-chan error) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "vtpm.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ln.Close()) })
	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		served <- errors.Join(serve(conn), conn.Close())
	}()
	return socket, served
}

func TestProbeReady_AnsweredCommandIsReady(t *testing.T) {
	cmd := make([]byte, len(readyProbe))
	socket, served := listenOnce(t, func(conn net.Conn) error {
		if _, err := io.ReadFull(conn, cmd); err != nil {
			return err
		}
		// A TPM error code still proves the TPM is serving commands.
		_, err := conn.Write(response(0x100))
		return err
	})

	require.NoError(t, probeReady(socket))
	require.NoError(t, <-served)
	assert.Equal(t, readyProbe, cmd)
}

// A vTPM that accepts the connect but exits before answering -- swtpm over
// state encrypted under another key -- must not count as ready.
func TestProbeReady_AcceptedButUnansweredIsNotReady(t *testing.T) {
	socket, served := listenOnce(t, func(net.Conn) error { return nil })

	assert.Error(t, probeReady(socket))
	require.NoError(t, <-served)
}

func TestProbeReady_NoSocketIsNotReady(t *testing.T) {
	assert.Error(t, probeReady(filepath.Join(t.TempDir(), "absent.sock")))
}

// TestManager_RestartsACrashedVTPMAndTheTransportFollows proves the
// supervisor replaces a vTPM that dies, and a client's Transport reconnects
// to the replacement without being reopened.
func TestManager_RestartsACrashedVTPMAndTheTransportFollows(t *testing.T) {
	m := newTestManager(t, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	require.NoError(t, m.Start(context.Background(), "acme"))

	tpm, err := m.Transport("acme")
	require.NoError(t, err)
	defer func() { require.NoError(t, tpm.Close()) }()
	getRandom(t, tpm)

	first := m.Status("acme").PID
	require.NoError(t, syscall.Kill(first, syscall.SIGKILL))

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	for restarted := false; !restarted; {
		select {
		case <-deadline.C:
			t.Fatal("the supervisor did not restart the vTPM")
		case <-poll.C:
			s := m.Status("acme")
			restarted = s.Restarts == 1 && s.Running && s.PID != first
		}
	}

	// The first command may land on the dead connection; the transport then
	// reports the loss and reconnects for the next one.
	if _, err := (tpm2.GetRandom{BytesRequested: 16}).Execute(tpm); err != nil {
		assert.ErrorIs(t, err, ErrConnectionLost)
	}
	getRandom(t, tpm)
}

// TestManager_TenantsAreSeparateTPMs proves two tenants get two TPMs: state
// one writes is not visible in the other.
func TestManager_TenantsAreSeparateTPMs(t *testing.T) {
	m := newTestManager(t, &fixedKeys{keys: map[string][]byte{"acme": key(1), "globex": key(3)}})
	ctx := context.Background()
	require.NoError(t, m.Start(ctx, "acme"))
	require.NoError(t, m.Start(ctx, "globex"))

	acme, err := m.Transport("acme")
	require.NoError(t, err)
	defer func() { require.NoError(t, acme.Close()) }()
	defineNV(t, acme, []byte("acme"))

	globex, err := m.Transport("globex")
	require.NoError(t, err)
	defer func() { require.NoError(t, globex.Close()) }()
	_, err = tpm2.NVReadPublic{NVIndex: testNVIndex}.Execute(globex)
	assert.Error(t, err, "globex's vTPM must not see acme's NV index")
}

// TestManager_RefusesBadInputs covers the construction and argument errors.
func TestManager_RefusesBadInputs(t *testing.T) {
	keys := &fixedKeys{keys: map[string][]byte{}}
	_, err := NewManager(Config{RunDir: "/run"}, keys)
	assert.ErrorIs(t, err, ErrStateDirRequired)
	_, err = NewManager(Config{StateDir: "/var"}, keys)
	assert.ErrorIs(t, err, ErrRunDirRequired)
	_, err = NewManager(Config{StateDir: "/var", RunDir: "/run"}, nil)
	assert.ErrorIs(t, err, ErrKeyProviderRequired)

	m := newTestManager(t, keys)
	ctx := context.Background()
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`} {
		assert.ErrorIs(t, m.Start(ctx, bad), ErrInvalidTenant, "tenant %q", bad)
	}

	keys.set("short", []byte("too short"))
	var sizeErr *StateKeySizeError
	require.True(t, errors.As(m.Start(ctx, "short"), &sizeErr))

	keys.err = errors.New("sealed key unavailable")
	var keyErr *StateKeyError
	require.True(t, errors.As(m.Start(ctx, "acme"), &keyErr))

	require.NoError(t, m.Close())
	assert.ErrorIs(t, m.Start(ctx, "acme"), ErrManagerClosed)
	_, err = m.Transport("acme")
	assert.ErrorIs(t, err, ErrManagerClosed)
}

// TestManager_MissingBinaryIsAConstructionError proves a node without swtpm
// reports it at NewManager rather than hanging, or launching whatever a
// later PATH lookup resolves a bare name to, at the first Start.
func TestManager_MissingBinaryIsAConstructionError(t *testing.T) {
	runDir, err := os.MkdirTemp("", "vtpm")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(runDir)) })
	_, err = NewManager(Config{
		Binary:   filepath.Join(t.TempDir(), "no-swtpm"),
		StateDir: t.TempDir(),
		RunDir:   runDir,
	}, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	var binErr *BinaryError
	require.True(t, errors.As(err, &binErr))
}

// TestManager_BareBinaryNameNotOnPATHIsAConstructionError proves the same
// fail-closed behavior for a bare command name exec.LookPath cannot find,
// not only for an absolute path that does not exist.
func TestManager_BareBinaryNameNotOnPATHIsAConstructionError(t *testing.T) {
	runDir, err := os.MkdirTemp("", "vtpm")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(runDir)) })
	_, err = NewManager(Config{
		Binary:   "no-such-vtpm-binary-xkms-test",
		StateDir: t.TempDir(),
		RunDir:   runDir,
	}, &fixedKeys{keys: map[string][]byte{"acme": key(1)}})
	var binErr *BinaryError
	require.True(t, errors.As(err, &binErr))
}
