// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// sealedWindowTestConfig builds the minimal qrdb DaemonConfig needed to
// construct a real, node-owned barrier over a Pebble data plane: exactly the
// shape buildXKMSQRDBConfig produces for a node-seal-enabled deployment, kept
// separate here so the fixture does not depend on a *Server.
func sealedWindowTestConfig(dataDir string) *qrdbsdk.DaemonConfig {
	return &qrdbsdk.DaemonConfig{
		Raft: qrdbsdk.DaemonRaftConfig{DataDir: dataDir},
		Databases: []qrdbsdk.DaemonDatabaseConfig{
			{Name: "default", Engine: "mvcc", Backend: "pebble"},
		},
		Seal: qrdbsdk.DaemonSealConfig{Enabled: true, Strategy: "passphrase"},
	}
}

// newSealedTestNode constructs a real qrdb standalone node whose barrier
// already exists on disk (initialized with rightPassphrase by an earlier
// construction) and attempts auto-unseal with attemptPassphrase. Supplying
// the wrong passphrase reproduces the documented failure mode this feature
// handles: auto-unseal does not succeed, and the node is returned sealed
// rather than as a constructor error.
func newSealedTestNode(t *testing.T, dataDir, rightPassphrase, attemptPassphrase string) *qrdbnode.Node {
	t.Helper()
	ctx := context.Background()

	// First boot: initializes the barrier on disk with the right passphrase.
	bootstrap, err := qrdbnode.NewStandaloneNode(ctx, sealedWindowTestConfig(dataDir), nil,
		qrdbnode.WithLogger(slog.Default()),
		qrdbnode.WithSealPassphrase([]byte(rightPassphrase)))
	require.NoError(t, err)
	require.False(t, bootstrap.IsSealed(), "fixture setup: first boot must auto-unseal")
	require.NoError(t, bootstrap.Close())

	// Second boot against the same data dir: the attempt passphrase decides
	// whether this node comes up sealed or unsealed.
	node, err := qrdbnode.NewStandaloneNode(ctx, sealedWindowTestConfig(dataDir), nil,
		qrdbnode.WithLogger(slog.Default()),
		qrdbnode.WithSealPassphrase([]byte(attemptPassphrase)))
	require.NoError(t, err)
	return node
}

// testSealedWindowServer builds a *Server with just enough state for
// serveSealedWindow: config, logger, and an independently cancelable ctx.
func testSealedWindowServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Server{
		config: cfg,
		logger: slog.Default(),
		ctx:    ctx,
		cancel: cancel,
	}
}

// TestServeSealedWindow_UnsealedNodeIsNoOp verifies the ESTABLISHED FACT this
// feature depends on directly against the SDK: a node that auto-unsealed at
// construction is unaffected by serveSealedWindow — no listener is started
// and the call returns immediately.
func TestServeSealedWindow_UnsealedNodeIsNoOp(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	defer func() { _ = node.Close() }()
	require.False(t, node.IsSealed(), "fixture: node must be unsealed for this test")

	cfg := createMinimalConfig(t)
	s := testSealedWindowServer(t, cfg)

	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("serveSealedWindow must return immediately for an unsealed node")
	}
	assert.False(t, node.IsSealed(), "an already-unsealed node must be unaffected")
}

// TestServeSealedWindow_SealedNodeProceedsAfterUnseal verifies the core
// behavior change: a sealed node opens the sealed window and, once an
// operator drives the barrier unsealed (here, directly — "any other path"
// per the SDK's own documented contract, exercising the same
// node.Unseal/completeBoot tail the REST listener would drive), the call
// completes the node's boot instead of failing fatally.
func TestServeSealedWindow_SealedNodeProceedsAfterUnseal(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "wrong-passphrase")
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed(), "fixture: node must be sealed for this test")
	require.Nil(t, node.Client(), "a sealed node must not expose a data-plane client")

	cfg := createMinimalConfig(t) // Server.Host is loopback; no allow-remote needed
	s := testSealedWindowServer(t, cfg)

	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()

	// Unseal "any other path" without waiting for the goroutine above to
	// start first: directly against the barrier service the listener itself
	// would serve (service.BarrierServicer.BarrierUnseal), NOT node.Unseal —
	// that call also completes the boot, and only serveSealedWindow is meant
	// to make it, exactly once, after the window observes the unseal. No
	// synchronization is needed here: go-qrdb's ServeSealedWindow checks
	// IsSealed() before its first wait and again on every poll tick
	// (sealedWindowPollInterval), so this unseal is observed whether it lands
	// before that first check or between polls.
	svcNode := node.Services()
	require.NotNil(t, svcNode, "a sealed node must still expose the seal-layer services")
	require.NotNil(t, svcNode.Barrier)
	require.NoError(t, svcNode.Barrier.BarrierUnseal(context.Background(), []byte("correct-horse-battery-staple")))

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("serveSealedWindow did not return after the barrier was unsealed")
	}

	assert.False(t, node.IsSealed())
	assert.NotNil(t, node.Client(), "boot must complete once the sealed window closes")
}

// TestServeSealedWindow_RefusesNonLoopbackByDefault verifies the default-safe
// bind policy: a sealed node with a non-loopback Server.Host is refused
// without ever starting a listener, unless the operator opts in via
// barrier.sealed_window_allow_remote.
func TestServeSealedWindow_RefusesNonLoopbackByDefault(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "wrong-passphrase")
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed())

	cfg := createMinimalConfig(t)
	cfg.Server.Host = "0.0.0.0"

	s := testSealedWindowServer(t, cfg)

	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()

	select {
	case err := <-done:
		var bindErr *SealedWindowBindError
		require.Error(t, err)
		require.True(t, errors.As(err, &bindErr), "expected *SealedWindowBindError, got %T: %v", err, err)
		assert.Equal(t, "0.0.0.0", bindErr.Host)
	case <-time.After(2 * time.Second):
		t.Fatal("a non-loopback bind must be refused immediately, not left to time out")
	}
	assert.True(t, node.IsSealed(), "a refused bind must leave the node sealed")

	// The escape hatch: explicit operator opt-in is honored (the call now
	// proceeds to open the window instead of refusing).
	cfg.Barrier.SealedWindowAllowRemote = true
	s2 := testSealedWindowServer(t, cfg)
	proceeded := make(chan error, 1)
	go func() { proceeded <- s2.serveSealedWindow(node) }()
	// Cancel immediately: this test only asserts the bind check was bypassed
	// (no *SealedWindowBindError), not that unseal completes, and
	// go-qrdb's ServeSealedWindow calls srv.Start() unconditionally before
	// ever checking ctx, so an already-canceled context still exercises the
	// same bind path and is observed on its first select.
	s2.cancel()
	select {
	case err := <-proceeded:
		var bindErr *SealedWindowBindError
		require.Error(t, err)
		assert.False(t, errors.As(err, &bindErr), "allow-remote must bypass the bind refusal")
	case <-time.After(5 * time.Second):
		t.Fatal("canceled sealed window must return promptly")
	}
}

// TestServeSealedWindow_CancellationClosesCleanly verifies that canceling the
// server context (the same path SIGTERM/SIGINT drive via Server.Shutdown)
// closes the sealed-window listener and returns promptly instead of hanging,
// leaving the node sealed rather than partially booted.
func TestServeSealedWindow_CancellationClosesCleanly(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "wrong-passphrase")
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed())

	cfg := createMinimalConfig(t)
	s := testSealedWindowServer(t, cfg)

	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()

	// Cancel immediately: go-qrdb's ServeSealedWindow calls srv.Start()
	// unconditionally before ever checking ctx, so an already-canceled
	// context still starts the listener and is observed on its first select.
	s.cancel()

	select {
	case err := <-done:
		var canceled *qrdbsdk.SealedWindowCanceledError
		require.Error(t, err)
		assert.True(t, errors.As(err, &canceled), "expected *qrdbsdk.SealedWindowCanceledError, got %T: %v", err, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation must close the sealed-window listener promptly")
	}
	assert.True(t, node.IsSealed(), "cancellation must not leave a half-completed boot")
}

// TestIsLoopbackHost documents the bind-address policy isolated from any
// node/listener machinery.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.5", false},
		{"example.com", false},
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"LOCALHOST", true},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isLoopbackHost(c.host), "host=%q", c.host)
	}
}

// TestBarrierConfig_SealedWindowTimeoutDuration exercises the config-level
// parsing the sealed window relies on for its wait bound.
func TestBarrierConfig_SealedWindowTimeoutDuration(t *testing.T) {
	t.Run("empty defaults", func(t *testing.T) {
		d, err := (config.BarrierConfig{}).SealedWindowTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, config.DefaultSealedWindowTimeout, d)
	})
	t.Run("zero disables", func(t *testing.T) {
		d, err := (config.BarrierConfig{SealedWindowTimeout: "0"}).SealedWindowTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), d)
	})
	t.Run("none disables", func(t *testing.T) {
		d, err := (config.BarrierConfig{SealedWindowTimeout: "none"}).SealedWindowTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), d)
	})
	t.Run("parses a duration", func(t *testing.T) {
		d, err := (config.BarrierConfig{SealedWindowTimeout: "10m"}).SealedWindowTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, 10*time.Minute, d)
	})
	t.Run("rejects garbage", func(t *testing.T) {
		_, err := (config.BarrierConfig{SealedWindowTimeout: "not-a-duration"}).SealedWindowTimeoutDuration()
		assert.Error(t, err)
	})
	t.Run("rejects negative", func(t *testing.T) {
		_, err := (config.BarrierConfig{SealedWindowTimeout: "-1m"}).SealedWindowTimeoutDuration()
		assert.Error(t, err)
	})
}

// TestServeSealedWindow_NetworkServingUsesUnifiedTLS reproduces the
// passphrase-barrier deployment with network transports: the node's pending
// boot serves REST, qrdb's transports are TLS-only, and the sealed-window
// listener must receive the same unified TLS material the full server
// serves. Without it the window fails to start ("no TLS configured") and
// xkmsd cannot boot. The test proves the window serves TLS with that
// certificate and completes the boot once the barrier is unsealed.
func TestServeSealedWindow_NetworkServingUsesUnifiedTLS(t *testing.T) {
	dataDir := t.TempDir()
	port := freeLoopbackPort(t)
	qcfg := sealedWindowTestConfig(dataDir)
	qcfg.Server.Host = "127.0.0.1"
	qcfg.Server.AdminPort = port
	qcfg.Protocols.REST = true

	ctx := context.Background()
	bootstrap, err := qrdbnode.NewStandaloneNode(ctx, sealedWindowTestConfig(dataDir), nil,
		qrdbnode.WithLogger(slog.Default()), qrdbnode.WithSealPassphrase([]byte("right")))
	require.NoError(t, err)
	require.NoError(t, bootstrap.Close())
	cfg := createMinimalConfig(t)
	cfg.Datastore.Path = t.TempDir()
	s := testSealedWindowServer(t, cfg)
	tlsCfg, err := s.buildUnifiedTLSConfig()
	require.NoError(t, err)
	s.sealedWindowTLS = tlsCfg

	// The node gets the TLS material at construction, as
	// initEmbeddedQRDBNode gives it, for the boot after the window.
	node, err := qrdbnode.NewStandaloneNode(ctx, qcfg, []qrdbsdk.ServerOption{qrdbsdk.WithServerTLS(tlsCfg)},
		qrdbnode.WithLogger(slog.Default()), qrdbnode.WithSealPassphrase([]byte("wrong")))
	require.NoError(t, err)
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed())
	served, err := s.ensureBootstrapCert()
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()

	// The window answers TLS with the unified certificate.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var conn *tls.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // insecure-ok: the test inspects the served certificate itself
		if err == nil {
			break
		}
		select {
		case winErr := <-done:
			t.Fatalf("the sealed window stopped before serving: %v", winErr)
		default:
		}
		require.True(t, time.Now().Before(deadline), "the sealed window never served TLS: %v", err)
		timer := time.NewTimer(50 * time.Millisecond)
		<-timer.C
	}
	peer := conn.ConnectionState().PeerCertificates
	require.NoError(t, conn.Close())
	require.NotEmpty(t, peer)
	assert.Equal(t, served.Certificate[0], peer[0].Raw, "the window serves the unified certificate")

	require.NoError(t, node.Services().Barrier.BarrierUnseal(ctx, []byte("right")))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("serveSealedWindow did not return after the barrier was unsealed")
	}
	assert.False(t, node.IsSealed())
}

// freeLoopbackPort returns a TCP port the kernel had free on 127.0.0.1.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}
