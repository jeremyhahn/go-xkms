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
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestNoiseStop_NilIsAuthoritative proves, against the pinned go-truststrap
// server rather than its description, the contract noiseStopDrained now rests
// on (go-truststrap#13, go-xkms#83):
//
//   - While a handshake worker is live, no Stop caller receives nil, however
//     many call concurrently and whatever deadline each brings, including one
//     already expired. Each gets ErrShutdownIncomplete: different callers may
//     observe different outcomes, but none an unbacked nil.
//   - Once the worker exits, Stop returns nil — and keeps returning nil under
//     an already-expired context. That is the row the previous decision got
//     wrong: it read the expired context over the nil and retained a key that
//     was safe to wipe.
//
// The worker is held by a client that completes the handshake and then sends
// nothing: the server-side worker is blocked reading the request frame under
// ReadTimeout, and nothing in Stop's teardown interrupts it, so the drain
// cannot complete until the client goes away. Run with -race -count=200 for
// the rate proof; the assertions leave no room for a lucky ordering.
func TestNoiseStop_NilIsAuthoritative(t *testing.T) {
	s := newSuiteTestServer(t, config.NoiseBootstrapConfig{})
	bundler := newTestBundler(t)

	keys, err := s.loadBootstrapKeys()
	require.NoError(t, err)
	defer keys.destroy()

	srv, err := bootstrap.NewNoiseServer(&bootstrap.NoiseServerConfig{
		ListenAddr:    "127.0.0.1:0",
		StaticKey:     bootstrap.NoiseServerStaticKey(keys.noise),
		P256StaticKey: keys.p256,
		CABundler:     bundler,
		// The held worker must outlive every deadline below.
		ReadTimeout: time.Minute,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	require.NoError(t, srv.Start())

	client, err := noiseboot.NewClient(&noiseboot.ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerP256StaticKey: keys.p256.PublicBytes(),
		Suite:               bootstrap.SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
	})
	require.NoError(t, err)

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	require.NoError(t, client.Connect(connectCtx), "the handshake that installs the held worker")

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	// Phase 1: the worker is live. Every concurrent caller, short deadline or
	// already expired, must be told the drain is incomplete.
	const callers = 8
	results := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stopCtx := expired
			if i%2 == 1 {
				var cancel context.CancelFunc
				stopCtx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
			}
			results[i] = srv.Stop(stopCtx)
		}(i)
	}
	wg.Wait()
	for i, stopErr := range results {
		require.ErrorIs(t, stopErr, noiseboot.ErrShutdownIncomplete,
			"caller %d: a worker is live, so no deadline may be answered with a drain", i)
		require.False(t, noiseStopDrained(stopErr),
			"caller %d: the decision would free pages the held worker is still reading", i)
	}

	// Phase 2: release the worker; the drain completes and nil is reported.
	require.NoError(t, client.Close())
	liveCtx, cancelLive := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelLive()
	stopErr := srv.Stop(liveCtx)
	require.NoError(t, stopErr, "with the worker gone the drain must complete inside a live deadline")
	require.True(t, noiseStopDrained(stopErr))

	// Phase 3: the drained server under an already-expired context. nil is
	// stable and authoritative; the caller's deadline says nothing about it.
	stopErr = srv.Stop(expired)
	require.NoError(t, stopErr, "a drained server must report the drain whatever the caller's deadline")
	require.True(t, noiseStopDrained(stopErr),
		"the decision must read this nil as the drain it is, not retain the key over an expired deadline")
}
