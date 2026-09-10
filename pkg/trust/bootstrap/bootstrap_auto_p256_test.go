// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package bootstrap

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/stretchr/testify/require"
)

// TestFetch_AutoP256OnlyBootstrapsOverNoise is the documented FIPS recipe,
// `xkmsctl bootstrap auto --p256-key`, at the library level: a client whose
// only Noise material is the server's P-256 point, under ModeAuto, completes
// the approved handshake. Before the Auto walk moved into this package the
// P-256 key never reached the wire under ModeAuto: go-truststrap's dispatcher
// built the Noise arm from its facade config, which cannot carry it, and the
// fetch died with ErrModeNotConfigured.
func TestFetch_AutoP256OnlyBootstrapsOverNoise(t *testing.T) {
	l := startListener(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := Fetch(ctx, Config{
		Mode:             ModeAuto,
		Noise:            &NoiseConfig{ServerAddr: l.addr, ServerP256StaticKey: l.p256Hex},
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
	})
	require.NoError(t, err)
	requireBundle(t, l, got)
}

// TestFetch_AutoP256OnlyUnreachableIsAnAttempt pins the error shape the
// reviewer of #487 found misleading: a P-256-only configuration that cannot
// connect is a tried-and-failed Noise arm inside the aggregate, never "mode
// not configured" from a config that plainly configures one.
func TestFetch_AutoP256OnlyUnreachableIsAnAttempt(t *testing.T) {
	key, err := GenerateP256StaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	_, err = Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		Noise:            &NoiseConfig{ServerAddr: "127.0.0.1:1", ServerP256StaticKey: hex.EncodeToString(key.PublicBytes())},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrModeNotConfigured), "a configured arm that fails is an attempt, not an unconfigured mode: %v", err)
	require.ErrorIs(t, err, ErrFetch)
	require.ErrorIs(t, err, truststrap.ErrAllMethodsFailed)
	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, ModeAuto, fe.Mode)
	var agg *truststrap.AggregateError
	require.ErrorAs(t, err, &agg)
	require.Len(t, agg.Attempts, 1)
	require.Equal(t, truststrap.MethodNoise, agg.Attempts[0].Method)
	require.NotNil(t, agg.Attempts[0].Err)
}

// TestFetch_AutoWalksTheDefaultOrder pins that moving the walk into this
// package kept go-truststrap's order: every armed method is tried, in
// DefaultMethodOrder, and each failure is one attempt in the aggregate.
func TestFetch_AutoWalksTheDefaultOrder(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        "http://127.0.0.1:1",
		DANE:             &DANEConfig{Hostname: "kms.example.com"},
		Noise:            &NoiseConfig{ServerAddr: "127.0.0.1:1", ServerP256StaticKey: "04" + strings.Repeat("00", 64)},
		SPKI:             &SPKIConfig{Pin: strings.Repeat("00", 32)},
		Direct:           &DirectConfig{},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.Error(t, err)
	var agg *truststrap.AggregateError
	require.ErrorAs(t, err, &agg)
	got := make([]truststrap.Method, 0, len(agg.Attempts))
	for _, a := range agg.Attempts {
		got = append(got, a.Method)
	}
	require.Equal(t, truststrap.DefaultMethodOrder, got)
}

// TestFetch_AutoP256NoiseFailureFallsThroughToDirect covers the walk
// continuing past a failed P-256 Noise arm to a later arm that succeeds.
func TestFetch_AutoP256NoiseFailureFallsThroughToDirect(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        srv.URL,
		Noise:            &NoiseConfig{ServerAddr: "127.0.0.1:1", ServerP256StaticKey: "04" + strings.Repeat("00", 64)},
		Direct:           &DirectConfig{},
		PerMethodTimeout: 500 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.NoError(t, err)
	require.Len(t, got.Certificates, 2)
}

// TestFetch_AutoCancelledContextStopsTheWalk pins that a context already
// cancelled before an arm runs ends the walk with that error rather than
// spending a per-method timeout on each arm.
func TestFetch_AutoCancelledContextStopsTheWalk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Fetch(ctx, Config{
		Mode:             ModeAuto,
		ServerURL:        "http://127.0.0.1:1",
		Direct:           &DirectConfig{},
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
	})
	require.ErrorIs(t, err, ErrFetch)
	require.ErrorIs(t, err, context.Canceled)
}
