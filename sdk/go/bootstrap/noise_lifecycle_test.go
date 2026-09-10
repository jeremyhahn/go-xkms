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
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// TestSDKNoiseServerLifecycleSentinels drives NoiseServer through every
// outcome its Start and Stop report and matches each with errors.Is on the
// re-exported sentinel, importing nothing from go-truststrap: that is the
// contract an SDK consumer orchestrating the server needs, and the one that
// was missing (go-xkms#498). A re-export nobody matches against is exactly
// the half that goes missing without anything failing.
//
// The server carries only the approved P-256 suite, so the test runs the
// same in a FIPS build, where X25519 is unavailable. The suite does not
// matter to the lifecycle: a connection that never sends its first message
// holds a handshake worker in its read whichever suite would have run.
func TestSDKNoiseServerLifecycleSentinels(t *testing.T) {
	key, err := GenerateP256StaticKey()
	if err != nil {
		t.Fatalf("GenerateP256StaticKey: %v", err)
	}
	defer key.Destroy()

	// The worker precondition below must be deterministic: net.Dial returns
	// once the TCP handshake completes, which says nothing about whether
	// the server has accepted the connection and registered its worker. The
	// server logs "new connection" from the worker itself, after it has been
	// counted for the drain, so a handler that signals on that record is
	// the precondition a Stop under an expired deadline can be measured
	// against.
	accepted := newLogSignal("new connection")

	srv, err := NewNoiseServer(&NoiseServerConfig{
		ListenAddr:    "127.0.0.1:0",
		P256StaticKey: key,
		CABundler:     staticBundler{bundle: []byte("test-ca-bundle")},
		// The held worker must outlive every deadline below.
		ReadTimeout: time.Minute,
		Logger:      slog.New(accepted),
	})
	if err != nil {
		t.Fatalf("NewNoiseServer: %v", err)
	}

	// Stop before Start.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Stop(ctx); !errors.Is(err, ErrNoiseServerNotStarted) {
		t.Fatalf("Stop before Start = %v, want ErrNoiseServerNotStarted", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	// A NoiseServer is single-use.
	if err := srv.Start(); !errors.Is(err, ErrNoiseServerAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrNoiseServerAlreadyStarted", err)
	}

	// Hold a handshake worker: a connection that never sends its first
	// message keeps the worker in its read, so a Stop under an expired
	// deadline cannot report a drain.
	held, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = held.Close() }()
	select {
	case <-accepted.seen:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never registered a worker for the held connection")
	}

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if err := srv.Stop(expired); !errors.Is(err, ErrNoiseShutdownIncomplete) {
		t.Fatalf("Stop with a live worker under an expired deadline = %v, want ErrNoiseShutdownIncomplete", err)
	}

	// Release the worker; the drain completes and nil is reported.
	if err := held.Close(); err != nil {
		t.Fatalf("close held connection: %v", err)
	}
	live, cancelLive := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelLive()
	if err := srv.Stop(live); err != nil {
		t.Fatalf("Stop after the worker released = %v, want nil", err)
	}
}

// logSignal is a slog.Handler that closes seen the first time a record with
// the given message is handled. It is how the test observes a server-side
// event through the one surface the SDK config exposes for it, the Logger.
type logSignal struct {
	message string
	seen    chan struct{}
	once    sync.Once
}

func newLogSignal(message string) *logSignal {
	return &logSignal{message: message, seen: make(chan struct{})}
}

func (l *logSignal) Enabled(context.Context, slog.Level) bool { return true }

func (l *logSignal) Handle(_ context.Context, r slog.Record) error {
	if r.Message == l.message {
		l.once.Do(func() { close(l.seen) })
	}
	return nil
}

func (l *logSignal) WithAttrs([]slog.Attr) slog.Handler { return l }

func (l *logSignal) WithGroup(string) slog.Handler { return l }
