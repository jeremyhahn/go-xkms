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

package http01

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client-side http-01 challenge responder.
//
// RFC 8555 Section 8.3 puts the ACME client on the hook for serving the key
// authorization at /.well-known/acme-challenge/{token} for the duration of one
// order. Responder is that server, scoped to a single order rather than to the
// process, so a caller can run several orders at once and can learn that the
// bind failed at the point of failure instead of inferring it from a rejected
// authorization several round trips later.
//
// The bind is eager: NewResponder returns only after the listener is accepting
// connections, so a caller may notify the ACME server immediately on return
// without racing its validation request.

const (
	// DefaultShutdownTimeout bounds a graceful shutdown when the caller's
	// context carries no deadline of its own.
	DefaultShutdownTimeout = 15 * time.Second

	// DefaultReadTimeout is the per-request header and body read budget.
	DefaultReadTimeout = 5 * time.Second

	// DefaultWriteTimeout is the per-request response write budget.
	DefaultWriteTimeout = 10 * time.Second

	// DefaultIdleTimeout is how long a keep-alive connection may sit unused.
	DefaultIdleTimeout = 120 * time.Second
)

// ResponderConfigError reports a ResponderConfig field that cannot be used.
type ResponderConfigError struct {
	Field  string
	Reason string
}

func (e ResponderConfigError) Error() string {
	return "http-01: invalid responder configuration: " + e.Field + " " + e.Reason
}

// ResponderBindError reports that the responder could not take the address it
// was asked to listen on. This is the error a caller lacking
// CAP_NET_BIND_SERVICE for port 80, or colliding with an existing listener,
// receives from NewResponder.
type ResponderBindError struct {
	Addr string
	Err  error
}

func (e ResponderBindError) Error() string {
	return "http-01: cannot listen on " + e.Addr + ": " + e.Err.Error()
}

// Unwrap exposes the underlying net error so callers can test for it with
// errors.Is and errors.As.
func (e ResponderBindError) Unwrap() error { return e.Err }

// ResponderShutdownError reports that a graceful shutdown did not complete,
// most often because the caller's context expired with requests still in
// flight.
type ResponderShutdownError struct {
	Addr string
	Err  error
}

func (e ResponderShutdownError) Error() string {
	return "http-01: shutdown of responder on " + e.Addr + " failed: " + e.Err.Error()
}

// Unwrap exposes the underlying shutdown error.
func (e ResponderShutdownError) Unwrap() error { return e.Err }

// ResponderConfig configures a Responder. The zero value of every field other
// than Addr and KeyAuth selects the corresponding Default constant.
type ResponderConfig struct {
	// Addr is the address to listen on. A value containing a colon is passed
	// to net.Listen verbatim ("127.0.0.1:0", ":80"); a value without one is
	// taken as a bare port and bound on every interface, so "80" and ":80"
	// are equivalent. Required.
	Addr string

	// KeyAuth is the key authorization served at the well-known challenge
	// path, in the "token.thumbprint" form of RFC 8555 Section 8.1. Required.
	KeyAuth string

	// ReadTimeout, WriteTimeout and IdleTimeout bound a single challenge
	// request. Zero selects the package default.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// ShutdownTimeout bounds Shutdown when the context passed to it carries
	// no deadline. Zero selects DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
}

// serveResult carries the terminal error of the serve goroutine. It exists so
// the error can be published through an atomic.Pointer without boxing an
// interface.
type serveResult struct {
	err error
}

// Responder serves the key authorization for one http-01 challenge.
//
// A Responder is bound and serving from the moment NewResponder returns until
// Shutdown or Close is called. It holds no package-level state, so concurrent
// orders each take their own Responder on their own port and cannot disturb
// one another. All methods are safe for concurrent use.
type Responder struct {
	keyAuth         string
	listener        net.Listener
	server          *http.Server
	shutdownTimeout time.Duration

	// stopMu serializes teardown so a Shutdown and a Close racing each other
	// cannot both close the listener, and stopped records that the teardown
	// succeeded so later calls are no-ops. A teardown that FAILED does not
	// set stopped, which is what lets a caller fall back from a Shutdown that
	// missed its deadline to a Close that forces the issue.
	stopMu  sync.Mutex
	stopped bool

	// serve is the terminal error of the serve goroutine, published when
	// done closes.
	serve atomic.Pointer[serveResult]
	done  chan struct{}
}

// NewResponder binds a listener and starts serving keyAuth at the well-known
// http-01 challenge path.
//
// The bind is performed before returning, so a non-nil error means nothing is
// listening and the caller must not notify the ACME server, while a nil error
// means the responder is already accepting connections and validation may be
// requested at once.
//
// The caller owns the returned Responder and must release it with Shutdown or
// Close; `defer responder.Close()` is safe even after an explicit Shutdown.
func NewResponder(cfg ResponderConfig) (*Responder, error) {

	if cfg.Addr == "" {
		return nil, ResponderConfigError{Field: "Addr", Reason: "must not be empty"}
	}
	if cfg.KeyAuth == "" {
		return nil, ResponderConfigError{Field: "KeyAuth", Reason: "must not be empty"}
	}

	addr := cfg.Addr
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, ResponderBindError{Addr: addr, Err: err}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownChallengePath, challengeHandlerHTTPx(cfg.KeyAuth))

	r := &Responder{
		keyAuth:         cfg.KeyAuth,
		listener:        listener,
		shutdownTimeout: durationOrDefault(cfg.ShutdownTimeout, DefaultShutdownTimeout),
		done:            make(chan struct{}),
		server: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  durationOrDefault(cfg.ReadTimeout, DefaultReadTimeout),
			WriteTimeout: durationOrDefault(cfg.WriteTimeout, DefaultWriteTimeout),
			IdleTimeout:  durationOrDefault(cfg.IdleTimeout, DefaultIdleTimeout),
		},
	}

	go func() {
		defer close(r.done)
		err := r.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		} else if err != nil {
			// The responder stopped without being asked to, so the challenge
			// will fail validation. Err reports this to a caller that checks;
			// the log is for one that does not.
			slog.Error("http-01 challenge responder stopped serving",
				slog.String("address", addr),
				slog.String("error", err.Error()))
		}
		r.serve.Store(&serveResult{err: err})
	}()

	return r, nil
}

// Addr reports the address the responder is listening on. When the
// configuration asked for port 0 this is where the kernel-assigned port can be
// read.
func (r *Responder) Addr() net.Addr { return r.listener.Addr() }

// KeyAuth reports the key authorization the responder serves.
func (r *Responder) KeyAuth() string { return r.keyAuth }

// Done returns a channel closed when the responder has stopped serving, either
// because it was shut down or because the listener failed.
func (r *Responder) Done() <-chan struct{} { return r.done }

// Err reports the terminal error of the serve loop, or nil while the responder
// is still serving and after an ordinary shutdown. A graceful stop is not an
// error.
func (r *Responder) Err() error {
	if result := r.serve.Load(); result != nil {
		return result.err
	}
	return nil
}

// Shutdown stops the responder gracefully, letting in-flight challenge
// requests finish.
//
// If ctx carries no deadline the configured ShutdownTimeout is applied. Once
// the responder has stopped, further calls to Shutdown or Close are no-ops
// returning nil, so `defer responder.Close()` is correct after an explicit
// Shutdown.
//
// A Shutdown that misses its deadline returns ResponderShutdownError and
// leaves the responder running; Close then forces the teardown.
func (r *Responder) Shutdown(ctx context.Context) error {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.shutdownTimeout)
		defer cancel()
	}

	r.stopMu.Lock()
	defer r.stopMu.Unlock()

	if r.stopped {
		return nil
	}
	if err := r.server.Shutdown(ctx); err != nil {
		return ResponderShutdownError{Addr: r.server.Addr, Err: err}
	}
	r.stopped = true
	return nil
}

// Close stops the responder immediately, without waiting for in-flight
// requests. It is the remedy for a Shutdown that missed its deadline.
//
// Once the responder has stopped, further calls to Close or Shutdown are
// no-ops returning nil.
func (r *Responder) Close() error {
	r.stopMu.Lock()
	defer r.stopMu.Unlock()

	if r.stopped {
		return nil
	}
	if err := r.server.Close(); err != nil {
		return ResponderShutdownError{Addr: r.server.Addr, Err: err}
	}
	r.stopped = true
	return nil
}

// durationOrDefault returns d, or fallback when d is not a usable duration.
func durationOrDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}
