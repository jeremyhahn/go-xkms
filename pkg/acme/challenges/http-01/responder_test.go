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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestResponder binds a responder on a loopback ephemeral port and
// registers its teardown.
func newTestResponder(t *testing.T, keyAuth string) *Responder {
	t.Helper()

	responder, err := NewResponder(ResponderConfig{Addr: "127.0.0.1:0", KeyAuth: keyAuth})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	t.Cleanup(func() { _ = responder.Close() })
	return responder
}

// responderPort reports the port a responder is listening on.
func responderPort(t *testing.T, r *Responder) string {
	t.Helper()

	_, port, err := net.SplitHostPort(r.Addr().String())
	if err != nil {
		t.Fatalf("split responder address %q: %v", r.Addr(), err)
	}
	return port
}

// getChallenge performs the GET the ACME server would perform and returns the
// status code and body.
func getChallenge(t *testing.T, r *Responder, token string) (int, string) {
	t.Helper()

	url := fmt.Sprintf("http://%s%s%s", r.Addr(), wellKnownChallengePath, token)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read challenge body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestNewResponder_Success(t *testing.T) {
	const keyAuth = "token-success.thumbprint"

	responder := newTestResponder(t, keyAuth)

	if responder.Addr() == nil {
		t.Fatal("Addr must report the bound address")
	}
	if got := responder.KeyAuth(); got != keyAuth {
		t.Errorf("KeyAuth = %q, want %q", got, keyAuth)
	}

	status, body := getChallenge(t, responder, "token-success")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != keyAuth {
		t.Errorf("body = %q, want %q", body, keyAuth)
	}
}

// TestNewResponder_ReadyOnReturn is the regression test for the readiness race
// the package-global Setup had: it deliberately performs the ACME server's
// validation GET on the very next statement after NewResponder returns, with
// no delay of any kind. It fails if the bind is ever made lazy again.
func TestNewResponder_ReadyOnReturn(t *testing.T) {
	const keyAuth = "token-ready.thumbprint"

	responder, err := NewResponder(ResponderConfig{Addr: "127.0.0.1:0", KeyAuth: keyAuth})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer func() { _ = responder.Close() }()

	status, body := getChallenge(t, responder, "token-ready")
	if status != http.StatusOK || body != keyAuth {
		t.Errorf("responder not serving immediately after NewResponder: status=%d body=%q", status, body)
	}
}

func TestNewResponder_BarePortIsNormalized(t *testing.T) {
	// "0" carries no colon, so it is taken as a bare port and bound on every
	// interface with a kernel-assigned number.
	responder, err := NewResponder(ResponderConfig{Addr: "0", KeyAuth: "token-bare.thumbprint"})
	if err != nil {
		t.Fatalf("NewResponder with a bare port: %v", err)
	}
	defer func() { _ = responder.Close() }()

	addr, ok := responder.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr is %T, want *net.TCPAddr", responder.Addr())
	}
	if addr.Port == 0 {
		t.Error("a bound responder must report a non-zero port")
	}
}

func TestNewResponder_EmptyAddrRejected(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{Addr: "", KeyAuth: "token.thumbprint"})
	if responder != nil {
		_ = responder.Close()
		t.Fatal("NewResponder returned a responder for an empty address")
	}

	var configErr ResponderConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error is %T (%v), want ResponderConfigError", err, err)
	}
	if configErr.Field != "Addr" {
		t.Errorf("Field = %q, want %q", configErr.Field, "Addr")
	}
}

func TestNewResponder_EmptyKeyAuthRejected(t *testing.T) {
	// An empty key authorization would bind happily and then serve an empty
	// body, failing validation with no indication of the cause.
	responder, err := NewResponder(ResponderConfig{Addr: "127.0.0.1:0", KeyAuth: ""})
	if responder != nil {
		_ = responder.Close()
		t.Fatal("NewResponder returned a responder for an empty key authorization")
	}

	var configErr ResponderConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error is %T (%v), want ResponderConfigError", err, err)
	}
	if configErr.Field != "KeyAuth" {
		t.Errorf("Field = %q, want %q", configErr.Field, "KeyAuth")
	}
}

// TestNewResponder_BindErrorPortInUse covers the defect that motivated the
// instance API: a bind failure must reach the caller as a typed error from the
// constructor, not as a log line and a later authorization rejection.
func TestNewResponder_BindErrorPortInUse(t *testing.T) {
	occupied, _ := occupyEphemeralPort(t)
	defer func() { _ = occupied.Close() }()

	responder, err := NewResponder(ResponderConfig{
		Addr:    occupied.Addr().String(),
		KeyAuth: "token-collision.thumbprint",
	})
	if responder != nil {
		_ = responder.Close()
		t.Fatal("NewResponder bound a port that was already in use")
	}

	var bindErr ResponderBindError
	if !errors.As(err, &bindErr) {
		t.Fatalf("error is %T (%v), want ResponderBindError", err, err)
	}
	if bindErr.Addr != occupied.Addr().String() {
		t.Errorf("Addr = %q, want %q", bindErr.Addr, occupied.Addr().String())
	}

	// The underlying net error survives the wrapping, so a caller can tell an
	// address collision from a permission denial.
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("bind error does not unwrap to *net.OpError: %v", err)
	}
	if !strings.Contains(err.Error(), "http-01: cannot listen on") {
		t.Errorf("error message %q does not identify its origin", err.Error())
	}
}

func TestNewResponder_BindErrorMalformedAddr(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		Addr:    "127.0.0.1:not-a-port",
		KeyAuth: "token-malformed.thumbprint",
	})
	if responder != nil {
		_ = responder.Close()
		t.Fatal("NewResponder bound a malformed address")
	}

	var bindErr ResponderBindError
	if !errors.As(err, &bindErr) {
		t.Fatalf("error is %T (%v), want ResponderBindError", err, err)
	}
}

func TestNewResponder_DefaultsApplied(t *testing.T) {
	responder := newTestResponder(t, "token-defaults.thumbprint")

	if responder.server.ReadTimeout != DefaultReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", responder.server.ReadTimeout, DefaultReadTimeout)
	}
	if responder.server.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("WriteTimeout = %v, want %v", responder.server.WriteTimeout, DefaultWriteTimeout)
	}
	if responder.server.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", responder.server.IdleTimeout, DefaultIdleTimeout)
	}
	if responder.shutdownTimeout != DefaultShutdownTimeout {
		t.Errorf("shutdownTimeout = %v, want %v", responder.shutdownTimeout, DefaultShutdownTimeout)
	}
}

func TestNewResponder_ConfigOverridesApplied(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		Addr:            "127.0.0.1:0",
		KeyAuth:         "token-overrides.thumbprint",
		ReadTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		IdleTimeout:     3 * time.Second,
		ShutdownTimeout: 4 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer func() { _ = responder.Close() }()

	if responder.server.ReadTimeout != time.Second {
		t.Errorf("ReadTimeout = %v, want %v", responder.server.ReadTimeout, time.Second)
	}
	if responder.server.WriteTimeout != 2*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", responder.server.WriteTimeout, 2*time.Second)
	}
	if responder.server.IdleTimeout != 3*time.Second {
		t.Errorf("IdleTimeout = %v, want %v", responder.server.IdleTimeout, 3*time.Second)
	}
	if responder.shutdownTimeout != 4*time.Second {
		t.Errorf("shutdownTimeout = %v, want %v", responder.shutdownTimeout, 4*time.Second)
	}
}

// TestResponder_VerifyRoundTrip drives the package's own server half against
// its client half, which is the contract the SDK consumer depends on.
func TestResponder_VerifyRoundTrip(t *testing.T) {
	const keyAuth = "token-roundtrip.thumbprint"

	responder := newTestResponder(t, keyAuth)

	if err := Verify(nil, "127.0.0.1", responderPort(t, responder), "token-roundtrip", keyAuth); err != nil {
		t.Fatalf("Verify against the responder: %v", err)
	}
}

func TestResponder_VerifyRoundTripKeyAuthMismatch(t *testing.T) {
	responder := newTestResponder(t, "token-roundtrip.correct")

	err := Verify(nil, "127.0.0.1", responderPort(t, responder), "token-roundtrip", "token-roundtrip.wrong")

	var mismatch ErrKeyAuthorizationMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("error is %T (%v), want ErrKeyAuthorizationMismatch", err, err)
	}
}

func TestResponder_ShutdownGraceful(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		Addr:    "127.0.0.1:0",
		KeyAuth: "token-shutdown.thumbprint",
	})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	addr := responder.Addr().String()

	if err := responder.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case <-responder.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done was not closed after Shutdown returned")
	}

	if err := responder.Err(); err != nil {
		t.Errorf("Err after a graceful stop = %v, want nil", err)
	}

	// The listener is released before Shutdown returns, so the port is free.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("responder on %s still accepting connections after Shutdown", addr)
	}
}

func TestResponder_ShutdownIsIdempotent(t *testing.T) {
	responder := newTestResponder(t, "token-idempotent.thumbprint")

	if err := responder.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := responder.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
	// The documented `defer responder.Close()` idiom must stay safe after an
	// explicit Shutdown.
	if err := responder.Close(); err != nil {
		t.Errorf("Close after Shutdown: %v", err)
	}
}

func TestResponder_CloseStopsTheResponder(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		Addr:    "127.0.0.1:0",
		KeyAuth: "token-close.thumbprint",
	})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	addr := responder.Addr().String()

	if err := responder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := responder.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	select {
	case <-responder.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done was not closed after Close returned")
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("responder on %s still accepting connections after Close", addr)
	}
}

// TestResponder_ShutdownContextExpired holds a request open across the
// shutdown so the graceful path cannot complete, and asserts the deadline is
// reported as a typed error rather than swallowed.
func TestResponder_ShutdownContextExpired(t *testing.T) {
	// A body far larger than any socket buffer keeps the server blocked in
	// its response write while the test refuses to read, so the connection is
	// unambiguously active when Shutdown runs.
	keyAuth := strings.Repeat("k", 8<<20)

	responder, err := NewResponder(ResponderConfig{
		Addr:         "127.0.0.1:0",
		KeyAuth:      keyAuth,
		WriteTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer func() { _ = responder.Close() }()

	conn, err := net.DialTimeout("tcp", responder.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial responder: %v", err)
	}
	defer func() { _ = conn.Close() }()

	request := fmt.Sprintf("GET %stoken-expired HTTP/1.1\r\nHost: acme\r\n\r\n", wellKnownChallengePath)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write challenge request: %v", err)
	}

	// Reading the status line proves the server accepted the connection and
	// entered the handler; the remaining megabytes stay unread.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	statusLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("status line = %q, want a 200", statusLine)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = responder.Shutdown(ctx)

	var shutdownErr ResponderShutdownError
	if !errors.As(err, &shutdownErr) {
		t.Fatalf("error is %T (%v), want ResponderShutdownError", err, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("shutdown error does not unwrap to context.Canceled: %v", err)
	}
	if !strings.Contains(err.Error(), "http-01: shutdown of responder on") {
		t.Errorf("error message %q does not identify its origin", err.Error())
	}

	// A Shutdown that missed its deadline leaves the responder running, and
	// Close is the remedy: it must actually force the teardown rather than
	// report the earlier failure and do nothing.
	if err := responder.Close(); err != nil {
		t.Fatalf("Close after a failed Shutdown: %v", err)
	}

	select {
	case <-responder.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop a responder whose Shutdown had timed out")
	}

	// The connection the server was still writing to must be gone. Draining it
	// has to end in an error well short of the full body: had Close been a
	// no-op, the write would have continued until the one-minute write
	// timeout. Bytes already sitting in the socket buffer read back first,
	// which is why this drains rather than reading a single byte.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set drain deadline: %v", err)
	}
	buf := make([]byte, 32<<10)
	drained := 0
	for {
		n, err := conn.Read(buf)
		drained += n
		if err != nil {
			break
		}
		// A killed connection yields at most what the socket buffers already
		// held, which is orders of magnitude below half the body. Reaching
		// this much means the server kept streaming, so Close did nothing.
		if drained > len(keyAuth)/2 {
			t.Fatalf("drained %d bytes of an %d-byte body; Close did not stop the response",
				drained, len(keyAuth))
		}
	}
}

// TestResponder_ShutdownAfterCloseIsNoop pins the other order of the pair: a
// stopped responder accepts either call without complaint.
func TestResponder_ShutdownAfterCloseIsNoop(t *testing.T) {
	responder := newTestResponder(t, "token-close-then-shutdown.thumbprint")

	if err := responder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := responder.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown after Close: %v", err)
	}
}

func TestResponder_ErrIsNilWhileServing(t *testing.T) {
	responder := newTestResponder(t, "token-err.thumbprint")

	if err := responder.Err(); err != nil {
		t.Errorf("Err while serving = %v, want nil", err)
	}
}

// TestResponder_ConcurrentOrders covers the defect that made the package
// globals unusable for a consumer running more than one order: two responders
// alive at the same time must serve their own key authorization, and stopping
// one must not stop the other.
func TestResponder_ConcurrentOrders(t *testing.T) {
	const (
		firstKeyAuth  = "token-first.thumbprint-first"
		secondKeyAuth = "token-second.thumbprint-second"
	)

	first := newTestResponder(t, firstKeyAuth)
	second := newTestResponder(t, secondKeyAuth)

	if first.Addr().String() == second.Addr().String() {
		t.Fatal("concurrent responders must not share an address")
	}

	const rounds = 25
	var wg sync.WaitGroup
	errs := make(chan error, 2*rounds)

	for _, order := range []struct {
		responder *Responder
		token     string
		keyAuth   string
	}{
		{first, "token-first", firstKeyAuth},
		{second, "token-second", secondKeyAuth},
	} {
		wg.Add(1)
		go func(r *Responder, token, keyAuth string) {
			defer wg.Done()
			_, port, err := net.SplitHostPort(r.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			for i := 0; i < rounds; i++ {
				if err := Verify(nil, "127.0.0.1", port, token, keyAuth); err != nil {
					errs <- err
					return
				}
			}
		}(order.responder, order.token, order.keyAuth)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent order failed verification: %v", err)
	}

	// Retiring the first order leaves the second serving, which the
	// process-global responder could not guarantee.
	if err := first.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown first responder: %v", err)
	}
	if err := Verify(nil, "127.0.0.1", responderPort(t, second), "token-second", secondKeyAuth); err != nil {
		t.Errorf("second order stopped serving when the first was shut down: %v", err)
	}
}

// TestResponder_ConcurrentUseOfOneResponder exercises every exported method of
// a single responder from many goroutines at once, so the race detector can
// judge the type's own synchronization.
func TestResponder_ConcurrentUseOfOneResponder(t *testing.T) {
	const keyAuth = "token-shared.thumbprint"

	responder := newTestResponder(t, keyAuth)

	const goroutines = 16
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			_ = responder.Addr()
			_ = responder.KeyAuth()
			_ = responder.Err()

			if i%4 == 3 {
				// A quarter of the goroutines race the teardown against the
				// readers; the first one through performs it.
				_ = responder.Shutdown(context.Background())
				return
			}
			if i%4 == 2 {
				_ = responder.Close()
			}
		}(i)
	}

	close(start)
	wg.Wait()

	select {
	case <-responder.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("responder did not stop after concurrent teardown")
	}
}

// TestSetup_ReplacesPreviousResponder pins the behaviour of the deprecated
// process-global path: a second Setup retires the first responder instead of
// leaking its listener.
func TestSetup_ReplacesPreviousResponder(t *testing.T) {
	firstPort := freePort(t)
	Setup(firstPort, "token-global-first.thumbprint")

	serverMu.Lock()
	firstResponder := activeResponder
	serverMu.Unlock()
	if firstResponder == nil {
		t.Fatal("Setup did not install a responder")
	}
	firstAddr := firstResponder.Addr().String()

	secondPort := freePort(t)
	Setup(secondPort, "token-global-second.thumbprint")
	defer Shutdown()

	select {
	case <-firstResponder.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced responder was left running")
	}

	conn, err := net.DialTimeout("tcp", firstAddr, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("the replaced responder on %s is still accepting connections", firstAddr)
	}

	// The current responder is the second one and is serving.
	if err := Verify(nil, "127.0.0.1", secondPort, "token-global-second", "token-global-second.thumbprint"); err != nil {
		t.Errorf("the current global responder is not serving: %v", err)
	}
}

func TestShutdown_WithNoActiveResponder(t *testing.T) {
	serverMu.Lock()
	previous := activeResponder
	activeResponder = nil
	serverMu.Unlock()

	t.Cleanup(func() {
		serverMu.Lock()
		activeResponder = previous
		serverMu.Unlock()
	})

	// Must not panic and must not reach the fatal handler.
	Shutdown()
}

func TestResponderErrors_MessagesAndUnwrapping(t *testing.T) {
	cause := errors.New("address already in use")

	configErr := ResponderConfigError{Field: "Addr", Reason: "must not be empty"}
	if got, want := configErr.Error(), "http-01: invalid responder configuration: Addr must not be empty"; got != want {
		t.Errorf("ResponderConfigError.Error() = %q, want %q", got, want)
	}

	bindErr := ResponderBindError{Addr: ":80", Err: cause}
	if got, want := bindErr.Error(), "http-01: cannot listen on :80: address already in use"; got != want {
		t.Errorf("ResponderBindError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(bindErr, cause) {
		t.Error("ResponderBindError does not unwrap to its cause")
	}

	shutdownErr := ResponderShutdownError{Addr: ":80", Err: cause}
	if got, want := shutdownErr.Error(), "http-01: shutdown of responder on :80 failed: address already in use"; got != want {
		t.Errorf("ResponderShutdownError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(shutdownErr, cause) {
		t.Error("ResponderShutdownError does not unwrap to its cause")
	}
}

func TestDurationOrDefault(t *testing.T) {
	testCases := []struct {
		name     string
		value    time.Duration
		fallback time.Duration
		want     time.Duration
	}{
		{"zero selects the fallback", 0, time.Second, time.Second},
		{"negative selects the fallback", -time.Second, time.Second, time.Second},
		{"positive is kept", 3 * time.Second, time.Second, 3 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := durationOrDefault(tc.value, tc.fallback); got != tc.want {
				t.Errorf("durationOrDefault(%v, %v) = %v, want %v", tc.value, tc.fallback, got, tc.want)
			}
		})
	}
}
