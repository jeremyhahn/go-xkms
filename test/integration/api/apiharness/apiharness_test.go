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

package apiharness

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// racingWindow fakes a sealed window that several test binaries unseal at
// once: /health stays 503 and the status stays sealed (every caller sees the
// barrier sealed and posts), the first unseal answers 204 and each later one
// answers lostCode, the status the node gives an already-unsealed barrier.
// /health/ready answers 200 once an unseal has succeeded. The status body is
// the shape go-qrdb v0.58.4 returns for a sealed barrier: the initialized
// flag set and initialized_at absent.
type racingWindow struct {
	lostCode int
	lostBody string
	unseals  atomic.Int32
	unsealed atomic.Bool
}

func (w *racingWindow) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		rw.WriteHeader(http.StatusServiceUnavailable)
	case "/v1/barrier/status":
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"sealed":true,"initialized":true}`))
	case "/v1/barrier/unseal":
		if w.unseals.Add(1) == 1 {
			w.unsealed.Store(true)
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		body := w.lostBody
		if body == "" {
			body = `{"error":"barrier is already unsealed"}`
		}
		rw.WriteHeader(w.lostCode)
		_, _ = rw.Write([]byte(body))
	case "/health/ready":
		if w.unsealed.Load() {
			rw.WriteHeader(http.StatusOK)
			return
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
	default:
		rw.WriteHeader(http.StatusNotFound)
	}
}

func TestOpenReady_LostUnsealRaceProceedsOnceReady(t *testing.T) {
	window := &racingWindow{lostCode: http.StatusConflict}
	srv := httptest.NewServer(window)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callers = 2
	// The first caller unseals before the second posts, so the second
	// deterministically loses the race the concurrent test binaries run.
	errs := make([]error, callers)
	for i := range errs {
		errs[i] = openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase))
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: openReady = %v, want nil", i, err)
		}
	}
	if got := window.unseals.Load(); got != callers {
		t.Fatalf("unseal posts = %d, want %d (each caller saw the barrier sealed)", got, callers)
	}
}

func TestOpenReady_OtherUnsealErrorFails(t *testing.T) {
	window := &racingWindow{lostCode: http.StatusInternalServerError}
	srv := httptest.NewServer(window)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase)); err != nil {
		t.Fatalf("first caller: openReady = %v, want nil", err)
	}
	err := openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase))
	var status *xkmsdtest.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusInternalServerError {
		t.Fatalf("second caller: openReady = %v, want the HTTP 500 *xkmsdtest.StatusError", err)
	}
}

// TestOpenReady_SealedWindowClosedProceedsOnceReady covers the race the unix
// package lost in CI: another package unsealed between this caller's status
// read and its unseal post, so the closing sealed-window listener answers 503
// SEALED_WINDOW_CLOSED. The barrier is open, so openReady must succeed.
func TestOpenReady_SealedWindowClosedProceedsOnceReady(t *testing.T) {
	window := &racingWindow{
		lostCode: http.StatusServiceUnavailable,
		lostBody: `{"error":"sealed-window listener closed: barrier unsealed","code":"SEALED_WINDOW_CLOSED"}`,
	}
	srv := httptest.NewServer(window)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := range 2 {
		if err := openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase)); err != nil {
			t.Fatalf("caller %d: openReady = %v, want nil", i, err)
		}
	}
	if got := window.unseals.Load(); got != 2 {
		t.Fatalf("unseal posts = %d, want 2", got)
	}
}

// TestOpenReady_OtherServiceUnavailableFails keeps a 503 without the
// SEALED_WINDOW_CLOSED code an error: only an unsealed barrier is success.
func TestOpenReady_OtherServiceUnavailableFails(t *testing.T) {
	window := &racingWindow{
		lostCode: http.StatusServiceUnavailable,
		lostBody: `{"error":"unseal backend unavailable","code":"UNAVAILABLE"}`,
	}
	srv := httptest.NewServer(window)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase)); err != nil {
		t.Fatalf("first caller: openReady = %v, want nil", err)
	}
	err := openReady(ctx, srv.Client(), srv.URL, []byte(BarrierPassphrase))
	var status *xkmsdtest.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusServiceUnavailable {
		t.Fatalf("second caller: openReady = %v, want the HTTP 503 *xkmsdtest.StatusError", err)
	}
}
