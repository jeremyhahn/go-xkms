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

package api

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// failingCloseBody is an io.ReadCloser whose Close always fails. It lets
// tests exercise CloseResponseBody's error branch without needing a real,
// faulty transport.
type failingCloseBody struct {
	io.Reader
}

func (failingCloseBody) Close() error {
	return errors.New("simulated close failure")
}

// TestCloseResponseBody_Success closes a response body that closes cleanly
// and confirms no error is logged.
func TestCloseResponseBody_Success(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	resp := &http.Response{Body: io.NopCloser(strings.NewReader("ok"))}

	CloseResponseBody(resp)

	if logBuf.Len() != 0 {
		t.Fatalf("expected no log output for a clean close, got: %s", logBuf.String())
	}
}

// TestCloseResponseBody_LogsCloseError confirms a failing Close is logged at
// debug level rather than silently discarded or returned as an error.
func TestCloseResponseBody_LogsCloseError(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	resp := &http.Response{Body: failingCloseBody{Reader: strings.NewReader("ok")}}

	// CloseResponseBody must not panic and must not return anything for the
	// caller to check - the close error changes nothing about a result the
	// caller has already produced.
	CloseResponseBody(resp)

	got := logBuf.String()
	if !strings.Contains(got, "failed to close response body") {
		t.Fatalf("expected close failure to be logged, got: %q", got)
	}
	if !strings.Contains(got, "simulated close failure") {
		t.Fatalf("expected the close error to be included in the log, got: %q", got)
	}
	if !strings.Contains(got, "level=DEBUG") {
		t.Fatalf("expected the close failure to be logged at debug level, got: %q", got)
	}
}
