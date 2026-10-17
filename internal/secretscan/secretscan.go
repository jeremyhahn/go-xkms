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

// Package secretscan records everything a slog.Logger emits, at every level,
// and asserts that a known secret appears in none of it, in any of the forms
// a log line could carry it: raw, lower or upper hex (which covers 0x-hex),
// std or URL base64 with or without padding, or Go's %v rendering of a byte
// slice.
//
// It is test support: a test attaches a Recorder to the code under test,
// drives the operations that handle the secret, then calls RequireAbsent.
package secretscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// lockedBuffer is the one output the Recorder's text and JSON handlers share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Recorder is a slog.Handler that keeps every record at Debug and above,
// rendered both as text and as JSON: the text handler writes strings
// verbatim and the JSON handler writes byte slices as base64, so between them
// a secret logged as a string, a byte slice or a formatted message is seen.
type Recorder struct {
	out      *lockedBuffer
	handlers []slog.Handler
}

var _ slog.Handler = (*Recorder)(nil)

// NewRecorder returns a Recorder with nothing recorded yet.
func NewRecorder() *Recorder {
	out := &lockedBuffer{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	return &Recorder{
		out: out,
		handlers: []slog.Handler{
			slog.NewTextHandler(out, opts),
			slog.NewJSONHandler(out, opts),
		},
	}
}

// Enabled reports whether level is recorded: everything from Debug up.
func (r *Recorder) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelDebug
}

// Handle records rec in every rendering.
func (r *Recorder) Handle(ctx context.Context, rec slog.Record) error {
	for _, h := range r.handlers {
		if err := h.Handle(ctx, rec.Clone()); err != nil {
			return err
		}
	}
	return nil
}

// WithAttrs returns a Recorder that adds attrs to every record and writes to
// the same output.
func (r *Recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &Recorder{out: r.out, handlers: make([]slog.Handler, len(r.handlers))}
	for i, h := range r.handlers {
		next.handlers[i] = h.WithAttrs(attrs)
	}
	return next
}

// WithGroup returns a Recorder that nests later attributes under name and
// writes to the same output.
func (r *Recorder) WithGroup(name string) slog.Handler {
	next := &Recorder{out: r.out, handlers: make([]slog.Handler, len(r.handlers))}
	for i, h := range r.handlers {
		next.handlers[i] = h.WithGroup(name)
	}
	return next
}

// Output returns everything recorded so far.
func (r *Recorder) Output() string {
	return r.out.String()
}

// Forms returns every rendering of secret the scan looks for, keyed by the
// name of the form.
func Forms(secret []byte) map[string]string {
	lowerHex := hex.EncodeToString(secret)
	return map[string]string{
		"raw":                string(secret),
		"lower hex":          lowerHex,
		"upper hex":          strings.ToUpper(lowerHex),
		"std base64":         base64.StdEncoding.EncodeToString(secret),
		"raw std base64":     base64.RawStdEncoding.EncodeToString(secret),
		"url base64":         base64.URLEncoding.EncodeToString(secret),
		"raw url base64":     base64.RawURLEncoding.EncodeToString(secret),
		"byte slice (%v)":    fmt.Sprintf("%v", secret),
		"byte slice (%#v)":   fmt.Sprintf("%#v", secret),
		"quoted string (%q)": fmt.Sprintf("%q", secret),
	}
}

// Find reports the first form of secret found in output. An empty secret is
// never found: it would match any output and prove nothing.
func Find(output string, secret []byte) (form string, found bool) {
	if len(secret) == 0 {
		return "", false
	}
	for name, rendered := range Forms(secret) {
		if strings.Contains(output, rendered) {
			return name, true
		}
	}
	return "", false
}

// RequireAbsent fails t when output carries secret, named name in the
// failure, in any form Forms lists.
func RequireAbsent(t testing.TB, output, name string, secret []byte) {
	t.Helper()
	require.NotEmpty(t, secret, "an empty secret proves nothing")
	require.NotEmpty(t, output, "the operation must have logged something to scan")
	form, found := Find(output, secret)
	require.Falsef(t, found, "%s was logged (%s form)", name, form)
}
