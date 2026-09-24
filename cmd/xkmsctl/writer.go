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

package main

import (
	"fmt"
	"io"
	"log/slog"
)

// outputWriter wraps an io.Writer and records the first write error,
// turning every later write into a no-op. A single command commonly writes
// many lines of output; checking each one individually would multiply
// every PrintX method by the number of lines it writes. Recording the
// first error and checking it once, after all writes, gives every write
// site the same safety without the repetition. Modeled on
// xkey/tools/skillgen's writer.
type outputWriter struct {
	w   io.Writer
	err error
}

// newOutputWriter wraps w for error-recording writes.
func newOutputWriter(w io.Writer) *outputWriter {
	return &outputWriter{w: w}
}

// Write implements io.Writer so an *outputWriter can be passed to APIs
// that require one, such as json.NewEncoder. A write attempted after an
// earlier failure is skipped and reported as fully written: the bytes are
// never sent to the underlying writer either way, and the real cause is
// the one recorded in err, not a follow-on "short write" from whatever
// wraps this Write call.
func (o *outputWriter) Write(p []byte) (int, error) {
	if o.err != nil {
		return len(p), nil
	}
	n, err := o.w.Write(p)
	if err != nil {
		o.err = err
	}
	return n, err
}

// printf writes a formatted line. It is a no-op once a write has failed.
func (o *outputWriter) printf(format string, a ...any) {
	if o.err == nil {
		_, o.err = fmt.Fprintf(o.w, format, a...)
	}
}

// println writes a, terminated by a newline. It is a no-op once a write
// has failed.
func (o *outputWriter) println(a ...any) {
	if o.err == nil {
		_, o.err = fmt.Fprintln(o.w, a...)
	}
}

// print writes a. It is a no-op once a write has failed.
func (o *outputWriter) print(a ...any) {
	if o.err == nil {
		_, o.err = fmt.Fprint(o.w, a...)
	}
}

// Err returns the first write error recorded, if any.
func (o *outputWriter) Err() error {
	return o.err
}

// closeQuietly closes c and logs a failure at debug level instead of
// discarding it. A deferred cleanup Close on a client or transport that has
// already been used is not actionable by the caller — the command's own
// result has already been determined by the time it runs — so the error is
// logged rather than returned, the standard idiom for best-effort deferred
// cleanup.
func closeQuietly(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		slog.Default().Debug("xkmsctl: cleanup close failed", "error", err)
	}
}

// closeFuncQuietly calls fn, if non-nil, and logs a failure at debug level
// instead of discarding it. It is the closeQuietly counterpart for the
// "cleanup func() error" shape used where a client does not itself
// implement io.Closer.
func closeFuncQuietly(fn func() error) {
	if fn == nil {
		return
	}
	if err := fn(); err != nil {
		slog.Default().Debug("xkmsctl: cleanup close failed", "error", err)
	}
}
