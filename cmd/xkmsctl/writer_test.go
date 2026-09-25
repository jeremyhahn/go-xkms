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
	"bytes"
	"errors"
	"log/slog"
	"testing"
)

// erroringWriter returns err from every Write call after the first n bytes
// (n=0 fails immediately), recording how many times Write was called.
type erroringWriter struct {
	err   error
	calls int
}

func (f *erroringWriter) Write(p []byte) (int, error) {
	f.calls++
	return 0, f.err
}

func TestOutputWriter_Success(t *testing.T) {
	var buf bytes.Buffer
	w := newOutputWriter(&buf)

	w.print("a")
	w.printf("%d", 1)
	w.println("b")

	if err := w.Err(); err != nil {
		t.Fatalf("Err: got %v, want nil", err)
	}
	if got, want := buf.String(), "a1b\n"; got != want {
		t.Errorf("buf: got %q, want %q", got, want)
	}
}

func TestOutputWriter_RecordsFirstErrorAndStopsWriting(t *testing.T) {
	fw := &erroringWriter{err: errors.New("disk full")}
	w := newOutputWriter(fw)

	w.println("first")
	if err := w.Err(); err == nil {
		t.Fatal("Err: got nil after a failing write")
	}
	if fw.calls != 1 {
		t.Fatalf("calls after first write: got %d, want 1", fw.calls)
	}

	w.println("second")
	w.printf("%d", 2)
	w.print("third")

	if fw.calls != 1 {
		t.Errorf("calls after error recorded: got %d, want 1 (no-op writes should not reach the underlying writer)", fw.calls)
	}
}

func TestOutputWriter_Write_ImplementsIOWriter(t *testing.T) {
	var buf bytes.Buffer
	w := newOutputWriter(&buf)

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: unexpected error %v", err)
	}
	if n != 5 {
		t.Errorf("Write: got n=%d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf: got %q, want %q", buf.String(), "hello")
	}

	fw := &erroringWriter{err: errors.New("boom")}
	w2 := newOutputWriter(fw)
	if _, err := w2.Write([]byte("x")); err == nil {
		t.Fatal("Write: got nil error, want the underlying failure")
	}
	// A write attempted after the failure is reported as fully written so
	// callers like json.Encoder do not bury the real error behind a
	// follow-on "short write" of their own.
	n, err = w2.Write([]byte("later"))
	if err != nil {
		t.Errorf("Write after failure: got err %v, want nil", err)
	}
	if n != len("later") {
		t.Errorf("Write after failure: got n=%d, want %d", n, len("later"))
	}
	if fw.calls != 1 {
		t.Errorf("calls: got %d, want 1 (write after failure must not reach the underlying writer)", fw.calls)
	}
}

func TestCloseQuietly(t *testing.T) {
	t.Run("nil closer is a no-op", func(t *testing.T) {
		closeQuietly(nil)
	})

	t.Run("logs rather than panics on a failing Close", func(t *testing.T) {
		orig := slog.Default()
		t.Cleanup(func() { slog.SetDefault(orig) })
		slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

		closeQuietly(&failingCloser{err: errors.New("close failed")})
	})

	t.Run("succeeding Close is silent", func(t *testing.T) {
		closeQuietly(&failingCloser{err: nil})
	})
}

type failingCloser struct{ err error }

func (f *failingCloser) Close() error { return f.err }

func TestCloseFuncQuietly(t *testing.T) {
	t.Run("nil func is a no-op", func(t *testing.T) {
		closeFuncQuietly(nil)
	})

	t.Run("logs rather than panics on a failing close func", func(t *testing.T) {
		closeFuncQuietly(func() error { return errors.New("close failed") })
	})

	t.Run("succeeding close func is silent", func(t *testing.T) {
		called := false
		closeFuncQuietly(func() error {
			called = true
			return nil
		})
		if !called {
			t.Error("closeFuncQuietly did not invoke fn")
		}
	})
}
