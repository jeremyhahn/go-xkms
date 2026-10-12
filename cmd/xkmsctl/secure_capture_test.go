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

// secure_capture_test.go holds the capture helpers used by tests whose subject
// is secret material, where the ordinary captureStdout is not good enough.
//
// captureStdout returns a string. A Go string cannot be wiped: once bytes are
// in one they stay readable on the heap until the collector happens to reuse
// the page, and anything that reads process memory in between -- a core dump,
// a debugger, another test in the same binary -- still sees them. For almost
// every test that is irrelevant, because its output is not secret. It is not
// irrelevant for a test whose whole subject is whether a command leaks a
// private key, because the case that test exists to catch is precisely the
// case where stdout contains the key.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// errCaptureOverflow reports that the reader produced more than the caller's
// declared limit. It is a distinct error rather than a truncation because
// silent truncation is the dangerous outcome: a leak assertion of the form
// "the key does not appear in the output" passes trivially against output
// that was cut short before the key. See TestReadAllSecret_RefusesToTruncate.
var errCaptureOverflow = errors.New("captured output exceeded the protected capture limit")

// readAllSecret reads r to EOF into mlocked memory, refusing to read more
// than limit bytes. It returns the buffer and the number of bytes read; the
// caller owns the buffer and must Destroy it.
//
// The read goes straight into the mlocked allocation. A bytes.Buffer is not
// usable here for the same reason a string is not: growing one reallocates
// and abandons the previous backing array with the secret still in it, out of
// reach of any wipe.
//
// limit is a hard limit rather than a starting capacity because the whole point
// is that the allocation never moves. Callers size it for the output they
// expect; overflow is an error, not a resize.
func readAllSecret(r io.Reader, limit int) (*secure.Buffer, int, error) {
	if limit <= 0 {
		return nil, 0, fmt.Errorf("capture limit must be positive, got %d", limit)
	}

	// One byte of slack above limit, so an input of exactly limit bytes is
	// distinguishable from one that ran over: a full read of limit+1 means
	// there was more to come.
	buf, err := secure.NewBuffer(limit + 1)
	if err != nil {
		return nil, 0, fmt.Errorf("allocating protected memory for the capture: %w", err)
	}

	var n int
	err = buf.WithBytes(func(b []byte) error {
		var readErr error
		n, readErr = io.ReadFull(r, b)
		return readErr
	})
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// ReadFull reports EOF for an empty reader and ErrUnexpectedEOF for
		// any short read; both mean "the reader is done", which is the normal
		// case for a closed pipe.
	default:
		buf.Destroy()
		return nil, 0, fmt.Errorf("reading the captured output: %w", err)
	}

	if n > limit {
		buf.Destroy()
		return nil, 0, fmt.Errorf("%w of %d bytes", errCaptureOverflow, limit)
	}
	return buf, n, nil
}

// captureStdoutSecret runs fn with os.Stdout redirected, capturing up to limit
// bytes of output into mlocked memory. The caller owns the returned buffer
// and must Destroy it; the output is the first n bytes WithBytes lends.
func captureStdoutSecret(t *testing.T, limit int, fn func()) (*secure.Buffer, int) {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = oldStdout

	buf, n, err := readAllSecret(r, limit)
	if err != nil {
		t.Fatalf("capturing stdout into protected memory: %v", err)
	}
	return buf, n
}

// lowerASCIIInPlace lowercases A-Z where they sit. bytes.ToLower would
// allocate an ordinary heap copy, which for secret-bearing input is another
// unwipeable copy of the secret -- the thing the protected buffer exists to
// avoid.
func lowerASCIIInPlace(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

// capturedString returns the first n captured bytes as a string, for the tests
// of the capture helper itself, whose input is not secret.
func capturedString(t *testing.T, buf *secure.Buffer, n int) string {
	t.Helper()
	var got string
	if err := buf.WithBytes(func(b []byte) error {
		got = string(b[:n])
		return nil
	}); err != nil {
		t.Fatalf("borrowing the capture: %v", err)
	}
	return got
}

func TestReadAllSecret_ReadsExactly(t *testing.T) {
	const want = "public: abcdef\n"

	buf, n, err := readAllSecret(strings.NewReader(want), 1024)
	if err != nil {
		t.Fatalf("readAllSecret: %v", err)
	}
	defer buf.Destroy()

	if n != len(want) {
		t.Fatalf("read %d bytes, want %d", n, len(want))
	}
	if got := capturedString(t, buf, n); got != want {
		t.Errorf("captured %q, want %q", got, want)
	}
}

// TestReadAllSecret_RefusesToTruncate is the assertion the whole helper exists
// for. If an over-long read were silently truncated instead of refused, a
// caller asserting "the private key does not appear in this output" would pass
// against output that had been cut short before the key -- a leak test that
// cannot see the leak.
func TestReadAllSecret_RefusesToTruncate(t *testing.T) {
	const limit = 8
	src := "0123456789abcdef" // twice the limit

	buf, n, err := readAllSecret(strings.NewReader(src), limit)
	if err == nil {
		buf.Destroy()
		t.Fatalf("over-long input was accepted (%d bytes captured); it must be refused, "+
			"because truncated output makes a no-leak assertion vacuous", n)
	}
	if !errors.Is(err, errCaptureOverflow) {
		t.Errorf("error was %v, want it to wrap errCaptureOverflow so callers can tell "+
			"an over-long capture from an I/O failure", err)
	}
	if buf != nil {
		t.Error("the protected buffer must not be handed back on the overflow path")
	}
}

// TestReadAllSecret_ExactFitIsNotOverflow pins the boundary: input of exactly
// limit bytes is a complete capture, not an overflow. Without the one byte of
// slack in the allocation the two are indistinguishable and this input would
// be rejected.
func TestReadAllSecret_ExactFitIsNotOverflow(t *testing.T) {
	const limit = 8
	src := "01234567" // exactly the limit

	buf, n, err := readAllSecret(strings.NewReader(src), limit)
	if err != nil {
		t.Fatalf("input of exactly the limit was rejected: %v", err)
	}
	defer buf.Destroy()

	if n != limit {
		t.Fatalf("read %d bytes, want %d", n, limit)
	}
	if got := capturedString(t, buf, n); got != src {
		t.Errorf("captured %q, want %q", got, src)
	}
}

func TestReadAllSecret_RejectsNonPositiveLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		buf, _, err := readAllSecret(strings.NewReader("x"), limit)
		if err == nil {
			buf.Destroy()
			t.Errorf("limit %d was accepted; a zero-length capture can only ever "+
				"read nothing", limit)
		}
	}
}

func TestLowerASCIIInPlace(t *testing.T) {
	// Boundaries either side of A-Z ('@' is 'A'-1, '[' is 'Z'+1) plus the
	// bytes hex output is actually made of.
	in := []byte("@AZ[az09 \n\xff")
	want := "@az[az09 \n\xff"

	lowerASCIIInPlace(in)

	if got := string(in); got != want {
		t.Errorf("lowerASCIIInPlace produced %q, want %q", got, want)
	}
}
