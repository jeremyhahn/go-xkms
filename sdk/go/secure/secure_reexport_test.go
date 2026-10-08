// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package secure_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ----------------------------------------------------------------------------
// Alias identity.
//
// This package's entire contract is that every identifier is a type ALIAS of
// the canonical qrdb type, not a parallel definition. If someone converted an
// alias into a struct copy, downstream code would stop being able to hand xkms
// SDK values to qrdb APIs and errors.As across the module boundary would break.
// These assignments are compile-time proofs of that contract.
// ----------------------------------------------------------------------------

var (
	_ *qrdbsecure.Secret            = (*secure.Secret)(nil)
	_ *qrdbsecure.Buffer            = (*secure.Buffer)(nil)
	_ qrdbsecure.PassphraseProvider = (secure.PassphraseProvider)(nil)
	_ *qrdbsecure.TerminalProvider  = (*secure.TerminalProvider)(nil)
	_ *qrdbsecure.StdinProvider     = (*secure.StdinProvider)(nil)
	_ *qrdbsecure.CallbackProvider  = (*secure.CallbackProvider)(nil)
	_ *qrdbsecure.NilSecretError    = (*secure.NilSecretError)(nil)
	_ *qrdbsecure.NilBufferError    = (*secure.NilBufferError)(nil)
	_ *qrdbsecure.OpenError         = (*secure.OpenError)(nil)
	_ *qrdbsecure.InvalidSizeError  = (*secure.InvalidSizeError)(nil)
	_ *qrdbsecure.ProviderError     = (*secure.ProviderError)(nil)
	_ *qrdbsecure.NestedBorrowError = (*secure.NestedBorrowError)(nil)
	_ *qrdbsecure.EmptyBorrowError  = (*secure.EmptyBorrowError)(nil)
)

// TestAliasedValuesCrossTheModuleBoundary proves at runtime that a Secret built
// through the xkms SDK is accepted by the canonical qrdb API — the practical
// consequence of the alias contract above.
func TestAliasedValuesCrossTheModuleBoundary(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("cross-boundary"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}

	// Hand the xkms-SDK Buffer straight to the qrdb constructor.
	sec, err := qrdbsecure.NewSecretFromBuffer(context.Background(), buf)
	if err != nil {
		t.Fatalf("qrdb NewSecretFromBuffer rejected an xkms SDK Buffer: %v", err)
	}
	t.Cleanup(sec.Destroy)

	opened, err := sec.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.Destroy()

	if !bytes.Equal(opened.Bytes(), []byte("cross-boundary")) {
		t.Errorf("round trip = %q", opened.Bytes())
	}
}

// ----------------------------------------------------------------------------
// NewSecretFromBuffer.
// ----------------------------------------------------------------------------

// TestNewSecretFromBuffer_RoundTrip covers the happy path: the buffer's
// contents must survive into the sealed Secret.
func TestNewSecretFromBuffer_RoundTrip(t *testing.T) {
	const plaintext = "sealed-from-buffer"

	buf, err := secure.NewBufferFromBytes([]byte(plaintext))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}

	sec, err := secure.NewSecretFromBuffer(context.Background(), buf)
	if err != nil {
		t.Fatalf("NewSecretFromBuffer: %v", err)
	}
	t.Cleanup(sec.Destroy)

	opened, err := sec.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.Destroy()

	if !bytes.Equal(opened.Bytes(), []byte(plaintext)) {
		t.Errorf("Open() = %q, want %q", opened.Bytes(), plaintext)
	}
}

// TestNewSecretFromBuffer_ConsumesBuffer pins the consumption contract stated
// in the doc comment. Reusing a consumed buffer must not silently hand back
// live plaintext — that would leave key material in an unmanaged buffer the
// caller believes it no longer owns.
func TestNewSecretFromBuffer_ConsumesBuffer(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("consume-me"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}

	sec, err := secure.NewSecretFromBuffer(context.Background(), buf)
	if err != nil {
		t.Fatalf("NewSecretFromBuffer: %v", err)
	}
	t.Cleanup(sec.Destroy)

	// The source buffer must no longer expose the plaintext.
	if got := buf.Bytes(); bytes.Equal(got, []byte("consume-me")) {
		t.Errorf("source buffer still holds plaintext after being consumed: %q", got)
	}
}

// TestNewSecretFromBuffer_NilBuffer is the error path: a nil buffer must
// produce a typed error rather than panic or an empty usable Secret.
func TestNewSecretFromBuffer_NilBuffer(t *testing.T) {
	sec, err := secure.NewSecretFromBuffer(context.Background(), nil)
	if err == nil {
		if sec != nil {
			sec.Destroy()
		}
		t.Fatal("expected an error for a nil buffer")
	}
	if sec != nil {
		t.Error("no Secret may be returned on failure")
	}

	// The typed error must be recognisable through the SDK alias.
	var nilBuf *secure.NilBufferError
	if !errors.As(err, &nilBuf) {
		t.Errorf("expected *NilBufferError, got %T (%v)", err, err)
	}
}

// ----------------------------------------------------------------------------
// Provider constructors.
// ----------------------------------------------------------------------------

// Compile-time proof that every provider constructor's concrete return type
// satisfies the PassphraseProvider contract callers accept as a parameter.
var (
	_ secure.PassphraseProvider = (*secure.TerminalProvider)(nil)
	_ secure.PassphraseProvider = (*secure.StdinProvider)(nil)
	_ secure.PassphraseProvider = (*secure.CallbackProvider)(nil)
)

// withStdin redirects os.Stdin to a pipe carrying content for the duration of
// the test and restores it afterwards.
func withStdin(t *testing.T, content string) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})

	go func() {
		defer func() { _ = w.Close() }()
		_, _ = io.WriteString(w, content)
	}()
}

// TestNewStdinProvider_ReadsPassphrase exercises the real read path: the
// provider must return the line without its terminator, in a Buffer.
func TestNewStdinProvider_ReadsPassphrase(t *testing.T) {
	withStdin(t, "correct horse battery staple\n")

	buf, err := secure.NewStdinProvider().Passphrase(context.Background(), "passphrase: ")
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	defer buf.Destroy()

	// A retained newline would be silently folded into the passphrase and
	// change every derived key.
	if got := string(buf.Bytes()); got != "correct horse battery staple" {
		t.Errorf("Passphrase() = %q, want the line without its terminator", got)
	}
}

// TestNewStdinProvider_RejectsEmptyInput is the error path: an empty line must
// not yield a zero-length passphrase Buffer.
func TestNewStdinProvider_RejectsEmptyInput(t *testing.T) {
	withStdin(t, "\n")

	buf, err := secure.NewStdinProvider().Passphrase(context.Background(), "passphrase: ")
	if err == nil {
		if buf != nil {
			buf.Destroy()
		}
		t.Fatal("an empty passphrase must be rejected")
	}
	var provErr *secure.ProviderError
	if !errors.As(err, &provErr) {
		t.Errorf("expected *ProviderError, got %T (%v)", err, err)
	}
}

// TestNewStdinProvider_RespectsContextCancellation ensures a cancelled context
// aborts before any read rather than blocking on stdin.
func TestNewStdinProvider_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	buf, err := secure.NewStdinProvider().Passphrase(ctx, "passphrase: ")
	if err == nil {
		if buf != nil {
			buf.Destroy()
		}
		t.Fatal("a cancelled context must abort the prompt")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected a context.Canceled cause, got %v", err)
	}
}
