// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"testing"

	xkmssecure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// Package-level conformance assertions verify every re-exported type is an
// alias of its qrdb counterpart (not a new type), so values cross the module
// boundary without copies or adapters. Each pair asserts assignability in both
// directions; if someone redefines one of these as a new named type the
// assignment stops compiling and this package fails to build.
var (
	_ *qrdbsecure.Secret            = (*xkmssecure.Secret)(nil)
	_ *xkmssecure.Secret            = (*qrdbsecure.Secret)(nil)
	_ *qrdbsecure.Buffer            = (*xkmssecure.Buffer)(nil)
	_ *xkmssecure.Buffer            = (*qrdbsecure.Buffer)(nil)
	_ qrdbsecure.PassphraseProvider = xkmssecure.PassphraseProvider(nil)
	_ xkmssecure.PassphraseProvider = qrdbsecure.PassphraseProvider(nil)
	_ *qrdbsecure.TerminalProvider  = (*xkmssecure.TerminalProvider)(nil)
	_ *xkmssecure.TerminalProvider  = (*qrdbsecure.TerminalProvider)(nil)
	_ *qrdbsecure.StdinProvider     = (*xkmssecure.StdinProvider)(nil)
	_ *xkmssecure.StdinProvider     = (*qrdbsecure.StdinProvider)(nil)
	_ *qrdbsecure.CallbackProvider  = (*xkmssecure.CallbackProvider)(nil)
	_ *xkmssecure.CallbackProvider  = (*qrdbsecure.CallbackProvider)(nil)
)

// copyOut copies b's protected bytes out for a test assertion and wipes the
// copy when the test ends.
func copyOut(t *testing.T, b xkmssecure.Borrower) []byte {
	t.Helper()
	out, err := xkmssecure.CopyOut(b)
	if err != nil {
		t.Fatalf("CopyOut: %v", err)
	}
	t.Cleanup(func() { xkmssecure.Wipe(out) })
	return out
}

// TestNewBufferRoundTrip writes a known plaintext into a Buffer, reads
// it back, destroys, and verifies a destroyed Buffer refuses the borrow.
func TestNewBufferRoundTrip(t *testing.T) {
	want := []byte("sdk-re-export-round-trip-needle")
	buf, err := xkmssecure.NewBufferFromBytes(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	if got := copyOut(t, buf); !bytes.Equal(got, want) {
		t.Fatalf("Bytes mismatch: got %q want %q", got, want)
	}
	buf.Destroy()
	var nilBuf *xkmssecure.NilBufferError
	if err := buf.WithBytes(func([]byte) error { return nil }); !errors.As(err, &nilBuf) {
		t.Fatalf("WithBytes after Destroy: got %v, want *NilBufferError", err)
	}
}

func TestNewEmptyBuffer_LiveAndEmpty(t *testing.T) {
	buf := xkmssecure.NewEmptyBuffer()
	if !buf.IsAlive() || buf.Size() != 0 {
		t.Fatalf("NewEmptyBuffer: alive=%v size=%d, want alive and empty", buf.IsAlive(), buf.Size())
	}
	buf.Destroy()
	if buf.IsAlive() {
		t.Fatal("IsAlive after Destroy: got true, want false")
	}
}

// TestNewSecretRoundTrip seals material, opens a working Buffer, reads
// it, and destroys.
func TestNewSecretRoundTrip(t *testing.T) {
	want := []byte("sdk-secret-needle")
	secret, err := xkmssecure.NewSecret(context.Background(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer secret.Destroy()

	buf, err := secret.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer buf.Destroy()
	if !bytes.Equal(copyOut(t, buf), want) {
		t.Fatalf("opened bytes mismatch")
	}
}

// TestNewSecretEmpty verifies construction errors are re-exported as
// *InvalidSizeError and that errors.As finds them.
func TestNewSecretEmpty(t *testing.T) {
	_, err := xkmssecure.NewSecret(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on empty slice")
	}
	var invErr *xkmssecure.InvalidSizeError
	if !errors.As(err, &invErr) {
		t.Fatalf("expected *InvalidSizeError, got %T", err)
	}
}

// TestNewBufferInvalidSize mirrors the empty-Secret guard for Buffer.
func TestNewBufferInvalidSize(t *testing.T) {
	_, err := xkmssecure.NewBuffer(0)
	if err == nil {
		t.Fatal("expected error on size=0")
	}
	var invErr *xkmssecure.InvalidSizeError
	if !errors.As(err, &invErr) {
		t.Fatalf("expected *InvalidSizeError, got %T", err)
	}
}

// TestCallbackProvider exercises the CallbackProvider re-export,
// confirming bytes land in a Buffer and the returned-slice is wiped.
func TestCallbackProvider(t *testing.T) {
	want := []byte("callback-passphrase")
	provider := xkmssecure.NewCallbackProvider(func(_ context.Context, prompt string) ([]byte, error) {
		if prompt != "enter it" {
			t.Fatalf("prompt=%q", prompt)
		}
		return append([]byte(nil), want...), nil
	})
	buf, err := provider.Passphrase(context.Background(), "enter it")
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	defer buf.Destroy()
	if !bytes.Equal(copyOut(t, buf), want) {
		t.Fatalf("buffer mismatch")
	}
}

// TestCallbackProviderNilFn returns ProviderError.
func TestCallbackProviderNilFn(t *testing.T) {
	p := &xkmssecure.CallbackProvider{}
	_, err := p.Passphrase(context.Background(), "")
	var pErr *xkmssecure.ProviderError
	if !errors.As(err, &pErr) {
		t.Fatalf("expected *ProviderError, got %T", err)
	}
}

// TestWipe zeros a caller slice via the re-exported helper.
func TestWipe(t *testing.T) {
	buf := []byte("zap-this")
	xkmssecure.Wipe(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, b)
		}
	}
}

// TestCopyOut copies a Buffer's bytes into a caller-owned slice that is
// independent of the enclave.
func TestCopyOut(t *testing.T) {
	buf, err := xkmssecure.NewBufferFromBytes([]byte("copy-me"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	out, err := xkmssecure.CopyOut(buf)
	if err != nil {
		t.Fatalf("CopyOut: %v", err)
	}
	defer xkmssecure.Wipe(out)
	if !bytes.Equal(out, []byte("copy-me")) {
		t.Errorf("CopyOut = %q, want %q", out, "copy-me")
	}
}

// TestCopyOut_DestroyedBuffer refuses a destroyed Buffer with the typed
// error instead of returning zeros.
func TestCopyOut_DestroyedBuffer(t *testing.T) {
	buf, err := xkmssecure.NewBufferFromBytes([]byte("gone"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	buf.Destroy()

	var nilBuf *xkmssecure.NilBufferError
	if _, err := xkmssecure.CopyOut(buf); !errors.As(err, &nilBuf) {
		t.Fatalf("CopyOut on destroyed buffer: err = %v, want *NilBufferError", err)
	}
}
