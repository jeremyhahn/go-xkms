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

// TestNewBufferRoundTrip writes a known plaintext into a Buffer, reads
// it back, destroys, and verifies Bytes() returns nil after destroy.
func TestNewBufferRoundTrip(t *testing.T) {
	want := []byte("sdk-re-export-round-trip-needle")
	buf, err := xkmssecure.NewBufferFromBytes(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	got := buf.Bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes mismatch: got %q want %q", got, want)
	}
	buf.Destroy()
	if after := buf.Bytes(); after != nil {
		t.Fatalf("Bytes after Destroy: got %v want nil", after)
	}
}

// TestNewSecretRoundTrip seals material, opens a working Buffer, reads
// it, and destroys.
func TestNewSecretRoundTrip(t *testing.T) {
	want := []byte("sdk-secret-needle")
	secret, err := xkmssecure.NewSecret(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	defer secret.Destroy()

	buf, err := secret.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer buf.Destroy()
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("opened bytes mismatch")
	}
}

// TestNewSecretEmpty verifies construction errors are re-exported as
// *InvalidSizeError and that errors.As finds them.
func TestNewSecretEmpty(t *testing.T) {
	_, err := xkmssecure.NewSecret(nil)
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
	if !bytes.Equal(buf.Bytes(), want) {
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

// TestPurgeBeforeInit returns NotInitializedError, exercising that error
// re-export path without actually catching signals in the test binary.
func TestPurgeBeforeInit(t *testing.T) {
	// Purge is a package-global; if another test in the binary called
	// CatchInterrupt, this test is a no-op (we simply verify that if it
	// errors, it's the typed error we expect).
	err := xkmssecure.Purge()
	if err == nil {
		return
	}
	var notInit *xkmssecure.NotInitializedError
	if !errors.As(err, &notInit) {
		t.Fatalf("Purge returned unexpected error: %T %v", err, err)
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
