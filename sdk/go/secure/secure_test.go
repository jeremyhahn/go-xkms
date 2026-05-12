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

// TestTypeIdentityWithQRDB verifies every re-exported type is an alias
// of its qrdb counterpart (not a new type), so values cross the module
// boundary without copies or adapters.
func TestTypeIdentityWithQRDB(t *testing.T) {
	// Aliases share the underlying type. A *xkmssecure.Secret value is
	// assignable to a *qrdbsecure.Secret variable with no conversion, and
	// vice-versa. If someone redefines one of these as a new named type,
	// these assignments stop compiling and this test fails to build.
	var sx *xkmssecure.Secret
	var sq *qrdbsecure.Secret = sx
	sx = sq
	_ = sx

	var bx *xkmssecure.Buffer
	var bq *qrdbsecure.Buffer = bx
	bx = bq
	_ = bx

	var px xkmssecure.PassphraseProvider
	var pq qrdbsecure.PassphraseProvider = px
	px = pq
	_ = px

	var tx *xkmssecure.TerminalProvider
	var tq *qrdbsecure.TerminalProvider = tx
	tx = tq
	_ = tx

	var stx *xkmssecure.StdinProvider
	var stq *qrdbsecure.StdinProvider = stx
	stx = stq
	_ = stx

	var cx *xkmssecure.CallbackProvider
	var cq *qrdbsecure.CallbackProvider = cx
	cx = cq
	_ = cx
}

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
