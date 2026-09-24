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

package ssh_test

import (
	"errors"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestErrors_Unwrap pins the Unwrap() contract for the error types that wrap
// an underlying cause, so errors.Is/errors.As keep working through them.
func TestErrors_Unwrap(t *testing.T) {
	underlying := errors.New("boom")

	t.Run("InvalidPublicKeyError", func(t *testing.T) {
		err := &sdkssh.InvalidPublicKeyError{Host: "h", Err: underlying}
		if !errors.Is(err, underlying) {
			t.Fatalf("errors.Is did not find the wrapped error")
		}
	})

	t.Run("ProtocolError", func(t *testing.T) {
		err := &sdkssh.ProtocolError{Message: "m", Err: underlying}
		if !errors.Is(err, underlying) {
			t.Fatalf("errors.Is did not find the wrapped error")
		}
	})
}

// TestEmbeddedFileStoreError_MessageAndUnwrap pins the Error() formatting
// and Unwrap() contract for the file-store constructors' wrapped failures.
func TestEmbeddedFileStoreError_MessageAndUnwrap(t *testing.T) {
	underlying := errors.New("boom")
	err := &sdkssh.EmbeddedFileStoreError{Op: "mkdir", Path: "/root/locked", Err: underlying}

	want := "sdk/ssh: file store mkdir /root/locked: boom"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, underlying) {
		t.Fatal("errors.Is did not find the wrapped error")
	}
}
