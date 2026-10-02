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

package backend_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestStaticPassword(t *testing.T) {
	t.Run("Bytes returns correct byte slice", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		result := pw.Bytes()
		expected := []byte("test123")

		if len(result) != len(expected) {
			t.Errorf("Bytes() length = %v, want %v", len(result), len(expected))
		}

		for i := range result {
			if result[i] != expected[i] {
				t.Errorf("Bytes()[%d] = %v, want %v", i, result[i], expected[i])
			}
		}
	})

	t.Run("String never returns the password", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		if got := pw.String(); got != types.PasswordRedacted {
			t.Errorf("String() = %q, want %q", got, types.PasswordRedacted)
		}
		if got := fmt.Sprintf("%v %s", pw, pw); strings.Contains(got, "test123") {
			t.Errorf("formatting leaked the password: %q", got)
		}
	})

	t.Run("WithBytes lends the password", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		var seen string
		if err := pw.WithBytes(func(b []byte) error {
			seen = string(b)
			return nil
		}); err != nil {
			t.Fatalf("WithBytes() unexpected error: %v", err)
		}
		if seen != "test123" {
			t.Errorf("WithBytes() lent %q, want %q", seen, "test123")
		}
	})

	t.Run("WithBytes returns the callback error", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		want := errors.New("callback failed")
		if err := pw.WithBytes(func([]byte) error { return want }); !errors.Is(err, want) {
			t.Errorf("WithBytes() = %v, want %v", err, want)
		}
	})

	t.Run("Clear does not panic", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		// Should not panic
		pw.Clear()
	})
}

func TestNoPassword(t *testing.T) {
	t.Run("Bytes returns nil", func(t *testing.T) {
		pw := backend.NoPassword{}
		result := pw.Bytes()
		if result != nil {
			t.Errorf("Bytes() = %v, want nil", result)
		}
	})

	t.Run("String is redacted", func(t *testing.T) {
		pw := backend.NoPassword{}
		if got := pw.String(); got != types.PasswordRedacted {
			t.Errorf("String() = %q, want %q", got, types.PasswordRedacted)
		}
	})

	t.Run("WithBytes lends nil", func(t *testing.T) {
		pw := backend.NoPassword{}
		called := false
		if err := pw.WithBytes(func(b []byte) error {
			called = true
			if b != nil {
				t.Errorf("WithBytes() lent %v, want nil", b)
			}
			return nil
		}); err != nil || !called {
			t.Errorf("WithBytes() = %v, called = %v", err, called)
		}
	})

	t.Run("Clear does not panic", func(t *testing.T) {
		pw := backend.NoPassword{}
		// Should not panic
		pw.Clear()
	})
}
