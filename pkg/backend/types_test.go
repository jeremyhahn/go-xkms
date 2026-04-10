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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
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

	t.Run("String returns correct string", func(t *testing.T) {
		pw := backend.StaticPassword("test123")
		result, err := pw.String()
		if err != nil {
			t.Errorf("String() unexpected error: %v", err)
		}
		if result != "test123" {
			t.Errorf("String() = %v, want %v", result, "test123")
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

	t.Run("String returns empty string", func(t *testing.T) {
		pw := backend.NoPassword{}
		result, err := pw.String()
		if err != nil {
			t.Errorf("String() unexpected error: %v", err)
		}
		if result != "" {
			t.Errorf("String() = %v, want empty string", result)
		}
	})

	t.Run("Clear does not panic", func(t *testing.T) {
		pw := backend.NoPassword{}
		// Should not panic
		pw.Clear()
	})
}
