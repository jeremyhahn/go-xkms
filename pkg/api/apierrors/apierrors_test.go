// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package apierrors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

// TestClassOf_MatchesSentinel proves ClassOf resolves a matching error
// (bare, or wrapped through fmt.Errorf's %w) to its table entry's Class.
func TestClassOf_MatchesSentinel(t *testing.T) {
	table := []SentinelClass{
		{backend.ErrExportNotSupported, ClassUnimplemented},
		{backend.ErrKeyNotExportable, ClassPermissionDenied},
	}

	t.Run("bare sentinel", func(t *testing.T) {
		class, ok := ClassOf(table, backend.ErrExportNotSupported)
		assert.True(t, ok)
		assert.Equal(t, ClassUnimplemented, class)
	})

	t.Run("wrapped sentinel", func(t *testing.T) {
		wrapped := fmt.Errorf("export failed: %w", backend.ErrKeyNotExportable)
		class, ok := ClassOf(table, wrapped)
		assert.True(t, ok)
		assert.Equal(t, ClassPermissionDenied, class)
	})

	t.Run("first match wins", func(t *testing.T) {
		// A single error satisfying errors.Is for more than one entry
		// resolves to whichever entry is listed first, exactly like
		// keyOpSentinelCodes in pkg/api/grpc and pkg/api/mcp.
		first := errors.New("first")
		second := errors.New("second")
		ordered := []SentinelClass{
			{first, ClassInvalidArgument},
			{second, ClassNotFound},
		}
		multi := fmt.Errorf("%w: %w", first, second)
		class, ok := ClassOf(ordered, multi)
		assert.True(t, ok)
		assert.Equal(t, ClassInvalidArgument, class)
	})
}

// TestClassOf_NoMatch proves ClassOf reports false, not a zero-value
// success, for both a nil error and an error absent from the table -- so a
// caller can distinguish "unclassified" from a legitimate ClassInternal
// entry.
func TestClassOf_NoMatch(t *testing.T) {
	table := []SentinelClass{
		{backend.ErrExportNotSupported, ClassUnimplemented},
	}

	t.Run("nil error", func(t *testing.T) {
		class, ok := ClassOf(table, nil)
		assert.False(t, ok)
		assert.Equal(t, ClassInternal, class)
	})

	t.Run("unrelated error", func(t *testing.T) {
		class, ok := ClassOf(table, errors.New("unrelated"))
		assert.False(t, ok)
		assert.Equal(t, ClassInternal, class)
	})
}
