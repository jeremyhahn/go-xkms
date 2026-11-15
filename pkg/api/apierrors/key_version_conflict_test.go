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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
)

// versionConflicts are the shapes a key-version conflict reaches a
// transport in: the typed error, its sentinel, and joined with a failed
// cleanup, as rotateKey reports it.
func versionConflicts() map[string]error {
	conflict := &keyversion.VersionConflictError{KeyID: "k", Backend: "software"}
	return map[string]error{
		"typed":    conflict,
		"sentinel": keyversion.ErrVersionConflict,
		"joined":   errors.Join(conflict, errors.New("release claim: store unavailable")),
	}
}

// TestKeyVersionClassOf_VersionConflict proves a refused concurrent write of
// a key's version record is a precondition failure, not an internal fault.
func TestKeyVersionClassOf_VersionConflict(t *testing.T) {
	for name, err := range versionConflicts() {
		got, ok := KeyVersionClassOf(err)
		assert.True(t, ok, name)
		assert.Equal(t, ClassFailedPrecondition, got, name)
	}
}
