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

package rest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// TestMapKeyOpError_KeyVersionConflict proves a stale or concurrent key
// rotation reports 409 Conflict with the retry guidance kept, not a 500.
func TestMapKeyOpError_KeyVersionConflict(t *testing.T) {
	for name, err := range versionConflicts() {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mapKeyOpError(w, err)
			if w.Code != http.StatusConflict {
				t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
			}
			if name != "sentinel" && !strings.Contains(w.Body.String(), "retry") {
				t.Errorf("body %q lost the retry guidance", w.Body.String())
			}
		})
	}
}
