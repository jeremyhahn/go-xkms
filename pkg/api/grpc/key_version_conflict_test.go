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

package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
// rotation reports FailedPrecondition with the retry guidance kept, not
// Internal.
func TestMapKeyOpError_KeyVersionConflict(t *testing.T) {
	for name, err := range versionConflicts() {
		t.Run(name, func(t *testing.T) {
			st := status.Convert(mapKeyOpError(context.Background(), nil, err))
			if st.Code() != codes.FailedPrecondition {
				t.Errorf("code = %v, want FailedPrecondition", st.Code())
			}
			if name != "sentinel" && !strings.Contains(st.Message(), "retry") {
				t.Errorf("message %q lost the retry guidance", st.Message())
			}
		})
	}
}
