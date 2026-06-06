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

package pinselect

import (
	"errors"
	"strings"
	"testing"
)

func TestSoftwareStorageError_WithCause(t *testing.T) {
	cause := errors.New("permission denied")
	e := &SoftwareStorageError{Cause: cause}
	if !strings.Contains(e.Error(), "permission denied") {
		t.Fatalf("Error() should include the cause, got %q", e.Error())
	}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is(e, cause) = false, want true via Unwrap")
	}
}

func TestSoftwareStorageError_NilCause(t *testing.T) {
	e := &SoftwareStorageError{}
	if e.Error() == "" {
		t.Fatal("Error() returned empty for nil cause")
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should be nil when Cause is nil")
	}
}
